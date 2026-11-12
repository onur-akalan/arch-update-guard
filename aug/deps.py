"""New dependencies brought in by an AUR update.

yay silently builds any AUR package an update newly depends on, so such a
package must be reviewed too - otherwise an attacker could put the payload
in a fresh dependency instead of the package the user is watching.
"""

from __future__ import annotations

import re
import urllib.parse
import json

from . import aur, review, rules, state
from .feeds import http_get
from .system import run

MAX_DEPTH = 2


def dep_name(spec: str) -> str:
    return re.split(r"[<>=:]", spec.strip(), maxsplit=1)[0].strip()


def unsatisfied(specs: list[str]) -> list[str]:
    """Dependency specs not satisfied by installed packages (pacman -T)."""
    specs = sorted({s.split(":", 1)[0].strip() for s in specs if s.strip()})
    if not specs:
        return []
    r = run(["pacman", "-T", *specs])
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def in_repos(name: str) -> bool:
    return run(["pacman", "-Sp", "--print-format", "%n", name]).returncode == 0


def aur_lookup(name: str) -> tuple[dict | None, list[str]]:
    """AUR package for a dependency name: exact name first, else a provider."""
    info = aur.rpc_info([name])
    if name in info:
        return info[name], []
    data = json.loads(http_get(f"{aur.AUR}/rpc/v5/search/{urllib.parse.quote(name)}?by=provides"))
    results = sorted(data.get("results", []), key=lambda r: -(r.get("NumVotes") or 0))
    if not results:
        return None, []
    best = aur.rpc_info([results[0]["Name"]]).get(results[0]["Name"])
    return best, [r["Name"] for r in results]


def new_dependencies(old_info: dict, new_info: dict) -> list[str]:
    old = {dep_name(d) for d in old_info.get("depends", [])}
    return sorted({d for d in new_info.get("depends", []) if dep_name(d) not in old})


def review_new_deps(parent: str, old_info: dict, new_info: dict, settings: dict, st: dict,
                    keep_keys: set[str], depth: int = 1, seen: set[str] | None = None) -> tuple[list[dict], list[str]]:
    """Returns (AUR dependency records, newly added official-repo deps)."""
    seen = seen if seen is not None else set()
    missing = unsatisfied(new_dependencies(old_info, new_info))
    aur_deps, repo_deps = [], []
    for spec in missing:
        name = dep_name(spec)
        if name in seen:
            continue
        seen.add(name)
        if in_repos(name):
            repo_deps.append(name)
            continue
        aur_deps.append(_review_dep(parent, name, settings, st, keep_keys, depth, seen))
    return aur_deps, repo_deps


def _review_dep(parent: str, name: str, settings: dict, st: dict, keep_keys: set[str],
                depth: int, seen: set[str]) -> dict:
    rec: dict = {"name": name, "required_by": parent}
    try:
        meta, providers = aur_lookup(name)
    except Exception as e:
        return {**rec, "status": "error", "error": f"AUR sorgusu başarısız: {e}", "findings": []}
    if not meta:
        return {**rec, "status": "error", "findings": [],
                "error": "Ne resmi depolarda ne de AUR'da bulunamadı; güncelleme büyük olasılıkla derlenemez."}
    pkg = meta["Name"]
    repo = aur.sync_mirror(meta["PackageBase"])
    target = aur.remote_head(repo)
    d = aur.diff(repo, None, target, settings["review"]["max_diff_chars"])
    info = aur.srcinfo_at(repo, target)
    commits = aur.commits_between(repo, None, target)[:20]
    findings = rules.scan(pkgname=pkg, diff_text=d["text"], has_base=False, old_info={}, new_info=info,
                          commits=commits, prev_authors=set(), meta=meta, known_maintainer=None)
    findings = [f for f in findings if f["code"] != "no-base"]
    if len(providers) > 1:
        findings.append(rules._f(rules.INFO, "multiple-providers",
                                 f"'{name}' birden fazla AUR paketi tarafından sağlanıyor; yay hangisini kuracağını soracak",
                                 ", ".join(providers[:8])))

    llm = None
    rcfg = settings["review"]
    if rcfg["enabled"]:
        key = state.review_key(meta["PackageBase"], target, rcfg["active_provider"])
        keep_keys.add(key)
        cached = st["reviews"].get(key)
        if cached and cached.get("status") == "ok":
            llm = cached
        else:
            ctx = {"pkgname": pkg, "pkgbase": meta["PackageBase"], "installed": "(not installed)",
                   "new_version": meta["Version"], "meta": meta, "has_base": False, "commits": commits,
                   "static_findings": findings, "stat": d["stat"], "diff": d["text"], "diff_chars": d["chars"],
                   "truncated": d["truncated"],
                   "note": f"This package is not installed yet. It is a NEW dependency that the update of "
                           f"'{parent}' would pull in and build automatically. Review the whole package."}
            llm = review.review(ctx, settings)
            st["reviews"][key] = llm

    nested: list[dict] = []
    nested_repo: list[str] = []
    if depth < MAX_DEPTH:
        nested, nested_repo = review_new_deps(pkg, {}, info, settings, st, keep_keys, depth + 1, seen)
    elif unsatisfied(info.get("depends", [])):
        findings.append(rules._f(rules.MEDIUM, "deep-deps",
                                 "Bu bağımlılığın da kurulu olmayan bağımlılıkları var ve incelenmedi"))

    return {**rec, "name": pkg, "pkgbase": meta["PackageBase"], "version": meta["Version"], "target": target,
            "status": combine_status(findings, llm, [n["status"] for n in nested]),
            "findings": findings, "llm": llm, "diff": d, "commits": commits,
            "maintainer": meta.get("Maintainer"), "votes": meta.get("NumVotes"),
            "first_submitted": int(meta.get("FirstSubmitted") or 0), "last_modified": int(meta["LastModified"]),
            "aur_url": f"{aur.AUR}/packages/{pkg}", "deps": nested, "repo_deps": nested_repo}


STATUS_RANK = {"clean": 0, "unreviewed": 1, "warning": 2, "error": 3, "danger": 4}


def combine_status(findings: list[dict], llm: dict | None, child_statuses: list[str] = ()) -> str:
    worst = rules.worst(findings)
    if worst == rules.HIGH or (llm and llm.get("verdict") == "malicious"):
        own = "danger"
    elif worst == rules.MEDIUM or (llm and llm.get("verdict") == "suspicious"):
        own = "warning"
    elif not llm or llm.get("status") != "ok":
        own = "unreviewed"
    else:
        own = "clean"
    return max([own, *child_statuses], key=lambda s: STATUS_RANK.get(s, 3))


def flatten(deps: list[dict]) -> list[dict]:
    out = []
    for d in deps:
        out.append(d)
        out.extend(flatten(d.get("deps", [])))
    return out


def approval_key(target: str, deps: list[dict]) -> str:
    flat = sorted(f"{d['name']}@{d.get('target', '?')}" for d in flatten(deps))
    return target if not flat else target + "|" + ",".join(flat)
