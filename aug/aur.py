"""AUR metadata, local git mirrors of AUR package repos, and diffs.

The mirrors are bare-ish clones (no checkout) under DATA_DIR/aur. They are
only ever read with git plumbing, so nothing from an AUR repo is executed.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from .config import AUR_MIRROR_DIR, YAY_CACHE
from .feeds import http_get
from .system import run, vercmp

AUR = "https://aur.archlinux.org"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
VCS_SUFFIXES = ("-git", "-svn", "-hg", "-bzr", "-darcs", "-fossil")

# Hardened git invocation: no external diff/textconv, no fsmonitor, no
# file:// protocol for submodules, no pager.
GIT = ["git", "-c", "core.fsmonitor=", "-c", "protocol.file.allow=never",
       "-c", "core.hooksPath=/dev/null", "--no-pager"]


def is_vcs(name: str) -> bool:
    return name.endswith(VCS_SUFFIXES)


def rpc_info(names: list[str]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(names), 100):
        chunk = names[i:i + 100]
        qs = urllib.parse.urlencode([("arg[]", n) for n in chunk])
        data = json.loads(http_get(f"{AUR}/rpc/v5/info?{qs}"))
        if data.get("type") == "error":
            raise RuntimeError("AUR RPC hatası: " + data.get("error", "?"))
        for r in data.get("results", []):
            out[r["Name"]] = r
    return out


def git(repo: Path, *args: str, timeout: int = 120, check: bool = True) -> str:
    r = run([*GIT, "-C", str(repo), *args], timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])}: {r.stderr.strip()[:300]}")
    return r.stdout


def sync_mirror(pkgbase: str) -> Path:
    if not re.fullmatch(r"[a-z0-9@._+-]+", pkgbase):
        raise ValueError(f"geçersiz paket adı: {pkgbase!r}")
    repo = AUR_MIRROR_DIR / pkgbase
    url = f"{AUR}/{pkgbase}.git"
    if not (repo / ".git").exists() and not (repo / "HEAD").exists():
        AUR_MIRROR_DIR.mkdir(parents=True, exist_ok=True)
        r = run([*GIT, "clone", "--quiet", "--no-checkout", url, str(repo)], timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"git clone {pkgbase}: {r.stderr.strip()[:300]}")
    else:
        git(repo, "fetch", "--quiet", "--prune", "origin", timeout=300)
    return repo


def remote_head(repo: Path) -> str:
    for ref in ("origin/master", "origin/main", "origin/HEAD"):
        out = run([*GIT, "-C", str(repo), "rev-parse", "--verify", "--quiet", ref + "^{commit}"]).stdout.strip()
        if out:
            return out
    raise RuntimeError("uzak dalın son commit'i bulunamadı")


def ls_remote_head(pkgbase: str) -> str | None:
    r = run([*GIT, "ls-remote", f"{AUR}/{pkgbase}.git", "HEAD"], timeout=60)
    return r.stdout.split()[0] if r.returncode == 0 and r.stdout.strip() else None


def has_commit(repo: Path, commit: str) -> bool:
    return run([*GIT, "-C", str(repo), "cat-file", "-e", commit + "^{commit}"]).returncode == 0


def srcinfo_text(repo: Path, commit: str | None) -> str:
    if not commit:
        return ""
    r = run([*GIT, "-C", str(repo), "show", f"{commit}:.SRCINFO"])
    return r.stdout if r.returncode == 0 else ""


def srcinfo_at(repo: Path, commit: str) -> dict:
    text = srcinfo_text(repo, commit)
    return parse_srcinfo(text) if text else {}


def parse_srcinfo(text: str) -> dict:
    """Return pkgbase-level keys plus aggregated source/checksum lists."""
    info: dict = {"sources": [], "checksums": [], "install": [], "validpgpkeys": [], "depends": []}
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or " = " not in line:
            continue
        key, val = line.split(" = ", 1)
        if key in ("pkgbase", "pkgname"):
            section = key
            info.setdefault(key + "s", []).append(val)
            continue
        if key.startswith("source"):
            info["sources"].append(val)
        elif re.fullmatch(r"(md5|sha1|sha224|sha256|sha384|sha512|b2|ck)sums(_\w+)?", key):
            info["checksums"].append(val)
        elif key == "install":
            info["install"].append(val)
        elif key == "validpgpkeys":
            info["validpgpkeys"].append(val)
        elif re.fullmatch(r"(make|check)?depends(_\w+)?", key):
            info["depends"].append(val)
        elif section == "pkgbase" and key in ("pkgver", "pkgrel", "epoch", "url"):
            info[key] = val
    return info


def srcinfo_version(info: dict) -> str | None:
    if not info.get("pkgver"):
        return None
    v = f"{info['pkgver']}-{info.get('pkgrel', '1')}"
    return f"{info['epoch']}:{v}" if info.get("epoch") else v


def find_base_commit(repo: Path, pkgbase: str, pkgname: str, installed_version: str) -> tuple[str | None, str]:
    """Commit the installed package was built from, and how we know.

    1. yay's build dir HEAD (what yay last built), if its .SRCINFO version
       matches the installed version (VCS packages: accepted as is).
    2. Otherwise the newest mirror commit whose .SRCINFO version matches.
    """
    ydir = YAY_CACHE / pkgbase
    if (ydir / ".git").exists():
        head = run([*GIT, "-C", str(ydir), "rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).stdout.strip()
        if head and has_commit(repo, head):
            v = srcinfo_version(srcinfo_at(repo, head))
            if v == installed_version or is_vcs(pkgname):
                return head, "yay derleme klasörü"
    log = git(repo, "log", "--format=%H", remote_head(repo))
    for commit in log.split():
        if srcinfo_version(srcinfo_at(repo, commit)) == installed_version:
            return commit, "sürüm eşleşmesi"
    return None, "bulunamadı"


def has_ref(repo: Path, ref: str) -> bool:
    return run([*GIT, "-C", str(repo), "rev-parse", "--verify", "--quiet", ref]).returncode == 0


def diff(repo: Path, base: str | None, target: str, max_chars: int) -> dict:
    a = base or EMPTY_TREE
    common = ["--no-ext-diff", "--no-textconv", "--no-color", "-M"]
    stat = git(repo, "diff", *common, "--stat=120", a, target)
    text = git(repo, "diff", *common, "--unified=5", a, target)
    truncated = len(text) > max_chars
    return {
        "base": base,
        "target": target,
        "stat": stat,
        "text": text[:max_chars],
        "chars": len(text),
        "truncated": truncated,
    }


def commits_between(repo: Path, base: str | None, target: str) -> list[dict]:
    rng = f"{base}..{target}" if base else target
    out = git(repo, "log", "--format=%H%x1f%an%x1f%ae%x1f%ct%x1f%s", rng)
    commits = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 5:
            commits.append({"hash": parts[0], "author": parts[1], "email": parts[2],
                            "time": int(parts[3]), "subject": parts[4]})
    return commits


def previous_authors(repo: Path, base: str | None) -> set[str]:
    if not base:
        return set()
    return set(git(repo, "log", "--format=%ae", base).split())


def needs_update(pkgname: str, installed: str, aur_version: str) -> bool:
    return vercmp(aur_version, installed) > 0
