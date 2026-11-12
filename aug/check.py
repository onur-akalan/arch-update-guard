"""The collector: builds report.json from the system, the AUR and the feeds."""

from __future__ import annotations

import logging
import time
import traceback
from datetime import datetime, timezone

from . import aur, deps, feeds, review, rules, runtime, state, system
from .config import REPORT_FILE, RUNTIME_DIR, atomic_write_json, load_settings, read_json

log = logging.getLogger("aug")

# Repo packages whose update deserves a closer look or a reboot.
IMPORTANT = {
    "linux", "linux-lts", "linux-zen", "linux-hardened", "linux-firmware", "systemd", "glibc", "pacman",
    "sudo", "openssl", "openssh", "grub", "mkinitcpio", "intel-ucode", "amd-ucode", "mesa", "nvidia",
    "plasma-desktop", "kwin", "pipewire", "wireplumber", "networkmanager", "python", "gcc-libs", "icu",
}
REBOOT_HINT = {"linux", "linux-lts", "linux-zen", "linux-hardened", "systemd", "glibc", "intel-ucode",
               "amd-ucode", "linux-firmware", "mesa", "nvidia"}

PROGRESS_FILE = RUNTIME_DIR / "progress.json"


def _progress(msg: str, done: int = 0, total: int = 0) -> None:
    try:
        atomic_write_json(PROGRESS_FILE, {"message": msg, "done": done, "total": total, "at": time.time()})
    except OSError:
        pass


def load_report() -> dict | None:
    return read_json(REPORT_FILE, None)


def _aur_item(name: str, installed: str, meta: dict | None, settings: dict, st: dict,
              keep_keys: set[str]) -> dict | None:
    """Return a dashboard item for one foreign package, or None if nothing to show."""
    base_item = {"name": name, "installed": installed, "kind": "aur"}
    if meta is None:
        return {**base_item, "status": "missing", "new_version": None,
                "findings": [rules._f(rules.MEDIUM, "not-in-aur", "Paket AUR'da yok",
                                      "Silinmiş, yeniden adlandırılmış ya da elle kurulmuş olabilir. "
                                      "AUR'dan kaldırılan paketler bazen zararlı olduğu için silinir.")]}

    pkgbase = meta["PackageBase"]
    vcs = aur.is_vcs(name)
    update = aur.needs_update(name, installed, meta["Version"])
    if not update and not vcs:
        # Still record the maintainer baseline for later comparison.
        st["maintainers"].setdefault(pkgbase, meta.get("Maintainer"))
        return None

    repo = aur.sync_mirror(pkgbase)
    target = aur.remote_head(repo)
    base, base_source = aur.find_base_commit(repo, pkgbase, name, installed)
    if vcs and not update and base == target:
        st["maintainers"].setdefault(pkgbase, meta.get("Maintainer"))
        return None

    d = aur.diff(repo, base, target, settings["review"]["max_diff_chars"])
    commits = aur.commits_between(repo, base, target)
    old_info = aur.srcinfo_at(repo, base) if base else {}
    new_info = aur.srcinfo_at(repo, target)
    known = st["maintainers"].get(pkgbase)
    findings = rules.scan(pkgname=name, diff_text=d["text"], has_base=bool(base), old_info=old_info,
                          new_info=new_info, commits=commits, prev_authors=aur.previous_authors(repo, base),
                          meta=meta, known_maintainer=known)

    llm = None
    rcfg = settings["review"]
    if rcfg["enabled"]:
        key = state.review_key(pkgbase, target, rcfg["active_provider"])
        keep_keys.add(key)
        cached = st["reviews"].get(key)
        if cached and cached.get("status") == "ok":
            llm = cached
        else:
            ctx = {"pkgname": name, "pkgbase": pkgbase, "installed": installed, "new_version": meta["Version"],
                   "meta": meta, "has_base": bool(base), "commits": commits, "static_findings": findings,
                   "stat": d["stat"], "diff": d["text"], "diff_chars": d["chars"], "truncated": d["truncated"]}
            llm = review.review(ctx, settings)
            st["reviews"][key] = llm

    new_aur_deps, new_repo_deps = deps.review_new_deps(name, old_info, new_info, settings, st, keep_keys)
    if new_aur_deps:
        findings.append(rules._f(rules.MEDIUM, "new-aur-dependency",
                                 "Güncelleme, kurulu olmayan yeni bir AUR paketini bağımlılık olarak ekliyor",
                                 ", ".join(d["name"] for d in deps.flatten(new_aur_deps))
                                 + ". yay bunları da derleyip kurar; aşağıda ayrıca incelendiler."))
    if new_repo_deps:
        findings.append(rules._f(rules.INFO, "new-repo-dependency",
                                 "Resmi depolardan yeni bağımlılık kurulacak", ", ".join(new_repo_deps)))
    status = deps.combine_status(findings, llm, [d["status"] for d in new_aur_deps])

    hold_until = int(meta["LastModified"]) + settings["hold_days"] * 86400
    akey = deps.approval_key(target, new_aur_deps)
    approval = st["approvals"].get(name)
    approved = bool(approval and approval.get("commit") == akey)
    held = time.time() < hold_until
    return {
        **base_item,
        "pkgbase": pkgbase,
        "new_version": meta["Version"],
        "vcs": vcs,
        "status": status,
        "findings": findings,
        "llm": llm,
        "diff": d,
        "commits": commits,
        "base_source": base_source,
        "target": target,
        "approval_key": akey,
        "new_aur_deps": new_aur_deps,
        "new_repo_deps": new_repo_deps,
        "maintainer": meta.get("Maintainer"),
        "known_maintainer": known,
        "votes": meta.get("NumVotes"),
        "popularity": meta.get("Popularity"),
        "out_of_date": bool(meta.get("OutOfDate")),
        "last_modified": int(meta["LastModified"]),
        "first_submitted": int(meta.get("FirstSubmitted") or 0),
        "hold_until": hold_until,
        "held": held,
        "approved": approved,
        "auto_ok": status == "clean" and not held,
        "aur_url": f"{aur.AUR}/packages/{name}",
    }


def run(settings: dict | None = None) -> dict:
    settings = settings or load_settings()
    with state.check_lock():
        try:
            return _run(settings)
        finally:
            PROGRESS_FILE.unlink(missing_ok=True)


def _run(settings: dict) -> dict:
    started = time.time()
    errors: list[str] = []
    st = state.load()

    _progress("Kurulu paketler okunuyor")
    installed = system.installed_packages()
    foreign = {n: v for n, v in system.foreign_packages().items() if not n.endswith("-debug")}

    _progress("Resmi depo güncellemeleri kontrol ediliyor")
    try:
        repo = system.repo_updates()
    except Exception as e:
        repo = []
        errors.append(f"Resmi depo kontrolü başarısız: {e}")
    repo_map = system.repo_of([r["name"] for r in repo])
    for r in repo:
        r["repo"] = repo_map.get(r["name"], "?")
        r["important"] = r["name"] in IMPORTANT
        r["reboot"] = r["name"] in REBOOT_HINT
        r["major"] = r["old"].split(".")[0].split(":")[-1] != r["new"].split(".")[0].split(":")[-1]

    _progress("AUR bilgileri alınıyor")
    aur_items: list[dict] = []
    keep: set[str] = set()
    try:
        metas = aur.rpc_info(sorted(foreign))
    except Exception as e:
        metas = None
        errors.append(f"AUR'a ulaşılamadı: {e}")
    if metas is not None:
        names = sorted(foreign)
        for i, name in enumerate(names, 1):
            _progress(f"AUR: {name}", i, len(names))
            try:
                item = _aur_item(name, foreign[name], metas.get(name), settings, st, keep)
            except Exception as e:
                log.exception("aur item %s", name)
                item = {"name": name, "installed": foreign[name], "kind": "aur", "status": "error",
                        "error": f"{type(e).__name__}: {e}"[:400], "findings": []}
            if item:
                aur_items.append(item)
            state.save(st)  # keep finished reviews even if a later package fails

    _progress("Arch haberleri alınıyor")
    last_up = system.last_full_upgrade()
    try:
        news = feeds.fetch_news()
    except Exception as e:
        news = []
        errors.append(f"Arch haberleri alınamadı: {e}")
    read = set(st["news_read"])
    for n in news:
        n["read"] = n["id"] in read
        n["since_last_upgrade"] = bool(last_up and n["published"]
                                       and datetime.fromisoformat(n["published"]) > last_up)

    _progress("Güvenlik açıkları kontrol ediliyor")
    pending = {r["name"]: r["new"] for r in repo}
    try:
        vulns = feeds.vulnerable_installed(feeds.fetch_advisories(), installed, pending)
    except Exception as e:
        vulns = []
        errors.append(f"Güvenlik takipçisine ulaşılamadı: {e}")
    fixes = {v["package"] for v in vulns if v["fix_pending"]}
    for r in repo:
        r["fixes_cve"] = r["name"] in fixes

    _progress("Çalışan servisler ve eski kütüphaneler kontrol ediliyor")
    try:
        rt = runtime.snapshot()
    except Exception as e:
        log.exception("runtime snapshot")
        rt = {"services": [], "user_processes": [], "open_ports": [], "reboot_packages": [],
              "reboot_recommended": False, "kernel_updated": False, "boot_time": 0, "_pkg_units": {}}
        errors.append(f"Çalışan servisler okunamadı: {e}")
    pkg_units = rt.pop("_pkg_units")

    _progress("Açıkların etkilediği uygulamalar bulunuyor")
    explicit = set(system.run(["pacman", "-Qeq"]).stdout.split())
    users_cache: dict[str, list[str]] = {}
    sev_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    for v in vulns:
        p = v["package"]
        if p not in users_cache:
            users_cache[p] = runtime.explicit_users(p, explicit)
        v["explicit"] = p in explicit
        v["used_by"] = users_cache[p]
        v["services"] = sorted(pkg_units.get(p, ()))
        # Higher = deal with it first.
        v["priority"] = (sev_rank.get(v["severity"], 0) * 10 + (8 if v["services"] else 0)
                         + (5 if v["fix_pending"] else 0) + min(len(v["used_by"]), 20) / 10
                         - (100 if v.get("stale") else 0))
    vulns.sort(key=lambda v: -v["priority"])

    _progress("Sistem durumu okunuyor")
    report = {
        "generated_at": int(time.time()),
        "duration": round(time.time() - started, 1),
        "errors": errors,
        "repo": repo,
        "aur": aur_items,
        "news": news,
        "vulns": vulns,
        "runtime": rt,
        "system": {
            "last_upgrade": last_up.isoformat() if last_up else None,
            "reboot_needed": rt["kernel_updated"],
            "pacnew": system.pacnew_files(),
            "disk_free_gb": round(system.disk_free_gb(), 1),
            "autosnap": system.autosnap_installed(),
            "installed_count": len(installed),
            "foreign_count": len(foreign),
        },
        "review_provider": settings["review"]["active_provider"] if settings["review"]["enabled"] else None,
        "hold_days": settings["hold_days"],
    }
    st["last_check"] = report["generated_at"]
    state.prune_reviews(st, keep)
    state.save(st)
    atomic_write_json(REPORT_FILE, report)
    return report


def summary(report: dict) -> dict:
    aur_items = report["aur"]
    return {
        "repo": len(report["repo"]),
        "aur": sum(1 for a in aur_items if a.get("new_version")),
        "danger": sum(1 for a in aur_items if a["status"] == "danger"),
        "warning": sum(1 for a in aur_items if a["status"] in ("warning", "missing")),
        "unread_news": sum(1 for n in report["news"] if n["since_last_upgrade"] and not n["read"]),
        "vulns_fixable": sum(1 for v in report["vulns"] if v["fix_pending"]),
        "critical_vulns": sum(1 for v in report["vulns"]
                              if v["severity"] in ("Critical", "High") and not v.get("stale")),
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
