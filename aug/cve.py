"""CVE details from NVD and evidence of whether the installed version is fixed.

NVD rate-limits anonymous clients to 5 requests per 30 s, so results are
cached on disk and each check only spends a bounded amount of time fetching;
the rest arrives on later checks. An optional NVD API key raises the limit.
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .config import DATA_DIR, atomic_write_json, read_json
from .system import vercmp

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CACHE_FILE = DATA_DIR / "cve-cache.json"
TTL = 7 * 86400
MISSING_TTL = 86400

# Arch package name -> CPE product names it corresponds to.
ALIASES = {
    "pam": {"linux-pam", "linux_pam"},
    "linux": {"linux_kernel"}, "linux-lts": {"linux_kernel"}, "linux-zen": {"linux_kernel"},
    "lua51": {"lua"}, "lua52": {"lua"}, "lua53": {"lua"},
    "jdk8-openjdk": {"jdk", "openjdk", "jre"}, "jre8-openjdk": {"jdk", "openjdk", "jre"},
    "jre8-openjdk-headless": {"jdk", "openjdk", "jre"},
    "jre17-openjdk": {"jdk", "openjdk", "jre"}, "jdk17-openjdk": {"jdk", "openjdk", "jre"},
    "openjpeg2": {"openjpeg"}, "ruby-bundler": {"bundler"}, "gnupg": {"gnupg", "gnupg2"},
    "xz": {"xz", "xz-utils"}, "util-linux": {"util-linux"}, "openssh": {"openssh"},
}


def _get(cve_id: str, api_key: str | None) -> dict | None:
    headers = {"User-Agent": f"arch-update-guard/{__version__}"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(NVD_URL + cve_id, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    vulns = data.get("vulnerabilities") or []
    return parse(vulns[0]["cve"]) if vulns else None


def parse(c: dict) -> dict:
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    cvss = None
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            d = m.get("cvssData", {})
            cvss = {"version": d.get("version"), "score": d.get("baseScore"),
                    "severity": d.get("baseSeverity") or m.get("baseSeverity"),
                    "vector": d.get("vectorString"),
                    "attack_vector": d.get("attackVector") or d.get("accessVector"),
                    "user_interaction": d.get("userInteraction"),
                    "privileges": d.get("privilegesRequired") or d.get("authentication")}
            break
    cpes = []
    for cfg in c.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable"):
                    continue
                parts = cm["criteria"].split(":")
                if len(parts) < 6 or parts[2] != "a":
                    continue  # applications only; OS entries (debian, ubuntu…) say nothing about upstream
                cpes.append({"vendor": parts[3], "product": parts[4], "version": parts[5],
                             "update": parts[6] if len(parts) > 6 else "*",
                             "start_incl": cm.get("versionStartIncluding"),
                             "start_excl": cm.get("versionStartExcluding"),
                             "end_incl": cm.get("versionEndIncluding"),
                             "end_excl": cm.get("versionEndExcluding")})
    refs = [{"url": r["url"], "tags": r.get("tags", [])} for r in c.get("references", [])][:25]
    return {"id": c["id"], "status": c.get("vulnStatus"), "published": c.get("published"),
            "description": desc, "cvss": cvss, "cpes": cpes[:200], "references": refs}


def fetch_many(cve_ids: list[str], budget_seconds: float, api_key: str | None = None) -> tuple[dict, int]:
    """Return ({cve: info}, number still pending) using the cache first."""
    cache = read_json(CACHE_FILE, {})
    now = time.time()
    out, todo = {}, []
    for c in dict.fromkeys(cve_ids):
        e = cache.get(c)
        if e and now - e["fetched"] < (TTL if e.get("data") else MISSING_TTL):
            if e.get("data"):
                out[c] = e["data"]
        else:
            todo.append(c)
    pause = 0.7 if api_key else 6.5
    started = time.time()
    done = 0
    for c in todo:
        if time.time() - started > budget_seconds:
            break
        try:
            info = _get(c, api_key)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):  # rate limited: stop for this run
                break
            info = None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError):
            break
        cache[c] = {"fetched": time.time(), "data": info}
        if info:
            out[c] = info
        done += 1
        if done % 5 == 0:
            atomic_write_json(CACHE_FILE, cache)
        time.sleep(pause)
    atomic_write_json(CACHE_FILE, cache)
    return out, len(todo) - done


def _names(pkg: str) -> set[str]:
    p = pkg.lower()
    names = {p, re.sub(r"\d+$", "", p), p.removeprefix("lib"), re.sub(r"-(bin|git|openjdk|headless)$", "", p),
             p.replace("-", "_")}
    return names | ALIASES.get(p, set())


def _upstream(version: str) -> str:
    return version.split(":", 1)[-1].rsplit("-", 1)[0]


def evidence(info: dict, pkg: str, installed: str) -> dict:
    """Is the installed upstream version affected according to NVD data?

    affected: True / False / None (no usable data). source says how we know.
    """
    up = _upstream(installed)
    names = _names(pkg)
    matches = [c for c in info.get("cpes", []) if c["product"] in names or c["product"].replace("_", "-") in names]
    fixed_in: set[str] = set()
    try:
        if matches:
            ranges = [c for c in matches if any(c[k] for k in ("start_incl", "start_excl", "end_incl", "end_excl"))]
            exact = [c for c in matches if c not in ranges and c["version"] not in ("*", "-")]
            for c in ranges:
                if c["end_excl"]:
                    fixed_in.add(c["end_excl"])
                lo_ok = ((not c["start_incl"] or vercmp(up, c["start_incl"]) >= 0)
                         and (not c["start_excl"] or vercmp(up, c["start_excl"]) > 0))
                hi_ok = ((not c["end_excl"] or vercmp(up, c["end_excl"]) < 0)
                         and (not c["end_incl"] or vercmp(up, c["end_incl"]) <= 0))
                if lo_ok and hi_ok and (c["end_excl"] or c["end_incl"]):
                    return {"affected": True, "source": "NVD sürüm aralığı", "fixed_in": sorted(fixed_in)}
            for c in exact:
                if c["update"] in ("*", "-") and vercmp(up, c["version"]) == 0:
                    return {"affected": True, "source": "NVD etkilenen sürüm listesi", "fixed_in": sorted(fixed_in)}
            if any(c["end_excl"] or c["end_incl"] for c in ranges):
                return {"affected": False, "source": "NVD sürüm aralığı", "fixed_in": sorted(fixed_in)}
            if exact and all(vercmp(up, c["version"]) > 0 for c in exact):
                last = max((c["version"] for c in exact), key=lambda v: (len(v.split(".")), v))
                return {"affected": False, "source": f"NVD listesindeki tüm etkilenen sürümlerden yeni (son: {last})",
                        "fixed_in": []}
        # Fall back to "before X" in the description, when it names this product.
        desc = info.get("description", "")
        if any(n.replace("_", " ") in desc.lower() or n in desc.lower() for n in names if len(n) > 2):
            befores = re.findall(r"\bbefore (?:version )?v?(\d+(?:\.\d+)+[a-z]?)", desc)
            if befores:
                fixed_in.update(befores)
                if all(vercmp(up, b) < 0 for b in befores):
                    return {"affected": True, "source": "CVE açıklaması", "fixed_in": sorted(fixed_in)}
                if all(vercmp(up, b) >= 0 for b in befores):
                    return {"affected": False, "source": "CVE açıklaması", "fixed_in": sorted(fixed_in)}
    except Exception:
        pass
    return {"affected": None, "source": "NVD'de sürüm bilgisi yok" if not matches else "karşılaştırılamadı",
            "fixed_in": sorted(fixed_in)}


# --- Arch's own patches ----------------------------------------------------
# Upstream version ranges cannot see fixes Arch backports as patches (e.g.
# lua51 5.1.5 carries cve-2014-5461.patch). Arch packaging names such patches
# after the CVE, so the PKGBUILD itself is the strongest evidence.

PKGBUILD_CACHE = DATA_DIR / "pkgbuild-cache.json"
PKGBUILD_URL = "https://gitlab.archlinux.org/archlinux/packaging/packages/{}/-/raw/main/PKGBUILD"


def pkgbase(pkg: str, installed: str) -> str:
    desc = Path(f"/var/lib/pacman/local/{pkg}-{installed}/desc")
    try:
        lines = desc.read_text().splitlines()
        return lines[lines.index("%BASE%") + 1]
    except (OSError, ValueError, IndexError):
        return pkg


def _gitlab_name(base: str) -> str:
    # GitLab project paths replace '+' (e.g. libsigc++ -> libsigcplusplus).
    return base.replace("++", "plusplus").replace("+", "plus")


def fetch_pkgbuild(base: str) -> str | None:
    cache = read_json(PKGBUILD_CACHE, {})
    e = cache.get(base)
    if e and time.time() - e["fetched"] < 86400:
        return e["text"]
    try:
        req = urllib.request.Request(PKGBUILD_URL.format(_gitlab_name(base)),
                                     headers={"User-Agent": f"arch-update-guard/{__version__}"})
        with urllib.request.urlopen(req, timeout=20) as r:
            text = r.read().decode("utf-8", "replace")[:200_000]
    except urllib.error.HTTPError as err:
        text = None if err.code == 404 else (e or {}).get("text")
        if err.code != 404:
            return text
    except (urllib.error.URLError, TimeoutError):
        return (e or {}).get("text")
    cache[base] = {"fetched": time.time(), "text": text}
    atomic_write_json(PKGBUILD_CACHE, cache)
    return text


def _pkgbuild_version(text: str) -> str | None:
    def val(k):
        m = re.search(rf"^{k}=['\"]?([^'\"\s]+)", text, re.M)
        return m[1] if m else None
    ver, rel, ep = val("pkgver"), val("pkgrel"), val("epoch")
    if not ver or "$" in ver:
        return None
    v = f"{ver}-{rel or '1'}"
    return f"{ep}:{v}" if ep else v


def arch_patch_evidence(pkg: str, installed: str, cve_ids: list[str]) -> dict[str, dict]:
    """cve -> evidence for CVEs that Arch's PKGBUILD patches explicitly."""
    base = pkgbase(pkg, installed)
    text = fetch_pkgbuild(base)
    if not text:
        return {}
    low = text.lower()
    pver = _pkgbuild_version(text)
    out = {}
    for c in cve_ids:
        if c.lower() not in low:
            continue
        if pver and vercmp(pver, installed) > 0:
            out[c] = {"affected": True, "source": f"Arch yaması {pver} sürümünde; henüz kurulu değil",
                      "fixed_in": [pver], "arch_patch": True}
        else:
            out[c] = {"affected": False, "source": f"Arch paketi bu CVE için yama uyguluyor ({base} PKGBUILD)",
                      "fixed_in": [], "arch_patch": True}
    return out


def verdict(cves: list[dict]) -> str | None:
    """Combine per-CVE evidence: 'fixed' if all fixed, 'open' if any open, else None."""
    states = [(c.get("evidence") or {}).get("affected") for c in cves]
    if not states:
        return None
    if any(s is True for s in states):
        return "open"
    if all(s is False for s in states):
        return "fixed"
    return None
