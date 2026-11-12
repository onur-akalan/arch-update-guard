"""Known incidents: published lists of compromised AUR packages, and local traces.

After the June 2026 "Atomic Arch" campaign (orphaned AUR packages adopted and
given build-time `npm install atomic-lockfile` / `bun install js-digest`),
Arch published the affected package names. This module checks whether any
package on such a list was installed or updated on this machine during or
after the campaign, including packages removed since, and looks for the
traces the campaign left: a fake `sudo` in a user-writable PATH directory
or a shell alias/function that wraps it.
"""

from __future__ import annotations

import gzip
import re
import time
from datetime import datetime
from pathlib import Path

from .config import DATA_DIR, HOME, atomic_write_json, read_json
from .feeds import http_get
from .i18n import t

CACHE = DATA_DIR / "compromised-cache.json"
TTL = 12 * 3600
NAME = re.compile(r"^[a-z0-9@._+-]+$")
PACMAN_LOGS = sorted(Path("/var/log").glob("pacman.log*"))

# Commands a password grabber or a backdoor would wrap.
SENSITIVE = ("sudo", "su", "doas", "pkexec", "ssh", "scp", "sftp", "gpg", "passwd", "pacman", "yay", "paru",
             "makepkg", "git", "systemctl")
USER_BIN_DIRS = (HOME / ".local/bin", HOME / "bin", HOME / ".bin", Path("/usr/local/bin"), Path("/usr/local/sbin"),
                 HOME / ".cargo/bin", HOME / ".deno/bin", HOME / "go/bin", HOME / ".npm-global/bin", HOME / ".bun/bin")
SHELL_RC = (".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", ".zshenv", ".config/fish/config.fish")
WRAP = re.compile(r"^\s*(alias\s+(sudo|su|doas|ssh|passwd)=|function\s+(sudo|su|doas|passwd)\b|(sudo|su|doas|passwd)\s*\(\)\s*\{)")


def fetch_lists(lists: list[dict]) -> dict[str, dict]:
    """name -> {campaign, since} from every configured list (cached)."""
    cache = read_json(CACHE, {})
    out: dict[str, dict] = {}
    for lst in lists:
        url = lst["url"]
        e = cache.get(url)
        if not e or time.time() - e["fetched"] > TTL:
            try:
                text = http_get(url, timeout=30).decode("utf-8", "replace")
                names = sorted({line.strip() for line in text.splitlines() if NAME.match(line.strip())})
                if names:
                    e = {"fetched": time.time(), "names": names}
                    cache[url] = e
                    atomic_write_json(CACHE, cache)
            except Exception:
                pass  # keep the stale copy, if any
        for n in (e or {}).get("names", []):
            out.setdefault(n, {"campaign": lst["name"], "since": lst.get("since")})
    return out


def package_history() -> dict[str, list[int]]:
    """Install/upgrade times per package from all pacman logs, rotated ones included."""
    rx = re.compile(r"^\[(\S+)\] \[ALPM\] (?:installed|upgraded|reinstalled|downgraded) (\S+) \(")
    out: dict[str, list[int]] = {}
    for p in PACMAN_LOGS:
        try:
            f = gzip.open(p, "rt", encoding="utf-8", errors="replace") if p.suffix == ".gz" else \
                p.open(encoding="utf-8", errors="replace")
            with f:
                for line in f:
                    m = rx.match(line)
                    if m:
                        try:
                            t = int(datetime.strptime(m[1], "%Y-%m-%dT%H:%M:%S%z").timestamp())
                        except ValueError:
                            continue
                        out.setdefault(m[2], []).append(t)
        except OSError:
            continue
    return out


def _day(ts: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def check_lists(bad: dict[str, dict], foreign: dict[str, str], history: dict[str, list[int]]) -> list[dict]:
    out = []
    for name, info in sorted(bad.items()):
        times = history.get(name, [])
        installed = name in foreign
        if not times and not installed:
            continue
        since = int(datetime.fromisoformat(info["since"]).timestamp()) if info.get("since") else 0
        during = [t for t in times if t >= since]
        if during:
            out.append({
                "kind": "compromised-package", "severity": "high", "package": name, "campaign": info["campaign"],
                "installed": installed, "last": max(during),
                "title": t("{name}: {campaign} saldırısında ele geçirilen paketlerden biri {v2}", name=name, campaign=info['campaign'], v2=t('kurulu') if installed else t('bu bilgisayarda kurulmuştu')),
                "detail": t("Saldırı başlangıcından ({v0}) sonra {v1} tarihinde kuruldu/güncellendi. Paketin o sürümü zararlıysa tarayıcı oturumları, SSH anahtarları ve API anahtarları çalınmış olabilir: bunları yenile, Arch'ın duyurusundaki adımları izle.", v0=info.get('since') or '?', v1=_day(max(during))),
            })
        elif installed:
            out.append({
                "kind": "compromised-package-old", "severity": "info", "package": name, "campaign": info["campaign"],
                "installed": True, "last": max(times) if times else None,
                "title": t("{name}: {campaign} listesinde, ama saldırıdan önce kurulmuş", name=name, campaign=info['campaign']),
                "detail": t("Saldırı tarihinden beri güncellenmedi, yani zararlı sürüm kurulmamış görünüyor. Bir sonraki "
                          "güncellemesini dikkatle incele."),
            })
    return out


def shadowing() -> list[dict]:
    out = []
    for d in USER_BIN_DIRS:
        for cmd in SENSITIVE:
            p = d / cmd
            if p.exists() or p.is_symlink():
                target = p.resolve() if p.is_symlink() else p
                if str(target).startswith(("/usr/bin/", "/usr/sbin/")):
                    continue  # a symlink back to the real command is harmless
                out.append({"kind": "shadowed-command", "severity": "high", "package": cmd,
                            "title": t("'{cmd}' komutunu gölgeleyen bir dosya var: {p}", cmd=cmd, p=p),
                            "detail": t("Bu dizin PATH'te /usr/bin'den önce gelirse, yazdığın komut yerine bu dosya çalışır. "
                                      "Haziran 2026 saldırısı ~/.local/bin/sudo ile sudo parolalarını topluyordu. "
                                      "Dosyayı sen koymadıysan çalıştırmadan incele ve sil.")})
    for rc in SHELL_RC:
        p = HOME / rc
        try:
            for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if WRAP.search(line):
                    out.append({"kind": "wrapped-command", "severity": "high", "package": rc,
                                "title": t("{rc} içinde sudo/su/ssh/passwd'yi saran bir tanım var (satır {i})", rc=rc, i=i),
                                "detail": line.strip()[:200] + " — bunu sen eklemediysen incele."})
        except OSError:
            continue
    return out
