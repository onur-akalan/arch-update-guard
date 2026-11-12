"""Read-only queries against the local system (pacman, logs, disk)."""

from __future__ import annotations

import functools
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path


def run(cmd: list[str], timeout: int = 120, check: bool = False, **kw) -> subprocess.CompletedProcess:
    env = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=check, env=env, **kw)


def installed_packages() -> dict[str, str]:
    out = run(["pacman", "-Q"], check=True).stdout
    return dict(line.split(" ", 1) for line in out.splitlines() if " " in line)


def foreign_packages() -> dict[str, str]:
    r = run(["pacman", "-Qm"])
    return dict(line.split(" ", 1) for line in r.stdout.splitlines() if " " in line)


@functools.lru_cache(maxsize=8192)
def vercmp(a: str, b: str) -> int:
    """<0 if a<b, 0 if equal, >0 if a>b (alpm semantics)."""
    out = run(["vercmp", a, b], check=True).stdout.strip()
    return int(out)


class CheckUpdatesError(RuntimeError):
    pass


def repo_updates() -> list[dict]:
    """Pending official-repo updates via checkupdates (uses a temp db, no root)."""
    r = run(["checkupdates", "--nocolor"], timeout=300)
    if r.returncode == 2:  # no updates
        return []
    if r.returncode != 0:
        raise CheckUpdatesError(r.stderr.strip() or f"checkupdates çıkış kodu {r.returncode}")
    items = []
    for line in r.stdout.splitlines():
        m = re.match(r"^(\S+) (\S+) -> (\S+)", line)
        if m:
            items.append({"name": m[1], "old": m[2], "new": m[3]})
    return items


def repo_of(names: list[str]) -> dict[str, str]:
    """Map package name -> sync repo (core/extra/multilib) using the local sync db."""
    if not names:
        return {}
    r = run(["pacman", "-Sl"], timeout=120)
    wanted = set(names)
    out = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in wanted:
            out[parts[1]] = parts[0]
    return out


PACMAN_LOG = Path("/var/log/pacman.log")
_LOG_TS = re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\]")


def last_full_upgrade() -> datetime | None:
    try:
        with PACMAN_LOG.open(encoding="utf-8", errors="replace") as f:
            last = None
            for line in f:
                if "starting full system upgrade" in line:
                    last = line
    except OSError:
        return None
    if not last:
        return None
    m = _LOG_TS.match(last)
    return datetime.strptime(m[1], "%Y-%m-%dT%H:%M:%S%z") if m else None


def pacnew_files() -> list[str]:
    if not shutil.which("pacdiff"):
        return []
    r = run(["pacdiff", "-o", "-f"], timeout=120)
    return [l for l in r.stdout.splitlines() if l.strip()]


def reboot_needed() -> bool:
    """True when the running kernel's modules are gone (kernel was upgraded)."""
    return not Path(f"/usr/lib/modules/{os.uname().release}").is_dir()


def disk_free_gb(path: str = "/") -> float:
    return shutil.disk_usage(path).free / 1e9


def autosnap_installed() -> bool:
    return Path("/usr/share/libalpm/hooks/00-timeshift-autosnap.hook").exists() or bool(shutil.which("timeshift-autosnap"))
