"""systemd user timer and desktop entry management."""

from __future__ import annotations

import subprocess
from pathlib import Path

from . import APP_ID, APP_NAME
from .config import HOME, PROJECT_DIR, SCHEDULES

UNIT_DIR = HOME / ".config/systemd/user"
SERVICE = UNIT_DIR / f"{APP_ID}-check.service"
TIMER = UNIT_DIR / f"{APP_ID}-check.timer"
DESKTOP = HOME / ".local/share/applications" / f"{APP_ID}.desktop"
AUG = PROJECT_DIR / "bin" / "aug"


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=60)


def _service_text() -> str:
    return f"""[Unit]
Description={APP_NAME}: güncelleme ve güvenlik kontrolü
Documentation=file://{PROJECT_DIR}/README.md

[Service]
Type=oneshot
# Wait (up to 5 min) for the network after boot/resume; the check copes without it anyway.
ExecStartPre=/bin/sh -c 'for i in $(seq 30); do getent hosts aur.archlinux.org >/dev/null && exit 0; sleep 10; done; exit 0'
ExecStart={AUG} check --notify
TimeoutStartSec=45min
Nice=10
IOSchedulingClass=idle
"""


def _timer_text(schedule: str) -> str:
    cal = "\n".join(f"OnCalendar={c}" for c in SCHEDULES[schedule])
    return f"""[Unit]
Description={APP_NAME}: zamanlanmış kontrol

[Timer]
{cal}
Persistent=true
RandomizedDelaySec=10min

[Install]
WantedBy=timers.target
"""


def _desktop_text() -> str:
    return f"""[Desktop Entry]
Type=Application
Name={APP_NAME}
GenericName=Arch güncelleme panosu
Comment=pacman ve AUR güncellemelerini inceleyip güvenle uygula
Exec={AUG} open
Icon=system-software-update
Terminal=false
Categories=System;PackageManager;
Keywords=update;pacman;aur;yay;güncelleme;
StartupWMClass={APP_ID}
"""


def install(schedule: str) -> list[str]:
    msgs = []
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    SERVICE.write_text(_service_text())
    TIMER.write_text(_timer_text(schedule))
    DESKTOP.parent.mkdir(parents=True, exist_ok=True)
    DESKTOP.write_text(_desktop_text())
    msgs.append(f"yazıldı: {SERVICE}, {TIMER}, {DESKTOP}")
    _systemctl("daemon-reload")
    r = _systemctl("enable", "--now", TIMER.name)
    msgs.append("zamanlayıcı etkin" if r.returncode == 0 else f"zamanlayıcı etkinleştirilemedi: {r.stderr.strip()}")
    subprocess.run(["update-desktop-database", str(DESKTOP.parent)], capture_output=True)
    return msgs


def apply(schedule: str) -> str:
    """Rewrite the timer for a new schedule (only if installed)."""
    if not TIMER.exists():
        return "zamanlayıcı kurulu değil"
    new = _timer_text(schedule)
    if TIMER.read_text() == new:
        return "değişmedi"
    TIMER.write_text(new)
    _systemctl("daemon-reload")
    _systemctl("restart", TIMER.name)
    return "güncellendi"


def uninstall() -> list[str]:
    _systemctl("disable", "--now", TIMER.name)
    removed = []
    for p in (SERVICE, TIMER, DESKTOP):
        if p.exists():
            p.unlink()
            removed.append(str(p))
    _systemctl("daemon-reload")
    return removed


def next_run() -> str | None:
    r = _systemctl("show", TIMER.name, "--property=NextElapseUSecRealtime", "--value")
    v = r.stdout.strip()
    return v or None
