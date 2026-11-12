"""Command line entry point: aug check | open | serve | install | uninstall."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time

from . import APP_ID, app_name, check, notify, schedule, server, sources, state
from .config import LOG_FILE, ensure_dirs, load_settings
from .i18n import t


def _background_setup(settings: dict) -> None:
    """Scheduled run: let the desktop finish starting, keep the network free."""
    try:
        uptime = float(open("/proc/uptime").read().split()[0])
    except (OSError, ValueError):
        uptime = 1e9
    wait = settings["startup_delay_minutes"] * 60 - uptime
    if wait > 0:
        logging.getLogger("aug").info("waiting %.0f s after boot", wait)
        time.sleep(wait)
    sources.set_rate(settings["sources"]["background_rate_mb"] * 1024 * 1024)


def _setup_logging(verbose: bool) -> None:
    ensure_dirs()
    handlers: list[logging.Handler] = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
    if verbose:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _notify(report: dict) -> None:
    """Notify only about new, important things (see notify.py)."""
    with state.mutate() as st:
        fresh = notify.select(report, st, load_settings()["notify_level"])
    logging.getLogger("aug").info("notify: %d new event(s)", len(fresh))
    parts = [e["text"] for e in fresh[:6]]
    if len(fresh) > 6:
        parts.append(t("… ve {v0} şey daha", v0=len(fresh) - 6))
    if not parts or not shutil.which("notify-send"):
        return
    critical = any(e["critical"] for e in fresh)
    urgency = "critical" if critical else "normal"
    # notify-send rejects non-ASCII text unless the locale is UTF-8.
    env = dict(os.environ, LC_ALL="C.UTF-8")
    try:
        r = subprocess.run(["notify-send", "-a", app_name(), "-i", "system-software-update", "-u", urgency,
                            "-A", t("open=Panoyu aç"), "-w", "-t", "600000" if critical else "30000", app_name(), "\n".join(parts)],
                           capture_output=True, text=True, timeout=660, env=env)
        logging.getLogger("aug").info("notify-send rc=%s out=%r err=%r", r.returncode, r.stdout.strip(),
                                      r.stderr.strip()[:200])
        if r.stdout.strip() == "open":
            open_dashboard()
    except subprocess.TimeoutExpired:
        pass


def open_dashboard() -> None:
    info = server.running_server()
    if not info:
        aug = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin", "aug")
        subprocess.Popen([aug, "serve"], start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            time.sleep(0.1)
            info = server.running_server()
            if info:
                break
    if not info:
        sys.exit(t("Pano sunucusu başlatılamadı; ayrıntılar için günlüğe bak: ") + str(LOG_FILE))
    url = f"http://127.0.0.1:{info['port']}/?t={info['token']}"
    browser = load_settings()["browser"]
    chromium = shutil.which("chromium")
    if browser == "chromium-app" and chromium:
        cmd = [chromium, f"--app={url}", f"--class={APP_ID}", "--window-size=1280,900"]
    else:
        cmd = ["xdg-open", url]
    subprocess.Popen(cmd, start_new_session=True, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main(argv: list[str] | None = None) -> int:
    from .i18n import init_from_settings
    init_from_settings()
    ap = argparse.ArgumentParser(prog="aug", description=t("{app}: Arch güncelleme panosu", app=app_name()))
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help=t("güncellemeleri topla ve incele"))
    c.add_argument("--notify", action="store_true", help=t("sonucu masaüstü bildirimi olarak göster"))
    c.add_argument("--quiet", action="store_true")
    c.add_argument("--background", action="store_true",
                   help=t("zamanlanmış çalışma: açılıştan sonra bekle, indirme hızını sınırla"))
    sub.add_parser("open", help=t("panoyu aç"))
    sub.add_parser("serve", help=t("pano sunucusunu ön planda çalıştır"))
    sub.add_parser("install", help=t("zamanlayıcıyı ve menü kısayolunu kur"))
    sub.add_parser("uninstall", help=t("zamanlayıcıyı ve menü kısayolunu kaldır"))
    args = ap.parse_args(argv)
    _setup_logging(args.verbose)

    if args.cmd == "check":
        if args.background:
            _background_setup(load_settings())
        try:
            report = check.run()
        except check.state.CheckRunning as e:
            print(e, file=sys.stderr)
            return 1
        if not args.quiet:
            print(check.summary(report))
            for e in report["errors"]:
                print(t("HATA:"), e, file=sys.stderr)
        if args.notify and load_settings()["notifications"]:
            _notify(report)
        return 0
    if args.cmd == "open":
        open_dashboard()
        return 0
    if args.cmd == "serve":
        server.serve()
        return 0
    if args.cmd == "install":
        for m in schedule.install(load_settings()["schedule"]):
            print(m)
        return 0
    if args.cmd == "uninstall":
        for m in schedule.uninstall():
            print("silindi:", m)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
