"""Command line entry point: aug check | open | serve | install | uninstall."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time

from . import APP_ID, APP_NAME, check, schedule, server
from .config import LOG_FILE, ensure_dirs, load_settings


def _setup_logging(verbose: bool) -> None:
    ensure_dirs()
    handlers: list[logging.Handler] = [logging.FileHandler(LOG_FILE, encoding="utf-8")]
    if verbose:
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.INFO, handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _notify(report: dict) -> None:
    s = check.summary(report)
    parts = []
    if s["danger"]:
        parts.append(f"⚠ {s['danger']} tehlikeli AUR paketi")
    if s["warning"]:
        parts.append(f"{s['warning']} uyarılı AUR paketi")
    if s["unread_news"]:
        parts.append(f"{s['unread_news']} okunmamış Arch haberi")
    if s["repo"] or s["aur"]:
        parts.append(f"{s['repo']} resmi, {s['aur']} AUR güncellemesi")
    if s["vulns_fixable"]:
        parts.append(f"{s['vulns_fixable']} güvenlik açığı bu güncellemeyle kapanıyor")
    if report["errors"]:
        parts.append(f"{len(report['errors'])} kontrol başarısız")
    if not parts or not shutil.which("notify-send"):
        return
    urgency = "critical" if s["danger"] else "normal"
    # notify-send rejects non-ASCII text unless the locale is UTF-8.
    env = dict(os.environ, LC_ALL="C.UTF-8")
    try:
        r = subprocess.run(["notify-send", "-a", APP_NAME, "-i", "system-software-update", "-u", urgency,
                            "-A", "open=Panoyu aç", "-w", "-t", "600000", APP_NAME, "\n".join(parts)],
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
        sys.exit("Pano sunucusu başlatılamadı; ayrıntılar için günlüğe bak: " + str(LOG_FILE))
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
    ap = argparse.ArgumentParser(prog="aug", description=f"{APP_NAME}: Arch güncelleme panosu")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="güncellemeleri topla ve incele")
    c.add_argument("--notify", action="store_true", help="sonucu masaüstü bildirimi olarak göster")
    c.add_argument("--quiet", action="store_true")
    sub.add_parser("open", help="panoyu aç")
    sub.add_parser("serve", help="pano sunucusunu ön planda çalıştır")
    sub.add_parser("install", help="zamanlayıcıyı ve menü kısayolunu kur")
    sub.add_parser("uninstall", help="zamanlayıcıyı ve menü kısayolunu kaldır")
    args = ap.parse_args(argv)
    _setup_logging(args.verbose)

    if args.cmd == "check":
        try:
            report = check.run()
        except check.state.CheckRunning as e:
            print(e, file=sys.stderr)
            return 1
        if not args.quiet:
            print(check.summary(report))
            for e in report["errors"]:
                print("HATA:", e, file=sys.stderr)
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
