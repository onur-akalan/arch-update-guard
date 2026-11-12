"""Builds and launches the update script in a Konsole window.

Nothing here runs as root: the script calls sudo itself, in a terminal the
user watches, so the password prompt and every pacman/yay question stay
with the user.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from . import aur, state
from .config import PROJECT_DIR, RUNTIME_DIR

RESULT_FILE = RUNTIME_DIR / "update-result.json"
RUNNING_FILE = RUNTIME_DIR / "update-running"


class UpdateError(RuntimeError):
    pass


def update_status() -> dict:
    running = RUNNING_FILE.exists()
    if running:
        try:
            pid = int(RUNNING_FILE.read_text().strip())
            os.kill(pid, 0)
        except (ValueError, ProcessLookupError, PermissionError, OSError):
            RUNNING_FILE.unlink(missing_ok=True)
            running = False
    result = None
    if RESULT_FILE.exists():
        try:
            result = json.loads(RESULT_FILE.read_text())
        except json.JSONDecodeError:
            result = None
    return {"running": running, "last": result}


def plan(report: dict, selected_aur: list[str]) -> list[dict]:
    """Validate the AUR selection against the report and approvals."""
    by_name = {a["name"]: a for a in report["aur"]}
    st = state.load()
    chosen = []
    for name in selected_aur:
        item = by_name.get(name)
        if not item or not item.get("target"):
            raise UpdateError(f"{name}: güncellenecek bir AUR sürümü yok")
        approval = st["approvals"].get(name)
        approved = bool(approval and approval.get("commit") == item["target"])
        if not (approved or item.get("auto_ok")):
            raise UpdateError(f"{name}: onaylanmamış (durum: {item['status']}"
                              f"{', bekleme süresinde' if item.get('held') else ''})")
        chosen.append(item)
    return chosen


def launch(report: dict, selected_aur: list[str], news_acknowledged: bool) -> dict:
    if update_status()["running"]:
        raise UpdateError("Bir güncelleme zaten çalışıyor.")
    unread = [n for n in report["news"] if n.get("since_last_upgrade") and not n.get("read")]
    if unread and not news_acknowledged:
        raise UpdateError("Son güncellemeden sonra yayımlanan Arch haberlerini okuduğunu onaylaman gerekiyor.")
    chosen = plan(report, selected_aur)

    # Final race check: the AUR repo must still be at the reviewed commit.
    for item in chosen:
        head = aur.ls_remote_head(item["pkgbase"])
        if head != item["target"]:
            raise UpdateError(f"{item['name']}: AUR deposu incelendikten sonra değişti. "
                              "Önce yeniden kontrol et.")

    terminal = shutil.which("konsole")
    if not terminal:
        raise UpdateError("Konsole bulunamadı.")

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    script = RUNTIME_DIR / f"update-{int(time.time())}.sh"
    script.write_text(_script(chosen, report), encoding="utf-8")
    script.chmod(0o700)
    RESULT_FILE.unlink(missing_ok=True)

    proc = subprocess.Popen([terminal, "--separate", "--hide-menubar", "-p", "tabtitle=Güncelleme Bekçisi",
                             "-e", "bash", str(script)],
                            start_new_session=True, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    RUNNING_FILE.write_text(str(proc.pid))
    return {"pid": proc.pid, "aur": [i["name"] for i in chosen], "repo": len(report["repo"])}


def _script(chosen: list[dict], report: dict) -> str:
    q = shlex.quote
    aur_checks = "\n".join(
        f'check_head {q(i["pkgbase"])} {q(i["target"])} {q(i["name"])}' for i in chosen)
    aug = q(str(PROJECT_DIR / "bin" / "aug"))
    return f"""#!/bin/bash
# Güncelleme Bekçisi tarafından oluşturuldu: {time.strftime('%Y-%m-%d %H:%M:%S')}
set -uo pipefail
RESULT={q(str(RESULT_FILE))}
RUNNING={q(str(RUNNING_FILE))}
started=$(date +%s)
repo_rc=-1; aur_rc=-1
AUR_PKGS=()

finish() {{
  printf '{{"started":%s,"finished":%s,"repo_rc":%s,"aur_rc":%s,"aur":"%s"}}\\n' \\
    "$started" "$(date +%s)" "$repo_rc" "$aur_rc" "${{AUR_PKGS[*]:-}}" > "$RESULT"
  rm -f "$RUNNING"
}}
trap finish EXIT

check_head() {{
  local base=$1 want=$2 name=$3 have
  have=$(git ls-remote "https://aur.archlinux.org/$base.git" HEAD | cut -f1)
  if [[ "$have" == "$want" ]]; then
    AUR_PKGS+=("$name")
  else
    echo "  ! $name incelendikten sonra AUR'da değişti; ATLANIYOR."
  fi
}}

bold=$'\\e[1m'; dim=$'\\e[2m'; red=$'\\e[31m'; green=$'\\e[32m'; yellow=$'\\e[33m'; off=$'\\e[0m'

echo "${{bold}}=== Güncelleme Bekçisi ===${{off}}"
echo "${{dim}}Timeshift, pacman işleminden önce otomatik anlık görüntü alır.${{off}}"
echo
echo "${{bold}}1/2 Resmi depolar ({len(report['repo'])} paket bekliyordu)${{off}}"
sudo pacman -Syu
repo_rc=$?
if [[ $repo_rc -ne 0 ]]; then
  echo "${{red}}pacman başarısız oldu (kod $repo_rc). AUR adımı atlanıyor.${{off}}"
else
  echo
  echo "${{bold}}2/2 AUR{f' ({len(chosen)} onaylı paket)' if chosen else ''}${{off}}"
{aur_checks or '  :'}
  if (( ${{#AUR_PKGS[@]}} )); then
    echo "  Kurulacak: ${{AUR_PKGS[*]}}"
    yay -S --aur --needed --answerdiff None --answerclean None --answeredit None --removemake "${{AUR_PKGS[@]}}"
    aur_rc=$?
  else
    echo "  Güncellenecek onaylı AUR paketi yok."
    aur_rc=0
  fi
fi

echo
if [[ ! -d "/usr/lib/modules/$(uname -r)" ]]; then
  echo "${{yellow}}${{bold}}Çekirdek güncellendi: değişikliklerin etkin olması için bilgisayarı yeniden başlat.${{off}}"
fi
pacnew=$(pacdiff -o -f 2>/dev/null)
if [[ -n "$pacnew" ]]; then
  echo "${{yellow}}Birleştirilmeyi bekleyen yapılandırma dosyaları (.pacnew):${{off}}"
  echo "$pacnew" | sed 's/^/  /'
fi
if [[ $repo_rc -eq 0 && $aur_rc -eq 0 ]]; then
  echo "${{green}}${{bold}}Güncelleme tamamlandı.${{off}}"
fi
finish
trap - EXIT
echo "${{dim}}Pano yeniden kontrol ediliyor...${{off}}"
{aug} check --quiet >/dev/null 2>&1 &
echo
read -rp "Pencereyi kapatmak için Enter'a bas. "
"""
