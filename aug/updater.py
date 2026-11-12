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

from . import aur, deps, state
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
        approved = bool(approval and approval.get("commit") == item.get("approval_key", item["target"]))
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

    # Final race check: every AUR repo involved (the package and any new AUR
    # dependency it pulls in) must still be at the reviewed commit.
    for item in chosen:
        for pkgbase, want, label in _heads(item):
            if aur.ls_remote_head(pkgbase) != want:
                raise UpdateError(f"{label}: AUR deposu incelendikten sonra değişti. Önce yeniden kontrol et.")

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


def launch_restart(report: dict, units: list[str]) -> dict:
    allowed = {s["unit"] for s in report.get("runtime", {}).get("services", []) if s.get("safe")}
    units = [u for u in units if u in allowed]
    if not units:
        raise UpdateError("Yeniden başlatılacak geçerli bir servis seçilmedi.")
    terminal = shutil.which("konsole")
    if not terminal:
        raise UpdateError("Konsole bulunamadı.")
    q = " ".join(shlex.quote(u) for u in units)
    aug = shlex.quote(str(PROJECT_DIR / "bin" / "aug"))
    script = RUNTIME_DIR / f"restart-{int(time.time())}.sh"
    script.write_text(f"""#!/bin/bash
echo "Yeniden başlatılacak servisler: {' '.join(units)}"
sudo systemctl restart {q} && echo "Tamam." || echo "Bazı servisler yeniden başlatılamadı."
systemctl --no-pager --lines=0 status {q} | grep -E '^(●|○|×)| Active:'
{aug} check --quiet >/dev/null 2>&1 &
read -rp "Pencereyi kapatmak için Enter'a bas. "
""", encoding="utf-8")
    script.chmod(0o700)
    subprocess.Popen([terminal, "--separate", "--hide-menubar", "-e", "bash", str(script)],
                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL)
    return {"units": units}


def _heads(item: dict) -> list[tuple[str, str, str]]:
    out = [(item["pkgbase"], item["target"], item["name"])]
    for d in deps.flatten(item.get("new_aur_deps", [])):
        if d.get("pkgbase") and d.get("target"):
            out.append((d["pkgbase"], d["target"], f"{d['name']} ({item['name']} bağımlılığı)"))
    return out


def _seeds(item: dict) -> list[tuple[str, list[str]]]:
    """(pkgbase, inspected and checksum-verified downloads) for the package and its new deps."""
    out = []
    for x in [item, *deps.flatten(item.get("new_aur_deps", []))]:
        files = [s["cached"] for s in ((x.get("sources") or {}).get("sources") or []) if s.get("cached")]
        if files and x.get("pkgbase"):
            out.append((x["pkgbase"], files))
    return out


def _script(chosen: list[dict], report: dict) -> str:
    q = shlex.quote
    seeds = "\n".join("  seed " + q(b) + " " + " ".join(q(f) for f in files)
                       for i in chosen for b, files in _seeds(i))
    aur_checks = "\n".join(
        "check_head " + q(i["name"]) + " " + " ".join(f"{q(b)} {q(c)}" for b, c, _ in _heads(i))
        for i in chosen)
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

# check_head NAME BASE1 COMMIT1 [BASE2 COMMIT2 ...]: the package and every new
# AUR dependency it pulls in must still be at the reviewed commit.
check_head() {{
  local name=$1 base want have; shift
  while (( $# )); do
    base=$1 want=$2; shift 2
    have=$(git ls-remote "https://aur.archlinux.org/$base.git" HEAD | cut -f1)
    if [[ "$have" != "$want" ]]; then
      echo "  ! $base incelendikten sonra AUR'da değişti; $name ATLANIYOR."
      return
    fi
  done
  AUR_PKGS+=("$name")
}}

# seed PKGBASE FILE...: hand the source files that were already downloaded,
# inspected and checksum-verified to yay's build dir so they are not fetched a
# second time. makepkg verifies their checksums again before building.
seed() {{
  local dir="$HOME/.cache/yay/$1" f; shift
  [[ -d "$dir/.git" ]] || return 0
  for f; do
    [[ -f "$f" && ! -e "$dir/${{f##*/}}" ]] && cp --reflink=auto -- "$f" "$dir/" 2>/dev/null
  done
  return 0
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
{seeds}
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
