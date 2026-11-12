"""Paths, settings and secret storage."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path

from . import APP_ID

HOME = Path.home()
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", HOME / ".config")) / APP_ID
DATA_DIR = Path(os.environ.get("XDG_DATA_HOME", HOME / ".local/share")) / APP_ID
STATE_DIR = Path(os.environ.get("XDG_STATE_HOME", HOME / ".local/state")) / APP_ID
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", HOME / ".cache")) / APP_ID
RUNTIME_DIR = Path(os.environ.get("XDG_RUNTIME_DIR", tempfile.gettempdir())) / APP_ID

SETTINGS_FILE = CONFIG_DIR / "settings.json"
STATE_FILE = DATA_DIR / "state.json"
REPORT_FILE = DATA_DIR / "report.json"
AUR_MIRROR_DIR = DATA_DIR / "aur"
LOG_FILE = STATE_DIR / "aug.log"
SERVER_FILE = RUNTIME_DIR / "server.json"

PROJECT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = PROJECT_DIR / "web"

YAY_CACHE = HOME / ".cache/yay"

DEFAULT_SETTINGS: dict = {
    "hold_days": 2,
    "schedule": "daily",  # daily | twice | weekly
    "notifications": True,
    "notify_level": "important",  # important: only new findings, news, critical vulns | all: every check with updates
    "startup_delay_minutes": 10,  # scheduled check waits this long after boot so it does not slow the login
    "browser": "chromium-app",  # chromium-app | default
    "security": {
        "auto_analyze": True,      # AI-assess active (not fixed / not stale) entries during checks
        "nvd_budget_seconds": 60,  # time per check spent fetching CVE details from NVD
    },
    "sources": {
        "enabled": True,     # download and inspect the source files of AUR updates
        "max_file_mb": 400,  # larger downloads are skipped (reported, not inspected)
        "baseline": True,    # first time: also fetch the installed version's sources to compare
        "time_budget_minutes": 15,  # download time per check; the rest resumes on the next check
        "background_rate_mb": 3,    # MB/s cap for downloads in scheduled checks (0 = no cap)
    },
    "review": {
        "enabled": True,
        "active_provider": "claude-code",
        "max_diff_chars": 120000,
        "timeout_seconds": 180,
    },
    "providers": [
        {
            "id": "claude-code",
            "name": "Claude Code (abonelik)",
            "type": "claude-code",
            "model": "sonnet",
        },
        {
            "id": "anthropic",
            "name": "Anthropic API",
            "type": "anthropic",
            "model": "claude-opus-5-5",
            "effort": "medium",
            "base_url": "",
        },
        {
            "id": "litellm",
            "name": "LiteLLM",
            "type": "openai",
            "model": "",
            "base_url": "http://localhost:4000/v1",
            "json_mode": "json_schema",  # json_schema | json_object | none
        },
    ],
}

PROVIDER_TYPES = ("anthropic", "openai", "claude-code")
SCHEDULES = {
    "daily": ["*-*-* 09:00:00"],
    "twice": ["*-*-* 09:00:00", "*-*-* 19:00:00"],
    "weekly": ["Mon *-*-* 09:00:00"],
}

_lock = threading.Lock()


def ensure_dirs() -> None:
    for d in (CONFIG_DIR, DATA_DIR, STATE_DIR, AUR_MIRROR_DIR):
        d.mkdir(parents=True, exist_ok=True)
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)


def atomic_write_json(path: Path, data, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return copy.deepcopy(default)


def _merge(defaults: dict, value: dict) -> dict:
    out = copy.deepcopy(defaults)
    for k, v in value.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings() -> dict:
    with _lock:
        return _merge(DEFAULT_SETTINGS, read_json(SETTINGS_FILE, {}))


class SettingsError(ValueError):
    pass


def validate_settings(s: dict) -> dict:
    s = _merge(DEFAULT_SETTINGS, s)
    try:
        s["hold_days"] = int(s["hold_days"])
    except (TypeError, ValueError):
        raise SettingsError("Bekleme süresi bir tam sayı olmalı.")
    if not 0 <= s["hold_days"] <= 30:
        raise SettingsError("Bekleme süresi 0 ile 30 gün arasında olmalı.")
    if s["schedule"] not in SCHEDULES:
        raise SettingsError("Geçersiz kontrol sıklığı.")
    if s["browser"] not in ("chromium-app", "default"):
        raise SettingsError("Geçersiz tarayıcı seçimi.")
    s["notifications"] = bool(s["notifications"])
    if s["notify_level"] not in ("important", "all"):
        raise SettingsError("Geçersiz bildirim düzeyi.")
    try:
        s["startup_delay_minutes"] = int(s["startup_delay_minutes"])
    except (TypeError, ValueError):
        raise SettingsError("Açılış gecikmesi bir tam sayı olmalı.")
    if not 0 <= s["startup_delay_minutes"] <= 120:
        raise SettingsError("Açılış gecikmesi 0 ile 120 dakika arasında olmalı.")
    sec = s["security"]
    sec["auto_analyze"] = bool(sec["auto_analyze"])
    try:
        sec["nvd_budget_seconds"] = int(sec["nvd_budget_seconds"])
    except (TypeError, ValueError):
        raise SettingsError("NVD süresi bir tam sayı olmalı.")
    if not 0 <= sec["nvd_budget_seconds"] <= 900:
        raise SettingsError("NVD süresi 0 ile 900 saniye arasında olmalı.")
    src = s["sources"]
    src["enabled"] = bool(src["enabled"])
    src["baseline"] = bool(src["baseline"])
    try:
        src["max_file_mb"] = int(src["max_file_mb"])
    except (TypeError, ValueError):
        raise SettingsError("Kaynak boyut sınırı bir tam sayı olmalı.")
    if not 1 <= src["max_file_mb"] <= 4096:
        raise SettingsError("Kaynak boyut sınırı 1 ile 4096 MB arasında olmalı.")
    try:
        src["time_budget_minutes"] = int(src["time_budget_minutes"])
    except (TypeError, ValueError):
        raise SettingsError("İndirme süresi bir tam sayı olmalı.")
    if not 1 <= src["time_budget_minutes"] <= 240:
        raise SettingsError("İndirme süresi 1 ile 240 dakika arasında olmalı.")
    try:
        src["background_rate_mb"] = float(src["background_rate_mb"])
    except (TypeError, ValueError):
        raise SettingsError("İndirme hızı sınırı bir sayı olmalı.")
    if not 0 <= src["background_rate_mb"] <= 1000:
        raise SettingsError("İndirme hızı sınırı 0 ile 1000 MB/s arasında olmalı.")
    r = s["review"]
    r["enabled"] = bool(r["enabled"])
    for key, lo, hi in (("max_diff_chars", 5000, 1_000_000), ("timeout_seconds", 20, 1800)):
        try:
            r[key] = int(r[key])
        except (TypeError, ValueError):
            raise SettingsError(f"{key} bir tam sayı olmalı.")
        if not lo <= r[key] <= hi:
            raise SettingsError(f"{key} {lo} ile {hi} arasında olmalı.")
    ids = set()
    clean = []
    for p in s["providers"]:
        pid = str(p.get("id", "")).strip()
        if not pid or not all(c.isalnum() or c in "-_" for c in pid):
            raise SettingsError("Sağlayıcı kimliği yalnızca harf, rakam, - ve _ içerebilir.")
        if pid in ids:
            raise SettingsError(f"Aynı kimlikte iki sağlayıcı var: {pid}")
        ids.add(pid)
        if p.get("type") not in PROVIDER_TYPES:
            raise SettingsError(f"{pid}: geçersiz sağlayıcı türü.")
        if p["type"] == "openai" and not str(p.get("base_url", "")).startswith(("http://", "https://")):
            raise SettingsError(f"{pid}: adres http:// ya da https:// ile başlamalı.")
        if p.get("effort") and p["effort"] not in ("low", "medium", "high", "xhigh", "max"):
            raise SettingsError(f"{pid}: geçersiz effort değeri.")
        if p.get("json_mode") and p["json_mode"] not in ("json_schema", "json_object", "none"):
            raise SettingsError(f"{pid}: geçersiz JSON kipi.")
        allowed = {"id", "name", "type", "model", "base_url", "effort", "json_mode"}
        clean.append({k: (str(v).strip() if isinstance(v, str) else v) for k, v in p.items() if k in allowed})
    s["providers"] = clean
    if r["active_provider"] not in ids:
        raise SettingsError("Etkin sağlayıcı listede yok.")
    return s


def save_settings(s: dict) -> dict:
    s = validate_settings(s)
    with _lock:
        atomic_write_json(SETTINGS_FILE, s)
    return s


# --- Secrets -------------------------------------------------------------
# API keys live in the desktop's Secret Service (KWallet / GNOME Keyring),
# never in settings.json.

def _secret_attrs(provider_id: str) -> list[str]:
    return ["service", APP_ID, "provider", provider_id]


def get_secret(provider_id: str) -> str | None:
    try:
        r = subprocess.run(["secret-tool", "lookup", *_secret_attrs(provider_id)],
                           capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 and r.stdout else None


def set_secret(provider_id: str, value: str) -> None:
    r = subprocess.run(["secret-tool", "store", "--label", f"{APP_ID}: {provider_id}",
                        *_secret_attrs(provider_id)],
                       input=value, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("Anahtar kasaya kaydedilemedi: " + (r.stderr.strip() or "bilinmeyen hata"))


def delete_secret(provider_id: str) -> None:
    subprocess.run(["secret-tool", "clear", *_secret_attrs(provider_id)],
                   capture_output=True, timeout=20)
