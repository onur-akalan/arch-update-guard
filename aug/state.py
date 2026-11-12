"""Persistent state: reviews, approvals, known maintainers, read news."""

from __future__ import annotations

import fcntl
import os
import threading
import time
from contextlib import contextmanager

from .config import RUNTIME_DIR, STATE_FILE, atomic_write_json, read_json

DEFAULT_STATE = {"reviews": {}, "approvals": {}, "maintainers": {}, "news_read": [], "vuln_ack": {},
                 "vuln_ai": {}, "last_check": None}


def vuln_ai_key(v: dict, provider: str | None) -> str:
    return f"{v['avg']}:{v['package']}:{v['installed']}#{provider or '-'}"
_lock = threading.RLock()


def load() -> dict:
    with _lock:
        s = read_json(STATE_FILE, DEFAULT_STATE)
        for k, v in DEFAULT_STATE.items():
            s.setdefault(k, type(v)() if isinstance(v, (dict, list)) else v)
        return s


def save(s: dict) -> None:
    with _lock:
        atomic_write_json(STATE_FILE, s)


@contextmanager
def mutate():
    with _lock:
        s = load()
        yield s
        save(s)


def review_key(pkgbase: str, commit: str, provider: str | None) -> str:
    return f"{pkgbase}@{commit}#{provider or '-'}"


def prune_reviews(s: dict, keep_keys: set[str], max_age_days: int = 60) -> None:
    cutoff = time.time() - max_age_days * 86400
    s["reviews"] = {k: v for k, v in s["reviews"].items() if k in keep_keys or v.get("at", 0) > cutoff}


class CheckRunning(RuntimeError):
    pass


@contextmanager
def check_lock():
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(RUNTIME_DIR / "check.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise CheckRunning("başka bir kontrol zaten çalışıyor")
        yield
    finally:
        os.close(fd)


def check_running() -> bool:
    try:
        with check_lock():
            return False
    except CheckRunning:
        return True
