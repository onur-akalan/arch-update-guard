"""Interface language for backend-produced text (findings, notifications, errors).

Turkish source strings are the keys; aug/locale/<lang>.json maps them to the
other language. t() looks the language up at call time, so a change in the
settings applies without restarting the dashboard server. AI providers are told
which language to answer in through localize_prompt().
"""

from __future__ import annotations

import json
from pathlib import Path

LANGUAGES = ("tr", "en")
LANGUAGE_NAMES = {"tr": "Turkish", "en": "English"}
_DIR = Path(__file__).resolve().parent / "locale"
_lang = "tr"
_dict: dict[str, str] = {}


def set_language(lang: str) -> None:
    global _lang, _dict
    lang = lang if lang in LANGUAGES else "tr"
    if lang == _lang and (lang == "tr" or _dict):
        return
    _lang = lang
    _dict = {}
    if lang != "tr":
        try:
            _dict = json.loads((_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _dict = {}


def language() -> str:
    return _lang


def t(s: str, **kw) -> str:
    out = _dict.get(s, s) if _dict else s
    if kw:
        try:
            return out.format(**kw)
        except (KeyError, IndexError, ValueError):
            return s.format(**kw)
    return out


def localize_prompt(system: str) -> str:
    """Prompts are written asking for Turkish output; switch that to the interface language."""
    if _lang == "tr":
        return system
    name = LANGUAGE_NAMES[_lang]
    return (system.replace("in Turkish", f"in {name}").replace("Turkish", name)
            + f"\n\nWrite every human-readable field (summary, explanations, reasoning, actions) in {name}.")


def init_from_settings() -> None:
    from .config import load_settings
    try:
        set_language(load_settings().get("language", "tr"))
    except Exception:
        pass
