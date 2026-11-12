"""Arch news (RSS) and the Arch security tracker (AVG list)."""

from __future__ import annotations

import html
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime

from . import __version__
from .system import vercmp

USER_AGENT = f"arch-update-guard/{__version__}"
NEWS_URL = "https://archlinux.org/feeds/news/"
AVG_URL = "https://security.archlinux.org/issues/all.json"


def http_get(url: str, timeout: int = 30, accept: str | None = None) -> bytes:
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


_TAG = re.compile(r"<[^>]+>")


def _text(desc_html: str, limit: int = 600) -> str:
    t = html.unescape(_TAG.sub(" ", desc_html or ""))
    t = re.sub(r"\s+", " ", t).strip()
    return t if len(t) <= limit else t[:limit].rsplit(" ", 1)[0] + " …"


def fetch_news(limit: int = 15) -> list[dict]:
    root = ET.fromstring(http_get(NEWS_URL))
    items = []
    for it in list(root.iter("item"))[:limit]:
        link = (it.findtext("link") or "").strip()
        pub = it.findtext("pubDate")
        try:
            published = parsedate_to_datetime(pub).isoformat() if pub else None
        except (TypeError, ValueError):
            published = None
        desc = it.findtext("description") or ""
        items.append({
            "id": link,
            "title": (it.findtext("title") or "").strip(),
            "link": link,
            "published": published,
            "summary": _text(desc),
            "html": desc,
        })
    return items


def news_since(news: list[dict], since: datetime | None) -> list[dict]:
    if since is None:
        return news[:3]
    out = []
    for n in news:
        if n["published"] and datetime.fromisoformat(n["published"]) > since:
            out.append(n)
    return out


SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}


def fetch_advisories() -> list[dict]:
    return json.loads(http_get(AVG_URL, timeout=60, accept="application/json"))


def vulnerable_installed(avgs: list[dict], installed: dict[str, str],
                         pending: dict[str, str]) -> list[dict]:
    """AVGs that affect an installed package version.

    pending: name -> new version from pending repo updates, used to tell
    whether the update waiting right now fixes the issue.
    """
    found = []
    for avg in avgs:
        if avg.get("status") == "Not affected":
            continue
        affected, fixed = avg.get("affected"), avg.get("fixed")
        for pkg in avg.get("packages", []):
            ver = installed.get(pkg)
            if not ver or not affected:
                continue
            try:
                if vercmp(ver, affected) < 0:
                    continue
                if fixed and vercmp(ver, fixed) >= 0:
                    continue
                fix_pending = bool(fixed and pkg in pending and vercmp(pending[pkg], fixed) >= 0)
            except Exception:
                continue
            found.append({
                "avg": avg["name"],
                "package": pkg,
                "installed": ver,
                "fixed": fixed,
                "fix_pending": fix_pending,
                "severity": avg.get("severity", "Unknown"),
                "type": avg.get("type", "unknown"),
                "status": avg.get("status", "Unknown"),
                "issues": avg.get("issues", [])[:12],
                "issue_count": len(avg.get("issues", [])),
                "url": f"https://security.archlinux.org/{avg['name']}",
            })
    found.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), not x["fix_pending"], x["package"]))
    return found
