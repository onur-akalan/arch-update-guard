"""Which results deserve a desktop notification.

The goal is silence on ordinary days: routine updates wait on the dashboard,
and the user is only interrupted for something new that needs a decision.
Every event has a stable key; once notified it is not repeated, so the same
warning does not come back every morning.
"""

from __future__ import annotations

import time

REMIND_DAYS = 14        # updates waiting longer than this get a gentle reminder...
REMIND_EVERY_DAYS = 7   # ...at most once a week
FORGET_DAYS = 90


def events(report: dict, st: dict, level: str) -> list[dict]:
    """[{key, text, critical}] for this report, before de-duplication."""
    out: list[dict] = []
    for i in report.get("incidents", []):
        if i["severity"] == "high":
            out.append({"key": f"incident:{i['kind']}:{i['package']}", "critical": True, "text": "⚠ " + i["title"]})
    for a in report.get("aur", []):
        rc = a.get("review_commit") or a.get("target") or a.get("new_version")
        if a["status"] == "danger":
            out.append({"key": f"aur-danger:{a['name']}@{rc}", "critical": True,
                        "text": f"⚠ {a['name']}: güncellemede tehlikeli bulgu var, kurmadan önce bak"})
        elif a["status"] in ("warning", "missing"):
            out.append({"key": f"aur-warn:{a['name']}@{rc}", "critical": False,
                        "text": f"{a['name']}: güncellemede incelemen gereken bir değişiklik var"})
    unread = [n for n in report.get("news", []) if n.get("since_last_upgrade") and n["id"] not in st["news_read"]]
    when_tr = {"before_update": "güncellemeden önce", "during_update": "güncelleme sırasında",
               "after_update": "güncellemeden sonra"}
    for n in unread:
        ai = n.get("ai") or {}
        if ai.get("status") == "ok" and ai["affects"] == "no" and ai["confidence"] != "low":
            continue  # it does not apply here; it still waits on the dashboard
        if ai.get("status") == "ok" and ai["affects"] == "yes":
            when = when_tr.get(ai["when"])
            text = f"Arch haberi seni etkiliyor{f' ({when} yapılacak bir şey var)' if when else ''}: {n['title']}"
        else:
            text = f"Arch haberi: {n['title']}"
        out.append({"key": f"news:{n['id']}", "critical": False, "text": text})
    acks = st.get("vuln_ack", {})
    for v in report.get("vulns", []):
        ack = acks.get(f"{v['avg']}:{v['package']}")
        if ack and ack.get("version") == v["installed"]:
            continue
        if v.get("stale") or v.get("evidence_verdict") == "fixed":
            continue
        ai = v.get("ai") or {}
        if ai.get("status") == "ok" and ai.get("assessment") in ("fixed", "not_applicable"):
            continue
        if v.get("fix_pending"):
            out.append({"key": f"vuln-fix:{v['avg']}:{v['package']}", "critical": False,
                        "text": f"{v['package']}: bir güvenlik açığı bekleyen güncellemeyle kapanıyor"})
        elif v["severity"] in ("Critical", "High"):
            out.append({"key": f"vuln:{v['avg']}:{v['package']}", "critical": v["severity"] == "Critical",
                        "text": f"{v['package']}: {'kritik' if v['severity'] == 'Critical' else 'yüksek'} önemde açık, "
                                f"düzeltmesi henüz yok"})
    pending = len(report.get("repo", [])) + sum(1 for a in report.get("aur", []) if a.get("new_version"))
    if level == "all" and pending:
        out.append({"key": f"updates:{report['generated_at']}", "critical": False,
                    "text": f"{pending} güncelleme bekliyor"})
    elif pending:
        last = (report.get("system") or {}).get("last_upgrade")
        if last:
            from datetime import datetime
            age = (time.time() - datetime.fromisoformat(last).timestamp()) / 86400
            if age > REMIND_DAYS:
                week = int(time.time() // (REMIND_EVERY_DAYS * 86400))
                out.append({"key": f"remind:{week}", "critical": False,
                            "text": f"{pending} güncelleme bekliyor; son güncelleme {int(age)} gün önce"})
    return out


def select(report: dict, st: dict, level: str) -> list[dict]:
    """Events not notified before; marks them as notified in st."""
    seen = st.setdefault("notified", {})
    now = int(time.time())
    for k in [k for k, t in seen.items() if now - t > FORGET_DAYS * 86400]:
        del seen[k]
    fresh = [e for e in events(report, st, level) if e["key"] not in seen]
    for e in fresh:
        seen[e["key"]] = now
    return fresh
