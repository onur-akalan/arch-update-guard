"""Local dashboard server (127.0.0.1 only, token-protected)."""

from __future__ import annotations

import copy
import http.cookies
import json
import logging
import mimetypes
import os
import secrets
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__, check, deps, review, schedule, state, updater
from .config import (SERVER_FILE, WEB_DIR, SettingsError, atomic_write_json, delete_secret, get_secret,
                     load_settings, read_json, save_settings, set_secret, validate_settings)

log = logging.getLogger("aug")
IDLE_EXIT_SECONDS = 20 * 60


class App:
    def __init__(self):
        self.token = secrets.token_urlsafe(24)
        self.last_request = time.time()
        self.check_thread: threading.Thread | None = None
        self.check_error: str | None = None
        self.review_busy: set[str] = set()
        self.lock = threading.Lock()

    # -- background check -------------------------------------------------
    def start_check(self) -> bool:
        with self.lock:
            if (self.check_thread and self.check_thread.is_alive()) or state.check_running():
                return False
            self.check_error = None
            self.check_thread = threading.Thread(target=self._check, daemon=True)
            self.check_thread.start()
            return True

    def _check(self):
        try:
            check.run()
        except state.CheckRunning:
            pass
        except Exception as e:
            log.exception("check failed")
            self.check_error = f"{type(e).__name__}: {e}"

    def busy(self) -> bool:
        return bool(self.check_thread and self.check_thread.is_alive()) or state.check_running()

    # -- single-package re-review ----------------------------------------
    def rereview(self, name: str, provider_id: str | None) -> dict:
        report = check.load_report()
        if not report:
            raise ValueError("Önce bir kontrol çalıştır.")
        item = next((a for a in report["aur"] if a["name"] == name), None)
        if not item or not item.get("diff"):
            raise ValueError("Bu paket için incelenecek bir diff yok.")
        with self.lock:
            if name in self.review_busy:
                raise ValueError("Bu paket zaten inceleniyor.")
            self.review_busy.add(name)
        try:
            settings = load_settings()
            d = item["diff"]
            ctx = {"pkgname": name, "pkgbase": item["pkgbase"], "installed": item["installed"],
                   "new_version": item["new_version"],
                   "meta": {"Maintainer": item.get("maintainer"), "NumVotes": item.get("votes"),
                            "Popularity": item.get("popularity"), "FirstSubmitted": item.get("first_submitted")},
                   "has_base": bool(d.get("base")), "commits": item.get("commits", []),
                   "static_findings": item.get("findings", []), "stat": d["stat"], "diff": d["text"],
                   "diff_chars": d["chars"], "truncated": d["truncated"]}
            res = review.review(ctx, settings, provider_id)
            pid = provider_id or settings["review"]["active_provider"]
            with state.mutate() as st:
                st["reviews"][state.review_key(item["pkgbase"], item["target"], pid)] = res
            # Patch the cached report so the dashboard updates without a full check.
            fresh = check.load_report()
            for a in fresh["aur"]:
                if a["name"] == name and a.get("target") == item["target"]:
                    a["llm"] = res
                    a["status"] = deps.combine_status(a["findings"], res,
                                                      [d["status"] for d in a.get("new_aur_deps", [])])
                    a["auto_ok"] = a["status"] == "clean" and not a.get("held")
            atomic_write_json(check.REPORT_FILE, fresh)
            return res
        finally:
            with self.lock:
                self.review_busy.discard(name)


def _public_settings(settings: dict) -> dict:
    s = copy.deepcopy(settings)
    for p in s["providers"]:
        p["has_key"] = get_secret(p["id"]) is not None if p["type"] in ("anthropic", "openai") else None
    return s


def _decorate_report(report: dict | None) -> dict | None:
    if not report:
        return None
    st = state.load()
    now = time.time()
    read = set(st["news_read"])
    for n in report["news"]:
        n["read"] = n["id"] in read
    for a in report["aur"]:
        if a.get("target"):
            ap = st["approvals"].get(a["name"])
            a["approved"] = bool(ap and ap.get("commit") == a.get("approval_key", a["target"]))
            a["held"] = now < a.get("hold_until", 0)
            a["auto_ok"] = a["status"] == "clean" and not a["held"]
    return report


def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = f"aug/{__version__}"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        # -- helpers -----------------------------------------------------
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                             "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, data, code: int = 200):
            self._send(code, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _error(self, msg: str, code: int = 400):
            self._json({"error": msg}, code)

        def _authorized(self) -> bool:
            if self.headers.get("Host") not in allowed_hosts:
                return False
            c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return "aug" in c and secrets.compare_digest(c["aug"].value, app.token)

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 2_000_000:
                raise ValueError("istek çok büyük")
            return json.loads(self.rfile.read(n) or b"{}")

        # -- routing -----------------------------------------------------
        def do_GET(self):
            app.last_request = time.time()
            url = urlparse(self.path)
            if self.headers.get("Host") not in allowed_hosts:
                return self._send(403, b"forbidden", "text/plain")
            if url.path == "/" and "t" in parse_qs(url.query):
                t = parse_qs(url.query)["t"][0]
                if not secrets.compare_digest(t, app.token):
                    return self._send(403, b"forbidden", "text/plain")
                return self._send(303, b"", "text/plain", {
                    "Location": "/", "Set-Cookie": f"aug={app.token}; Path=/; HttpOnly; SameSite=Strict"})
            if not self._authorized():
                return self._send(403, "Erişim reddedildi. Panoyu 'aug open' ile aç.".encode(),
                                  "text/plain; charset=utf-8")
            if url.path == "/":
                return self._static("index.html")
            if url.path.startswith("/static/"):
                return self._static(url.path.removeprefix("/static/"))
            if url.path == "/api/state":
                return self._json(self._state())
            if url.path == "/api/settings":
                return self._json(_public_settings(load_settings()))
            return self._error("bulunamadı", 404)

        def do_POST(self):
            app.last_request = time.time()
            if not self._authorized() or self.headers.get("X-Requested-With") != "aug":
                return self._error("yetkisiz", 403)
            path = urlparse(self.path).path
            try:
                body = self._body()
                handler = ROUTES.get(path)
                if not handler:
                    return self._error("bulunamadı", 404)
                return self._json(handler(body))
            except (ValueError, SettingsError, updater.UpdateError) as e:
                return self._error(str(e))
            except Exception as e:
                log.exception("POST %s", path)
                return self._error(f"Beklenmeyen hata: {type(e).__name__}: {e}", 500)

        def _static(self, rel: str):
            p = (WEB_DIR / rel).resolve()
            if WEB_DIR.resolve() not in p.parents or not p.is_file():
                return self._error("bulunamadı", 404)
            ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            self._send(200, p.read_bytes(), ctype)

        def _state(self) -> dict:
            progress = read_json(check.PROGRESS_FILE, None) if app.busy() else None
            return {
                "version": __version__,
                "report": _decorate_report(check.load_report()),
                "busy": app.busy(),
                "progress": progress,
                "check_error": app.check_error,
                "update": updater.update_status(),
                "reviewing": sorted(app.review_busy),
            }

    # -- POST routes ------------------------------------------------------
    def r_check(_):
        return {"started": app.start_check()}

    def r_news_read(body):
        ids = body.get("ids") or []
        with state.mutate() as st:
            read = set(st["news_read"]) | {str(i) for i in ids}
            st["news_read"] = sorted(read)[-500:]
        return {"ok": True}

    def r_approve(body):
        name, commit = body.get("name"), body.get("commit")
        report = check.load_report() or {"aur": []}
        item = next((a for a in report["aur"]
                     if a["name"] == name and a.get("target") and a.get("approval_key", a["target"]) == commit), None)
        if not item:
            raise ValueError("Paket ya da commit güncel raporda yok; yeniden kontrol et.")
        if item["status"] in ("danger", "warning") and body.get("confirm") != name:
            raise ValueError("Uyarılı paketi onaylamak için paket adını yazman gerekiyor.")
        with state.mutate() as st:
            st["approvals"][name] = {"commit": commit, "at": int(time.time()), "status": item["status"]}
            st["maintainers"][item["pkgbase"]] = item.get("maintainer")
        return {"ok": True}

    def r_unapprove(body):
        with state.mutate() as st:
            st["approvals"].pop(body.get("name"), None)
        return {"ok": True}

    def r_rereview(body):
        return app.rereview(body.get("name"), body.get("provider"))

    def r_settings(body):
        saved = save_settings(body)
        schedule_msg = schedule.apply(saved["schedule"])
        return {"settings": _public_settings(saved), "schedule": schedule_msg}

    def r_secret(body):
        pid = body.get("provider")
        settings = load_settings()
        if not any(p["id"] == pid for p in settings["providers"]):
            raise ValueError("Önce sağlayıcıyı kaydet.")
        value = body.get("value")
        if value:
            set_secret(pid, value.strip())
        else:
            delete_secret(pid)
        return {"ok": True, "has_key": bool(value)}

    def r_test_provider(body):
        settings = validate_settings(body.get("settings") or load_settings())
        return review.test_provider(settings, body.get("provider"))

    def r_update(body):
        report = check.load_report()
        if not report:
            raise ValueError("Önce bir kontrol çalıştır.")
        if app.busy():
            raise ValueError("Kontrol sürüyor; bitmesini bekle.")
        if time.time() - report["generated_at"] > 6 * 3600:
            raise ValueError("Rapor 6 saatten eski; önce yeniden kontrol et.")
        report = _decorate_report(report)
        return updater.launch(report, body.get("aur") or [], bool(body.get("news_ack")))

    def r_restart(body):
        report = check.load_report()
        if not report:
            raise ValueError("Önce bir kontrol çalıştır.")
        return updater.launch_restart(report, body.get("units") or [])

    ROUTES = {"/api/restart": r_restart, "/api/check": r_check, "/api/news/read": r_news_read, "/api/approve": r_approve,
              "/api/unapprove": r_unapprove, "/api/rereview": r_rereview, "/api/settings": r_settings,
              "/api/secret": r_secret, "/api/test-provider": r_test_provider, "/api/update": r_update}
    return Handler


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def running_server() -> dict | None:
    info = read_json(SERVER_FILE, None)
    if not info:
        return None
    try:
        os.kill(info["pid"], 0)
        with socket.create_connection(("127.0.0.1", info["port"]), timeout=1):
            return info
    except (OSError, KeyError, TypeError):
        SERVER_FILE.unlink(missing_ok=True)
        return None


def serve() -> None:
    app = App()
    port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port))
    httpd.daemon_threads = True
    atomic_write_json(SERVER_FILE, {"pid": os.getpid(), "port": port, "token": app.token})

    def idle_watch():
        while True:
            time.sleep(30)
            if (time.time() - app.last_request > IDLE_EXIT_SECONDS and not app.busy()
                    and not app.review_busy):
                httpd.shutdown()
                return

    threading.Thread(target=idle_watch, daemon=True).start()
    log.info("serving on 127.0.0.1:%s", port)
    try:
        httpd.serve_forever()
    finally:
        info = read_json(SERVER_FILE, None)
        if info and info.get("pid") == os.getpid():
            SERVER_FILE.unlink(missing_ok=True)
