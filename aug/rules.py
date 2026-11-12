"""Static, model-independent checks on an AUR update.

These run on every update whether or not an LLM is configured, and an LLM
verdict can never clear a finding raised here.
"""

from __future__ import annotations

import re
import urllib.parse

from .aur import is_vcs

HIGH, MEDIUM, INFO = "high", "medium", "info"

# (severity, code, title, regex) - matched against lines the update adds.
LINE_RULES: list[tuple[str, str, str, re.Pattern]] = [
    (HIGH, "pipe-to-shell", "İnternetten indirilen içerik doğrudan kabukta çalıştırılıyor",
     re.compile(r"(curl|wget|fetch)\b[^|#\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")),
    (HIGH, "download-exec", "İndirilen dosya çalıştırılabilir yapılıp çalıştırılıyor",
     re.compile(r"\b(curl|wget)\b[^#\n]*(-o|-O|--output|>)\s*\S+[^#\n]*(&&|;|\|\|)\s*(chmod\s+[^#\n]*\+?x|(ba|z)?sh\s|\.?/\S+|\S*/tmp/)")),
    (HIGH, "tmp-exec", "Geçici ya da gizli bir dosya çalıştırılıyor",
     re.compile(r"(^|[;&|]\s*|\s)(/tmp|/dev/shm|/var/tmp)/\S*\s*&?\s*$|(/tmp|/dev/shm)/\.[\w.-]+\s*(&|;|$)")),
    (MEDIUM, "network-in-build", "Kaynak listesi dışında ağdan indirme yapılıyor (curl/wget)",
     re.compile(r"\b(curl|wget|aria2c)\b\s")),
    (MEDIUM, "base64-decode", "Kodlanmış (base64) içerik çözülüyor",
     re.compile(r"base64\s+(-d|--decode)|b64decode")),
    (HIGH, "decode-exec", "Kodlanmış (base64/hex) içerik çözülüp çalıştırılıyor",
     re.compile(r"(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)[^#\n]*\|\s*(ba|z)?sh\b|eval\s+[\"']?\$\((echo|printf)[^)]*\|\s*base64")),
    (HIGH, "eval-subst", "Komut çıktısı eval ile çalıştırılıyor",
     re.compile(r"\beval\s+[\"']?\$\((curl|wget)")),
    (HIGH, "reverse-shell", "Ters kabuk / ağ soketi kalıbı",
     re.compile(r"/dev/(tcp|udp)/|\bnc\b[^#\n]*\s-e\s|\bsocat\b[^#\n]*exec:|bash\s+-i\s+>&")),
    (HIGH, "exfil-endpoint", "Bilinen veri sızdırma / yapıştırma servisi adresi",
     re.compile(r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw|transfer\.sh|ngrok(-free)?\.(io|app)|hastebin|0x0\.st|webhook\.site|paste\.ee", re.I)),
    (HIGH, "persistence", "Sistem dışına kalıcılık (kabuk açılışı, cron, sudoers, ssh anahtarları, ld.so.preload)",
     re.compile(r"(~|\$HOME|/home/[^/\s]+|/root)/\.(bashrc|zshrc|profile|bash_profile|config/autostart)|/etc/(sudoers|ld\.so\.preload|cron\.|profile\.d)|crontab\s+-|authorized_keys")),
    (HIGH, "python-net-exec", "Python ile ağdan kod indirip çalıştırma",
     re.compile(r"python[0-9.]*\s+-c\s+[\"'][^\"']*(urllib|requests|socket)[^\"']*(exec|eval|system)")),
    (MEDIUM, "raw-ip-url", "Alan adı yerine çıplak IP adresine bağlantı",
     re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")),
    (MEDIUM, "setuid", "setuid/setgid izni veriliyor",
     re.compile(r"chmod\s+([ugoa]*\+[rwx]*s|[0-7]?[2467][0-7]{3})\b")),
    (MEDIUM, "systemd-enable", "Kurulumda bir servis etkinleştiriliyor",
     re.compile(r"systemctl\s+(--\S+\s+)*(enable|start)")),
    (MEDIUM, "build-time-network", "Derleme sırasında paket yöneticisiyle ağdan ek kod çekiliyor",
     re.compile(r"\b(npm|pnpm|yarn)\s+(i|install|add)\b[^#\n]*-g|\bpip3?\s+install\b(?![^#\n]*--no-deps)|\bgo\s+install\b|\bcargo\s+install\b")),
    (MEDIUM, "obfuscation", "Gizlenmiş görünen uzun kodlanmış metin",
     re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")),
    (MEDIUM, "ld-preload", "LD_PRELOAD kullanımı",
     re.compile(r"\bLD_PRELOAD=")),
]

CODE_FILE = re.compile(r"(^|/)(PKGBUILD|[^/]+\.(install|sh|bash|py|hook|service|desktop))$")


def added_lines(diff_text: str) -> list[tuple[str, str]]:
    """(file, line) pairs for lines the diff adds."""
    out, current = [], ""
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            current = line[4:].removeprefix("b/")
        elif line.startswith("+") and not line.startswith("+++"):
            out.append((current, line[1:]))
    return out


def changed_files(diff_text: str) -> dict[str, str]:
    """file -> 'added' | 'deleted' | 'modified'."""
    files, current = {}, None
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+) b/(.+)$", line)
            current = m[2] if m else None
            if current:
                files[current] = "modified"
        elif current and line.startswith("new file mode"):
            files[current] = "added"
        elif current and line.startswith("deleted file mode"):
            files[current] = "deleted"
    return files


def _hosts(sources: list[str]) -> set[str]:
    hosts = set()
    for s in sources:
        url = s.split("::", 1)[-1]
        url = re.sub(r"^[a-z0-9]+\+", "", url)  # git+https:// -> https://
        p = urllib.parse.urlparse(url)
        if p.scheme in ("http", "https", "ftp", "git", "ssh") and p.hostname:
            hosts.add(p.hostname.lower())
    return hosts


def _f(sev, code, title, detail="", file="", line=""):
    return {"severity": sev, "code": code, "title": title, "detail": detail, "file": file, "line": line[:300]}


def scan(*, pkgname: str, diff_text: str, has_base: bool, old_info: dict, new_info: dict,
         commits: list[dict], prev_authors: set[str], meta: dict | None,
         known_maintainer: str | None) -> list[dict]:
    findings: list[dict] = []
    seen = set()

    for file, line in added_lines(diff_text):
        if not CODE_FILE.search(file):
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for sev, code, title, rx in LINE_RULES:
            if rx.search(line) and (code, file, stripped) not in seen:
                seen.add((code, file, stripped))
                findings.append(_f(sev, code, title, file=file, line=stripped))

    # Structural checks from .SRCINFO (only meaningful against a base).
    if has_base and old_info and new_info:
        new_hosts = _hosts(new_info.get("sources", [])) - _hosts(old_info.get("sources", []))
        if new_hosts:
            findings.append(_f(MEDIUM, "new-source-host", "Kaynak dosyalar yeni bir adresten indiriliyor",
                               ", ".join(sorted(new_hosts))))
        old_skip = old_info.get("checksums", []).count("SKIP")
        new_skip = new_info.get("checksums", []).count("SKIP")
        if new_skip > old_skip and not is_vcs(pkgname):
            findings.append(_f(MEDIUM, "checksum-skip", "Sağlama toplamı doğrulaması kapatıldı (SKIP)",
                               f"SKIP sayısı {old_skip} → {new_skip}"))
        if set(new_info.get("install", [])) - set(old_info.get("install", [])):
            findings.append(_f(MEDIUM, "new-install-script", "Yeni bir kurulum betiği (.install) eklendi",
                               ", ".join(new_info["install"])))
        if old_info.get("validpgpkeys") and set(old_info["validpgpkeys"]) - set(new_info.get("validpgpkeys", [])):
            findings.append(_f(MEDIUM, "pgp-key-changed", "Kaynak imzasını doğrulayan PGP anahtarı değişti/kaldırıldı"))
        if old_info.get("url") and new_info.get("url") and old_info["url"] != new_info["url"]:
            findings.append(_f(MEDIUM, "url-changed", "Projenin ana sayfası değişti",
                               f"{old_info['url']} → {new_info['url']}"))

    files = changed_files(diff_text)
    for f, kind in files.items():
        if kind == "modified" and f.endswith(".install") and has_base:
            findings.append(_f(MEDIUM, "install-script-changed", "Kurulum betiği (.install) değişti", file=f))
        if kind == "added" and has_base and CODE_FILE.search(f) and not f.endswith("PKGBUILD"):
            findings.append(_f(INFO, "new-file", "Pakete yeni bir betik dosyası eklendi", file=f))

    # People.
    if has_base and prev_authors:
        new_people = {c["email"] for c in commits} - prev_authors
        if new_people:
            names = sorted({f"{c['author']} <{c['email']}>" for c in commits if c["email"] in new_people})
            findings.append(_f(MEDIUM, "new-committer", "Paketi daha önce değiştirmemiş biri commit atmış",
                               ", ".join(names)))
    if meta:
        maint = meta.get("Maintainer")
        if known_maintainer and maint != known_maintainer:
            findings.append(_f(MEDIUM, "maintainer-changed", "Paketin bakımcısı değişti",
                               f"{known_maintainer} → {maint or 'sahipsiz'}"))
        if not maint:
            findings.append(_f(INFO, "orphaned", "Paketin şu an bakımcısı yok (sahipsiz)"))
        if meta.get("OutOfDate"):
            findings.append(_f(INFO, "out-of-date", "AUR'da 'güncel değil' olarak işaretli"))
        if (meta.get("NumVotes") or 0) < 5:
            findings.append(_f(INFO, "low-votes", "Çok az oy almış, az kişi tarafından kullanılıyor",
                               f"{meta.get('NumVotes', 0)} oy"))
    if not has_base:
        findings.append(_f(INFO, "no-base", "Kurulu sürümün commit'i bulunamadı; paketin tamamı inceleniyor"))
    return findings


def worst(findings: list[dict]) -> str | None:
    order = {HIGH: 3, MEDIUM: 2, INFO: 1}
    return max((f["severity"] for f in findings), key=lambda s: order[s], default=None)
