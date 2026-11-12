"""Download the source files of an AUR update and look inside them.

The PKGBUILD diff cannot show what is inside a downloaded tarball, .deb or
AppImage, and in real AUR attacks the payload was sometimes there. This
module downloads the remote sources the new commit names (exactly what
makepkg would fetch), verifies the checksums the PKGBUILD pins, and builds a
manifest of each archive: every member's path, size, mode and hash, plus the
text of the files that matter for safety (install hooks, autostart and
systemd entries, build scripts, executable scripts).

Nothing is ever extracted to disk or executed: tar, zip and .deb are read in
memory with the standard library; AppImage, rpm and other formats are only
listed and read through `7z ... -so`. Downloads are deleted as soon as the
manifest exists. Manifests are kept per AUR commit, so after an update the
installed version becomes the baseline the next update is compared against.
"""

from __future__ import annotations

import difflib
import gzip
import hashlib
import io
import json
import logging
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from . import __version__, rules
from .config import CACHE_DIR, DATA_DIR
from .i18n import t

log = logging.getLogger("aug")

MANIFEST_DIR = DATA_DIR / "sources"
DL_DIR = CACHE_DIR / "sources"
ALGOS = ("b2", "sha512", "sha384", "sha256", "sha224", "sha1", "md5")
VCS = ("git", "svn", "hg", "bzr", "fossil")
TEXT_MAX = 256 * 1024          # keep the text of one notable file up to this size...
BUILD_TEXT_MAX = 3 * 1024 * 1024  # ...or this for build machinery (a generated configure is big)
TEXT_BUDGET = 24 * 1024 * 1024    # all kept text per source file
HASH_BUDGET = 6 * 1024 ** 3    # stop hashing members after this many bytes (archive bombs)
MAX_MEMBERS = 300_000
FORMAT_VERSION = 1

# --- Where a file lands decides how much it matters --------------------------
# "persist": runs automatically or changes how the system starts programs.
PERSIST = re.compile(
    r"(^|/)(etc/ld\.so\.preload|etc/sudoers(\.d/.+)?|etc/crontab|etc/cron\.[^/]+/.+|var/spool/cron/.+"
    r"|etc/profile(\.d/.+)?|etc/bash\.bashrc|etc/zsh/.+|etc/environment|etc/xdg/autostart/.+"
    r"|\.config/autostart/.+|\.(bashrc|zshrc|profile|bash_profile|zprofile)"
    r"|usr/share/libalpm/hooks/.+|etc/pacman\.d/hooks/.+)$")
# "system": integrates with the system as root (services, udev, polkit, pam...).
SYSTEM = re.compile(
    r"(^|/)((usr/)?lib/systemd/(system|user)(-[a-z]+)?/.+|etc/systemd/.+|(usr/)?lib/udev/rules\.d/.+|etc/udev/.+"
    r"|usr/share/dbus-1/(system-)?services/.+|usr/share/dbus-1/system\.d/.+|etc/dbus-1/.+"
    r"|usr/share/polkit-1/rules\.d/.+|etc/polkit-1/.+|etc/pam\.d/.+|(usr/)?lib/security/.+"
    r"|etc/ld\.so\.conf(\.d/.+)?|(usr/)?lib/modprobe\.d/.+|etc/modprobe\.d/.+|etc/modules-load\.d/.+"
    r"|usr/lib/(sysusers|tmpfiles)\.d/.+|etc/sysctl\.d/.+|usr/lib/sysctl\.d/.+)$")
# Run during `makepkg` when they sit near the top of a source tree.
BUILD_NAMES = re.compile(
    r"^(Makefile|GNUmakefile|makefile|configure|configure\.ac|setup\.py|pyproject\.toml|build\.rs|Cargo\.toml"
    r"|CMakeLists\.txt|meson\.build|package\.json|build\.gradle(\.kts)?|build\.sh|install\.sh|bootstrap"
    r"|autogen\.sh|Rakefile|build\.zig|go\.mod|\.npmrc|\.yarnrc(\.yml)?)$")
# Build machinery anywhere in the tree: this is where the xz backdoor's trigger hid
# (m4/build-to-host.m4, a file nobody reads because autotools generates such files).
BUILD_ANY_DEPTH = re.compile(
    r"(\.m4|\.cmake|/configure\.(ac|in)|/Makefile\.(am|in)|/CMakeLists\.txt|/meson\.build|/meson(_options)?\.(txt|options)"
    r"|/build\.rs|/SConstruct|/SConscript|/Kbuild|/wscript)$")
DEB_SCRIPTS = {"preinst", "postinst", "prerm", "postrm", "config", "triggers"}
AI_MAGIC = (b"AI\x01", b"AI\x02")


def category(path: str) -> str | None:
    if path.startswith("control/") and path.split("/")[-1] in DEB_SCRIPTS:
        return "deb-script"
    if PERSIST.search(path):
        return "persist"
    if SYSTEM.search(path):
        return "system"
    parts = path.split("/")
    if len(parts) <= 3 and (BUILD_NAMES.match(parts[-1]) or parts[-1].endswith(".sh") or parts[-1] == "aclocal.m4"):
        return "build"
    if BUILD_ANY_DEPTH.search("/" + path):
        return "build"
    return None


CATEGORY_TR = {"persist": "otomatik çalışma / kalıcılık noktası", "system": "sistem bileşeni (servis, udev, polkit…)",
               "deb-script": ".deb kurulum betiği", "build": "derleme betiği", "script": "çalıştırılabilir betik"}


# --- .SRCINFO sources ------------------------------------------------------------

def list_sources(srcinfo_text: str, arch: str = "x86_64") -> list[dict]:
    """Sources for this architecture with the strongest checksum pinned for each."""
    keys: dict[str, list[str]] = {}
    section = None
    for raw in srcinfo_text.splitlines():
        line = raw.strip()
        if " = " not in line:
            continue
        k, v = line.split(" = ", 1)
        if k in ("pkgbase", "pkgname"):
            section = k
            continue
        if section == "pkgbase":
            keys.setdefault(k, []).append(v)
    out = []
    for suffix in ("", "_" + arch):
        for i, s in enumerate(keys.get("source" + suffix, [])):
            name, url = s.split("::", 1) if "::" in s else (None, s)
            scheme = url.split("://", 1)[0].lower() if "://" in url else ""
            if not scheme:
                kind = "local"
            elif "+" in scheme or scheme in VCS:
                kind = "vcs"
            elif scheme in ("http", "https", "ftp"):
                kind = "remote"
            else:
                kind = "other"
            if kind == "vcs":
                fname = name or url.split("#")[0].rstrip("/").split("/")[-1].removesuffix(".git")
            else:
                fname = name or urllib.parse.unquote(url.split("#")[0].split("?")[0].rstrip("/").split("/")[-1])
            checksum = None
            for algo in ALGOS:
                lst = keys.get(f"{algo}sums{suffix}")
                if lst and i < len(lst):
                    checksum = (algo, lst[i].lower())
                    break
            out.append({"file": fname, "url": url, "kind": kind, "arch": suffix.lstrip("_") or "any",
                        "checksum": checksum})
    return out


# --- download ----------------------------------------------------------------------

class TooLarge(Exception):
    pass


class Deferred(Exception):
    """The per-check download time ran out; the partial file is resumed next time."""


_deadline: float | None = None
_rate: float = 0  # bytes per second, 0 = unlimited


def set_rate(bytes_per_second: float) -> None:
    global _rate
    _rate = max(0.0, bytes_per_second)


def set_deadline(seconds: float | None) -> None:
    global _deadline
    _deadline = time.time() + seconds if seconds else None


def _hasher(algo: str):
    return hashlib.blake2b() if algo == "b2" else hashlib.new(algo)


def file_digest(path: Path, algo: str) -> str:
    h = _hasher(algo)
    with open(path, "rb") as f:
        while chunk := f.read(4 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, max_bytes: int) -> int:
    """Fetch url to dest, resuming a previous partial download. Returns the size."""
    if _deadline and time.time() > _deadline:
        raise Deferred()
    part = dest.with_name(dest.name + ".part")
    have = part.stat().st_size if part.exists() else 0
    headers = {"User-Agent": f"arch-update-guard/{__version__} (makepkg-like)"}
    if have:
        headers["Range"] = f"bytes={have}-"
    req = urllib.request.Request(url, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        if e.code == 416 and have:  # range not satisfiable: start over
            part.unlink(missing_ok=True)
            return download(url, dest, max_bytes)
        raise
    with r:
        if have and r.status != 206:
            have = 0
        length = r.headers.get("Content-Length")
        if length and length.isdigit() and have + int(length) > max_bytes:
            raise TooLarge(have + int(length))
        size = have
        t0 = time.monotonic()
        with open(part, "ab" if have else "wb") as f:
            while chunk := r.read(256 * 1024 if _rate else 1024 * 1024):
                if _rate:  # keep the connection free for the user
                    ahead = (size - have + len(chunk)) / _rate - (time.monotonic() - t0)
                    if ahead > 0:
                        time.sleep(min(ahead, 5))
                size += len(chunk)
                if size > max_bytes:
                    f.close()
                    part.unlink(missing_ok=True)
                    raise TooLarge(size)
                f.write(chunk)
                if _deadline and time.time() > _deadline:
                    raise Deferred(size)
    part.replace(dest)
    return size


# --- archive manifests ---------------------------------------------------------------

def _is_text(data: bytes) -> bool:
    if b"\0" in data[:8192]:
        return False
    try:
        data[:8192].decode("utf-8")
        return True
    except UnicodeDecodeError as e:
        return e.start > 8180  # cut in the middle of a multibyte char


def _norm(path: str) -> str:
    while path.startswith("./"):
        path = path[2:]
    return path


class _Builder:
    def __init__(self, fmt: str):
        self.m = {"format": fmt, "members": {}, "texts": {}, "notes": [], "issues": [], "root": ""}
        self.text_used = 0
        self.hashed = 0

    def add(self, path: str, size: int, mode: int, kind: str, reader=None, link: str = "",
            cat_override: str | None = None) -> None:
        if len(self.m["members"]) >= MAX_MEMBERS:
            if "too-many" not in self.m["notes"]:
                self.m["notes"].append("too-many")
            return
        raw = path
        path = _norm(path)
        if raw.startswith("/") or ".." in raw.split("/"):
            self.m["issues"].append({"code": "path-traversal", "path": raw})
            path = path.lstrip("/")
        if kind == "d" or not path:
            return
        rec = {"size": size, "mode": mode & 0o7777, "type": kind}
        if link:
            rec["link"] = link[:300]
        cat = cat_override or category(path)
        if kind == "f" and reader is not None:
            want_all = self.hashed < HASH_BUDGET
            if want_all or cat:
                data_head, digest, text = self._read(reader, size,
                                                     BUILD_TEXT_MAX if cat == "build" else TEXT_MAX)
                rec["sha"] = digest
                rec["elf"] = data_head.startswith(b"\x7fELF")
                if data_head and not rec["elf"] and not _is_text(data_head):
                    rec["bin"] = True  # opaque data: images, compressed "test files"...
                is_script = data_head.startswith(b"#!") and _is_text(data_head)
                if not cat and is_script and mode & 0o111:
                    cat = "script"
                if cat and text is not None and self.text_used + len(text) <= TEXT_BUDGET:
                    self.m["texts"][path] = text
                    self.text_used += len(text)
        if cat:
            rec["cat"] = cat
        self.m["members"][path] = rec

    def _read(self, reader, size: int, limit: int):
        f = reader()
        if f is None:
            return b"", None, None
        h = hashlib.sha256()
        head = b""
        buf = io.BytesIO() if size <= limit else None
        while chunk := f.read(1024 * 1024):
            if not head:
                head = chunk[:8192]
            h.update(chunk)
            self.hashed += len(chunk)
            if buf is not None:
                buf.write(chunk)
                if buf.tell() > limit:
                    buf = None
        text = None
        if buf is not None and _is_text(buf.getvalue()):
            text = buf.getvalue().decode("utf-8", "replace")
        return head, h.hexdigest()[:24], text

    def finish(self) -> dict:
        # Strip a single common top-level directory (foo-1.2/...) so versions compare.
        names = list(self.m["members"])
        firsts = {n.split("/", 1)[0] for n in names}
        if len(firsts) == 1 and all("/" in n for n in names) and self.m["format"] != "deb":
            root = firsts.pop() + "/"
            self.m["root"] = root
            self.m["members"] = {k[len(root):]: v for k, v in self.m["members"].items()}
            self.m["texts"] = {k[len(root):]: v for k, v in self.m["texts"].items()}
        return self.m


def _tar_into(b: _Builder, tf: tarfile.TarFile, prefix: str = "") -> None:
    for ti in tf:
        kind = "f" if ti.isreg() else "l" if ti.issym() or ti.islnk() else "d" if ti.isdir() else "o"
        b.add(prefix + _norm(ti.name), ti.size, ti.mode, kind,
              reader=(lambda ti=ti: tf.extractfile(ti)) if kind == "f" else None,
              link=ti.linkname if kind == "l" else "")


class _Slice(io.RawIOBase):
    """Read-only window into a file (one member of an ar archive)."""

    def __init__(self, f, offset: int, size: int):
        self.f, self.left = f, size
        f.seek(offset)

    def readable(self):
        return True

    def readinto(self, b):
        n = min(len(b), self.left)
        if n <= 0:
            return 0
        data = self.f.read(n)
        b[:len(data)] = data
        self.left -= len(data)
        return len(data)


def _deb(path: Path) -> dict:
    b = _Builder("deb")
    with open(path, "rb") as f:
        if f.read(8) != b"!<arch>\n":
            raise ValueError(t("ar başlığı yok"))
        while hdr := f.read(60):
            if len(hdr) < 60:
                break
            name = hdr[:16].decode("ascii", "replace").strip().rstrip("/")
            size = int(hdr[48:58].decode().strip() or 0)
            start = f.tell()
            if name.startswith(("control.tar", "data.tar")):
                part = "control/" if name.startswith("control") else "data/"
                stream = io.BufferedReader(_Slice(f, start, size))
                with tarfile.open(fileobj=stream, mode="r|*") as tf:
                    _tar_into(b, tf, part)
            f.seek(start + size + (size & 1))
    return b.finish()


def _seven_zip(path: Path, fmt: str) -> dict:
    """List an archive 7z understands (AppImage squashfs, rpm, iso...) and read notable files."""
    b = _Builder(fmt)
    r = subprocess.run(["7z", "l", "-slt", "-ba", "-spd", "--", str(path)], capture_output=True,
                       timeout=300, env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin"})
    if r.returncode != 0:
        raise ValueError(t("7z arşivi okuyamadı"))
    for block in r.stdout.decode("utf-8", "replace").split("\n\n"):
        rec = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
        p = rec.get("Path")
        if not p:
            continue
        mode_s = rec.get("Mode") or rec.get("Attributes") or ""
        kind = "d" if rec.get("Folder") == "+" or mode_s.startswith("d") else "l" if mode_s.startswith("l") else "f"
        mode = 0
        perm = mode_s[-9:] if len(mode_s) >= 10 else ""
        for i, ch in enumerate(perm):
            if ch not in "-":
                mode |= 1 << (8 - i)
        if len(perm) == 9 and perm[2] in "sS":
            mode |= stat.S_ISUID
        if len(perm) == 9 and perm[5] in "sS":
            mode |= stat.S_ISGID
        size = int(rec.get("Size") or 0)
        cat = category(p)
        exec_small = kind == "f" and mode & 0o111 and size <= TEXT_MAX

        def reader(p=p):
            out = subprocess.run(["7z", "x", "-so", "-spd", "--", str(path), p], capture_output=True,
                                 timeout=120, env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin"})
            return io.BytesIO(out.stdout[:TEXT_MAX + 1]) if out.returncode == 0 else None

        if kind == "f" and (cat or exec_small):
            b.add(p, size, mode, kind, reader=reader)
        else:
            b.add(p, size, mode, kind, link=rec.get("Symbolic Link", ""))
            if kind == "f":
                b.m["members"].get(_norm(p), {}).setdefault("crc", rec.get("CRC", ""))
    b.m["notes"].append("size-only")  # members are not hashed in this format
    return b.finish()


def inspect(path: Path, name: str) -> dict:
    with open(path, "rb") as f:
        head = f.read(512)
    try:
        if head.startswith(b"!<arch>\n"):
            m = _deb(path)
        elif head.startswith(b"\x7fELF") and head[8:11] in AI_MAGIC:
            m = _seven_zip(path, "appimage")
        elif head.startswith(b"\xed\xab\xee\xdb"):
            m = _seven_zip(path, "rpm")
        elif zipfile.is_zipfile(path) and not head.startswith(b"\x7fELF"):
            b = _Builder("zip")
            with zipfile.ZipFile(path) as z:
                for zi in z.infolist():
                    mode = zi.external_attr >> 16
                    kind = "d" if zi.is_dir() else "l" if stat.S_ISLNK(mode) else "f"
                    b.add(zi.filename, zi.file_size, mode, kind,
                          reader=(lambda zi=zi: z.open(zi)) if kind == "f" else None)
            m = b.finish()
        elif _looks_tar(path):
            b = _Builder("tar")
            with tarfile.open(path, mode="r|*") as tf:
                _tar_into(b, tf)
            m = b.finish()
        elif name.lower().endswith((".iso", ".7z", ".cab", ".msi", ".dmg")):
            m = _seven_zip(path, name.rsplit(".", 1)[-1].lower())
        else:
            # A plain file (a script, a binary, a JSON manifest...): keep its text if it is text.
            b = _Builder("file")
            size = path.stat().st_size
            text_like = _is_text(head) and size <= TEXT_MAX
            b.add(name, size, 0o755 if head.startswith((b"\x7fELF", b"#!")) else 0o644, "f",
                  reader=lambda: open(path, "rb"),
                  cat_override=("script" if head.startswith(b"#!") else "text") if text_like else None)
            m = b.m
    except Exception as e:  # any parser failure means "not inspected", never "clean"
        m = {"format": "unreadable", "members": {}, "texts": {}, "notes": [t("okunamadı: {e}", e=e)[:200]],
             "issues": [], "root": ""}
    return m


def _looks_tar(path: Path) -> bool:
    try:
        with tarfile.open(path, mode="r|*") as tf:
            return tf.next() is not None
    except (tarfile.TarError, EOFError, OSError):
        return False


# --- manifests on disk -----------------------------------------------------------

def _mpath(pkgbase: str, commit: str) -> Path:
    return MANIFEST_DIR / pkgbase / f"{commit}.json.gz"


def load_manifest(pkgbase: str, commit: str | None) -> dict | None:
    if not commit:
        return None
    try:
        with gzip.open(_mpath(pkgbase, commit), "rt", encoding="utf-8") as f:
            data = json.load(f)
        return data if data.get("version") == FORMAT_VERSION else None
    except (OSError, json.JSONDecodeError, EOFError):
        return None


def _save_manifest(pkgbase: str, commit: str, data: dict) -> None:
    p = _mpath(pkgbase, commit)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    tmp.replace(p)


def prune(pkgbase: str, keep: set[str]) -> None:
    d = MANIFEST_DIR / pkgbase
    if d.is_dir():
        for p in d.glob("*.json.gz"):
            if p.name.removesuffix(".json.gz") not in keep:
                p.unlink(missing_ok=True)


def _opaque(m: dict) -> bool:
    """A plain non-text file: an old copy adds nothing to the comparison."""
    return m.get("format") == "file" and not m.get("texts")


def _safe_name(name: str) -> str | None:
    return name if name and "/" not in name and name not in (".", "..") and not name.startswith(".") else None


def collect(pkgbase: str, commit: str, srcinfo_text: str, max_file_mb: int, *,
            keep_files: bool, save_incomplete: bool = False, skip_roles: frozenset = frozenset()) -> dict:
    """Download and inspect the remote sources of one commit (cached per commit).

    keep_files: keep checksum-verified downloads in DL_DIR so the update can hand
    them to yay instead of downloading them a second time.
    """
    cached = load_manifest(pkgbase, commit)
    if cached:
        return cached
    work_dir = DL_DIR / pkgbase if keep_files else DL_DIR / pkgbase / ".baseline"
    work_dir.mkdir(parents=True, exist_ok=True)
    out = {"version": FORMAT_VERSION, "commit": commit, "created": int(time.time()), "sources": []}
    retry = False
    for s in list_sources(srcinfo_text):
        rec = {k: s[k] for k in ("file", "url", "kind", "arch")}
        rec["checksum"] = list(s["checksum"]) if s["checksum"] else None
        if s["kind"] != "remote":
            rec["status"] = {"local": "in-repo", "vcs": "vcs"}.get(s["kind"], "unsupported")
            out["sources"].append(rec)
            continue
        if _role(s) in skip_roles:
            rec["status"] = "skipped"  # comparing it would say nothing (e.g. a single compiled binary)
            out["sources"].append(rec)
            continue
        algo = s["checksum"][0] if s["checksum"] and s["checksum"][1] != "skip" else None
        name = _safe_name(s["file"])
        tmp = None
        if name:
            dest = work_dir / name
        else:
            tmp = Path(tempfile.mkdtemp(dir=work_dir))
            dest = tmp / "src"
        try:
            reuse = dest.exists() and algo and file_digest(dest, algo) == s["checksum"][1]
            if not reuse:
                dest.unlink(missing_ok=True)
                download(s["url"], dest, max_file_mb * 1024 * 1024)
            rec["size"] = dest.stat().st_size
            rec["verified"] = (file_digest(dest, algo) == s["checksum"][1]) if algo else None
            rec["manifest"] = inspect(dest, s["file"])
            rec["status"] = "ok"
            if keep_files and name and rec["verified"]:
                rec["cached"] = str(dest)
            else:
                dest.unlink(missing_ok=True)
        except Deferred:
            rec["status"] = "deferred"
            retry = True
        except TooLarge as e:
            rec["status"] = "too-large"
            rec["size"] = e.args[0] if e.args else None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            rec["status"] = "download-failed"
            rec["error"] = str(e)[:200]
            retry = retry or not save_incomplete
            dest.with_name(dest.name + ".part").unlink(missing_ok=True)
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
        out["sources"].append(rec)
    if not keep_files:
        shutil.rmtree(work_dir, ignore_errors=True) if not retry else None
    if not retry:
        _save_manifest(pkgbase, commit, out)
    return out


def prune_downloads(pkgbase: str, keep_names: set[str]) -> None:
    d = DL_DIR / pkgbase
    if not d.is_dir():
        return
    for p in d.iterdir():
        if p.is_file() and p.name.removesuffix(".part") not in keep_names:
            p.unlink(missing_ok=True)


# --- release tarball vs. the upstream git tag ------------------------------------
# The xz backdoor existed only in the release tarball, never in git. A tarball
# that a maintainer uploads (as opposed to one the forge generates from git)
# can contain anything, so it is compared with the forge's archive of the same
# tag. Autotools/gettext output legitimately exists only in tarballs; those
# files are listed separately and still scanned, everything else is flagged.

GH_RELEASE = re.compile(r"^https?://github\.com/([^/]+)/([^/]+)/releases/download/([^/]+)/")
GIT_GENERATED = re.compile(r"^https?://(github\.com/[^/]+/[^/]+/archive/|codeload\.github\.com/|[^/]+/.+/-/archive/"
                           r"|codeberg\.org/[^/]+/[^/]+/archive/)")
GH_REPO = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$")
GL_REPO = re.compile(r"^https?://(gitlab\.[\w.-]+|codeberg\.org|salsa\.debian\.org|invent\.kde\.org)/([\w./-]+?)"
                     r"(?:\.git)?/?$")
TARBALL_ONLY_OK = re.compile(
    r"(^|/)(configure|aclocal\.m4|config\.h\.in~?|Makefile\.in|GNUmakefile|ltmain\.sh|libtool|compile|depcomp"
    r"|install-sh|missing|config\.(guess|sub|rpath)|ar-lib|test-driver|ylwrap|mkinstalldirs|py-compile|ABOUT-NLS"
    r"|INSTALL|ChangeLog|\.tarball-version|\.version|\.prev-version|stamp-[\w.-]+|[\w.-]+\.gmo|[\w.-]+\.pot"
    r"|[\w.-]+\.info(-\d+)?|Makefile\.in\.in|Rules-quot|[\w.@-]+\.(sed|sin|header)|PKG-INFO|setup\.cfg"
    r"|[\w.-]+\.egg-info/.+|MANIFEST)$"
    r"|(^|/)(build-aux|m4|gnulib-m4|autom4te\.cache|intl|vendor)/"
    r"|\.(1|3|5|7|8|html|pdf|ps|dvi)$")
TESTISH = re.compile(r"(^|/)(tests?|testdata|testsuite|test-?files|fixtures?|t|corpus)/")
# Hand-maintained build machinery. A regenerated `configure` / `aclocal.m4` changes in
# every autotools release, so those alone do not count; m4/*.m4 (where the xz trigger
# hid) only changes when the maintainer touches the build system.
MACHINERY = re.compile(r"((^|/)m4/[^/]+\.m4|(^|/)configure\.(ac|in)|\.cmake|(^|/)CMakeLists\.txt|(^|/)meson\.build"
                       r"|(^|/)build\.rs)$")


def _ls_tags(repo_url: str) -> set[str]:
    from .aur import GIT  # hardened git
    r = subprocess.run([*GIT, "ls-remote", "--tags", "--refs", repo_url], capture_output=True, text=True,
                       timeout=60, env={"LC_ALL": "C.UTF-8", "PATH": "/usr/bin", "GIT_TERMINAL_PROMPT": "0"})
    if r.returncode != 0:
        return set()
    return {line.split("refs/tags/", 1)[1] for line in r.stdout.splitlines() if "refs/tags/" in line}


def git_origin(url: str, homepage: str, pkgver: str, names: list[str]) -> dict:
    """Where the git version of this source lives: {status, archive_url?, repo?, tag?}."""
    if GIT_GENERATED.match(url):
        return {"status": "git-archive"}  # the forge built it from git: nothing to compare
    m = GH_RELEASE.match(url)
    if m:
        o, r, tag = m.group(1), m.group(2), urllib.parse.unquote(m.group(3))
        return {"status": "found", "repo": f"https://github.com/{o}/{r}", "tag": tag,
                "archive_url": f"https://codeload.github.com/{o}/{r}/tar.gz/refs/tags/{urllib.parse.quote(tag)}"}
    for i, cand in enumerate((url, homepage or "")):
        gh, gl = GH_REPO.match(cand), GL_REPO.match(cand)
        if gh:
            host, path, kind = "github.com", f"{gh.group(1)}/{gh.group(2)}", "github"
        elif gl and i == 1:  # a GitLab-style homepage; download URLs there are not repo URLs
            host, path, kind = gl.group(1), gl.group(2).strip("/"), "gitlab"
        else:
            continue
        repo = f"https://{host}/{path}"
        tags = _ls_tags(repo + ".git")
        if not tags:
            return {"status": "no-tag", "repo": repo}
        base = path.rsplit("/", 1)[-1]
        variants = [pkgver, f"v{pkgver}", pkgver.replace(".", "_"), f"v{pkgver.replace('.', '_')}",
                    f"release-{pkgver}", f"release_{pkgver.replace('.', '_')}"]
        variants += [f"{n}-{pkgver}" for n in dict.fromkeys([base, *names])]
        variants += [f"{n}_{pkgver}" for n in dict.fromkeys([base, *names])]
        tag = next((v for v in variants if v in tags), None)
        if not tag:
            return {"status": "no-tag", "repo": repo}
        q = urllib.parse.quote(tag)
        if kind == "github":
            archive = f"https://codeload.github.com/{path}/tar.gz/refs/tags/{q}"
        elif host == "codeberg.org":
            archive = f"https://codeberg.org/{path}/archive/{q}.tar.gz"
        else:
            archive = f"https://{host}/{path}/-/archive/{q}/{base}-{q}.tar.gz"
        return {"status": "found", "repo": repo, "tag": tag, "archive_url": archive}
    return {"status": "no-repo"}


def compare_with_git(tar_m: dict, git_m: dict) -> dict:
    t, g = tar_m["members"], git_m["members"]
    only_tar = sorted(p for p, r in t.items() if p not in g and r["type"] == "f")
    modified = sorted(p for p, r in t.items() if p in g and r.get("sha") and g[p].get("sha")
                      and r["sha"] != g[p]["sha"] and not TARBALL_ONLY_OK.search(p))
    expected = [p for p in only_tar if TARBALL_ONLY_OK.search(p)]
    unexpected = [p for p in only_tar if not TARBALL_ONLY_OK.search(p)]
    diffs, budget = [], 30000
    for p in modified:
        a, b = git_m["texts"].get(p), tar_m["texts"].get(p)
        if a is None or b is None or budget <= 0:
            continue
        body = "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), f"git/{p}", f"tarball/{p}",
                                              lineterm="", n=3))[:min(budget, 8000)]
        budget -= len(body)
        diffs.append({"path": p, "diff": body})
    return {"only_tar": unexpected, "only_tar_expected": expected, "modified": modified,
            "only_git": sum(1 for p, r in g.items() if p not in t and r["type"] == "f"), "diffs": diffs}


def tag_compare(pkgbase: str, new: dict, srcinfo: dict, names: list[str], max_file_mb: int) -> list[dict]:
    """Compare each uploaded release archive of the new commit with its git tag."""
    out = []
    for s in new["sources"]:
        m = s.get("manifest") or {}
        if s.get("status") != "ok" or m.get("format") not in ("tar", "zip"):
            continue
        rec = {"file": s["file"]}
        try:
            origin = git_origin(s["url"], srcinfo.get("url", ""), srcinfo.get("pkgver", ""), names)
        except (OSError, subprocess.TimeoutExpired) as e:
            origin = {"status": "failed", "error": str(e)[:200]}
        rec.update({k: v for k, v in origin.items() if k != "archive_url"})
        if origin["status"] == "found":
            work = DL_DIR / pkgbase / ".tagcmp"
            work.mkdir(parents=True, exist_ok=True)
            dest = work / "git.tar.gz"
            try:
                download(origin["archive_url"], dest, max_file_mb * 1024 * 1024)
                git_m = inspect(dest, "git.tar.gz")
                if git_m["format"] == "unreadable":
                    raise ValueError(t("git arşivi açılamadı"))
                rec.update(compare_with_git(m, git_m))
                rec["status"] = "ok"
                shutil.rmtree(work, ignore_errors=True)
            except Deferred:
                rec["status"] = "deferred"
            except (TooLarge, urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
                rec["status"] = "failed"
                rec["error"] = str(e)[:200]
                shutil.rmtree(work, ignore_errors=True)
        out.append(rec)
    return out


def tag_findings(tc: list[dict], new: dict) -> list[dict]:
    F, out = rules._f, []
    by_file = {s["file"]: (s.get("manifest") or {}) for s in new["sources"]}
    for r in tc:
        if r["status"] == "deferred":
            out.append(F(rules.INFO, "tag-compare-deferred", t("Git etiketiyle karşılaştırma sonraki kontrolde tamamlanacak"),
                         file=r["file"]))
        elif r["status"] == "failed":
            out.append(F(rules.INFO, "tag-compare-failed", t("Sürüm arşivi git etiketiyle karşılaştırılamadı"),
                         r.get("error", ""), file=r["file"]))
        if r["status"] != "ok":
            continue
        members = by_file.get(r["file"], {}).get("members", {})
        bins = [p for p in r["only_tar"] if members.get(p, {}).get("elf") or members.get(p, {}).get("bin")]
        texts = [p for p in r["only_tar"] if p not in bins]
        where = f"{r['repo']} @ {r['tag']}"
        if r["modified"]:
            out.append(F(rules.MEDIUM, "tarball-differs-from-git",
                         t("Sürüm arşivindeki dosyalar git etiketindekinden farklı"),
                         f"{', '.join(r['modified'][:10])}{' …' if len(r['modified']) > 10 else ''} ({where})",
                         file=r["file"]))
        if bins:
            out.append(F(rules.MEDIUM, "tarball-only-binary", t("Sürüm arşivinde git'te olmayan ikili/veri dosyası var"),
                         f"{', '.join(bins[:10])} ({where})", file=r["file"]))
        if texts:
            scripts = [p for p in texts if members.get(p, {}).get("cat")]
            sev = rules.MEDIUM if scripts else rules.INFO
            out.append(F(sev, "tarball-only-file", t("Sürüm arşivinde git'te olmayan dosya var")
                         + (t(" (betik/derleme dosyası dahil)") if scripts else ""),
                         f"{', '.join((scripts or texts)[:10])} ({where})", file=r["file"]))
    return out


# --- comparison and findings ---------------------------------------------------------

def _role(src: dict) -> str:
    return f"{src['arch']}:" + re.sub(r"\d+([._-]\d+)*", "#", src["file"])


def pair(old: dict | None, new: dict) -> list[tuple[dict | None, dict]]:
    olds = [s for s in (old or {}).get("sources", []) if s.get("status") == "ok"]
    news = [s for s in new["sources"] if s.get("status") == "ok"]
    by_role = {}
    for s in olds:
        by_role.setdefault(_role(s), s)
    out, used = [], set()
    for s in news:
        o = by_role.get(_role(s))
        if o is not None and id(o) not in used:
            used.add(id(o))
            out.append((o, s))
        else:
            out.append((None, s))
    # One unmatched on each side (renamed download): compare those two.
    left = [s for s in olds if id(s) not in used]
    lone = [i for i, (o, _) in enumerate(out) if o is None]
    if len(left) == 1 and len(lone) == 1:
        out[lone[0]] = (left[0], out[lone[0]][1])
    return out


def _changed(om: dict | None, nm: dict) -> dict:
    o = (om or {}).get("members", {})
    n = nm["members"]
    size_only = "size-only" in nm.get("notes", [])

    def differs(a, b):
        if a.get("sha") and b.get("sha"):
            return a["sha"] != b["sha"]
        return a.get("size") != b.get("size") or a.get("link") != b.get("link")
    return {
        "added": sorted(set(n) - set(o)),
        "removed": sorted(set(o) - set(n)),
        "changed": sorted(p for p in set(n) & set(o) if differs(o[p], n[p])),
        "size_only": size_only,
    }


def _line_hits(text: str, old_text: str | None, cat: str) -> list[tuple[str, str, str, str]]:
    """(severity, code, title, line) for rule matches in the lines this version adds."""
    if old_text is not None:
        lines = [l[1:] for l in difflib.unified_diff(old_text.splitlines(), text.splitlines(), lineterm="", n=0)
                 if l.startswith("+") and not l.startswith("+++")]
    else:
        lines = text.splitlines()
    hits, seen = [], set()
    for line in lines[:20000]:
        s = line.strip()
        if not s or s.startswith(("#", "//")) or len(s) > 2000:
            continue
        for sev, code, title, rx in rules.LINE_RULES:
            # Hooks get every rule; build and other scripts only the high-confidence ones,
            # because upstream build systems use curl, base64 and friends legitimately.
            if cat not in ("persist", "system", "deb-script") and sev != rules.HIGH and code not in rules.BUILD_SAFE:
                continue
            if rx.search(line) and (code, s) not in seen:
                seen.add((code, s))
                hits.append((sev, code, title, s))
    return hits


def analyze(old: dict | None, new: dict, binary_package: bool, tagcmp: list[dict] | None = None) -> dict:
    """Findings plus a compact summary (and text diffs) for the dashboard and the LLM."""
    F, findings, summaries = rules._f, [], []
    for s in new["sources"]:
        st = s.get("status")
        if st == "download-failed":
            findings.append(F(rules.INFO, "source-not-inspected", t("Kaynak dosya indirilemedi; içi incelenmedi"),
                              f"{s['file']}: {s.get('error', '')}", file=s["file"]))
        elif st == "deferred":
            findings.append(F(rules.INFO, "source-deferred", "Kaynak dosya hâlâ iniyor; sonraki kontrolde incelenecek",
                              t("Bu kontrolün indirme süresi doldu; indirme kaldığı yerden devam edecek. "
                              "İnceleme bitene kadar paket otomatik seçilmez."), file=s["file"]))
        elif st == "too-large":
            findings.append(F(rules.INFO, "source-too-large", t("Kaynak dosya boyut sınırını aşıyor; içi incelenmedi"),
                              t("{file}: {v1} MB (sınır Ayarlar → Kaynak inceleme bölümünde)", file=s['file'], v1=round((s.get('size') or 0) / 1048576)), file=s["file"]))
        elif st == "vcs":
            findings.append(F(rules.INFO, "source-vcs", t("Kaynak bir git/svn deposu; içeriği derleme anında çekilir, "
                              "önceden incelenemez"), s["url"][:200], file=s["file"]))
        if s.get("verified") is False:
            findings.append(F(rules.MEDIUM, "checksum-mismatch",
                              t("İndirilen kaynak, PKGBUILD'deki sağlama toplamıyla eşleşmiyor"),
                              t("Dosya sunucuda değişmiş ya da yolda değiştirilmiş olabilir; makepkg de derlemeyi durdurur."),
                              file=s["file"]))
    has_any_baseline = bool(old)
    for o, s in pair(old, new):
        m = _canon(s["manifest"])
        om = _canon(o["manifest"]) if o else None
        ch = _changed(om, m)
        fname = s["file"]
        members = m["members"]
        for iss in m.get("issues", [])[:5]:
            findings.append(F(rules.HIGH, "archive-path-traversal",
                              t("Arşivde mutlak yol ya da '..' içeren dosya adı var"), iss["path"], file=fname))
        if m["format"] == "unreadable":
            findings.append(F(rules.INFO, "source-unreadable", t("Kaynak dosya açılamadı; içi incelenmedi"),
                              "; ".join(m.get("notes", [])), file=fname))
        new_paths = set(ch["added"]) if om else set(members)
        mod_paths = set(ch["changed"])
        # Persistence / system integration points.
        for p in sorted(new_paths | mod_paths):
            rec = members[p]
            cat = rec.get("cat")
            if cat not in ("persist", "system"):
                continue
            is_new = p in new_paths
            if p.endswith("ld.so.preload"):
                sev = rules.HIGH
            elif om and is_new:
                sev = rules.HIGH if cat == "persist" else rules.MEDIUM
            elif om:
                sev = rules.MEDIUM
            else:
                sev = rules.INFO
            what = t("eklendi") if is_new and om else t("değişti") if om else t("var")
            findings.append(F(sev, f"source-{cat}", t("Kaynak arşivinde {v0} {what}", v0=t(CATEGORY_TR[cat]), what=what), p, file=fname))
        # setuid / setgid.
        for p in sorted(new_paths | mod_paths):
            rec = members[p]
            if rec["type"] != "f" or not rec["mode"] & 0o6000:
                continue
            was = (om or {}).get("members", {}).get(p, {}).get("mode", 0) & 0o6000
            if was:
                continue
            sandbox = p.endswith("chrome-sandbox")
            sev = (rules.MEDIUM if sandbox else rules.HIGH) if om else (rules.INFO if sandbox else rules.MEDIUM)
            findings.append(F(sev, "source-setuid", t("Kaynak arşivinde setuid/setgid izinli dosya")
                              + (t(" (Electron'un sandbox yardımcısı)") if sandbox else ""), p, file=fname))
        # Hidden executables.
        for p in sorted(new_paths):
            rec = members[p]
            if p.split("/")[-1].startswith(".") and rec["type"] == "f" and (rec.get("elf") or rec.get("cat") == "script"):
                findings.append(F(rules.MEDIUM, "source-hidden-exec", t("Kaynak arşivinde gizli (nokta ile başlayan) "
                                  "çalıştırılabilir dosya"), p, file=fname))
        # Compiled binaries appearing in a source tarball (the xz backdoor hid in "test data").
        if om and not binary_package:
            old_elf = any(r.get("elf") for r in om["members"].values())
            new_elf = [p for p in new_paths if members[p].get("elf")]
            if new_elf and not old_elf:
                findings.append(F(rules.MEDIUM, "source-new-binary", t("Kaynak kod arşivine derlenmiş ikili dosya eklendi"),
                                  ", ".join(sorted(new_elf)[:8]), file=fname))
        # Binary "test data" and build machinery changing in the same release: the
        # shape of the xz attack (payload in tests/files, trigger in m4/).
        if om and not binary_package:
            data = sorted(p for p in new_paths | mod_paths if members[p].get("bin") and TESTISH.search(p))
            mach = sorted(p for p in new_paths | mod_paths if MACHINERY.search(p))
            if data and mach:
                tc = next((r for r in tagcmp or [] if r["file"] == fname and r["status"] == "ok"), None)
                unverified = [p for p in mach if not tc or p in tc["only_tar"] or p in tc["only_tar_expected"]
                              or p in tc["modified"]]
                findings.append(F(rules.MEDIUM if unverified else rules.INFO, "test-data-with-build-change",
                                  t("Aynı sürümde hem ikili test/veri dosyaları hem de derleme betikleri değişti "
                                  "(xz saldırısının biçimi)"),
                                  t("veri: {data}; derleme: {build}", data=", ".join(data[:6]), build=", ".join(mach[:6]))
                                  + ("" if unverified else t(" — derleme dosyaları git etiketindekiyle aynı"))
                                  + (t(" — git'te olmayan ya da farklı olanlar: {v0}", v0=', '.join(unverified[:6]))
                                     if unverified and tc else ""),
                                  file=fname))
        # Rules on notable text.
        hits = 0
        for p, text in m["texts"].items():
            if p not in new_paths and p not in mod_paths:
                continue
            cat = members.get(p, {}).get("cat") or "script"
            old_text = (om or {}).get("texts", {}).get(p) if om else None
            for sev, code, title, line in _line_hits(text, old_text, cat):
                if hits >= 25:
                    break
                hits += 1
                findings.append(F(sev, code, t("{title} (kaynak arşivinde)", title=t(title)), file=f"{fname}: {p}", line=line))
        summaries.append(_summary(o, s, ch, m, om))
    findings.extend(tag_findings(tagcmp or [], new))
    return {"findings": findings, "summaries": summaries, "baseline": has_any_baseline}


def _notable(members: dict, paths) -> list[str]:
    def rank(p):
        r = members.get(p, {})
        return (0 if r.get("cat") in ("persist", "system", "deb-script") else 1 if r.get("cat") else
                2 if r.get("elf") else 3, p)
    return sorted(paths, key=rank)


def _canon(m: dict) -> dict:
    """A single plain file's name carries the version (manifest-2.1.319.json); compare it as one entry."""
    if m.get("format") != "file" or len(m.get("members", {})) != 1:
        return m
    (name, rec), = m["members"].items()
    texts = {"content": m["texts"][name]} if name in m.get("texts", {}) else {}
    return {**m, "members": {"content": rec}, "texts": texts}


GENERATED_BUILD = re.compile(r"(^|/)(configure|aclocal\.m4|Makefile\.in|config\.h\.in)$")


def _summary(o: dict | None, s: dict, ch: dict, m: dict, om: dict | None) -> dict:
    members = m["members"]
    paths = (ch["added"] + ch["changed"]) if om else list(m["texts"])
    candidates = []
    for p in paths:
        if p not in m["texts"]:
            continue
        new_t = m["texts"][p]
        old_t = (om or {}).get("texts", {}).get(p)
        cat = members[p].get("cat")
        if om and old_t is not None:
            body = "\n".join(difflib.unified_diff(old_t.splitlines(), new_t.splitlines(),
                                                  f"a/{p}", f"b/{p}", lineterm="", n=3))
        elif om or cat in ("persist", "system", "deb-script"):
            body = f"--- /dev/null\n+++ b/{p}\n" + "\n".join("+" + l for l in new_t.splitlines())
        else:
            continue  # no baseline: show full text only for hooks, not every build file
        # What a human should read first: hooks, then hand-written build machinery and
        # scripts, then regenerated autotools output. Small diffs first in each group:
        # an injected trigger is a few lines, a regenerated configure is thousands.
        group = (0 if cat in ("persist", "system", "deb-script") else
                 2 if GENERATED_BUILD.search(p) else 1)
        candidates.append((group, len(body), p, cat, body))
    diffs, budget = [], 40000
    for group, _, p, cat, body in sorted(candidates):
        if budget <= 0:
            break
        body = body[:min(budget, 12000)]
        budget -= len(body)
        diffs.append({"path": p, "cat": cat, "diff": body})
    elf = sum(1 for r in members.values() if r.get("elf"))
    return {
        "file": s["file"], "old_file": o["file"] if o else None, "url": s["url"], "format": m["format"],
        "size": s.get("size"), "old_size": o.get("size") if o else None, "verified": s.get("verified"),
        "members": len(members), "elf": elf, "root": m.get("root"),
        "baseline": bool(om), "size_only": ch["size_only"],
        "added": len(ch["added"]) if om else None, "removed": len(ch["removed"]) if om else None,
        "changed": len(ch["changed"]) if om else None,
        "added_list": _notable(members, ch["added"])[:40] if om else [],
        "removed_list": ch["removed"][:20] if om else [],
        "changed_list": _notable(members, ch["changed"])[:40] if om else [],
        "notable": [{"path": p, "cat": r["cat"]} for p, r in members.items()
                    if r.get("cat") in ("persist", "system", "deb-script")][:40],
        "diffs": diffs,
    }


def prompt_section(src: dict | None) -> tuple[str, str]:
    """(plain summary lines, untrusted text diffs) for the LLM prompt."""
    if not src:
        return "", ""
    lines, bodies = [], []
    for s in src["sources"]:
        if s["status"] != "ok":
            lines.append(f"- {s['file']}: not inspected ({s['status']})")
    for sm in src["summaries"]:
        ver = {True: "checksum verified", False: "CHECKSUM MISMATCH", None: "no checksum pinned"}[sm["verified"]]
        head = f"- {sm['file']} ({sm['format']}, {sm['size']} bytes, {sm['members']} entries, {sm['elf']} ELF; {ver})"
        if sm["baseline"]:
            head += (f" vs installed {sm['old_file']}: {sm['added']} added, {sm['removed']} removed, "
                     f"{sm['changed']} changed" + (" (compared by size only)" if sm["size_only"] else ""))
            if sm["added_list"]:
                head += "\n    added: " + ", ".join(sm["added_list"][:25])
            if sm["changed_list"]:
                head += "\n    changed: " + ", ".join(sm["changed_list"][:25])
        else:
            head += " - no copy of the installed version's sources to compare against"
        if sm["notable"]:
            head += "\n    install hooks / system integration files: " + ", ".join(n["path"] for n in sm["notable"][:20])
        lines.append(head)
        for d in sm["diffs"]:
            bodies.append(f"### {sm['file']}: {d['path']} ({d['cat'] or 'text'})\n{d['diff']}")
    for r in src.get("tag_compare", []):
        if r["status"] == "git-archive":
            lines.append(f"- {r['file']}: generated by the forge from git, so it matches the git tag")
        elif r["status"] == "ok":
            lines.append(f"- {r['file']} compared with git tag {r['tag']} of {r['repo']}: "
                         f"{len(r['modified'])} files differ from git, {len(r['only_tar'])} unexpected files only in the "
                         f"tarball, {len(r['only_tar_expected'])} tarball-only files of kinds autotools/gettext "
                         f"normally generate, {r['only_git']} files only in git"
                         + (f"\n    differ: {', '.join(r['modified'][:20])}" if r["modified"] else "")
                         + (f"\n    only in tarball: {', '.join(r['only_tar'][:20])}" if r["only_tar"] else "")
                         + (f"\n    generated-kind, only in tarball: {', '.join(r['only_tar_expected'][:30])}"
                            if r["only_tar_expected"] else ""))
            for d in r["diffs"]:
                bodies.append(f"### {r['file']}: {d['path']} - git tag vs. release tarball\n{d['diff']}")
        else:
            lines.append(f"- {r['file']}: could not be compared with git ({r['status']})")
    return "\n".join(lines), "\n\n".join(bodies)[:60000]


def pending(src: dict | None) -> bool:
    return bool(src) and any(s.get("status") == "deferred"
                             for s in [*src.get("sources", []), *src.get("tag_compare", [])])


def fingerprint(src: dict | None) -> str:
    if not src:
        return "none"
    h = hashlib.sha256()
    for s in src["sources"]:
        h.update(f"{s['file']}|{s['status']}|{s.get('verified')}\n".encode())
    h.update(str(src.get("baseline")).encode())
    for r in src.get("tag_compare", []):
        h.update(f"tag|{r['file']}|{r['status']}|{r.get('tag')}\n".encode())
    return h.hexdigest()[:10]


def review(pkgbase: str, name: str, new_commit: str, new_srcinfo: str, base_commit: str | None,
           old_srcinfo: str | None, settings: dict) -> dict | None:
    """Inspect the sources of new_commit, compared with base_commit's when possible."""
    cfg = settings["sources"]
    if not cfg["enabled"]:
        return None
    new = collect(pkgbase, new_commit, new_srcinfo, cfg["max_file_mb"], keep_files=True)
    old = None
    if base_commit and base_commit != new_commit:
        old = load_manifest(pkgbase, base_commit)
        if old is None and cfg["baseline"] and old_srcinfo:
            # First time for this package: fetch the installed version's sources once.
            # Old URLs sometimes disappear; keep whatever could be fetched.
            # Not worth fetching: old counterparts of single binaries (nothing to compare
            # but "changed") and of sources that could not be inspected now.
            skip = frozenset(_role(s) for s in new["sources"]
                             if s.get("status") != "ok" or _opaque(s.get("manifest") or {}))
            old = collect(pkgbase, base_commit, old_srcinfo, cfg["max_file_mb"], keep_files=False,
                          save_incomplete=True, skip_roles=skip)
        if old is not None and not any(s.get("status") == "ok" for s in old["sources"]):
            old = None
    prune(pkgbase, {c for c in (base_commit, new_commit) if c})
    prune_downloads(pkgbase, {s["file"] for s in new["sources"] if s.get("cached") or s["status"] == "deferred"})
    formats = {(s.get("manifest") or {}).get("format") for s in new["sources"]}
    binary = name.endswith(("-bin", "-appimage")) or bool(formats & {"deb", "appimage", "rpm"})
    tc = None
    if cfg["tag_compare"] and not binary:
        tc = new.get("tag_compare")
        if tc is None or any(r["status"] == "deferred" for r in tc):
            from .aur import parse_srcinfo
            info = parse_srcinfo(new_srcinfo)
            tc = tag_compare(pkgbase, new, info, [*info.get("pkgnames", []), pkgbase], cfg["max_file_mb"])
            new["tag_compare"] = tc
            if load_manifest(pkgbase, new_commit) and not any(r["status"] == "deferred" for r in tc):
                _save_manifest(pkgbase, new_commit, new)
    res = analyze(old, new, binary, tc)
    return {
        "sources": [{k: v for k, v in s.items() if k != "manifest"} for s in new["sources"]],
        "summaries": res["summaries"],
        "baseline": res["baseline"],
        "findings": res["findings"],
        "tag_compare": tc or [],
    }
