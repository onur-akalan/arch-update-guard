"""What is running right now: stale libraries, services to restart, open ports.

An updated library only protects you once every process that had the old
copy loaded is restarted. Root-owned processes cannot be inspected without
root, so system services are judged by start time versus the upgrade time of
the packages that own their binary and its shared libraries.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from .i18n import t
from .system import PACMAN_LOG, run

LOADER = "/usr/lib/ld-linux-x86-64.so.2"
# Restarting these ends the session or the system; recommend a reboot instead.
NO_RESTART = re.compile(r"^(dbus(-broker)?|systemd-logind|systemd-journald|sddm|lightdm|gdm|display-manager|"
                        r"user@\d+|getty@.*|systemd-udevd|polkit|systemd-userdbd|systemd-machined)\.service$")
# Packages whose upgrade means "reboot" rather than "restart a service".
REBOOT_PKGS = {"linux", "linux-lts", "linux-zen", "linux-hardened", "systemd", "systemd-libs", "glibc",
               "dbus", "dbus-broker", "intel-ucode", "amd-ucode", "linux-firmware", "mesa", "nvidia",
               "nvidia-open", "nvidia-utils"}
SESSION = re.compile(r"^(plasmashell|kwin_wayland|kwin_x11|ksmserver|kded6|Xwayland|xdg-desktop-portal.*|"
                     r"pipewire.*|wireplumber|kglobalacceld|startplasma.*)$")


def upgrade_times() -> dict[str, int]:
    """Last install/upgrade time (unix) per package from pacman.log."""
    from datetime import datetime
    rx = re.compile(r"^\[(\S+)\] \[ALPM\] (?:upgraded|installed|reinstalled|downgraded) (\S+) \(")
    out: dict[str, int] = {}
    try:
        with PACMAN_LOG.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                m = rx.match(line)
                if m:
                    try:
                        out[m[2]] = int(datetime.strptime(m[1], "%Y-%m-%dT%H:%M:%S%z").timestamp())
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def boot_time() -> int:
    for line in Path("/proc/stat").read_text().splitlines():
        if line.startswith("btime "):
            return int(line.split()[1])
    return 0


def owners(paths: list[str]) -> dict[str, str]:
    """file -> owning package (batched pacman -Qo)."""
    out: dict[str, str] = {}
    paths = sorted(set(paths))
    for i in range(0, len(paths), 200):
        r = run(["pacman", "-Qo", *paths[i:i + 200]], timeout=120)
        for line in r.stdout.splitlines():
            m = re.match(r"^(.+?) is owned by (\S+) ", line)
            if m:
                out[m[1]] = m[2]
    return out


def shared_libs(binary: str) -> list[str]:
    """Libraries a binary links, via the dynamic loader's --list (does not run the binary)."""
    r = run([LOADER, "--list", binary], timeout=20)
    if r.returncode != 0:
        return []
    return [m[1] for m in re.finditer(r"=> (/\S+) \(", r.stdout)]


def running_services() -> list[dict]:
    r = run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"])
    units = [l.split()[0] for l in r.stdout.splitlines() if l.strip()]
    if not units:
        return []
    r = run(["systemctl", "show", *units, "-p", "Id", "-p", "ExecMainStartTimestamp", "-p", "ExecStart",
             "--timestamp=unix"])
    services, cur = [], {}
    for line in r.stdout.splitlines() + [""]:
        if not line.strip():
            if cur.get("Id"):
                services.append(cur)
            cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k] = v
    out = []
    for s in services:
        m = re.search(r"path=(\S+)", s.get("ExecStart", ""))
        ts = s.get("ExecMainStartTimestamp", "").lstrip("@")
        out.append({"unit": s["Id"], "binary": m[1] if m else None, "started": int(ts) if ts.isdigit() else 0})
    return out


def stale_user_processes() -> list[dict]:
    """Own processes that still map a deleted (replaced) file from /usr."""
    uid = os.getuid()
    groups: dict[str, dict] = {}
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if d.stat().st_uid != uid:
                continue
            maps = (d / "maps").read_text(errors="replace")
            comm = (d / "comm").read_text().strip()
        except OSError:
            continue
        stale = {m[1] for m in re.finditer(r"\s(/usr/\S+) \(deleted\)$", maps, re.M)}
        if not stale:
            continue
        g = groups.setdefault(comm, {"name": comm, "pids": [], "files": set()})
        g["pids"].append(int(d.name))
        g["files"].update(stale)
    out = []
    for g in groups.values():
        out.append({"name": g["name"], "pids": sorted(g["pids"])[:20], "count": len(g["pids"]),
                    "files": sorted(g["files"])[:10], "session": bool(SESSION.match(g["name"]))})
    return sorted(out, key=lambda x: (not x["session"], x["name"]))


def service_restarts(services: list[dict], times: dict[str, int]) -> tuple[list[dict], dict[str, set[str]]]:
    """Services started before a package they load was upgraded.

    Also returns package -> {units} for every running service, used to tell
    which vulnerable packages are loaded by a running service.
    """
    lib_cache: dict[str, list[str]] = {}
    files_per_unit: dict[str, list[str]] = {}
    for s in services:
        b = s["binary"]
        if not b or not os.path.exists(b):
            continue
        if b not in lib_cache:
            lib_cache[b] = shared_libs(b)
        files_per_unit[s["unit"]] = [b, *lib_cache[b]]
    own = owners([f for fs in files_per_unit.values() for f in fs])
    pkg_units: dict[str, set[str]] = defaultdict(set)
    need = []
    for s in services:
        files = files_per_unit.get(s["unit"])
        if not files:
            continue
        pkgs = {own[f] for f in files if f in own}
        for p in pkgs:
            pkg_units[p].add(s["unit"])
        newer = sorted(p for p in pkgs if times.get(p, 0) > s["started"] > 0)
        if newer:
            need.append({"unit": s["unit"], "started": s["started"], "packages": newer,
                         "safe": not NO_RESTART.match(s["unit"])})
    return sorted(need, key=lambda x: (not x["safe"], x["unit"])), pkg_units


KNOWN_PORTS = {22: "SSH", 53: "DNS", 67: "DHCP (libvirt/dnsmasq)", 80: "HTTP", 443: "HTTPS", 631: "CUPS yazdırma",
               3306: "MySQL", 5353: "mDNS (avahi)", 5355: "LLMNR (systemd-resolved)", 5432: "PostgreSQL",
               6379: "Redis", 8080: "HTTP", 41641: "Tailscale", 27017: "MongoDB", 4000: "HTTP (LiteLLM?)"}


def open_ports() -> list[dict]:
    """TCP/UDP listeners bound to a non-loopback address."""
    r = run(["ss", "-H", "-tulnp"])
    ports = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%")[0].strip("[]")
        if addr.startswith("127.") or addr in ("::1",) or not port.isdigit():
            continue
        port_n = int(port)
        if proto == "udp" and port_n >= 32768 and port_n not in KNOWN_PORTS:
            continue  # ephemeral client sockets (browsers, WebRTC), not services
        proc = re.search(r'users:\(\("([^"]+)"', line)
        ports.append({"proto": proto, "address": addr, "port": port_n, "process": proc[1] if proc else None,
                      "service": t(KNOWN_PORTS[port_n]) if port_n in KNOWN_PORTS else None, "public": addr in ("0.0.0.0", "*", "::")})
    docker = _docker_ports()
    for p in ports:
        p["container"] = docker.get(p["port"])
    # One row per proto/port: IPv4 and IPv6 wildcard listeners are the same service.
    uniq: dict = {}
    for p in ports:
        k = (p["proto"], p["port"]) if p["public"] else (p["proto"], p["port"], p["address"])
        uniq.setdefault(k, p)
    return sorted(uniq.values(), key=lambda p: (not p["public"], p["port"], p["proto"]))


def _docker_ports() -> dict[int, str]:
    try:
        r = run(["docker", "ps", "--format", "{{.Names}}\t{{.Ports}}"], timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    out = {}
    for line in r.stdout.splitlines():
        name, _, ports = line.partition("\t")
        for m in re.finditer(r"(?:[\d.]+|\[::\]):(\d+)->", ports):
            out[int(m[1])] = name
    return out


def snapshot() -> dict:
    times = upgrade_times()
    booted = boot_time()
    services = running_services()
    restarts, pkg_units = service_restarts(services, times)
    reboot_pkgs = sorted(p for p in REBOOT_PKGS if times.get(p, 0) > booted)
    kernel_gone = not Path(f"/usr/lib/modules/{os.uname().release}").is_dir()
    users = stale_user_processes()
    return {
        "boot_time": booted,
        "reboot_packages": reboot_pkgs,
        "reboot_recommended": kernel_gone or bool(reboot_pkgs) or any(not r["safe"] for r in restarts)
                              or any(u["session"] for u in users),
        "kernel_updated": kernel_gone,
        "services": restarts,
        "user_processes": users,
        "open_ports": open_ports(),
        "_pkg_units": pkg_units,  # internal, removed before saving
    }


def explicit_users(pkg: str, explicit: set[str]) -> list[str]:
    """Explicitly installed packages that depend (directly or not) on pkg."""
    r = run(["pactree", "-r", "-u", pkg], timeout=30)
    return sorted((set(r.stdout.split()) & explicit) - {pkg})
