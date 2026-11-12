# arch-update-guard

**A local update dashboard for Arch Linux that reviews AUR updates before you install them.**

[Türkçe](README.tr.md)

`yay -Syu` builds whatever the AUR serves you. In June 2026 hundreds of orphaned AUR packages were adopted and given a single malicious line (`npm install atomic-lockfile`); in 2024 the xz backdoor lived only in a release tarball. arch-update-guard sits between you and the update: it checks daily in the background, reviews every pending AUR change, and tells you only when something needs your attention. You start the update yourself, from the dashboard, in a terminal you watch.

## What it checks

| | |
|---|---|
| **AUR diffs** | The git diff between the commit you have installed and the new one (PKGBUILD, `.install`, patches), run through fixed rules and optionally an AI reviewer. An AI verdict can never clear a rule finding; any AI error means "not reviewed", never "clean". |
| **Downloaded sources** | Tarballs, `.deb`, AppImage and single files are downloaded, checksum-verified and read **without extracting or running anything**, then compared with the installed version's sources: new autostart/systemd/cron/pacman-hook files, setuid files, hidden executables, binaries added to a source tree, changed build scripts. |
| **xz-style attacks** | Uploaded release tarballs are compared with the upstream git tag; m4/configure/CMake changes and binary test data changing together are flagged; rules for the xz backdoor's tricks (`grep -a`, `tr` swaps, byte slicing, decompress-to-`eval`). |
| **Package takeovers** | Adoption of orphaned packages, maintainer changes, first-time committers, named `npm`/`bun`/`pip` installs (as root in `.install`: dangerous), new AUR dependencies (reviewed recursively). |
| **Known incidents** | Your install history (including removed packages) against Arch's published list of compromised AUR packages; files shadowing `sudo`/`ssh`/`pacman` in user-writable PATH dirs. |
| **Arch news** | You must acknowledge news published since your last update. The AI checks each item against your system (installed packages, files, mkinitcpio hooks, LUKS, boot loader, GPU driver) and says whether it affects you, when to act and which commands to run. |
| **Vulnerabilities** | security.archlinux.org entries for installed versions, with fix evidence (Arch PKGBUILD patches, NVD version ranges), the apps and running services they touch, and an AI assessment with concrete steps. |
| **After updating** | Services and apps still running old libraries, whether a reboot is needed, `.pacnew` files, ports open to the network. |

Approvals are bound to the reviewed commit (of the package and of every new AUR dependency) and re-checked right before yay runs. New AUR versions wait in a hold period (default 2 days) unless you approve them earlier.

## Quiet by design

The scheduled check runs at idle CPU/IO priority, waits 10 minutes after boot and caps downloads at 3 MB/s. An ordinary day takes seconds and sends **no notification**. You hear from it only about something new and important: a dangerous or suspicious AUR update, news that affects you, a critical vulnerability without a fix, a known-compromised package, or a shadowed `sudo`.

## Requirements

Arch Linux with `yay`, Python ≥ 3.14 (Arch's default), `git`, `pacman-contrib` (`checkupdates`, `pacdiff`), `libsecret` (`secret-tool`, for API keys), `libnotify`, Konsole (the update runs in it). Optional: `7zip` (AppImage/rpm listing), Chromium (app window), `timeshift-autosnap` (snapshot before each transaction).

AI review is optional and pluggable:

- **Claude Code**: the installed `claude` CLI.
- **Anthropic API**: needs `pip install -r requirements.txt` in a virtualenv.
- **Any OpenAI-compatible endpoint**: LiteLLM, Ollama, OpenRouter, vLLM…

## Install

```bash
git clone https://github.com/onur-akalan/arch-update-guard.git
cd arch-update-guard
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # optional, for the Anthropic API
bin/aug install    # systemd user timer + menu entry
bin/aug open       # open the dashboard
```

Other commands: `bin/aug check` (check now), `bin/aug uninstall`. The interface is available in English and Turkish (Settings → General → Language).

## Security notes

- The dashboard listens on 127.0.0.1 only, with a random per-start token, a Host check and a CSRF header; it exits after 20 idle minutes.
- AUR repositories are read with hardened git (no checkout, no hooks, no external diff, no `file://`).
- Nothing runs as root. `sudo` and every pacman/yay prompt happen in the terminal you watch.
- API keys live in the Secret Service keyring, not in the settings file.
- Text from packages and news is passed to the AI inside a nonce-delimited untrusted block; instructions in it are treated as a sign of malice.

## Limits

This is a second pair of eyes, not a guarantee. A careful attacker can hide code deep inside upstream sources where no diff review will find it; git sources (`-git` packages) are fetched at build time and cannot be inspected beforehand; official repository packages are out of scope. Keep snapshots (Timeshift) as your way back.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
