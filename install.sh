#!/usr/bin/env bash
#
# SymbiVPN installer for Linux (Debian, Ubuntu, Raspberry Pi OS, Fedora, Arch).
#
#   curl -fsSL https://raw.githubusercontent.com/mikeynator21/Symbivpn/HEAD/install.sh | sudo bash
#
# or, from a clone:  sudo ./install.sh
#
# Installs to /opt/symbivpn, puts a launcher in /usr/local/bin, and sets up a
# systemd unit. It does not start filtering until you say so.

set -euo pipefail

PREFIX="${PREFIX:-/opt/symbivpn}"
BINDIR="${BINDIR:-/usr/local/bin}"
CONFDIR="${CONFDIR:-/etc/symbivpn}"
STATEDIR="${STATEDIR:-/var/lib/symbivpn}"
REPO="${REPO:-https://github.com/mikeynator21/Symbivpn}"

info()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m warning:\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[1;31m error:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run this with sudo: sudo $0"

# --- Python ------------------------------------------------------------------
PYTHON="$(command -v python3 || true)"
[[ -n "$PYTHON" ]] || die "python3 is not installed"
"$PYTHON" - <<'PY' || die "SymbiVPN needs Python 3.11 or newer (it uses tomllib)"
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
info "using $("$PYTHON" --version)"

# --- optional system packages -------------------------------------------------
install_packages() {
    local packages=("$@")
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y --no-install-recommends "${packages[@]}"
    elif command -v dnf >/dev/null; then
        dnf install -y "${packages[@]}"
    elif command -v pacman >/dev/null; then
        pacman -Sy --noconfirm "${packages[@]}"
    else
        warn "unknown package manager; install these yourself: ${packages[*]}"
        return 1
    fi
}

MISSING=()
command -v nft      >/dev/null || MISSING+=(nftables)
command -v hostapd  >/dev/null || MISSING+=(hostapd)
command -v wg       >/dev/null || MISSING+=(wireguard-tools)
command -v iw       >/dev/null || MISSING+=(iw)

if [[ ${#MISSING[@]} -gt 0 ]]; then
    info "installing: ${MISSING[*]}"
    install_packages "${MISSING[@]}" || warn "carry on without them; hotspot and VPN features need them"
    # Distributions ship hostapd masked; we start it ourselves, not via systemd.
    systemctl disable --now hostapd 2>/dev/null || true
fi

# --- source -------------------------------------------------------------------
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SOURCE_DIR/symbivpn" ]]; then
    info "installing from $SOURCE_DIR"
    mkdir -p "$PREFIX"
    cp -r "$SOURCE_DIR/symbivpn" "$PREFIX/"
    [[ -d "$SOURCE_DIR/deploy" ]] && cp -r "$SOURCE_DIR/deploy" "$PREFIX/"
else
    command -v git >/dev/null || die "git is needed to fetch the source"
    info "cloning $REPO"
    rm -rf "$PREFIX.tmp"
    git clone --depth 1 "$REPO" "$PREFIX.tmp"
    rm -rf "$PREFIX"
    mv "$PREFIX.tmp" "$PREFIX"
fi

"$PYTHON" -m compileall -q "$PREFIX/symbivpn"

# --- launcher -----------------------------------------------------------------
# /usr/local/bin exists on most systems but not all of them, and BINDIR can be
# pointed anywhere.
mkdir -p "$BINDIR"
cat > "$BINDIR/symbivpn" <<LAUNCHER
#!/bin/sh
# SymbiVPN launcher, written by install.sh
exec ${PYTHON} -m symbivpn.cli "\$@"
LAUNCHER
sed -i "1a PYTHONPATH=\"${PREFIX}:\${PYTHONPATH}\"; export PYTHONPATH" "$BINDIR/symbivpn"
chmod +x "$BINDIR/symbivpn"

# --- directories and config ---------------------------------------------------
mkdir -p "$CONFDIR" "$STATEDIR"
chmod 700 "$STATEDIR"

if [[ -f "$CONFDIR/symbivpn.toml" ]]; then
    info "keeping the existing $CONFDIR/symbivpn.toml"
elif [[ -t 0 ]]; then
    # Interactive: ask the four questions rather than leaving a reference file
    # for someone to work through.
    info "let's configure it"
    echo
    "$BINDIR/symbivpn" setup --out "$CONFDIR/symbivpn.toml" || {
        warn "setup did not finish; writing a starter config instead"
        "$BINDIR/symbivpn" init-config > "$CONFDIR/symbivpn.toml"
        chmod 600 "$CONFDIR/symbivpn.toml"
    }
else
    info "no terminal, so writing a commented starter config"
    "$BINDIR/symbivpn" init-config > "$CONFDIR/symbivpn.toml"
    chmod 600 "$CONFDIR/symbivpn.toml"
    RAN_SETUP=no
fi

# --- service ------------------------------------------------------------------
# `systemctl` being present does not mean systemd is running it: a container, a
# chroot, or WSL without systemd all have the binary and no bus behind it. The
# install is complete either way, so a failure here is reported, not fatal --
# `set -e` would otherwise abort a working install with "Host is down".
SERVICE=no
if command -v systemctl >/dev/null && [[ -f "$PREFIX/deploy/symbivpn.service" ]]; then
    if install -m 644 "$PREFIX/deploy/symbivpn.service" \
            /etc/systemd/system/symbivpn.service 2>/dev/null \
            && systemctl daemon-reload 2>/dev/null; then
        info "systemd unit installed (not enabled yet)"
        SERVICE=yes
    else
        warn "systemd is not running here, so there is no service to enable"
        warn "start it yourself with: sudo symbivpn run"
    fi
elif [[ -f "$PREFIX/deploy/symbivpn.service" ]]; then
    warn "no systemd on this machine; start it with: sudo symbivpn run"
fi

# --- verify -------------------------------------------------------------------
info "running the self-test"
if "$BINDIR/symbivpn" selftest --port 15353 >/tmp/symbivpn-selftest.log 2>&1; then
    tail -3 /tmp/symbivpn-selftest.log
else
    warn "the self-test reported problems; see /tmp/symbivpn-selftest.log"
fi

if [[ "$SERVICE" == "yes" ]]; then
    START_COMMAND="sudo systemctl enable --now symbivpn"
    RESOLVED_NOTE=$'Port 53 is usually held by systemd-resolved. If `doctor` says so:\n  sudo systemctl disable --now systemd-resolved\n  sudo rm -f /etc/resolv.conf\n  echo \'nameserver 127.0.0.1\' | sudo tee /etc/resolv.conf\n'
else
    START_COMMAND="sudo symbivpn run"
    RESOLVED_NOTE=$'If `doctor` says port 53 is already taken, stop whatever holds it\nfirst -- on most systems that is systemd-resolved.\n'
fi

# `fill` substitutes the two lines that depend on this machine. The heredocs
# stay quoted so that nothing else in them is expanded by accident.
fill() {
    python3 -c 'import os,sys; sys.stdout.write(sys.stdin.read().replace("START_COMMAND", os.environ["START_COMMAND"]).replace("RESOLVED_NOTE", os.environ["RESOLVED_NOTE"]))'
}
export START_COMMAND RESOLVED_NOTE

if [[ "${RAN_SETUP:-yes}" == "no" ]]; then
cat <<'NEXT'

SymbiVPN is installed, but not configured.

  sudo symbivpn setup      four questions, then a working config

Or edit /etc/symbivpn/symbivpn.toml by hand -- every setting in it is
commented.
NEXT
else
fill <<'NEXT'

SymbiVPN is installed and configured.

  symbivpn doctor      is this machine ready?
  symbivpn fieldtest   what is this network doing to my DNS?
  symbivpn selftest    does the filtering work? (no root needed)
  symbivpn harden      any weak settings?

Then start it:
  START_COMMAND

RESOLVED_NOTE
For the laptop hotspot or your phone, see docs/laptop-gateway.md and
docs/phone.md.
NEXT
fi
