#!/usr/bin/env bash
# ============================================================================
# DarkSec MALSTROM — Debian installer
#
# Tuned installer for Debian 13 "trixie" (current stable) and newer.
#
# Two of MALSTROM's post-exploitation tools are packaged by Kali but NOT by
# Debian, so this installer pulls them from upstream and drops them on PATH
# where the daemon's health checks look for them:
#   * netexec   (crackmapexec successor — lateral movement / cred spray)
#   * responder (LLMNR/mDNS/NBT-NS hash catch — MITM)
# Everything else goes through the shared install.sh: apt core deps, /opt
# layout, systemd unit, `malstrom` CLI, desktop launcher + icon.
#
#   sudo ./install-debian.sh                normal install
#   sudo ./install-debian.sh --start --enable-boot
#   sudo ./install-debian.sh --skip-tools   don't fetch netexec/responder
#   sudo ./install-debian.sh --no-deps      don't touch apt at all
# (all other options are passed through to install.sh)
# ============================================================================

set -u

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_ID="debian"
DISTRO_NAME="Debian"
VALIDATED_FROM='Debian 13 "trixie"'
MIN_MAJOR=12
CORE_PKGS="hostapd dnsmasq iw iptables aircrack-ng tcpdump nmap smbclient python3"
SKIP_TOOLS=0
NO_DEPS=0
ASSUME_YES=0
ROOT_STAGED=0
opts=()

info() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }

usage() {
    cat <<EOF
usage: $0 [install.sh options]

  --skip-tools   skip fetching netexec/responder from upstream
                 ('lateral' and 'mitm' then show MISSING; the rest
                 installs normally)
  --no-deps      skip ALL dependency work (apt + netexec/responder)

All other options are forwarded verbatim to install.sh — see:
  ./install.sh --help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-tools) SKIP_TOOLS=1; shift ;;
        --no-deps)    NO_DEPS=1; opts+=("$1"); shift ;;
        --yes|-y)     ASSUME_YES=1; opts+=("$1"); shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            opts+=("$1"); shift ;;
    esac
done

for a in "${opts[@]}"; do
    [ "$a" = "--root" ] && ROOT_STAGED=1
done

need_root() {
    [ "$ROOT_STAGED" = 1 ] && return 0
    [ "$(id -u)" = 0 ] && return 0
    err "run as root: sudo $0"
    exit 1
}

# --- OS check ---------------------------------------------------------------
[ -f /etc/os-release ] || { err "no /etc/os-release — not a Linux distro?"; exit 1; }
# shellcheck disable=SC1091
. /etc/os-release
if [ "${ID:-}" != "$TARGET_ID" ]; then
    err "this installer is for $DISTRO_NAME only (detected: ${ID:-unknown})"
    info "on other distros use the generic installer: sudo ./install.sh"
    exit 1
fi
major="${VERSION_ID:-}"
major="${major%%.*}"
case "$major" in
    *[!0-9]*|'') major=0 ;;
esac
if [ "$major" -lt "$MIN_MAJOR" ] 2>/dev/null; then
    warn "$DISTRO_NAME $VERSION_ID is older than the validated target — installs anyway, but only $VALIDATED_FROM was tested"
fi
info "$DISTRO_NAME detected: ${PRETTY_NAME:-$NAME $VERSION_ID}"

# --- netexec + responder (absent from the Debian archive) -------------------
ensure_build_tools() {
    want=""
    command -v git  >/dev/null 2>&1 || want="$want git"
    command -v pipx >/dev/null 2>&1 || want="$want pipx"
    [ -z "$want" ] && return 0
    info "installing (needed to fetch netexec/responder):$want"
    apt-get update -y >/dev/null 2>&1 || true
    if [ "$ASSUME_YES" = 1 ]; then
        apt-get install -y $want || { err "failed to install:$want"; return 1; }
    else
        printf '%s' "[?] apt-get install:$want  [Y/n] ? "
        read -r a || true
        case "${a:-y}" in
            y|Y|'') apt-get install -y $want || { err "failed to install:$want"; return 1; } ;;
            *) warn "skipped — netexec/responder will not be fetched" ;;
        esac
    fi
    return 0
}

provision_netexec() {
    command -v netexec >/dev/null 2>&1 && return 0
    command -v pipx >/dev/null 2>&1 || { err "pipx not available — 'lateral' will show MISSING"; return 1; }
    info "installing netexec via pipx (not in the $DISTRO_NAME archive)"
    if ! pipx install git+https://github.com/Pennyw0rth/NetExec; then
        err "netexec install failed (lateral movement will show MISSING)"
        return 1
    fi
    bin="$HOME/.local/bin/netexec"
    [ -x "$bin" ] || return 0
    ln -sf "$bin" /usr/bin/netexec
    info "netexec -> /usr/bin/netexec"
}

provision_responder() {
    command -v responder >/dev/null 2>&1 && return 0
    if [ ! -x /opt/Responder/Responder.py ]; then
        info "fetching Responder (LLMNR/mDNS/NBT-NS hash catch)"
        git clone -q --depth 1 https://github.com/lgandx/Responder.git /opt/Responder \
            || { err "could not fetch Responder (mitm will show MISSING)"; return 1; }
    fi
    ln -sf /opt/Responder/Responder.py /usr/bin/responder
    info "responder -> /usr/bin/responder"
}

# --- main -------------------------------------------------------------------
need_root

if [ "$NO_DEPS" = 0 ] && [ "$ROOT_STAGED" = 0 ]; then
    if [ "$SKIP_TOOLS" = 0 ]; then
        ensure_build_tools || exit 1
        provision_netexec
        provision_responder
    fi
fi

export MALSTROM_APT_PKGS="$CORE_PKGS"
exec "$REPO_DIR/install.sh" "${opts[@]}"