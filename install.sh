#!/bin/sh
# ============================================================================
# DarkSec MALSTROM — Linux installer
#
# Installs the app under /opt, wires a systemd service, a `malstrom` CLI,
# a desktop launcher + icon, and (optionally) installs missing apt deps.
#
#   sudo ./install.sh              normal install
#   sudo ./install.sh --enable-boot --start
#   sudo ./install.sh --in-place   point service at this checkout (dev)
#   sudo ./install.sh --uninstall  full uninstall (delegates to uninstall.sh)
#   sudo ./install.sh --uninstall --purge   ...also delete captured loot
# ============================================================================

set -u

APP_NAME="malstrom"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/${APP_NAME}"
# Apt sources for hard deps. netexec + responder are Kali packages — distros
# like Debian/Ubuntu don't ship them, so their installers (install-debian.sh,
# install-ubuntu.sh) provision those from upstream and pass the reduced list
# here via MALSTROM_APT_PKGS.
DEPS="${MALSTROM_APT_PKGS:-hostapd dnsmasq iw iptables aircrack-ng tcpdump nmap netexec responder smbclient python3}"
ROOT_DIR=""                 # DESTDIR-style staging root (sandbox/testing)
ENABLE_BOOT=0
START_NOW=0
SKIP_DEPS=0
ASSUME_YES=0
MODE=install
PURGE=0
KEEP_LOOT=""
DRY_RUN=0
IN_PLACE=0

usage() {
    cat <<EOF
usage: $0 [options]

  --prefix DIR     install the app into DIR (default /opt/malstrom)
  --enable-boot    enable the daemon at boot
  --start          start the daemon right after install
  --in-place       install CLI/service/launcher pointing at this checkout
  --no-deps        skip apt dependency installation
  --yes            assume "yes" for apt prompts (non-interactive)
  --root DIR       stage all system paths under DIR (sandbox/testing)
  --uninstall      full uninstall (service, CLI, launcher, config, state,
                   install tree, firewall + vif cleanup) — uninstall.sh
  --purge          with --uninstall: also delete captured loot
  --keep-loot      with --uninstall: never touch the loot tree
  --dry-run        with --uninstall: preview without removing anything
  -h, --help       this help

distro installers (tuned for each archive):
  ./install-debian.sh   Debian 13 "trixie" and newer (apt + netexec/responder
                        fetched from upstream — not shipped by Debian)
  ./install-ubuntu.sh   Ubuntu 26.04 LTS "Resolute Raccoon" and newer (same)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)  [ $# -ge 2 ] || { echo "--prefix needs DIR" >&2; exit 2; }
                   INSTALL_DIR="$2"; shift ;;
        --root)    [ $# -ge 2 ] || { echo "--root needs DIR" >&2; exit 2; }
                   ROOT_DIR="$2"; shift ;;
        --enable-boot) ENABLE_BOOT=1 ;;
        --start)       START_NOW=1 ;;
        --in-place)    INSTALL_DIR="$REPO_DIR" ; IN_PLACE=1 ;;
        --no-deps)     SKIP_DEPS=1 ;;
        --yes)         ASSUME_YES=1 ;;
        --purge)       PURGE=1 ;;
        --keep-loot)   KEEP_LOOT=1 ;;
        --dry-run)     DRY_RUN=1 ;;
        --uninstall)   MODE=uninstall ;;
        -h|--help)     usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

sysroot() { printf '%s%s' "$ROOT_DIR" "$1"; }

info() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }

need_root() {
    [ -n "$ROOT_DIR" ] && return 0
    [ "$(id -u)" = 0 ] && return 0
    err "run as root: sudo $0 $*"
    exit 1
}

# --- dependencies ---------------------------------------------------------
install_deps() {
    [ "$SKIP_DEPS" = 1 ] && return 0
    command -v apt-get >/dev/null 2>&1 || { warn "apt-get not found — skipping deps"; return 0; }
    missing=""
    for p in $DEPS; do
        dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"
    done
    [ -z "$missing" ] && return 0
    info "installing missing dependencies:$missing"
    if [ "$ASSUME_YES" = 1 ]; then
        apt-get update -y >/dev/null 2>&1 || true
        apt-get install -y $missing || { err "dependency install failed"; exit 1; }
    else
        printf '%s' "[?] apt-get install:$missing  [Y/n] ? "
        read -r a || true
        case "${a:-y}" in
            y|Y|'') apt-get update -y >/dev/null 2>&1 || true
                    apt-get install -y $missing || { err "dependency install failed"; exit 1; } ;;
            *) warn "dependencies skipped — the service may fail to run" ;;
        esac
    fi
    return 0
}

# --- install ---------------------------------------------------------------
install() {
    info "installing MALSTROM into $INSTALL_DIR"
    [ -n "$ROOT_DIR" ] || systemctl stop "$APP_NAME" >/dev/null 2>&1 || true

    mkdir -p "$(sysroot "$INSTALL_DIR")"
    for d in malstrom www portal bin legacy deploy; do
        [ -d "$REPO_DIR/$d" ] && cp -a "$REPO_DIR/$d" "$(sysroot "$INSTALL_DIR")/"
    done
    [ -f "$REPO_DIR/README.md" ] && cp -a "$REPO_DIR/README.md" "$(sysroot "$INSTALL_DIR")/"
    [ "$REPO_DIR" != "$INSTALL_DIR" ] && for s in install.sh install-debian.sh install-ubuntu.sh; do
        [ -f "$REPO_DIR/$s" ] && cp -a "$REPO_DIR/$s" "$(sysroot "$INSTALL_DIR")/"
    done
    [ -f "$REPO_DIR/uninstall.sh" ] && [ "$REPO_DIR" != "$INSTALL_DIR" ] \
        && cp -a "$REPO_DIR/uninstall.sh" "$(sysroot "$INSTALL_DIR")/" \
        && chmod 755 "$(sysroot "$INSTALL_DIR/uninstall.sh")"

    mkdir -p "$(sysroot /usr/local/bin)" "$(sysroot /usr/bin)"
    sed "s|__MALSTROM_DIR__|$INSTALL_DIR|g" "$REPO_DIR/deploy/malstrom-cli" \
        > "$(sysroot /usr/local/bin/$APP_NAME)"
    chmod 755 "$(sysroot /usr/local/bin/$APP_NAME)"
    # /usr/bin is the only dir in sudo's default PATH on some distros
    ln -sf "$(sysroot /usr/local/bin/$APP_NAME)" "$(sysroot /usr/bin/$APP_NAME)"

    mkdir -p "$(sysroot /usr/lib/systemd/system)"
    sed "s|__MALSTROM_DIR__|$INSTALL_DIR|g" "$REPO_DIR/deploy/malstrom.service" \
        > "$(sysroot /usr/lib/systemd/system/${APP_NAME}.service)"

    mkdir -p "$(sysroot /etc/$APP_NAME)" "$(sysroot /var/lib/${APP_NAME})"
    [ -f "$(sysroot /etc/$APP_NAME/env)" ] \
        || cp "$REPO_DIR/deploy/malstrom.env" "$(sysroot /etc/$APP_NAME/env)"

    mkdir -p "$(sysroot /usr/share/applications)" \
             "$(sysroot /usr/share/icons/hicolor/scalable/apps)"
    cp "$REPO_DIR/deploy/malstrom.svg" \
       "$(sysroot /usr/share/icons/hicolor/scalable/apps/${APP_NAME}.svg)"
    cp "$REPO_DIR/deploy/malstrom.desktop" \
       "$(sysroot /usr/share/applications/${APP_NAME}.desktop)"

    if [ -n "$ROOT_DIR" ]; then
        info "staged under $ROOT_DIR (no systemctl changes made)"
        return 0
    fi

    systemctl daemon-reload
    if [ "$ENABLE_BOOT" = 1 ]; then
        info "enabling daemon at boot"
        systemctl enable "$APP_NAME" >/dev/null 2>&1 || true
    fi
    if [ "$START_NOW" = 1 ]; then
        info "starting daemon"
        systemctl start "$APP_NAME" || err "service failed to start — check: journalctl -u $APP_NAME"
    fi
    command -v gtk-update-icon-cache >/dev/null 2>&1 \
        && gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true
    return 0
}

# --- uninstall --------------------------------------------------------------
# Full teardown lives in uninstall.sh (service, CLI, launcher, config, state,
# iptables chain, virtual interfaces, optional loot). Delegate to it.
uninstall() {
    args="--prefix $INSTALL_DIR"
    [ -n "$ROOT_DIR" ] && args="$args --root $ROOT_DIR"
    [ "$ASSUME_YES" = 1 ] && args="$args --yes"
    [ "$PURGE" = 1 ] && args="$args --purge"
    [ -n "$KEEP_LOOT" ] && args="$args --keep-loot"
    [ "$DRY_RUN" = 1 ] && args="$args --dry-run"
    [ "$IN_PLACE" = 1 ] && args="$args --keep-in-place"
    exec "$REPO_DIR/uninstall.sh" $args
}

# --- main -------------------------------------------------------------------
case "$MODE" in
    install)   need_root install
               install_deps
               install ;;
    uninstall) need_root uninstall
               uninstall ;;
esac

if [ "$MODE" = install ]; then
cat <<EOF

  MALSTROM installed.

  Quick start:
    sudo malstrom start       start the daemon (prints URL + token)
    sudo malstrom enable      + start at boot
    malstrom open             open the dashboard (auto-signed-in)
    malstrom status           service status
    sudo malstrom run         run in the foreground (debug)
    malstrom token            print the access token

  Dashboard  : http://127.0.0.1:8888
  Token      : printed by 'sudo malstrom start' — or run: malstrom token
EOF
fi

exit 0