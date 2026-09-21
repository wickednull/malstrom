#!/bin/sh
# ============================================================================
# DarkSec MALSTROM — standalone uninstaller
#
# Removes the systemd service, CLI, desktop launcher + icon, config, state,
# the installed app tree and (optionally) the captured loot. Also does a
# best-effort cleanup of runtime leftovers (the MALSTROM iptables chain and
# the ap0/mon0 virtual interfaces) even if the daemon was killed hard.
#
#   sudo ./uninstall.sh              full uninstall (asks about loot)
#   sudo ./uninstall.sh --purge      ...and delete the captured loot too
#   sudo ./uninstall.sh --keep-loot  never touch the loot tree
#   sudo ./uninstall.sh --dry-run    preview what would be removed
#   sudo ./uninstall.sh --prefix DIR --root STAGE   staged/testing mode
# ============================================================================

set -u

APP_NAME="malstrom"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/${APP_NAME}"
ROOT_DIR=""                 # DESTDIR-style staging root (sandbox/testing)
PURGE=0
ASSUME_YES=0
DRY_RUN=0
KEEP_LOOT=""
KEEP_IN_PLACE=0
AUTO_REMOVE_LIVE=1

usage() {
    cat <<EOF
usage: $0 [options]

  --prefix DIR     app install dir to remove (default /opt/malstrom)
  --root DIR       stage all system paths under DIR (sandbox/testing)
  --purge          also delete captured loot (~/loot/malstrom) — no prompts
  --keep-loot      never delete the loot tree
  --keep-in-place  leave the app dir in place (used for --in-place installs)
  --yes            non-interactive: skip the loot prompt (loot is kept)
  --dry-run        print what would be removed and exit
  -h, --help       this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)  [ $# -ge 2 ] || { echo "--prefix needs DIR" >&2; exit 2; }
                   INSTALL_DIR="$2"; shift ;;
        --root)    [ $# -ge 2 ] || { echo "--root needs DIR" >&2; exit 2; }
                   ROOT_DIR="$2"; shift ;;
        --purge)          PURGE=1 ;;
        --keep-loot)      KEEP_LOOT=1 ;;
        --keep-in-place)  KEEP_IN_PLACE=1 ;;
        --yes)            ASSUME_YES=1 ;;
        --dry-run)        DRY_RUN=1 ;;
        -h|--help)        usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

sysroot() { printf '%s%s' "$ROOT_DIR" "$1"; }

info() { printf '\033[1;36m[*]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[x]\033[0m %s\n' "$*"; }

need_root() {
    [ "$DRY_RUN" = 1 ] && return 0
    [ -n "$ROOT_DIR" ] && return 0
    [ "$(id -u)" = 0 ] && return 0
    err "run as root: sudo $0"
    exit 1
}

# Dry run: just say what is going away.
mark() {
    if [ "$DRY_RUN" = 1 ]; then
        info "would remove: $1"
    else
        rm -rf -- "$1" 2>/dev/null || true
    fi
}

# Walk up from an emptied dir and remove now-empty parents (never touches a
# dir that still has content, and never the staging root itself).
prune_empty() {
    d="${1%/}"
    while [ -n "$d" ] && [ -n "$ROOT_DIR" ] && [ "$d" != "$ROOT_DIR" ] \
          && [ "$d" != "/" ]; do
        rmdir "$d" 2>/dev/null || break
        parent="$(dirname "$d")"
        [ "$parent" = "$d" ] && break
        d="$parent"
    done
}

# --- runtime leftovers -------------------------------------------------------
# Read override names before we blow away /etc/malstrom/env so a hard-killed
# daemon's chain/vifs can still be matched.
AP_VIF="ap0"
MON_VIF="mon0"
PORTAL_NET="172.16.52.0/24"
[ -r "$(sysroot /etc/$APP_NAME/env)" ] && {
    . "$(sysroot /etc/$APP_NAME/env)" 2>/dev/null || true
}
AP_VIF="${MALSTROM_AP_VIF:-$AP_VIF}"
MON_VIF="${MALSTROM_MON_VIF:-$MON_VIF}"
PORTAL_NET="${MALSTROM_PORTAL_NET:-$PORTAL_NET}"

# Only ever touch a virtual interface we created. Plain wlan*/eth* names from
# MALSTROM_AP_IFACE/MON_IFACE are real hardware links — never deleted here.
del_vif() {
    name="$1"
    [ -n "$name" ] || return 0
    # Never touch a real hardware link (a hard-killed daemon could have left
    # ap0/mon0, but MALSTROM_AP_VIF/MALSTROM_MON_VIF overrides must not point
    # at a physical card).
    case "$name" in
        wlan[0-9]*|eth[0-9]*|wlo[0-9]*|wlp[0-9]*|wlx[0-9]*|en[a-z]*) return 0 ;;
    esac
    ip link show dev "$name" >/dev/null 2>&1 || return 0
    if [ "$DRY_RUN" = 1 ]; then
        info "would delete leftover interface: $name"
        return 0
    fi
    iw dev "$name" del >/dev/null 2>&1 \
        || ip link del dev "$name" >/dev/null 2>&1 \
        || warn "could not delete interface: $name (remove it manually)"
}

cleanup_runtime() {
    # MALSTROM iptables nat chain (unique marker — safe to flush/delete).
    if iptables -t nat -L MALSTROM -n >/dev/null 2>&1; then
        info "tearing down leftover MALSTROM firewall chain"
        if [ "$DRY_RUN" = 1 ]; then
            info "would flush + delete iptables nat chain: MALSTROM"
            info "would remove DNAT/FORWARD/MASQUERADE rules for $PORTAL_NET"
        else
            iptables -D PREROUTING -t nat -i "$AP_VIF" -j MALSTROM >/dev/null 2>&1 || true
            iptables -t nat -F MALSTROM >/dev/null 2>&1 || true
            iptables -t nat -X MALSTROM >/dev/null 2>&1 || true
            iptables -t nat -D POSTROUTING -s "$PORTAL_NET" ! -d "$PORTAL_NET" -j MASQUERADE >/dev/null 2>&1 || true
            iptables -D FORWARD -i "$AP_VIF" -j ACCEPT >/dev/null 2>&1 || true
            iptables -D FORWARD -o "$AP_VIF" -j ACCEPT >/dev/null 2>&1 || true
        fi
    else
        warn "no leftover MALSTROM firewall chain — skipping iptables cleanup"
    fi

    del_vif "$AP_VIF"
    del_vif "$MON_VIF"
}

# --- loot --------------------------------------------------------------------
loot_dir="${MALSTROM_LOOT_DIR:-$HOME/loot/$APP_NAME}"
handle_loot() {
    if [ "$PURGE" = 1 ]; then
        if [ "$DRY_RUN" = 1 ]; then
            info "would delete loot: $loot_dir"
        else
            info "removing loot: $loot_dir"
            rm -rf -- "$loot_dir" 2>/dev/null || true
        fi
        return 0
    fi
    if [ "$KEEP_LOOT" = 1 ] || [ -n "$ROOT_DIR" ] \
       || [ "$ASSUME_YES" = 1 ] || [ "$DRY_RUN" = 1 ]; then
        warn "keeping loot: $loot_dir"
        return 0
    fi
    printf '%s' "[?] delete captured loot in $loot_dir?  [y/N] "
    read -r a || true
    case "${a:-n}" in
        y|Y)
            info "removing loot: $loot_dir"
            rm -rf -- "$loot_dir" 2>/dev/null || true ;;
        *) warn "keeping loot: $loot_dir" ;;
    esac
}

# --- main --------------------------------------------------------------------
need_root uninstall

info "uninstalling MALSTROM"
if [ "$DRY_RUN" = 1 ]; then
    info "dry run — nothing will be removed"
fi

# 1. stop + disable the service (triggers the daemon's own stack teardown)
if [ -z "$ROOT_DIR" ] && [ "$DRY_RUN" = 0 ] \
   && command -v systemctl >/dev/null 2>&1; then
    systemctl stop "$APP_NAME" >/dev/null 2>&1 || true
    systemctl disable "$APP_NAME" >/dev/null 2>&1 || true
fi

# 2. runtime leftovers (only matters if the daemon died hard)
cleanup_runtime

# 3. system-level files
mark "$(sysroot /usr/lib/systemd/system/${APP_NAME}.service)"
mark "$(sysroot /usr/local/bin/$APP_NAME)"
mark "$(sysroot /usr/bin/$APP_NAME)"
mark "$(sysroot /usr/share/applications/${APP_NAME}.desktop)"
mark "$(sysroot /usr/share/icons/hicolor/scalable/apps/${APP_NAME}.svg)"

# 4. config + operator state
mark "$(sysroot /etc/$APP_NAME)"
mark "$(sysroot /var/lib/$APP_NAME)"
mark "$(sysroot /tmp/$APP_NAME)"

# 5. the installed app tree (a dev checkout --in-place install is kept)
if [ "$KEEP_IN_PLACE" = 1 ]; then
    warn "install dir kept in place (--in-place install): $INSTALL_DIR"
elif [ -d "$(sysroot "$INSTALL_DIR")" ]; then
    mark "$(sysroot "$INSTALL_DIR")"
else
    warn "install dir not found (skipping): $INSTALL_DIR"
fi

# collapse empty ancestor dirs left by the installer (staged runs only — a
# real system's /usr/bin, /etc, /var/lib, ... are never empty, so nothing
# risky happens if --root is unset)
if [ -n "$ROOT_DIR" ] && [ "$DRY_RUN" = 0 ]; then
    for d in \
        "$(sysroot /usr/lib/systemd/system)" \
        "$(sysroot /usr/local/bin)" \
        "$(sysroot /usr/bin)" \
        "$(sysroot /usr/share/applications)" \
        "$(sysroot /usr/share/icons/hicolor/scalable/apps)" \
        "$(sysroot /etc/$APP_NAME)" \
        "$(sysroot /var/lib/$APP_NAME)" \
        "$(sysroot /tmp/$APP_NAME)" \
        "$(sysroot "$INSTALL_DIR")" \
        "$(sysroot /opt)" \
        "$(sysroot /var/lib)" \
        "$(sysroot /var)" \
        "$(sysroot /etc)"
    do
        [ -d "$d" ] && prune_empty "$d"
    done
fi

# 6. captured loot (prompted unless --purge/--keep-loot/--yes/--root)
handle_loot

if [ -z "$ROOT_DIR" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
command -v gtk-update-icon-cache >/dev/null 2>&1 \
    && gtk-update-icon-cache -f /usr/share/icons/hicolor >/dev/null 2>&1 || true

echo
info "uninstall complete."
if [ "$DRY_RUN" = 1 ]; then
    info "(dry run — nothing was removed)"
fi
warn "if you removed the service while it was armed, the original wifi config was"
warn "already restored on daemon stop; a reboot clears any residual kernel state."
warn "apt packages were not touched — remove them with:"
warn "  sudo apt remove hostapd dnsmasq aircrack-ng tcpdump nmap netexec responder smbclient"
exit 0