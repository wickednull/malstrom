#!/bin/sh
# ============================================================================
# DarkSec MALSTROM — cleanup library
#
# Sourced by payload.sh and cgi-bin/api.sh. All functions are idempotent:
# running them multiple times (payload trap + dashboard Cleanup + double
# clicks) is safe.
#
# Environment expected (set by payload.sh):
#   PAYLOAD_DIR   -> this payload's directory
#   MALSTROM_STATE_DIR  -> /tmp/malstrom
# ============================================================================

MALSTROM_STATE_DIR="${MALSTROM_STATE_DIR:-/tmp/malstrom}"
PAYLOAD_DIR="${PAYLOAD_DIR:-/root/payloads/user/interception/malstrom}"

WIFI_BACKUP="$MALSTROM_STATE_DIR/wifi_backup"
FIREWALL_MARKER="Malstrom"

malstrom_emit_event() {
    local type="$1" msg="$2"
    printf '{"ts":"%s","type":"%s","msg":"%s"}\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$type" "$msg" >> "$MALSTROM_STATE_DIR/events" 2>/dev/null
}

# --- WiFi config backup / restore ---------------------------------------------
malstrom_backup_wifi() {
    [ -f "$WIFI_BACKUP" ] && return 0
    {
        echo "wlan0open_ssid=$(uci -q get wireless.wlan0open.ssid)"
        echo "wlan0open_mac=$(uci -q get wireless.wlan0open.macaddr)"
        echo "wlan0open_disabled=$(uci -q get wireless.wlan0open.disabled)"
        echo "wlan0wpa_ssid=$(uci -q get wireless.wlan0wpa.ssid)"
        echo "wlan0wpa_mac=$(uci -q get wireless.wlan0wpa.macaddr)"
        echo "wlan0wpa_key=$(uci -q get wireless.wlan0wpa.key)"
        echo "wlan0wpa_disabled=$(uci -q get wireless.wlan0wpa.disabled)"
    } > "$WIFI_BACKUP" 2>/dev/null
}

malstrom_restore_wifi() {
    [ -f "$WIFI_BACKUP" ] || return 0
    local restored=0
    local key val
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        key="${line%%=*}"
        val="${line#*=}"
        case "$key" in
            wlan0open_ssid) uci -q set wireless.wlan0open.ssid="$val"; restored=1;;
            wlan0open_mac) uci -q set wireless.wlan0open.macaddr="$val";;
            wlan0wpa_ssid) uci -q set wireless.wlan0wpa.ssid="$val" ; restored=1;;
            wlan0wpa_mac)  uci -q set wireless.wlan0wpa.macaddr="$val";;
            wlan0wpa_key)  uci -q set wireless.wlan0wpa.key="$val";;
        esac
    done < "$WIFI_BACKUP"
    if [ "$restored" -eq 1 ]; then
        uci -q commit wireless 2>/dev/null
        wifi reload 2>/dev/null
    fi
    malstrom_emit_event "CLEANUP" "Original WiFi config restored"
}

# Remove the backup permanently — only on real payload exit.
malstrom_finalize_wifi() {
    rm -f "$WIFI_BACKUP"
}

# --- Firewall DNAT rules --------------------------------------------------------
malstrom_remove_firewall() {
    # Remove any firewall redirect entries whose name starts with our marker.
    # Indices shift on delete, so process highest index first.
    local indices
    indices=$(uci show firewall 2>/dev/null \
        | grep -E "name=.*${FIREWALL_MARKER}" \
        | sed -n 's/.*\[\([0-9]*\)\].*/\1/p' \
        | sort -rn)
    if [ -n "$indices" ]; then
        for idx in $indices; do
            uci -q delete "firewall.@redirect[$idx]" 2>/dev/null
        done
        uci -q commit firewall 2>/dev/null
        /etc/init.d/firewall reload 2>/dev/null || /etc/init.d/firewall restart 2>/dev/null
        malstrom_emit_event "CLEANUP" "Firewall DNAT rules removed"
    fi
}

# --- Services --------------------------------------------------------------------
malstrom_mark_nginx() {
    # If we overwrote nginx.conf, restore the original backup, else drop our
    # config so OpenWrt's UCI nginx can regenerate from its own config.
    if grep -q "DarkSec MALSTROM" /etc/nginx/nginx.conf 2>/dev/null; then
        if [ -f /etc/nginx/nginx.conf.malstrom.bak ]; then
            cp /etc/nginx/nginx.conf.malstrom.bak /etc/nginx/nginx.conf 2>/dev/null
            rm -f /etc/nginx/nginx.conf.malstrom.bak 2>/dev/null
        else
            rm -f /etc/nginx/nginx.conf 2>/dev/null
        fi
        uci -q set nginx.global.uci_enable=true 2>/dev/null
        uci -q commit nginx 2>/dev/null
    fi
}

malstrom_stop_services() {
    # nginx — only if it is serving our config
    if grep -q "DarkSec MALSTROM" /etc/nginx/nginx.conf 2>/dev/null; then
        /etc/init.d/nginx stop 2>/dev/null
        killall nginx 2>/dev/null
    fi
    malstrom_mark_nginx
    # rogue dnsmasq on port 1053
    local pids
    pids=$(netstat -tulpn 2>/dev/null | grep ':1053 ' | awk '{print $NF}' | sed 's|/.*||' | sort -u)
    [ -z "$pids" ] && pids=$(pidof dnsmasq 2>/dev/null)
    for p in $pids; do
        [ "$p" = "$$" ] && continue
        # only kill the one bound to 1053 or started with --no-hosts (ours)
        if [ "$(cat /proc/"$p"/cmdline 2>/dev/null | tr '\0' ' ' | grep -c 'no-hosts')" -gt 0 ] 2>/dev/null; then
            kill "$p" 2>/dev/null
        fi
    done
    # php-fpm only needed by portal
    killall php-fpm php8-fpm 2>/dev/null
    malstrom_emit_event "CLEANUP" "Services stopped (nginx/dnsmasq/php-fpm)"
}

malstrom_restore_network_state() {
    echo 0 > /proc/sys/net/ipv4/conf/all/arp_ignore 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/conf/all/arp_announce 2>/dev/null
    local ipf="$MALSTROM_STATE_DIR/.ip_forward_original"
    if [ -f "$ipf" ]; then
        cat "$ipf" > /proc/sys/net/ipv4/ip_forward 2>/dev/null
        rm -f "$ipf"
    fi
}

malstrom_disarm() {
    # set state.active=false for the engine
    if [ -f "$MALSTROM_STATE_DIR/state" ]; then
        sed -i 's/"active": *true/"active": false/' "$MALSTROM_STATE_DIR/state" 2>/dev/null
    fi
    malstrom_emit_event "CLEANUP" "Engine disarmed"
}

# --- Full cleanup ---------------------------------------------------------------
malstrom_full_cleanup() {
    malstrom_disarm
    malstrom_stop_services
    malstrom_remove_firewall
    malstrom_restore_wifi
    malstrom_restore_network_state
    malstrom_emit_event "CLEANUP" "MALSTROM fully cleaned up"
}

# deploy-time helper: back up wireless before first attack uses it
malstrom_ensure_backup() {
    malstrom_backup_wifi
}

# expose a small CLI (unused by sourced contexts)
case "${1:-cleanup}" in
    backup) malstrom_backup_wifi ;;
    cleanup) malstrom_full_cleanup ;;
esac