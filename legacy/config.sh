#!/bin/sh
# ============================================================================
# DarkSec MALSTROM — runtime configuration
#
# All values here are defaults. The operator can override most of these at
# runtime from the web dashboard or the Pager menu; those overrides are applied
# per-attack and written into the engine's state file, and the device returns
# to these defaults on the next run.
#
# Secrets (discord webhook URL, telegram token, ...) go in a SEPARATE file,
# never on the device by default. This file ships with the payload.
# ============================================================================

# --- Network -----------------------------------------------------------------
# Interface that will carry the rogue AP. wlan0open = native Open AP
# (open network), wlan0wpa = native Evil WPA (WPA2 secured).
# MALSTROM clones the selected target's identity onto whichever is active.
OPEN_AP_IFACE="wlan0open"
WPA_AP_IFACE="wlan0wpa"

# Portal mode: "open" or "wpa". Toggleable from the dashboard while idle.
PORTAL_MODE="open"

# If PORTAL_MODE=wpa, this PSK is used for the evil WPA network.
# Leave empty to generate a random one per session and print it on the
# dashboard / Pager LCD.
WPA_PSK=""

# Where victims land after submitting credentials ("real" internet on success).
# NOTE: this is the post-auth redirect target and is never a live service by
# default. Change to a harmless public page you control, or keep example.com.
REDIRECT_TARGET="http://example.com"

# --- Attack: deauth ----------------------------------------------------------
# Deauth mode: "broadcast" (FF:FF:FF:FF:FF:FF), "targeted" (recon clients),
# or "adaptive" (bursts timed to client appearance, low-noise).
DEAUTH_MODE="broadcast"

# Packets per deauth burst.
DEAUTH_BURST=25

# Seconds between bursts.
DEAUTH_DELAY=1

# 1 = run deauth continuously until the attack is stopped.
# 0 = run a single series of bursts then let the portal do the work.
DEAUTH_CONTINUOUS=1

# --- Monitor -----------------------------------------------------------------
# Seconds between network environment scans (client/ARP diffing).
MONITOR_INTERVAL=4

# --- Portal ------------------------------------------------------------------
# Template name served to new victims (before per-device detection).
DEFAULT_TEMPLATE="wifi_login"

# Seconds to wait before nginx is reloaded after template switch.
PORTAL_RELOAD_DELAY=2

# --- Exfil (reserved for future use) -----------------------------------------
# Nothing is sent off-device in v1.0. All captured data is written to
# /root/loot/malstrom/ in structured JSON + plain text.
EXFIL_ENABLED=0
# EXFIL_WEBHOOK=""
# EXFIL_CHANNEL="telegram|discord|webhook"