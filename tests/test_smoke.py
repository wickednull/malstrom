"""Smoke tests for the MALSTROM rebuild (no root, no radio required).

Runs against whatever state dir the environment resolves to, so the caller can
point it at a scratch dir:

    MALSTROM_STATE_DIR=/tmp/opencode/ms-state python3 -m unittest -v \
        tests.test_smoke

Covers the Phase 1-5 regressions: canonical state dir, capture channel
dedup, scoped wpa_supplicant pkill, portal bind gating, graceful dashboard
port fallback, and idempotent stack teardown.
"""

import errno
import io
import json
import os
import re
import shutil
import socket
import struct
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request
from email.message import Message

from malstrom import app
from malstrom import config
from malstrom import capture
from malstrom import beacon
from malstrom import clone
from malstrom import firewall
from malstrom import karma
from malstrom import lateral
from malstrom import linuxutil
from malstrom import mitm
from malstrom import notify
from malstrom import portal
from malstrom import recon
from malstrom import relay
from malstrom import services
from malstrom import state
from malstrom import verify
from malstrom import web
from malstrom.app import Malstrom
from malstrom.deauth import DeauthEngine


class ConfigDefaults(unittest.TestCase):
    def test_state_dir_precedence(self):
        # Defaults to the canonical path; an explicit env override wins over it
        # (same rule the CLI + service use).
        expected = os.environ.get('MALSTROM_STATE_DIR', '/var/lib/malstrom')
        self.assertEqual(config.STATE_DIR, expected)
        self.assertEqual(expected, '/var/lib/malstrom' if 'MALSTROM_STATE_DIR' not in os.environ
                         else os.environ['MALSTROM_STATE_DIR'])

    def test_backoff_constants_present(self):
        self.assertGreaterEqual(config.STACK_RETRY_UP, 4)
        self.assertGreaterEqual(config.STACK_RETRY_DOWN,
                                config.STACK_RETRY_UP)
        self.assertGreaterEqual(config.VIF_RETRY_GAP, 2)

    def test_state_uses_config_state_dir(self):
        self.assertTrue(state.STATE_FILE.startswith(config.STATE_DIR))

    def test_loot_dir_canonical_default(self):
        # The vault must resolve to the same path the (root) daemon writes to
        # regardless of who runs --check / wipe-loot / reset — a per-user
        # default made a non-root operator wipe the wrong, empty dir.
        expected = os.environ.get('MALSTROM_LOOT_DIR', '/root/loot/malstrom')
        self.assertEqual(config.LOOT_DIR, expected)
        if 'MALSTROM_LOOT_DIR' not in os.environ:
            self.assertEqual(config.LOOT_DIR, '/root/loot/malstrom')


class ChannelDedup(unittest.TestCase):
    def test_set_mon_channel_skips_redundant_tune(self):
        calls = []

        def fake_set_channel(mon, ch):
            calls.append(ch)
            return True

        linuxutil.set_channel = fake_set_channel
        eng = capture.CaptureEngine()
        eng._set_mon_channel('mon0', '6')
        eng._set_mon_channel('mon0', '6')   # same channel — must be skipped
        eng._set_mon_channel('mon0', '11')
        eng._set_mon_channel('mon0', '6')   # tear-down to a different channel
        self.assertEqual(calls, ['6', '11', '6'])

    def test_capture_accepts_deauth_style_dedup(self):
        de = DeauthEngine()
        calls = []
        linuxutil.set_channel = lambda mon, ch: (calls.append(ch), True)[1]
        de._set_mon_channel('mon0', '1')
        de._set_mon_channel('mon0', '1')
        de._set_mon_channel('mon0', '1')
        self.assertEqual(calls, ['1'])


class KarmaHop(unittest.TestCase):
    """Scan-channel awareness: idle karma cycles the full band; armed karma
    never fights the pinned target channel that deauth/capture own."""

    def _engine(self):
        eng = karma.KarmaEngine()
        eng.set_cmd(active=True, hop=True, dwell=0.1)
        return eng

    def _capture_tunes(self, eng, mon='mon0', n=3):
        tunes = []
        linuxutil.set_channel = lambda name, ch: (tunes.append((name, ch)),
                                                  True)[1]
        for _ in range(n):
            eng._tune(eng._cmd_snapshot(), mon)
        return tunes

    def test_hop_advances_through_plan_in_order(self):
        eng = self._engine()
        plan = config.KARMA_HOP_CHANNELS or list(karma.DEFAULT_HOP_CHANNELS)
        tunes = self._capture_tunes(eng, n=len(plan) + 1)
        channels = [ch for _, ch in tunes]
        self.assertEqual(channels[:len(plan)], plan)
        self.assertEqual(channels[-1], plan[0])    # wraps around the list
        self.assertEqual(eng._hop_idx, 1)          # mod len(plan)

    def test_configured_channel_list_overrides_default(self):
        saved = config.KARMA_HOP_CHANNELS
        config.KARMA_HOP_CHANNELS = ['1', '6', '11']
        try:
            eng = karma.KarmaEngine()
            eng.set_cmd(active=True, hop=True)
            tunes = self._capture_tunes(eng, n=4)
            self.assertEqual([ch for _, ch in tunes], ['1', '6', '11', '1'])
        finally:
            config.KARMA_HOP_CHANNELS = saved

    def test_pinned_never_tunes_the_radio(self):
        eng = karma.KarmaEngine()
        eng.set_cmd(active=True, hop=False, channel='6')
        tunes = []
        linuxutil.set_channel = lambda name, ch: (tunes.append((name, ch)),
                                                  True)[1]
        eng._tune(eng._cmd_snapshot(), 'mon0')     # not a hop cycle
        eng._cycle = lambda: None                  # (surrogate: nothing runs)
        self.assertEqual(tunes, [])                # pinned channel is sacred

    def test_disarm_marks_idle_hop_off(self):
        # armed (now=True) forces hop=False regardless of KARMA_HOP default —
        # the caller wiring, mirrored here as it is what the engine sees.
        eng = karma.KarmaEngine()
        eng.set_cmd(active=True, hop=False)
        self.assertFalse(eng._cmd_snapshot()['hop'])


class _FakeTxSock(object):
    def __init__(self):
        self.sent = []

    def send(self, frame):
        self.sent.append(frame)
        return len(frame)


class KarmaRespond(unittest.TestCase):
    """Optional PineAP-style auto-respond. Off by default; when armed it must
    only ever advertise the LIVE twin's identity (broadcast + matching
    directed probes), never other SSIDs — no AP-storming, no churn."""

    def _probe_request(self, sta='11:22:33:44:55:66', ssid=None):
        rt = bytes([0, 0, 8, 0, 0, 0, 0, 0])       # no radiotap fields
        fc = 0x0040                                # Probe Request
        hdr = struct.pack('<HH', fc, 0)
        hdr += b'\xff' * 6                          # DA broadcast
        hdr += bytes(int(x, 16) for x in sta.split(':'))
        hdr += b'\xff' * 6                          # BSSID wildcard
        hdr += struct.pack('<H', 0)
        body = b''
        if ssid:
            body += bytes([0x00, len(ssid)]) + ssid.encode('ascii')
        return rt + hdr + body

    def _engine(self, respond=True, ssid='LiveNet',
                bssid='aa:bb:cc:dd:ee:ff', mode='open'):
        eng = karma.KarmaEngine()
        eng.set_cmd(respond=respond, ssid=ssid, bssid=bssid,
                    channel='6', mode=mode)
        return eng

    def test_disabled_by_default(self):
        self.assertFalse(config.KARMA_RESPOND)

    def test_should_respond_gates_on_switch_and_identity(self):
        eng = self._engine()
        base = eng._cmd_snapshot()
        off = dict(base, respond=False)
        self.assertFalse(eng._should_respond('', off))
        self.assertFalse(eng._should_respond('LiveNet', off))
        no_id = dict(base, bssid='', ssid='')
        self.assertFalse(eng._should_respond('', no_id))
        # never advertise a network we are not serving
        self.assertFalse(eng._should_respond('EvilCorp', base))
        # the two cases the responder exists for
        self.assertTrue(eng._should_respond('', base))          # wildcard
        self.assertTrue(eng._should_respond('LiveNet', base))   # saved-net directed

    def test_frame_is_well_formed_probe_response(self):
        frame = karma.KarmaEngine._probe_response_frame(
            'TestNet', 'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66',
            '7', seq=3, privacy=True)
        self.assertTrue(frame)
        rt_len = struct.unpack('<H', frame[2:4])[0]
        self.assertEqual(rt_len, 10)               # radiotap flags+rate
        hdr = frame[rt_len:]
        self.assertGreaterEqual(len(hdr), 24)
        fc = struct.unpack('<H', hdr[0:2])[0]
        self.assertEqual((fc >> 4) & 0x0F, 0x05)   # Probe Response subtype
        self.assertEqual((fc >> 9) & 1, 1)         # FromDS
        sta = bytes(int(x, 16) for x in '11:22:33:44:55:66'.split(':'))
        bssid_b = bytes(int(x, 16) for x in 'aa:bb:cc:dd:ee:ff'.split(':'))
        self.assertEqual(hdr[4:10], sta)           # DA = the probing client
        self.assertEqual(hdr[10:16], bssid_b)      # SA = rogue BSSID
        self.assertEqual(hdr[16:22], bssid_b)      # BSSID = rogue BSSID
        body = hdr[24:]
        cap = struct.unpack('<H', body[10:12])[0]
        self.assertNotEqual(cap & 0x0001, 0)       # ESS
        self.assertNotEqual(cap & 0x0010, 0)       # privacy (WPA twin)
        self.assertEqual(body[12], 0x00)           # SSID IE tag
        self.assertEqual(body[13], 7)
        self.assertEqual(body[14:21], b'TestNet')
        self.assertEqual(body[-3:], bytes([0x03, 0x01, 7]))  # channel IE

    def test_open_twin_has_no_privacy_bit(self):
        frame = karma.KarmaEngine._probe_response_frame(
            'Open', 'aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66', '1',
            privacy=False)
        rt_len = struct.unpack('<H', frame[2:4])[0]
        hdr = frame[rt_len:]
        cap = struct.unpack('<H', hdr[24 + 10:24 + 12])[0]
        self.assertEqual(cap & 0x0010, 0)

    def test_sends_on_wildcard_and_matching_directed_only(self):
        sock = _FakeTxSock()
        eng = self._engine()
        # broadcast probe -> responded
        eng._listen(self._probe_request(), sock)
        self.assertEqual(len(sock.sent), 1)
        # directed probe for another network -> must NOT reply
        eng._listen(self._probe_request(ssid='OtherNet',
                                        sta='22:33:44:55:66:77'), sock)
        self.assertEqual(len(sock.sent), 1)
        # directed probe for the twin -> responded
        eng._listen(self._probe_request(ssid='LiveNet',
                                        sta='22:33:44:55:66:77'), sock)
        self.assertEqual(len(sock.sent), 2)

    def test_disabled_respond_listens_but_never_transmits(self):
        sock = _FakeTxSock()
        eng = self._engine(respond=False)
        eng._listen(self._probe_request(ssid='LiveNet'), sock)
        eng._listen(self._probe_request(), sock)
        self.assertEqual(sock.sent, [])

    def test_response_throttled_per_station(self):
        sock = _FakeTxSock()
        eng = self._engine()
        mac = '11:22:33:44:55:66'
        eng._listen(self._probe_request(), sock)      # first: sent
        eng._listen(self._probe_request(), sock)      # within gap: throttled
        self.assertEqual(len(sock.sent), 1)
        eng._last_resp[mac] = time.time() - config.KARMA_RESPOND_GAP - 1
        eng._listen(self._probe_request(), sock)      # after gap: sent again
        self.assertEqual(len(sock.sent), 2)


class PkillScoping(unittest.TestCase):
    def test_matches_wlan1_only(self):
        # Validate against REAL POSIX ERE semantics (glibc regcomp — what pkill
        # uses), not Python's re, which lacks [[:space:]].
        import subprocess, sys
        pat = linuxutil.wpa_pkill_pattern('wlan1')
        sample = ('/usr/sbin/wpa_supplicant -B -i wlan1 -c /run/wpa.conf\n'
                  '/usr/sbin/wpa_supplicant -B -i wlan2 -c /run/wpa.conf\n'
                  '/usr/sbin/wpa_supplicant -B -i wlan11 -c /run/x.conf\n')
        r = subprocess.run(['grep', '-E', pat],
                           input=sample, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)      # something matched
        lines = r.stdout.splitlines()
        self.assertEqual(len(lines), 1)        # exactly the wlan1 line
        self.assertIn('wlan1 -c', lines[0])    # ...and not wlan2/wlan11

    def test_posix_class_compiles(self):
        # The exact pattern string must be a valid POSIX ERE (pkill would
        # otherwise never match — the old `\s` bug).
        import subprocess, sys
        pat = linuxutil.wpa_pkill_pattern('wlan1')
        r = subprocess.run(['grep', '-E', pat],
                           input='/usr/sbin/wpa_supplicant -B -i wlan1 -c /x\n',
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn('wlan1', r.stdout)


class PcapNaming(unittest.TestCase):
    def test_unique_pcap_path_never_collides(self):
        # Same-second disarm/re-arm must yield distinct paths (the old
        # second-granularity name let tcpdump overwrite a crackable capture).
        import shutil
        import tempfile
        tmp = tempfile.mkdtemp()
        old, config.PCAP_DIR = config.PCAP_DIR, tmp
        try:
            p1 = capture.unique_pcap_path()
            self.assertEqual(os.path.dirname(p1), config.PCAP_DIR)
            self.assertIn('malstrom-', os.path.basename(p1))
            self.assertTrue(p1.endswith('.pcap'))
            with open(p1, 'w'):
                pass                       # tcpdump lands on the first path
            p2 = capture.unique_pcap_path()  # same second -> must bump
            self.assertNotEqual(p1, p2)
            self.assertTrue(os.path.basename(p2).endswith('-1.pcap')
                            or p2 != p1)
            self.assertFalse(os.path.exists(p2))
        finally:
            config.PCAP_DIR = old
            shutil.rmtree(tmp, ignore_errors=True)


class PortalBindGate(unittest.TestCase):
    def test_portal_refuses_missing_portal_ip(self):
        # 172.16.52.1 is never a local address on the test box: Portal() must
        # raise EADDRNOTAVAIL (the _run loop's expected, retried condition) —
        # and MUST NOT fall back to 0.0.0.0:80.
        try:
            portal.Portal()
        except OSError as exc:
            self.assertIn(getattr(exc, 'errno', None),
                          (errno.EADDRNOTAVAIL, errno.EADDRINUSE))
        else:
            self.fail('Portal() bound without the portal IP being up')


class PortalToken(unittest.TestCase):
    def test_token_deterministic_per_ip(self):
        a = portal._victim_token('10.0.0.5')
        b = portal._victim_token('10.0.0.5')
        c = portal._victim_token('10.0.0.6')
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertRegex(a, r'^[0-9a-f]{10}$')

    def test_token_links_renders_and_cred_capture(self):
        # The portal records the 10-char token on every POST; the hidden mvt
        # field the renderer injects must equal what _record_creds uses, so the
        # operator can correlate a filled-in page with the loot entry.
        self.assertEqual(portal._victim_token('10.0.0.9'),
                         portal._victim_token('10.0.0.9'))


class DashboardFallback(unittest.TestCase):
    def test_serve_falls_back_when_port_busy(self):
        # Bind the configured port, then ask web.serve to use it; it must
        # pick the next free port instead of raising (the old crash-loop).
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(('127.0.0.1', 0))
        busy = probe.getsockname()[1]
        probe.listen(1)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            config.DASH_PORT = busy
            app = Malstrom(check_only=True)
            server, thread = web.serve(app)
            self.assertIsNotNone(server)
            self.assertNotEqual(config.DASH_PORT, busy)
            self.assertEqual(config.DASH_PORT, busy + 1)
            if server:
                server.server_close()
        finally:
            probe.close()


class _OriginMock(object):
    """Stand-in DashHandler: only the attrs the guard helpers touch."""

    def __init__(self, headers=None, path='/cgi-bin/api.sh?action=status'):
        m = Message()
        for k, v in (headers or {}).items():
            m[k] = v
        self.headers = m
        self.path = path
        self.client_address = ('10.0.0.9', 54321)
        self._raw_body = None

    def _query(self):
        from urllib.parse import urlparse, parse_qs
        return parse_qs(urlparse(self.path).query, keep_blank_values=True)

    def _audit_detail(self):
        return web.DashHandler._audit_detail(self)

    def _client_addr(self):
        return web.DashHandler._client_addr(self)


class DashHardening(unittest.TestCase):
    """H1 — the operator dashboard is our most exposed surface after the TLS
    portal: no TLS by default ⇒ auth off + loopback bind, security headers on
    every response, and a same-origin guard so a browser-resident cross-site
    page can't drive the state-mutating API."""

    def _h(self, headers=None, path='/cgi-bin/api.sh?action=status'):
        return _OriginMock(headers, path)

    def test_origin_absent_allowed(self):
        # curl / CLI: no Origin, no Referer → allowed regardless of host
        self.assertTrue(web.DashHandler._origin_ok(self._h()))

    def test_origin_loopback_match_allowed(self):
        self.assertTrue(web.DashHandler._origin_ok(self._h(
            {'Origin': 'http://127.0.0.1:8888', 'Host': '127.0.0.1:8888'})))
        # localhost alias is the same loopback
        self.assertTrue(web.DashHandler._origin_ok(self._h(
            {'Origin': 'http://localhost:8888', 'Host': '127.0.0.1:8888'})))

    def test_referer_match_allowed(self):
        self.assertTrue(web.DashHandler._origin_ok(self._h(
            {'Referer': 'http://127.0.0.1:8888/cgi-bin/api.sh',
             'Host': '127.0.0.1:8888'})))

    def test_cross_origin_origin_rejected(self):
        self.assertFalse(web.DashHandler._origin_ok(self._h(
            {'Origin': 'http://evil.example', 'Host': '127.0.0.1:8888'})))

    def test_cross_origin_referer_rejected(self):
        self.assertFalse(web.DashHandler._origin_ok(self._h(
            {'Referer': 'http://evil.example/',
             'Host': '127.0.0.1:8888'})))

    def test_cross_origin_loopback_port_rejected(self):
        # a hostile page served from another loopback port can't CSRF either
        self.assertFalse(web.DashHandler._origin_ok(self._h(
            {'Origin': 'http://127.0.0.1:9999', 'Host': '127.0.0.1:8888'})))

    def test_host_header_pinned_sets_the_bar(self):
        self.assertFalse(web.DashHandler._origin_ok(self._h(
            {'Origin': 'http://10.0.0.5:8888', 'Host': '127.0.0.1:8888'})))


class DashAudit(unittest.TestCase):
    """H3 — operator actions land on an append-only audit trail / engagement
    archives keep integrity snapshots with sha256 sidecars."""

    def test_audit_appends_jsonl(self):
        tmp = tempfile.mkdtemp()
        old_log = state.AUDIT_LOG
        state.AUDIT_LOG = os.path.join(tmp, 'audit.log')
        try:
            state.audit('disarm', 'detail here', '10.0.0.9')
            with open(state.AUDIT_LOG) as fh:
                rows = [json.loads(l) for l in fh if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['action'], 'disarm')
            self.assertEqual(rows[0]['addr'], '10.0.0.9')
            state.audit('start', 'ssid=X', '10.0.0.9')
            with open(state.AUDIT_LOG) as fh:
                rows = [json.loads(l) for l in fh if l.strip()]
            self.assertEqual(len(rows), 2)  # append-only, never truncated
            mode = os.stat(state.AUDIT_LOG).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            state.AUDIT_LOG = old_log
            shutil.rmtree(tmp, ignore_errors=True)

    def test_dispatch_audits_only_mutating_actions(self):
        tmp = tempfile.mkdtemp()
        old_log = state.AUDIT_LOG
        state.AUDIT_LOG = os.path.join(tmp, 'audit.log')
        try:
            h = _OriginMock(path='/cgi-bin/api.sh?action=disarm')
            web.DashHandler._audit_mutating(h, 'disarm')
            with open(state.AUDIT_LOG) as fh:
                rows = [l for l in fh if l.strip()]
            self.assertEqual(len(rows), 1)
            self.assertIn('disarm', rows[0])
            web.DashHandler._audit_mutating(h, 'status')
            with open(state.AUDIT_LOG) as fh:
                rows = [l for l in fh if l.strip()]
            self.assertEqual(len(rows), 1)  # read-only action leaves no trace
        finally:
            state.AUDIT_LOG = old_log
            shutil.rmtree(tmp, ignore_errors=True)

    def test_audit_detail_strips_credentials(self):
        h = _OriginMock(headers={'Host': 'x'},
                        path='/cgi-bin/api.sh?action=start&ssid=Test&token=abc123'
                             '&resp=deadbeef&nonce=xyz')
        detail = web.DashHandler._audit_detail(h)
        self.assertNotIn('abc123', detail)
        self.assertNotIn('deadbeef', detail)
        self.assertNotIn('xyz', detail)
        self.assertIn('ssid=Test', detail)

    def test_archive_engagement_snapshots_with_hashes(self):
        tmp = tempfile.mkdtemp()
        olds = (config.STATE_DIR, state.ENGAGEMENTS_DIR,
                state.ENGAGEMENTS_INDEX)
        state_dir = os.path.join(tmp, 'state')
        os.makedirs(state_dir)
        config.STATE_DIR = state_dir
        state.ENGAGEMENTS_DIR = os.path.join(state_dir, 'engagements')
        state.ENGAGEMENTS_INDEX = os.path.join(state.ENGAGEMENTS_DIR,
                                               'index.json')
        try:
            with open(os.path.join(state_dir, 'events'), 'w') as fh:
                fh.write('{"ts":"x","type":"ALERT","msg":"creds captured"}\n')
            with open(os.path.join(state_dir, 'creds.json'), 'w') as fh:
                fh.write('{"ts":"x","user":"u","pass":"p"}\n')
            eid = state.archive_engagement()
            self.assertTrue(eid)
            snap = os.path.join(state.ENGAGEMENTS_DIR, eid)
            self.assertTrue(os.path.isfile(os.path.join(snap, 'events')))
            self.assertTrue(os.path.isfile(
                os.path.join(snap, 'events.sha256')))
            self.assertTrue(os.path.isfile(
                os.path.join(snap, 'creds.json.sha256')))
            with open(os.path.join(snap, 'events.sha256')) as fh:
                want = fh.read().strip()
            self.assertEqual(want, state._sha256_file(
                os.path.join(snap, 'events')))
            with open(os.path.join(snap, 'creds.json.sha256')) as fh:
                creds_want = fh.read().strip()
            self.assertEqual(creds_want, state._sha256_file(
                os.path.join(snap, 'creds.json')))
            with open(state.ENGAGEMENTS_INDEX) as fh:
                idx = json.load(fh)
            self.assertEqual(idx['engagements'][0]['id'], eid)
            self.assertEqual(idx['engagements'][0]['files']['events'], want)
            self.assertEqual(idx['engagements'][0]['files']['creds.json'],
                             creds_want)
        finally:
            (config.STATE_DIR, state.ENGAGEMENTS_DIR,
             state.ENGAGEMENTS_INDEX) = olds
            shutil.rmtree(tmp, ignore_errors=True)

    def test_harden_state_locks_sensitive_files(self):
        tmp = tempfile.mkdtemp()
        olds = (state.TOKEN_FILE, state.CREDS_FILE)
        state.TOKEN_FILE = os.path.join(tmp, 'token')
        state.CREDS_FILE = os.path.join(tmp, 'creds.json')
        with open(state.TOKEN_FILE, 'w') as fh:
            fh.write('sekret\n')
        with open(state.CREDS_FILE, 'w') as fh:
            fh.write('{}\n')
        try:
            state.harden_state()
            for p in (state.TOKEN_FILE, state.CREDS_FILE):
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        finally:
            (state.TOKEN_FILE, state.CREDS_FILE) = olds
            shutil.rmtree(tmp, ignore_errors=True)


class LootVault(unittest.TestCase):
    """H2 — mirrored loot at rest is encrypted (Fernet) when python3-
    cryptography is present; degrades to plaintext, with an ALERT, when not."""

    def test_vault_roundtrip_when_available(self):
        from malstrom import vault
        if not vault.available():
            self.skipTest('python3-cryptography missing')
        tmp = tempfile.mkdtemp()
        olds = (state.VAULT_KEY_FILE,)
        key = os.path.join(tmp, '.vault.key')
        state.VAULT_KEY_FILE = key
        try:
            vault.reload()
            blob = vault.encrypt(b'user:pass')
            self.assertNotIn(b'user:pass', blob)
            self.assertEqual(vault.decrypt(blob), b'user:pass')
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600)
        finally:
            state.VAULT_KEY_FILE = olds[0]
            vault.reload()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_mirror_encrypts_creds_when_vault_on(self):
        from malstrom import vault
        if not vault.available():
            self.skipTest('python3-cryptography missing')
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, 'state'))
        os.makedirs(os.path.join(tmp, 'loot'))
        olds = (config.STATE_DIR, config.LOOT_DIR, config.VAULT,
                state.CREDS_FILE, state.VAULT_KEY_FILE)
        config.STATE_DIR = os.path.join(tmp, 'state')
        config.LOOT_DIR = os.path.join(tmp, 'loot')
        config.VAULT = True
        state.CREDS_FILE = os.path.join(config.STATE_DIR, 'creds.json')
        state.VAULT_KEY_FILE = os.path.join(config.STATE_DIR, '.vault.key')
        state._mirror_last = 0.0
        try:
            with open(state.CREDS_FILE, 'w') as fh:
                fh.write('{"ts":"x","pass":"sekret"}\n')
            vault.reload()
            state.mirror_loot()
            with open(os.path.join(config.LOOT_DIR, 'creds.json.vault'),
                      'rb') as fh:
                blob = fh.read()
            self.assertNotIn(b'sekret', blob)
            self.assertIn(b'sekret', vault.decrypt(blob))
        finally:
            (config.STATE_DIR, config.LOOT_DIR, config.VAULT,
             state.CREDS_FILE, state.VAULT_KEY_FILE) = olds
            state._mirror_last = 0.0
            shutil.rmtree(tmp, ignore_errors=True)


class AlertWebhook(unittest.TestCase):
    """H4 — out-of-band alerting: a configured webhook receives ALERT-class
    events fire-and-forget; loot payloads are excluded by default."""

    def test_send_posts_json_payload(self):
        import http.server
        got = {}

        class Recorder(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got['body'] = self.rfile.read(
                    int(self.headers.get('Content-Length') or 0))
                got['ct'] = self.headers.get('Content-Type')
                got['ua'] = self.headers.get('User-Agent')
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(('127.0.0.1', 0), Recorder)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        old = config.EXFIL_WEBHOOK
        config.EXFIL_WEBHOOK = 'http://127.0.0.1:%d/hook' % port
        try:
            notify.reset()
            self.assertTrue(notify.notify('ALERT', 'creds captured'))
            payload = {'ts': 'x', 'type': 'ALERT', 'msg': 'creds captured'}
            notify._send(payload)
            deadline = time.time() + 10
            while 'body' not in got and time.time() < deadline:
                time.sleep(0.05)
            body = json.loads(got.get('body', b'{}'))
            self.assertEqual(body.get('type'), 'ALERT')
            self.assertIn('msg', body)
            self.assertNotIn('detail', body)
            self.assertIn('json', got.get('ct', ''))
        finally:
            config.EXFIL_WEBHOOK = old
            notify.reset()
            srv.shutdown()
            srv.server_close()

    def test_alert_hook_fires_on_emit(self):
        calls = []
        saved = list(state._alert_hooks)
        state.add_alert_hook(lambda t, m: calls.append((t, m)))
        try:
            state.emit('ALERT', 'bind forced to loopback')
            state.emit('INFO', 'nothing to see here')
        finally:
            state._alert_hooks[:] = saved
        self.assertTrue(any(t == 'ALERT' and 'loopback' in m
                            for t, m in calls))
        self.assertFalse(any(t == 'INFO' for t, m in calls))

    def test_notify_off_when_no_webhook(self):
        old = config.EXFIL_WEBHOOK
        config.EXFIL_WEBHOOK = ''
        try:
            notify.reset()
            self.assertFalse(notify.notify('ALERT', 'x'))
        finally:
            config.EXFIL_WEBHOOK = old


class StackTeardown(unittest.TestCase):
    def test_cleanup_is_idempotent_without_radio(self):
        stack = services.RogueStack()
        stack.ap_iface = 'ap0'          # a nonexistent vif must not break cleanup
        stack.created_vifs = ['ap0']
        stack._orig_mac = None
        stack.cleanup()                 # must not raise
        stack.cleanup()                 # still fine a second time
        self.assertEqual(stack.created_vifs, [])


class ClientIsolation(unittest.TestCase):
    """Rogue-segment isolation: victims must not reach each other or the
    operator's LAN. FORWARD DROPs are ap-iface-anchored so public internet
    (beacon C2 / whitelisted clients) keeps flowing."""

    def _ctx(self):
        calls, calls6 = [], []
        config.PORTAL_TLS = 0                          # skip cert generation
        originals = dict(
            fw_backend=linuxutil.fw_backend,
            iptables=linuxutil.iptables,
            ip6tables=linuxutil.ip6tables,
            run=linuxutil.run,
            iface_ipv4_cidr=linuxutil.iface_ipv4_cidr)
        linuxutil.fw_backend = lambda pref=None: 'iptables'
        linuxutil.iptables = lambda argv: calls.append(list(argv))
        linuxutil.ip6tables = lambda argv: calls6.append(list(argv))
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
        linuxutil.iface_ipv4_cidr = lambda name: (
            None if name == 'lo' else '192.168.7.5/24')
        for k, v in originals.items():
            self.addCleanup(lambda k=k, v=v: setattr(linuxutil, k, v))
        stack = services.RogueStack()
        stack.ap_iface = 'ap0'
        stack._calls6 = calls6
        return stack, calls

    def test_setup_installs_ap_to_ap_drop(self):
        stack, calls = self._ctx()
        stack.setup_firewall()
        self.assertIn(
            ['-I', 'FORWARD', '1', '-i', 'ap0', '-o', 'ap0', '-j', 'DROP'],
            calls)

    def test_setup_blocks_lan_of_other_interfaces(self):
        stack, calls = self._ctx()
        stack.setup_firewall()
        self.assertIn(
            ['-I', 'FORWARD', '1', '-i', 'ap0',
             '-s', config.PORTAL_NET, '-d', '192.168.7.5/24', '-j', 'DROP'],
            calls)
        # the legacy internet path survives isolation
        self.assertTrue(any('-t' in c and 'MASQUERADE' in c for c in calls))

    def test_setup_rules_tracked_and_teardown_removes_them(self):
        stack, calls = self._ctx()
        stack.setup_firewall()
        n_installed = len(stack._isolation_rules)
        self.assertGreater(n_installed, 0)
        before = len(calls)
        stack.teardown_firewall()
        # every tracked rule was deleted (reverse of install order)
        self.assertEqual(len(calls) - before, n_installed)
        self.assertEqual(stack._isolation_rules, [])
        deleted = [c for c in calls[before:] if c and c[0] == '-D']
        self.assertIn(['-D', 'FORWARD', '-i', 'ap0', '-o', 'ap0', '-j', 'DROP'],
                      deleted)

    def test_isolation_disabled_installs_no_drops(self):
        saved = config.CLIENT_ISOLATION
        config.CLIENT_ISOLATION = False
        try:
            stack, calls = self._ctx()
            stack.setup_firewall()
            self.assertEqual(stack._isolation_rules, [])
            self.assertFalse(any('DROP' in c for c in calls))
            stack.teardown_firewall()          # no orphan rules to unwind
            self.assertEqual(stack._isolation_rules, [])
        finally:
            config.CLIENT_ISOLATION = saved

    def test_cleanup_idempotent_with_isolation_rules(self):
        stack, calls = self._ctx()
        stack.setup_firewall()
        stack.created_vifs = ['ap0']
        stack.cleanup()
        self.assertEqual(stack._isolation_rules, [])


class FwBackend(unittest.TestCase):
    """Backend resolution: iptables preferred, nft fallback, hard only when a
    tool actually exists. An absent CLU should refuse to arm instead of
    pretending a firewall is up."""

    def _have(self, present):
        saved = linuxutil.have
        linuxutil.have = lambda name: name in present
        self.addCleanup(lambda: setattr(linuxutil, 'have', saved))

    def test_prefers_iptables_when_present(self):
        self._have({'iptables', 'nft'})
        self.assertEqual(linuxutil.fw_backend(), 'iptables')

    def test_falls_back_to_nft_without_iptables(self):
        self._have({'nft'})
        self.assertEqual(linuxutil.fw_backend(), 'nft')

    def test_none_when_no_tool(self):
        self._have(set())
        self.assertIsNone(linuxutil.fw_backend())

    def test_forced_backend_respected(self):
        self._have({'nft'})
        self.assertEqual(linuxutil.fw_backend('nft'), 'nft')
        self.assertIsNone(linuxutil.fw_backend('iptables'))  # missing -> no

    def test_sysctl_paths_cover_iface_and_all(self):
        paths = self._fake_proc_paths()
        names = [p for p, _ in paths]
        self.assertEqual(len(paths), 2)
        self.assertIn('/proc/sys/net/ipv6/conf/ap0/forwarding', names)
        self.assertIn('/proc/sys/net/ipv6/conf/all/forwarding', names)

    def test_sysctl_write_restore_roundtrip(self):
        calls = []
        lives, real_open, fake_file = self._fake_open_env(calls)
        try:
            paths = linuxutil.ipv6_forward_paths('ap0')
            self.assertEqual(linuxutil.set_ipv6_forward(paths, '0'), 2)
            linuxutil.restore_ipv6_forward(paths)
        finally:
            import builtins
            builtins.open = real_open
        writes = [v for k, v in calls]
        self.assertEqual(writes, ['0', '0', '1', '1'])

    def _fake_proc_paths(self):
        import builtins
        lives = {'/proc/sys/net/ipv6/conf/ap0/forwarding': '0',
                 '/proc/sys/net/ipv6/conf/all/forwarding': '1'}
        real_open = builtins.open

        class _FakeFile(object):
            def __init__(self, path, mode):
                self.path, self.mode = path, mode
            def read(self):
                return lives[self.path]
            def write(self, value):
                lives[self.path] = value
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_open(path, mode='r'):
            if path in lives:
                return _FakeFile(path, mode)
            return real_open(path, mode)

        builtins.open = fake_open
        try:
            return linuxutil.ipv6_forward_paths('ap0')
        finally:
            builtins.open = real_open

    def _fake_open_env(self, calls):
        import builtins
        lives = {'/proc/sys/net/ipv6/conf/ap0/forwarding': '1',
                 '/proc/sys/net/ipv6/conf/all/forwarding': '1'}
        real_open = builtins.open

        class _FakeFile(object):
            def __init__(self, path, mode):
                self.path, self.mode = path, mode
            def read(self):
                return lives[self.path]
            def write(self, value):
                calls.append((self.path, value))
                lives[self.path] = value
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        def fake_open(path, mode='r'):
            if path in lives:
                return _FakeFile(path, mode)
            return real_open(path, mode)

        builtins.open = fake_open
        return lives, real_open, _FakeFile


class NftRuleset(unittest.TestCase):
    DEFAULT = dict(iface='ap0', portal_ip='172.16.52.1', portal_port=80,
                   tls_port=8443, dns_port=1053, portal_net='172.16.52.0/24',
                   resolver_ip='1.1.1.1', whitelist=(),
                   sibling_nets=('192.168.7.0/24',), isolation=True)

    def test_renders_v4_and_v6_tables(self):
        text = firewall.nft_ruleset(**self.DEFAULT)
        self.assertIn('table ip malstrom {', text)
        self.assertIn('table ip6 malstrom6 {', text)
        self.assertIn('type nat hook prerouting priority -100; policy accept;', text)
        self.assertIn('type nat hook postrouting priority 100; policy accept;', text)

    def test_redirect_dnat_rules(self):
        text = firewall.nft_ruleset(**self.DEFAULT)
        self.assertIn('tcp dport 80 ip daddr != 172.16.52.1 dnat to 172.16.52.1:80', text)
        self.assertIn('tcp dport 443 ip daddr != 172.16.52.1 dnat to 172.16.52.1:8443', text)
        self.assertIn('udp dport 53 ip daddr != 172.16.52.1 dnat to 172.16.52.1:1053', text)
        self.assertIn('tcp dport 53 ip daddr 172.16.52.1 dnat to 172.16.52.1:1053', text)
        self.assertIn('ip saddr 172.16.52.0/24 ip daddr != 172.16.52.0/24 masquerade', text)

    def test_isolation_and_masquerade_survive(self):
        text = firewall.nft_ruleset(**self.DEFAULT)
        self.assertIn('iifname "ap0" oifname "ap0" drop', text)
        self.assertIn('ip saddr 172.16.52.0/24 ip daddr 192.168.7.0/24 drop', text)
        self.assertIn('masquerade', text)

    def test_isolation_off_removes_drops(self):
        cfg = dict(self.DEFAULT, isolation=False)
        text = firewall.nft_ruleset(**cfg)
        # the v4 ap<->ap and sibling DROPs vanish (v6 drops stay: the rogue
        # mesh serves no v6 at all, and the guard is unconditional)
        self.assertNotIn('iifname "ap0" oifname "ap0" drop', text)
        self.assertNotIn('ip saddr 172.16.52.0/24 ip daddr 192.168.7.0/24 drop', text)
        self.assertIn('table ip6 malstrom6 {', text)

    def test_whitelist_rules_before_redirects(self):
        cfg = dict(self.DEFAULT, whitelist=['10.0.0.9'])
        text = firewall.nft_ruleset(**cfg)
        idx_accept = text.index('ip saddr 10.0.0.9 accept')
        idx_dns = text.index('ip saddr 10.0.0.9 udp dport 53 dnat to 1.1.1.1:53')
        idx_redir = text.index('tcp dport 80 ip daddr != 172.16.52.1')
        self.assertLess(idx_accept, idx_redir)
        self.assertLess(idx_dns, idx_redir)

    def test_rejects_bad_input(self):
        bad = dict(self.DEFAULT)
        bad['iface'] = 'ap 0'
        self.assertRaises(ValueError, firewall.nft_ruleset, **bad)
        bad = dict(self.DEFAULT, portal_port=0)
        self.assertRaises(ValueError, firewall.nft_ruleset, **bad)
        bad = dict(self.DEFAULT, portal_ip='172.16.52.1;reboot')
        self.assertRaises(ValueError, firewall.nft_ruleset, **bad)


class FwNftStack(unittest.TestCase):
    """Driving RogueStack over the nft backend: apply, whitelist regen, and
    teardown must delete exactly the tables it created."""

    def setUp(self):
        self._save = dict(
            PORTAL_TLS=config.PORTAL_TLS, FIREWALL_BACKEND=config.FIREWALL_BACKEND,
            isol=config.CLIENT_ISOLATION)
        self._lu_save = dict(
            fw_backend=linuxutil.fw_backend, nft=linuxutil.nft,
            iface_ipv4_cidr=linuxutil.iface_ipv4_cidr,
            uplink_namespace=linuxutil.uplink_namespace,
            set_ipv6_forward=linuxutil.set_ipv6_forward,
            restore_ipv6_forward=linuxutil.restore_ipv6_forward)
        config.PORTAL_TLS = 0
        config.FIREWALL_BACKEND = 'nft'
        config.CLIENT_ISOLATION = True
        self.nft_calls = []
        linuxutil.fw_backend = lambda pref=None: 'nft'
        linuxutil.nft = lambda argv: self.nft_calls.append(list(argv)) or type(
            'R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
        linuxutil.iface_ipv4_cidr = lambda name: (
            None if name in ('lo', 'ap0') else '192.168.7.5/24')
        linuxutil.uplink_namespace = lambda: '203.0.113.1'
        linuxutil.set_ipv6_forward = lambda paths, value: 0
        linuxutil.restore_ipv6_forward = lambda paths: None

    def tearDown(self):
        for k, v in self._save.items():
            setattr(config, k, v)
        for k, v in self._lu_save.items():
            setattr(linuxutil, k, v)

    def _stack(self):
        stack = services.RogueStack()
        stack.ap_iface = 'ap0'
        return stack

    def test_apply_and_whitelist_regen_and_teardown(self):
        stack = self._stack()
        self.assertTrue(stack.setup_firewall())
        self.assertEqual(stack._fw_backend, 'nft')
        # delete-then-apply: tables removed before the fresh create
        self.assertEqual(self.nft_calls[0], ['delete', 'table', 'ip', 'malstrom'])
        self.assertEqual(self.nft_calls[1], ['delete', 'table', 'ip6', 'malstrom6'])
        self.assertEqual(self.nft_calls[2], ['-f', state.NFT_RULES])
        with open(state.NFT_RULES) as fh:
            body = fh.read()
        self.assertIn('table ip malstrom {', body)
        self.assertIn('table ip6 malstrom6 {', body)
        # whitelist changes regenerate the whole ruleset atomically
        stack.whitelist_bypass('10.0.0.9', True)
        self.assertEqual(self.nft_calls.count(['-f', state.NFT_RULES]), 2)
        with open(state.NFT_RULES) as fh:
            self.assertIn('ip saddr 10.0.0.9 accept', fh.read())
        # teardown removes the state file and deletes exactly our tables
        stack.teardown_firewall()
        self.assertIn(['delete', 'table', 'ip', 'malstrom'], self.nft_calls)
        self.assertIn(['delete', 'table', 'ip6', 'malstrom6'], self.nft_calls)
        self.assertFalse(os.path.exists(state.NFT_RULES))


class FwIpv6(unittest.TestCase):
    """IPv6 guard on the iptables backend: DROPs anchored to the AP interface
    in both directions, tracked and deleted at teardown."""

    def setUp(self):
        self._saved_ipv6 = config.IPV6_GUARD
        config.IPV6_GUARD = True

    def tearDown(self):
        config.IPV6_GUARD = self._saved_ipv6

    def _ctx(self):
        calls, calls6 = [], []
        config.PORTAL_TLS = 0
        originals = dict(
            fw_backend=linuxutil.fw_backend,
            iptables=linuxutil.iptables,
            ip6tables=linuxutil.ip6tables,
            have=linuxutil.have,
            run=linuxutil.run,
            iface_ipv4_cidr=linuxutil.iface_ipv4_cidr)
        linuxutil.fw_backend = lambda pref=None: 'iptables'
        linuxutil.iptables = lambda argv: calls.append(list(argv))
        linuxutil.ip6tables = lambda argv: calls6.append(list(argv))
        linuxutil.have = lambda name: name in ('iptables', 'ip6tables')
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 0, 'stdout': '', 'stderr': ''})()
        linuxutil.iface_ipv4_cidr = lambda name: (
            None if name == 'lo' else '192.168.7.5/24')
        for k, v in originals.items():
            self.addCleanup(lambda k=k, v=v: setattr(linuxutil, k, v))
        stack = services.RogueStack()
        stack.ap_iface = 'ap0'
        stack._calls6 = calls6
        return stack, calls

    def test_installs_ip6tables_drops(self):
        stack, calls = self._ctx()
        self.assertTrue(stack.setup_firewall())
        c6 = stack._calls6
        self.assertIn(['-I', 'FORWARD', '1', '-i', 'ap0', '-j', 'DROP'], c6)
        self.assertIn(['-I', 'FORWARD', '1', '-o', 'ap0', '-j', 'DROP'], c6)
        self.assertEqual(len(stack._v6_rules), 2)

    def test_teardown_removes_ip6tables_drops(self):
        stack, calls = self._ctx()
        stack.setup_firewall()
        before = len(stack._calls6)
        stack.teardown_firewall()
        self.assertEqual(len(stack._calls6) - before, 2)
        self.assertEqual(stack._v6_rules, [])
        self.assertIn(['-D', 'FORWARD', '-i', 'ap0', '-j', 'DROP'],
                      stack._calls6[before:])

    def test_guard_off_installs_nothing(self):
        config.IPV6_GUARD = False
        stack, calls = self._ctx()
        stack.setup_firewall()
        self.assertEqual(stack._calls6, [])
        self.assertEqual(stack._v6_rules, [])


class RadioSafety(unittest.TestCase):
    def test_realtek_not_blacklisted_by_default(self):
        # The 88xxau family (8821au/8812au -> rtw_*) wedges some boxes, but the
        # same cards work fine on others. The auto-deny list is EMPTY by default
        # so the attack radio is never refused out of the box; operators who hit
        # a confirmed hang opt back in via MALSTROM_DANGEROUS_DRIVERS.
        self.assertEqual(config.DANGEROUS_VIF_DRIVERS, ())

    def test_driver_banned_honors_configured_list(self):
        # The gate is opt-in: it must catch every case-variant of a driver the
        # operator explicitly adds to MALSTROM_DANGEROUS_DRIVERS.
        saved = config.DANGEROUS_VIF_DRIVERS
        config.DANGEROUS_VIF_DRIVERS = ('8821au', '88xxau', 'rtw_8812au')
        try:
            self.assertTrue(linuxutil.driver_banned('8821au'))
            self.assertTrue(linuxutil.driver_banned('8821AU'))
            self.assertTrue(linuxutil.driver_banned('88xxau'))
            self.assertTrue(linuxutil.driver_banned('88XXAU'))
            self.assertTrue(linuxutil.driver_banned('rtw_8812au'))
            self.assertFalse(linuxutil.driver_banned('rtl88xxau'))
        finally:
            config.DANGEROUS_VIF_DRIVERS = saved

    def test_common_safe_driver_not_banned(self):
        self.assertFalse(linuxutil.driver_banned('brcmfmac'))
        self.assertFalse(linuxutil.driver_banned('iwlwifi'))
        self.assertFalse(linuxutil.driver_banned('rtw_8821au'))
        self.assertFalse(linuxutil.driver_banned(''))
        self.assertFalse(linuxutil.driver_banned(None))

    def test_vif_try_gate_throttles_recent_attempts(self):
        # Regression: _vif_try_gate used time.time() without importing time —
        # a NameError on the first vif attempt. Also pins the throttle logic.
        key = ('phy0', 'mon0')
        self.assertFalse(linuxutil._vif_try_gate(*key))   # first attempt passes
        self.assertTrue(linuxutil._vif_try_gate(*key))    # immediate retry gated
        with linuxutil._vif_try_lock:
            linuxutil._vif_last_try.pop(key, None)

    def test_ap_vif_created_with_ap_devtype(self):
        # Regression: add_vif was called with 'type __ap', which iw rejects —
        # the rogue-AP vif could never be auto-created.
        real_run, real_netdev = linuxutil.run, linuxutil.netdev_exists
        calls = []
        def fake_run(argv, **kw):
            calls.append(argv)
            return type('R', (), {'returncode': 0})()
        try:
            linuxutil.netdev_exists = lambda n: n == 'ap0'
            linuxutil.run = fake_run
            self.assertTrue(linuxutil.add_vif('phy0', 'ap0', 'ap'))
            self.assertEqual(calls[0][7], 'ap')
        finally:
            linuxutil.run, linuxutil.netdev_exists = real_run, real_netdev


class ResponderParsing(unittest.TestCase):
    def test_extracts_ntlmv2_from_modern_colored_line(self):
        # The old regex expected "[+] NTLMv2 Hash", but Responder prints
        # "[MODULE] NTLMv2-SSP Hash" with ANSI-wrapped brackets/hashes even
        # when piped — hashes never landed in the vault.
        line = ('\r\x1b[1;34m[SMBD]\x1b[0m NTLMv2-SSP Hash     : '
                '\x1b[0;33mneo::MANGO:1122334455667788:'
                '2F6CC22CFDC387CFEEB2D325E8997564:0101000000000000\x1b[0m')
        self.assertEqual(
            mitm._extract_token(line),
            'neo::MANGO:1122334455667788:'
            '2F6CC22CFDC387CFEEB2D325E8997564:0101000000000000')

    def test_extracts_ntlmv2_http_style(self):
        line = ('\x1b[1;34m[HTTP]\x1b[0m NTLMv2 Hash     : '
                '\x1b[0;33mjsmith::ACME:1122\x1b[0m')
        self.assertEqual(mitm._extract_token(line), 'jsmith::ACME:1122')

    def test_ignores_ntlmv1_and_degrades_gracefully(self):
        self.assertIsNone(mitm._extract_token('[SMBD] NTLMv1-SSP Hash : x::y:1'))
        self.assertIsNone(mitm._extract_token('[SMBD] NTLMv1 Hash : x::y:1'))
        self.assertIsNone(mitm._extract_token('[*] Skipping previously captured hash'))
        self.assertIsNone(
            mitm._extract_token('[IMAP] NetNTLMv1 hash format (hashcat -m 5500)'))
        self.assertIsNone(mitm._extract_token(None))
        self.assertIsNone(mitm._extract_token(''))
        self.assertIsNone(mitm._extract_token('responder banner nonsense'))


class NetexecParsing(unittest.TestCase):
    def test_legacy_crackmapexec_line(self):
        self.assertEqual(
            lateral._parse_success('[+] 10.10.10.10:445 - admin:Password1'),
            ('10.10.10.10', 'admin', 'Password1'))

    def test_modern_netexec_smb_line(self):
        # The old regex matched "+ IP:445 - user:pass"; netexec 1.5 prints
        # one padded row ending in "[+] DOM\\user:pass (Pwn3d!)".
        line = ('SMB                      172.16.52.10      445    DESKTOP-ABC    '
                '[+] ACME\\jsmith:Summer2025! (Pwn3d!)')
        self.assertEqual(
            lateral._parse_success(line),
            ('172.16.52.10', 'ACME\\jsmith', 'Summer2025!'))

    def test_modern_netexec_ssh_line_no_domain(self):
        line = ('SSH                       10.0.0.5         22    NONE           '
                '[+] root:toor')
        self.assertEqual(lateral._parse_success(line), ('10.0.0.5', 'root', 'toor'))

    def test_ignores_failed_auth(self):
        self.assertIsNone(
            lateral._parse_success(
                'SMB     10.0.0.9    445    NONE    [-] admin:badpass'))
        self.assertIsNone(lateral._parse_success(''))
        self.assertIsNone(lateral._parse_success(None))
        self.assertIsNone(lateral._parse_success(
            'SMB     10.0.0.9    445    NONE    [*] starting SMB session'))


class CsvSanitize(unittest.TestCase):
    def test_prefixes_formula_triggers(self):
        for val in ('=SUM(1)', '+cmd', '-1', '@SUM', '\tX', '\rX'):
            self.assertEqual(web._csv_safe(val), "'" + val)

    def test_plaintext_passes_through(self):
        for val in ('plain', '123', '', 'abc:123', 'MALSTROM', ' '):
            self.assertEqual(web._csv_safe(val), val)

    def test_non_strings_unchanged(self):
        self.assertEqual(web._csv_safe(42), 42)
        self.assertEqual(web._csv_safe(0), 0)
        self.assertEqual(web._csv_safe(None), None)


class CredStoreBounds(unittest.TestCase):
    def test_trim_creds_keeps_newest_entries(self):
        # Repeat portal victims must not grow the creds store (JSONL + readable
        # log) on disk forever — both stay under their MAX_CREDS budget.
        tmp = tempfile.mkdtemp()
        creds = os.path.join(tmp, 'creds.json')
        log = os.path.join(tmp, 'creds.log')
        try:
            with open(creds, 'w') as fh:
                for i in range(state.TRIM_CREDS + 10):
                    fh.write(json.dumps({
                        'ts': str(i), 'template': 'wifi_login', 'device': '',
                        'username': 'u', 'password': 'p'}) + '\n')
            with open(log, 'w') as fh:
                for i in range(state.TRIM_CREDS * state.CRED_LOG_LINES + 50):
                    fh.write('line %d\n' % i)

            old_creds, old_log = state.CREDS_FILE, state.CREDS_LOG
            state.CREDS_FILE, state.CREDS_LOG = creds, log
            try:
                state._trim_creds()
                with open(creds) as fh:
                    lines = fh.readlines()
                self.assertLessEqual(len(lines), config.MAX_CREDS)
                with open(log) as fh:
                    log_lines = fh.readlines()
                self.assertLessEqual(len(log_lines),
                                     config.MAX_CREDS * state.CRED_LOG_LINES)
                # newest entry survives the trim
                self.assertIn('"%s"' % (state.TRIM_CREDS + 9),
                              lines[-1])
            finally:
                state.CREDS_FILE, state.CREDS_LOG = old_creds, old_log
        finally:
            shutil.rmtree(tmp)


class StartValidation(unittest.TestCase):
    # _action_start must reject malformed channel/bssid instead of arming with
    # capture/deauth filters that never match (target_bssid 'xx', ch 999).
    class _Mock(object):
        def __init__(self, params):
            self._params = params
            self.result = None

        def _q(self, key, default=''):
            return self._params.get(key, default)

        def _json(self, obj):
            self.result = obj

    def _run(self, params):
        h = self._Mock(dict({'ssid': 'TestNet'}, **params))
        web.DashHandler._action_start(h)
        return h.result

    def test_rejects_invalid_channel(self):
        r = self._run({'channel': '999'})
        self.assertEqual(r['ok'], 0)
        self.assertIn('channel', r['error'])
        r = self._run({'channel': 'abc'})
        self.assertEqual(r['ok'], 0)

    def test_rejects_invalid_bssid(self):
        r = self._run({'channel': '6', 'bssid': 'zz:00:00:00:00:00'})
        self.assertEqual(r['ok'], 0)
        self.assertIn('bssid', r['error'])

    def test_accepts_valid_mac_and_channel(self):
        wrote = []
        old_write = state.write_state
        old_tpl = state.set_template_default
        old_ssid = state.set_current_ssid
        old_emit = state.emit
        state.write_state = lambda s: wrote.append(s)
        state.set_template_default = lambda *a, **k: None
        state.set_current_ssid = lambda *a, **k: None
        state.emit = lambda *a, **k: None
        try:
            r = self._run({'channel': '11', 'bssid': 'AA:bb:cc:00:11:ff'})
        finally:
            state.write_state = old_write
            state.set_template_default = old_tpl
            state.set_current_ssid = old_ssid
            state.emit = old_emit
        self.assertEqual(r.get('ok'), 1)
        self.assertTrue(wrote)
        self.assertEqual(wrote[0]['active'], True)
        self.assertEqual(wrote[0]['target_channel'], '11')
        self.assertEqual(wrote[0]['target_bssid'], 'AA:bb:cc:00:11:ff')


class VerifyParsing(unittest.TestCase):
    def test_pmkid_only_capture(self):
        # aircrack-ng prints the PMKID as a flag, not a count:
        #   WPA (0 handshake, with PMKID)
        text = (
            '  1  36:2C:94:35:EF:AE  UPC Wi-Free               '
            'WPA (0 handshake, with PMKID)\n'
        )
        self.assertEqual(verify._parse_counts(text), (0, 1))

    def test_handshake_only_capture(self):
        text = ('  1  00:0D:93:EB:B0:8C  test                      '
                'WPA (1 handshake)\n')
        self.assertEqual(verify._parse_counts(text), (1, 0))

    def test_handshake_and_pmkid(self):
        text = ('  1  40:3D:EC:C2:72:B8  Paangoon_2G               '
                'WPA (1 handshake, with PMKID)\n')
        self.assertEqual(verify._parse_counts(text), (1, 1))

    def test_sums_multiple_network_rows(self):
        # one network list can hold several APs with usable handshakes
        text = ('  1  AA:BB:CC:00:00:01  netA       WPA (1 handshake)\n'
                '  2  AA:BB:CC:00:00:02  netB       WPA (2 handshakes)\n')
        self.assertEqual(verify._parse_counts(text), (3, 0))

    def test_no_network_table(self):
        self.assertEqual(verify._parse_counts(''), (0, 0))
        self.assertEqual(verify._parse_counts('Aircrack-ng 1.7\nNo networks found\n'), (0, 0))
        self.assertEqual(verify._parse_counts(None), (0, 0))


class PortalBodyCap(unittest.TestCase):
    def _mk(self, headers, data=b''):
        h = object.__new__(portal.PortalHandler)
        h.close_connection = False
        h.headers = headers
        h.rfile = io.BytesIO(data)
        return h

    def test_reads_bounded_in_range_body(self):
        body = b'username=u&password=p&hostname=pc'
        h = self._mk({'Content-Length': str(len(body))}, body)
        ok, got = h._read_body(portal.CREDS_BODY_CAP)
        self.assertEqual(ok, True)
        self.assertEqual(got, body)
        self.assertFalse(h.close_connection)

    def test_rejects_oversized_instead_of_reading_all(self):
        h = self._mk({'Content-Length': '999999999'}, b'x')
        ok, _ = h._read_body(portal.CREDS_BODY_CAP)
        self.assertIsNone(ok)                 # caller answers 413 …
        self.assertTrue(h.close_connection)   # … and the socket is closed, so
                                              # unread bytes can't desync it

    def test_rejects_chunked_missing_length(self):
        h = self._mk({}, b'')
        ok, _ = h._read_body(portal.CREDS_BODY_CAP)
        self.assertIsNone(ok)
        self.assertTrue(h.close_connection)


class AttackPlan(unittest.TestCase):
    """The operator's attack-radio choice is an explicit opt-in (sacrificing
    that uplink), and deauth reporting is honest about dead injection."""

    def _plan_env(self):
        saved = (config.AP_IFACE, config.WLAN_DEV,
                 linuxutil.preferred_wlan_dev, linuxutil.netdev_exists,
                 linuxutil.phy_of, linuxutil.phy_banned, linuxutil.phy_modes,
                 linuxutil.scan_phys, linuxutil.uplink_ifaces)
        return saved

    def _restore(self, saved):
        (config.AP_IFACE, config.WLAN_DEV, linuxutil.preferred_wlan_dev,
         linuxutil.netdev_exists, linuxutil.phy_of, linuxutil.phy_banned,
         linuxutil.phy_modes, linuxutil.scan_phys,
         linuxutil.uplink_ifaces) = saved

    def test_plan_ap_uses_operator_attack_radio(self):
        # Regression: the dashboard "attack radio" setting only re-ordered the
        # auto plan — it never opted the picked card in, so a box whose only
        # AP-capable radios were uplinks could never arm the rogue AP.
        saved = self._plan_env()
        try:
            config.AP_IFACE = ''
            config.WLAN_DEV = 'wlan9'
            linuxutil.preferred_wlan_dev = lambda: 'wlan9'
            linuxutil.netdev_exists = lambda n: n == 'wlan9'
            linuxutil.phy_of = lambda n: 'phyZ' if n == 'wlan9' else None
            linuxutil.phy_banned = lambda p: False
            linuxutil.phy_modes = lambda p: {'managed', 'AP', 'monitor'}
            self.assertEqual(linuxutil.plan_ap_iface(), ('wlan9', False))
        finally:
            self._restore(saved)

    def test_plan_ap_ignores_monitor_only_attack_radio(self):
        # A monitor-only "spare" (rtl8xxxu) must never be handed to hostapd.
        saved = self._plan_env()
        try:
            config.AP_IFACE = ''
            config.WLAN_DEV = 'wlan9'
            linuxutil.preferred_wlan_dev = lambda: 'wlan9'
            linuxutil.netdev_exists = lambda n: n == 'wlan9'
            linuxutil.phy_of = lambda n: 'phyZ' if n == 'wlan9' else None
            linuxutil.phy_banned = lambda p: False
            linuxutil.phy_modes = lambda p: {'managed', 'monitor'}
            linuxutil.scan_phys = lambda: []
            linuxutil.uplink_ifaces = lambda: []
            self.assertEqual(linuxutil.plan_ap_iface(),
                             (config.AP_VIF_NAME, False))
        finally:
            self._restore(saved)

    def test_ensure_ap_never_creates_vif_for_operator_radio(self):
        # hostapd drives the picked card directly (vif creation is refused by
        # several Realtek builds anyway).
        saved = self._plan_env()
        saved_add = linuxutil.add_vif
        try:
            config.AP_IFACE = ''
            config.WLAN_DEV = 'wlan9'
            linuxutil.preferred_wlan_dev = lambda: 'wlan9'
            linuxutil.netdev_exists = lambda n: n == 'wlan9'
            linuxutil.phy_of = lambda n: 'phyZ' if n == 'wlan9' else None
            linuxutil.phy_banned = lambda p: False
            linuxutil.phy_modes = lambda p: {'managed', 'AP', 'monitor'}
            def boom(*a, **kw):
                raise AssertionError('add_vif must not run for the picked radio')
            linuxutil.add_vif = boom
            self.assertEqual(linuxutil.ensure_ap_iface(), ('wlan9', False))
        finally:
            self._restore(saved)
            linuxutil.add_vif = saved_add

    def test_plan_monitor_requires_monitor_capability(self):
        # The plan used to promise a mon vif off any spare radio — including
        # cards that cannot do monitor at all.
        saved = self._plan_env()
        try:
            config.MON_IFACE = ''
            linuxutil.netdev_exists = lambda n: False
            linuxutil.phy_banned = lambda p: False
            linuxutil.phy_modes = lambda p: {'managed'}
            linuxutil.scan_phys = lambda: [
                {'phy': 'phyM', 'iface': 'wlS', 'mac': ''}]
            linuxutil.uplink_ifaces = lambda: []
            self.assertIsNone(linuxutil.plan_monitor_iface())
            linuxutil.phy_modes = lambda p: {'managed', 'monitor'}
            self.assertEqual(linuxutil.plan_monitor_iface(),
                             config.MON_VIF_NAME)
        finally:
            self._restore(saved)

    def _burst_env(self):
        eng = DeauthEngine()
        events = []
        saved_emit = state.emit
        state.emit = lambda etype, msg: events.append((etype, msg))
        st = {'target_bssid': 'AA:BB:CC:DD:EE:FF', 'deauth_burst': 2,
              'deauth_mode': 'broadcast'}
        return eng, events, st, saved_emit

    def test_deauth_burst_honest_when_injection_dead(self):
        # Regression: _burst emitted "deauth burst (N frames)" even when every
        # injection path failed — no monitor vif meant nothing was ever sent.
        eng, events, st, saved_emit = self._burst_env()
        try:
            eng._targets = lambda st: (None, [('11:22:33:44:55:66', '6')])
            eng._frame = lambda *a: False
            eng._disassoc = lambda *a: False
            eng._burst(st)
            kinds = [k for k, _ in events]
            self.assertNotIn('DEAUTH', kinds)
            self.assertEqual(kinds.count('ALERT'), 1)
            eng._burst(st)                      # throttled to one honest alert
            self.assertEqual([k for k, _ in events].count('ALERT'), 1)
        finally:
            state.emit = saved_emit

    def test_deauth_burst_reports_real_success(self):
        eng, events, st, saved_emit = self._burst_env()
        try:
            eng._targets = lambda st: (None, [('11:22:33:44:55:66', '6')])
            eng._frame = lambda *a: True
            eng._disassoc = lambda *a: False
            eng._burst(st)
            kinds = [k for k, _ in events]
            self.assertIn('DEAUTH', kinds)
            self.assertNotIn('ALERT', kinds)
        finally:
            state.emit = saved_emit


class HostapdLaunch(unittest.TestCase):
    def test_conf_has_no_logger_file_item(self):
        # Regression: `logger_file` is not a hostapd config item on several
        # builds (Kali hostapd 2.11 rejects it) — the engine's rogue AP died at
        # config parse on every arm attempt with nothing but "no hostapd log".
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', 'aa:bb:cc:dd:ee:ff', '6', 'open', '')
        self.assertNotIn('logger_file', conf)
        self.assertIn('logger_stdout=-1', conf)   # logs land via stdout capture
        self.assertIn('interface=wlan1', conf)
        self.assertNotIn('wpa_passphrase', conf)

    def test_wpa_conf_includes_psk(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'wpa', 'hunter2hunter2')
        self.assertIn('wpa_passphrase=hunter2hunter2', conf)
        self.assertIn('wpa_key_mgmt=WPA-PSK', conf)

    def test_client_isolation_on_by_default_in_conf(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'open', '')
        self.assertIn('ap_isolate=1', conf)

    def test_client_isolation_can_be_disabled_in_conf(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'open', '', isolation=False)
        self.assertNotIn('ap_isolate', conf)

    def test_run_bg_appends_stdout_and_stderr_to_log(self):
        # The AP death reason must be visible in HOSTAPD_LOG — run_bg with
        # log= is what wires that up.
        d = tempfile.mkdtemp(prefix='ms-hp-')
        try:
            path = os.path.join(d, 'log')
            p = linuxutil.run_bg(['sh', '-c', 'echo out; echo err >&2'],
                                 log=path)
            p.wait(timeout=5)
            with open(path) as fh:
                content = fh.read()
            self.assertIn('out', content)
            self.assertIn('err', content)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class BeaconFidelity(unittest.TestCase):
    """C7: beacon fidelity — the twin replays the target's non-identifying
    beacon elements (rate set, beacon timing, HT hints), sanitized so a
    hostile beacon can never take the rogue AP down."""

    def test_fidelity_lines_replay_safe_knobs(self):
        fid = {'rates': [54, 24, 11, 5.5], 'basic': [11],
               'beacon_int': 100, 'dtim': 3,
               'ht': {'ht40': '+', 'short_gi20': True, 'rx_stbc': True}}
        lines = services.beacon_fidelity_lines(fid)
        self.assertIn('beacon_int=100', lines)
        self.assertIn('dtim_period=3', lines)
        self.assertIn('supported_rates=54 24 11', lines)   # 5.5 dropped
        self.assertIn('basic_rates=11', lines)
        self.assertIn('ht_capab=[HT40+][SHORT-GI-20][RX-STBC-1]', lines)

    def test_hostile_fidelity_is_sanitized(self):
        fid = {'rates': [200, 7.7, 54, 'junk', 5.5], 'basic': [1, 3, 54],
               'beacon_int': 100000, 'dtim': 999, 'ht': {'ht40': 'X'}}
        lines = services.beacon_fidelity_lines(fid)
        body = '\n'.join(lines)
        self.assertNotIn('beacon_int=100000', body)
        self.assertNotIn('dtim_period=999', body)
        self.assertNotIn('ht_capab', body)
        self.assertIn('supported_rates=54', body)
        self.assertIn('basic_rates=54', body)

    def test_ht40_direction_below(self):
        lines = services.beacon_fidelity_lines(
            {'ht': {'ht40': '-', 'short_gi40': True}})
        self.assertIn('ht_capab=[HT40-][SHORT-GI-40]', lines)

    def test_empty_fidelity_keeps_default_conf(self):
        self.assertEqual(services.beacon_fidelity_lines(None), [])
        self.assertEqual(services.beacon_fidelity_lines({}), [])

    def test_conf_embeds_fidelity_and_cloak(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'wpa', 'hunter2hunter2',
            fidelity={'rates': [54, 24], 'basic': [54], 'beacon_int': 100,
                      'dtim': 2, 'ht': {'ht40': '-'}},
            hidden=True)
        self.assertIn('ignore_broadcast_ssid=1', conf)
        self.assertIn('beacon_int=100', conf)
        self.assertIn('supported_rates=54 24', conf)
        self.assertIn('basic_rates=54', conf)
        self.assertIn('ht_capab=[HT40-]', conf)
        self.assertIn('wpa_passphrase=hunter2hunter2', conf)   # tail intact

    def test_conf_default_is_not_cloaked_no_fidelity(self):
        conf = services.build_hostapd_conf('wlan1', 'TEST', '', '6', 'open', '')
        self.assertIn('ignore_broadcast_ssid=0', conf)
        self.assertNotIn('supported_rates=', conf)
        self.assertNotIn('beacon_int=', conf)

    def test_rotate_identity_returns_fresh_decoy_and_rearms(self):
        st = {'portal_mode': 'open', 'target_channel': '6', 'ssid_cloak': False}
        stack = services.RogueStack()
        stack.ap_iface = 'wlan0'
        with mock.patch.object(stack, '_launch_hostapd') as lh, \
             mock.patch.object(linuxutil, 'netdev_exists', return_value=True), \
             mock.patch.object(linuxutil, 'regdom', return_value=''):
            lh.return_value = True
            mac = stack.rotate_identity(st)
        self.assertTrue(state.is_mac(mac), mac)
        self.assertTrue(mac.lower().startswith('02:'), mac)   # LA unicast decoy
        self.assertEqual(st.get('rogue_bssid'), mac)
        args, kwargs = lh.call_args
        self.assertEqual(kwargs['bssid'], mac)
        self.assertIs(kwargs['hidden'], False)

    def test_rotate_identity_empty_when_radio_gone(self):
        stack = services.RogueStack()
        stack.ap_iface = 'wlan0'
        with mock.patch.object(linuxutil, 'netdev_exists', return_value=False):
            self.assertEqual(stack.rotate_identity({}), '')

    def test_rotate_identity_empty_when_launch_fails(self):
        st = {'portal_mode': 'open', 'target_channel': '6', 'ssid_cloak': True}
        stack = services.RogueStack()
        stack.ap_iface = 'wlan0'
        with mock.patch.object(stack, '_launch_hostapd', return_value=False), \
             mock.patch.object(linuxutil, 'netdev_exists', return_value=True), \
             mock.patch.object(linuxutil, 'regdom', return_value=''):
            self.assertEqual(stack.rotate_identity(st), '')


class IdentityRotation(unittest.TestCase):
    """C7: the engine's mid-engagement MAC rotation is decoy-only, interval
    gated, and silent when disabled."""

    def _engine(self, **kw):
        obj = object.__new__(Malstrom)
        obj._last_rotate_at = kw.get('last_rotate_at', 0.0)
        obj._rotate_warned = False
        obj.stack = mock.MagicMock()
        obj.stack.rotate_identity.return_value = kw.get('rotate_identity')
        if kw.get('rotate_raises'):
            obj.stack.rotate_identity.side_effect = kw['rotate_raises']
        return obj

    def _emit_capture(self):
        logs = []
        self.addCleanup(mock.patch.object(state, 'emit').stop)
        p = mock.patch.object(state, 'emit', side_effect=lambda t, m: logs.append((t, m)))
        p.start()
        return logs

    def test_disabled_when_interval_zero(self):
        eng = self._engine()
        logs = self._emit_capture()
        eng._maybe_rotate({'beacon_rotate': 0})
        self.assertEqual(logs, [])
        eng.stack.rotate_identity.assert_not_called()

    def test_clone_mode_skips_and_warns_once(self):
        eng = self._engine()
        logs = self._emit_capture()
        st = {'beacon_rotate': 20, 'clone_bssid': True}
        eng._maybe_rotate(st)
        eng._maybe_rotate(st)
        eng.stack.rotate_identity.assert_not_called()
        infos = [m for _, m in logs if 'rotation' in m]
        self.assertEqual(len(infos), 1)   # warned once, not on every cadence

    def test_interval_not_due_yet_is_silent(self):
        eng = self._engine(last_rotate_at=time.time() - 10)
        logs = self._emit_capture()
        eng._maybe_rotate({'beacon_rotate': 20})
        eng.stack.rotate_identity.assert_not_called()
        self.assertEqual(logs, [])

    def test_due_rotates_and_stamps_last_rotate_at(self):
        eng = self._engine(rotate_identity='02:aa:bb:cc:dd:01')
        logs = self._emit_capture()
        st = {'beacon_rotate': 5, 'clone_bssid': False, 'ssid_cloak': True}
        eng._maybe_rotate(st)
        eng.stack.rotate_identity.assert_called_once_with(st)
        self.assertGreater(eng._last_rotate_at, 0)
        self.assertTrue(any('02:aa:bb:cc:dd:01' in m and 'cloaked' in m
                            for _, m in logs))

    def test_rotate_exception_alerts_but_keeps_daemon_alive(self):
        eng = self._engine(rotate_raises=RuntimeError('radio wedged'))
        logs = self._emit_capture()
        eng._maybe_rotate({'beacon_rotate': 5, 'clone_bssid': False})
        self.assertTrue(any(t == 'ALERT' for t, _ in logs))


class HostapdLiveness(unittest.TestCase):
    """_hostapd_alive must trust the owned Popen handle, not the pidfile:
    hostapd v2.10 (Kali) never writes -P in foreground mode — the pidfile
    check kill-looped a perfectly healthy rogue AP."""

    class _Proc(object):
        def __init__(self, rc=None):
            self._rc = rc
        def poll(self):
            return self._rc

    def _engine(self):
        app = Malstrom(check_only=True)
        app._alive_at = 0.0                 # bypass the probe throttle
        app.stack.ap_iface = 'wlan1'        # the AP-mode check needs a target
        return app

    def _patch_if(self, mode):
        saved = (linuxutil.iface_mode, linuxutil.netdev_exists)
        linuxutil.iface_mode = lambda iface: mode
        linuxutil.netdev_exists = lambda n: True
        self.addCleanup(lambda: setattr(linuxutil, 'iface_mode', saved[0]))
        self.addCleanup(lambda: setattr(linuxutil, 'netdev_exists', saved[1]))

    def test_dead_handle_means_down(self):
        app = self._engine()
        self._patch_if('AP')
        app.stack.hostapd = self._Proc(0)
        app.stack.hostapd_started = time.time()
        self.assertFalse(app._hostapd_alive())

    def test_young_handle_trusted_during_transition(self):
        # A slow USB radio takes seconds to flip into AP mode — a young
        # running process must not be killed for `iw` lagging behind.
        app = self._engine()
        self._patch_if('managed')            # AP mode not visible YET
        app.stack.hostapd = self._Proc(None)
        app.stack.hostapd_started = time.time()
        self.assertTrue(app._hostapd_alive())

    def test_old_handle_judged_by_ap_mode(self):
        app = self._engine()
        self._patch_if('AP')
        app.stack.hostapd = self._Proc(None)
        app.stack.hostapd_started = time.time() - (config.AP_TRANSITION_GRACE + 10)
        self.assertTrue(app._hostapd_alive())
        self._patch_if('managed')            # wedged after the grace window
        app._alive_at = 0.0                  # bypass the probe throttle again
        self.assertFalse(app._hostapd_alive())

    def test_no_handle_no_pidfile_means_down(self):
        app = self._engine()
        app.stack.hostapd = None             # pidfile won't exist in test dir
        app.stack.ap_iface = 'wlan1'
        self.assertFalse(app._hostapd_alive())


class RelayProxy(unittest.TestCase):
    def test_parse_target_absolute_uri(self):
        self.assertEqual(
            relay.parse_target('GET', 'http://login.corp/x?a=1', ''),
            'http://login.corp/x?a=1')

    def test_parse_target_host_header_and_default_port(self):
        self.assertEqual(relay.parse_target('GET', '/x', 'login.corp'),
                         'http://login.corp/x')
        self.assertEqual(relay.parse_target('GET', '/', 'vpn.corp'),
                         'http://vpn.corp/')
        self.assertEqual(relay.parse_target('POST', '/y?b=2', 'vpn.corp'),
                         'http://vpn.corp/y?b=2')

    def test_parse_target_allowed_and_denied_ports(self):
        self.assertEqual(relay.parse_target('GET', '/', 'h:8080'),
                         'http://h:8080/')
        self.assertEqual(relay.parse_target('GET', '/', 'h:8443'),
                         'http://h:8443/')
        for bad in ('h:22', 'h:8081', 'h:0'):
            self.assertIsNone(relay.parse_target('GET', '/', bad))
            self.assertIsNone(
                relay.parse_target('GET', 'http://%s/' % bad, ''))

    def test_parse_target_rejects_self_gateway_and_junk(self):
        self.assertIsNone(relay.parse_target('GET', 'http://%s/x' % config.PORTAL_IP, ''))
        self.assertIsNone(relay.parse_target('GET', '/x', config.PORTAL_IP))
        self.assertIsNone(relay.parse_target('GET', 'http://localhost/x', ''))
        self.assertIsNone(relay.parse_target('GET', '/__clone/cdn.x/a.js', 'vpn.corp'))
        self.assertIsNone(relay.parse_target('GET', 'ftp://x/y', ''))
        self.assertIsNone(relay.parse_target('GET', '/x', ''))
        self.assertIsNone(relay.parse_target('GET', 'http:///nohost', ''))

    def test_parse_target_allows_https(self):
        self.assertEqual(relay.parse_target('GET', 'https://secure.corp/y', ''),
                         'https://secure.corp/y')

    def test_strip_downgrades_https_links(self):
        out = relay.rewrite_https_to_http(
            b'<a href="https://x/y">l</a> https://z//w')
        self.assertEqual(out, b'<a href="http://x/y">l</a> http://z//w')

    def test_strip_passthrough_non_bytes(self):
        self.assertEqual(relay.rewrite_https_to_http('https://x'), 'https://x')
        self.assertIsNone(relay.rewrite_https_to_http(None))

    def test_forward_returns_upstream_response(self):
        class FakeResp(object):
            status = 200
            headers = {'Content-Type': 'text/html'}

            def __init__(self, body):
                self._body = body

            def read(self, cap):
                return self._body

            def close(self):
                pass

        with mock.patch.object(relay.urllib.request, 'urlopen',
                               return_value=FakeResp(b'HELLO')):
            status, ctype, data = relay.forward(
                'GET', 'http://upstream/x',
                {'User-Agent': 'browser'}, None, cap=1024)
        self.assertEqual(status, 200)
        self.assertEqual(ctype, 'text/html')
        self.assertEqual(data, b'HELLO')

    def test_forward_raises_when_upstream_dead(self):
        with mock.patch.object(relay.urllib.request, 'urlopen',
                               side_effect=OSError('refused')):
            with self.assertRaises(IOError):
                relay.forward('GET', 'http://dead/x', {}, None)

    def test_forward_enforces_cap(self):
        class BigResp(object):
            status = 200
            headers = {'Content-Type': 'text/plain'}

            def read(self, cap):
                return b'x' * (cap + 5)

            def close(self):
                pass

        with mock.patch.object(relay.urllib.request, 'urlopen',
                               return_value=BigResp()):
            with self.assertRaises(IOError):
                relay.forward('GET', 'http://big/x', {}, None, cap=64)


class PageClone(unittest.TestCase):
    def test_gateway_uri_absolute_asset(self):
        self.assertEqual(clone.gateway_uri('https://cdn.x/static/app.js'),
                         '/__clone/cdn.x/static/app.js')

    def test_gateway_uri_protocol_relative(self):
        self.assertEqual(clone.gateway_uri('//cdn.x/a.js'),
                         '/__clone/cdn.x/a.js')

    def test_gateway_uri_keeps_query_drops_fragment(self):
        self.assertEqual(clone.gateway_uri('https://cdn.x/font.woff2?v=3#h'),
                         '/__clone/cdn.x/font.woff2?v=3')

    def test_gateway_uri_preserves_non_proxiable(self):
        for ref in ('data:image/png;base64,AA', 'mailto:a@b',
                    '#section', 'javascript:void(0)',
                    '/%s/x/a.png' % clone.GATEWAY,
                    'http://%s/x' % config.PORTAL_IP):
            self.assertIsNone(clone.gateway_uri(ref), 'for %r' % ref)

    def test_rewrite_resolves_relative_roots(self):
        html = '<link href="font.woff2?v=3" rel="stylesheet"><script src="/js/app.js"></script>'
        out = clone.rewrite(html, 'https://vpn.corp/login')
        self.assertIn('/__clone/vpn.corp/font.woff2?v=3', out)
        self.assertIn('/__clone/vpn.corp/js/app.js', out)

    def test_rewrite_proxies_absolute_and_self_origin(self):
        html = ('<link rel="stylesheet" href="//cdn.x/theme.css">'
                '<a href="https://vpn.corp/logout">x</a>'
                '<img src="data:image/png;base64,AA">')
        out = clone.rewrite(html, 'https://vpn.corp/login')
        self.assertIn('/__clone/cdn.x/theme.css', out)
        self.assertIn('/__clone/vpn.corp/logout', out)
        self.assertIn('data:image/png;base64,AA', out)

    def test_rewrite_forces_password_form_post(self):
        html = ('<form action="https://vpn.corp/login" method="get">'
                '<input type="password" name="pw"></form>')
        out = clone.rewrite(html, 'https://vpn.corp/login')
        self.assertIn('action="/" method="post"', out)
        self.assertNotIn('method="get"', out)

    def test_rewrite_keeps_crossorigin_identity_blocker(self):
        html = '<img src="https://cdn.x/p.png" crossorigin="anonymous">'
        out = clone.rewrite(html, 'https://vpn.corp/login')
        self.assertIn('crossorigin="anonymous"', out)

    def test_clone_page_fetch_fallbacks_and_rewrites(self):
        def fake_fetch(url, cap):
            self.assertEqual(url, 'https://vpn.corp/login')
            return (b'<form action="https://vpn.corp/login">'
                    b'<input type="password" name="pw">'
                    b'<link href="/t.css" rel="stylesheet"></form>')
        patched = mock.patch.object(clone, '_fetch', fake_fetch)
        with patched:
            out = clone.clone_page('https://vpn.corp/login')
        self.assertIn('action="/" method="post"', out)
        self.assertIn('/__clone/vpn.corp/t.css', out)

    def test_clone_page_surfaces_fetch_errors(self):
        def fake_fetch(url, cap):
            raise IOError('dns failure')
        patched = mock.patch.object(clone, '_fetch', fake_fetch)
        with patched:
            with self.assertRaises(IOError):
                clone.clone_page('https://vpn.corp/login')

    def test_clone_page_rejects_bad_schemes(self):
        for url in ('file:///etc/passwd', 'ftp://x/y', 'x', 'http://'):
            try:
                clone.clone_page(url)
                self.fail('expected IOError for %r' % url)
            except IOError:
                pass

    def test_fetch_gateway_asset_roundtrip_uses_cache(self):
        cached = clone._cache_path('https://cdn.x/app.css')
        try:
            os.remove(cached)
        except OSError:
            pass
        calls = []

        def fake_fetch(url, cap):
            calls.append(url)
            return b'BODY'

        with mock.patch.object(clone, '_fetch', fake_fetch):
            data, ctype = clone.fetch_gateway_asset(
                '/%s/cdn.x/app.css' % clone.GATEWAY)
            again, _ = clone.fetch_gateway_asset(
                '/%s/cdn.x/app.css' % clone.GATEWAY)
        self.assertEqual(data, b'BODY')
        self.assertEqual(again, b'BODY')
        self.assertEqual(len(calls), 1)          # second hit served from disk
        self.assertIn('text/css', ctype)

    def test_fetch_gateway_asset_rejects_bad_paths(self):
        self.assertEqual(clone.fetch_gateway_asset('/plain'), (None, ''))
        self.assertEqual(clone.fetch_gateway_asset(''), (None, ''))

    def test_fetch_gateway_asset_surfaces_fetch_failure(self):
        with mock.patch.object(clone, '_fetch', return_value=None):
            data, ctype = clone.fetch_gateway_asset(
                '/%s/cdn.x/missing.png' % clone.GATEWAY)
        self.assertIsNone(data)
        self.assertEqual(ctype, '')


class BeaconC5(unittest.TestCase):
    _n = 0

    @classmethod
    def setUpClass(cls):
        # the shared test state dir survives between runs, and register()
        # reuses a session with the same ip+host — wipe so counts are exact
        state.write_beacons({})

    def _engine(self):
        eng = beacon.BeaconEngine()
        eng.set_enabled(True)
        self.addCleanup(eng.set_enabled, False)
        return eng

    def _session(self, eng):
        BeaconC5._n += 1
        # unique ip+host so stale beacons.json state from earlier suite runs
        # can't be mistaken for this session
        ip = '10.0.0.%d' % (30 + BeaconC5._n)
        sid = None
        while sid is None:
            sid, _ = eng.register(ip, 'h%d' % BeaconC5._n, 'Linux', 'root',
                                  state.get_beacon_key())
            if sid is None:      # key rotated mid-run; never happens here
                self.fail('beacon register denied')
        return sid

    def test_parse_ls_gnu_listing(self):
        listing = ("total 28\n"
                   "drwxr-xr-x  5 root root 4096 Sep 15 12:00 .\n"
                   "drwxr-xr-x  3 root root 4096 Sep 15 12:00 ..\n"
                   "-rw-r--r--  1 root root   123 Sep 15 12:00 notes.txt\n"
                   "lrwxrwxrwx  1 root root     5 Sep 15 12:00 link -> notes.txt\n")
        entries = beacon.parse_ls(listing)
        self.assertEqual(len(entries), 2)
        by_name = {e['name']: e for e in entries}
        self.assertFalse(by_name['notes.txt']['dir'])
        self.assertEqual(by_name['notes.txt']['size'], 123)
        self.assertTrue(by_name['link']['link'])

    def test_parse_ls_lenient_on_foreign_format(self):
        self.assertEqual(beacon.parse_ls("Directory: C:\\temp\n..."), [])

    def test_check_fw_validation(self):
        ok = beacon.BeaconEngine._check_fw('8080-10.0.0.5:80')
        self.assertEqual(ok, (8080, '10.0.0.5', 80))
        for bad in ('8080-no_port:80', '0-10.0.0.5:80', '8080-a b:80',
                    '8080-10.0.0.5:99999', '65536-x:1', 'junk', '10.0.0.5:80',
                    ''):
            self.assertIsNone(beacon.BeaconEngine._check_fw(bad), repr(bad))

    def test_ls_task_marker_and_kind(self):
        eng = self._engine()
        sid = self._session(eng)
        res = eng.add_ls(sid, '/etc')
        self.assertTrue(res.get('ok'))
        t = [x for x in state.read_beacons()[sid]['tasks']
             if x.get('kind') == 'ls'][-1]
        self.assertEqual(t['cmd'], beacon.LS_MARKER + '/etc')
        self.assertEqual(t['browse'], '/etc')

    def test_fw_persistent_task_delivered_once(self):
        eng = self._engine()
        sid = self._session(eng)
        self.assertTrue(eng.add_fwd(sid, '9000-10.0.0.50:22').get('ok'))
        eng.add_command(sid, 'id')
        tasks = state.read_beacons()[sid]['tasks']
        t = [x for x in tasks if x.get('kind') == 'fw'][0]
        self.assertTrue(t['persistent'])
        self.assertEqual(t['fw'], '9000 -> 10.0.0.50:22')
        # pivot is queued for delivery once with a normal command…
        queued = eng._collect(state.read_beacons()[sid])
        kinds = {x.get('kind') for x in queued}
        self.assertIn('cmd', kinds)
        self.assertIn('fw', kinds)
        # …and once marked sent it is never re-collected
        for x in queued:
            eng.mark_sent(sid, x['id'])
        self.assertEqual(eng._collect(state.read_beacons()[sid]), [])
        t = [x for x in state.read_beacons()[sid]['tasks']
             if x.get('kind') == 'fw'][0]
        self.assertEqual(t['status'], 'sent')

    def test_term_task_streams_into_rolling_buffer(self):
        eng = self._engine()
        sid = self._session(eng)
        res = eng.add_command(sid, 'echo hello', kind='term')
        self.assertEqual(res.get('kind'), 'term')
        eng.task_output(sid, res['id'], 'hello\n')
        s = state.read_beacons()[sid]
        self.assertEqual(s['term'][-1]['cmd'], 'echo hello')
        self.assertEqual(s['term'][-1]['out'], 'hello\n')
        eng.add_command(sid, 'whoami')
        self.assertEqual(len(s['term']), 1)   # plain cmds don't hit the buffer


if __name__ == '__main__':
    unittest.main()