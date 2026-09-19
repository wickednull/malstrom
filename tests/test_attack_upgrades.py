"""Tests for the attack upgrade package (no root, no radio required).

    MALSTROM_STATE_DIR=/tmp/opencode/ms-state python3 -m pytest tests/ -q

Covers: deauth disassociation frames + honest burst accounting, the
handshake auto-shield, hostapd clone-fidelity conf (WPA3 transition,
country/11d + 11ac, BSSID-clone toggle), the auto-crack pipeline (wordlist
resolution, KEY FOUND parsing, cracked store), SAM/LSA dump hash parsing
and job honesty, the hashcat NTLMv2/NT crack shape, the nmap service-scan
kind, the portal TLS cert, and the hashcat 22000 export action.
"""

import os
import shutil
import struct
import tempfile
import time
import unittest

from malstrom import config
from malstrom import capture
from malstrom import deauth
from malstrom import lateral
from malstrom import linuxutil
from malstrom import portal
from malstrom import scan
from malstrom import services
from malstrom import state
from malstrom import verify
from malstrom import web


class DisassocFrames(unittest.TestCase):
    def _engine(self):
        eng = deauth.DeauthEngine()
        frames = []
        eng._raw_socket = lambda: type('S', (), {'send': lambda s, b:
                                                 frames.append(b)})()
        eng._set_mon_channel = lambda *a: None
        eng._stop.is_set = lambda: False
        return eng, frames

    def test_disassoc_uses_a0_fc(self):
        eng, frames = self._engine()
        self.assertTrue(eng._send_raw('AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66',
                                      '6', 2, disassoc=True))
        self.assertEqual(len(frames), 2)
        self.assertEqual(struct.unpack('<H', frames[0][0:2])[0], 0x00A0)

    def test_deauth_still_uses_c0_fc(self):
        eng, frames = self._engine()
        eng._send_raw('AA:BB:CC:DD:EE:FF', 'FF:FF:FF:FF:FF:FF', '6', 1)
        self.assertEqual(struct.unpack('<H', frames[0][0:2])[0], 0x00C0)

    def test_burst_sends_disassoc_followup(self):
        eng, frames = self._engine()
        events = []
        saved_emit = state.emit
        calls = []
        saved_shield = state.read_shield_macs
        state.emit = lambda etype, msg: events.append((etype, msg))
        state.read_shield_macs = lambda: set()
        eng._frame = lambda *a: calls.append('deauth') or True
        eng._disassoc = lambda *a: calls.append('disassoc') or True
        try:
            eng._burst({'target_bssid': 'AA:BB:CC:DD:EE:FF',
                        'deauth_mode': 'broadcast', 'deauth_burst': 5})
            self.assertEqual(calls, ['deauth', 'disassoc'])
            ev = [m for k, m in events if k == 'DEAUTH']
            self.assertEqual(len(ev), 1)
            self.assertIn('deauth+disassoc', ev[0])
        finally:
            state.emit = saved_emit
            state.read_shield_macs = saved_shield

    def test_disassoc_reaches_air_without_deauth(self):
        eng, frames = self._engine()
        events = []
        saved_emit = state.emit
        saved_shield = state.read_shield_macs
        state.emit = lambda etype, msg: events.append((etype, msg))
        state.read_shield_macs = lambda: set()
        eng._frame = lambda *a: False
        eng._disassoc = lambda *a: True
        try:
            eng._burst({'target_bssid': 'AA:BB:CC:DD:EE:FF',
                        'deauth_mode': 'broadcast', 'deauth_burst': 3})
            kinds = [k for k, _ in events]
            self.assertNotIn('ALERT', kinds)   # honest: something DID go out
            self.assertIn('DEAUTH', kinds)
        finally:
            state.emit = saved_emit
            state.read_shield_macs = saved_shield


class AutoShield(unittest.TestCase):
    def setUp(self):
        self._saved = (state.load_state, state.read_whitelist,
                       state.add_whitelist, state.emit)

    def tearDown(self):
        (state.load_state, state.read_whitelist, state.add_whitelist,
         state.emit) = self._saved

    def test_shields_sta_on_capture(self):
        added, emitted = [], []
        state.load_state = lambda: {'shield_after_capture': True}
        state.read_whitelist = lambda: []
        state.add_whitelist = lambda mac: added.append(mac)
        state.emit = lambda etype, msg: emitted.append((etype, msg))
        capture.CaptureEngine()._auto_shield_sta('AA:BB:CC:DD:EE:01',
                                                 'handshake')
        self.assertEqual(added, ['AA:BB:CC:DD:EE:01'])
        self.assertEqual(emitted[0][0], 'INFO')

    def test_no_shield_when_toggle_off_or_already_set(self):
        added = []
        state.load_state = lambda: {'shield_after_capture': False}
        state.read_whitelist = lambda: []
        state.add_whitelist = lambda mac: added.append(mac)
        eng = capture.CaptureEngine()
        eng._auto_shield_sta('AA:BB:CC:DD:EE:01', 'handshake')
        self.assertEqual(added, [])
        state.load_state = lambda: {'shield_after_capture': True}
        state.read_whitelist = lambda: ['aa:bb:cc:dd:ee:01']
        eng._auto_shield_sta('AA:BB:CC:DD:EE:01', 'handshake')
        self.assertEqual(added, [])


class HostapdFidelity(unittest.TestCase):
    def test_wpa3_transition_lines(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'wpa', 'hunter22!', wpa3=True)
        self.assertIn('wpa_key_mgmt=WPA-PSK SAE', conf)
        self.assertIn('ieee80211w=1', conf)

    def test_wpa3_flag_needs_wpa_mode(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'open', '', wpa3=True)
        self.assertNotIn('wpa_key_mgmt', conf)

    def test_country_and_vht_only_on_5ghz(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '36', 'open', '', country='US', vht=True)
        self.assertIn('country_code=US', conf)
        self.assertIn('ieee80211d=1', conf)
        self.assertIn('ieee80211ac=1', conf)
        conf24 = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'open', '', country='US', vht=True)
        self.assertNotIn('country_code', conf24)
        self.assertNotIn('ieee80211ac', conf24)

    def test_wpa2_conf_unchanged_by_default(self):
        conf = services.build_hostapd_conf(
            'wlan1', 'TEST', '', '6', 'wpa', 'hunter2hunter2')
        self.assertIn('wpa_key_mgmt=WPA-PSK\n', conf)
        self.assertNotIn('SAE', conf)
        self.assertNotIn('logger_file', conf)


class HostapdIfaceGate(unittest.TestCase):
    def test_start_refuses_missing_iface_loudly(self):
        # Clone/SAE fidelity paths sit behind the iface gate and an explicit
        # alert — never a silent launch or a wedged retry loop.
        stk = services.RogueStack()
        stk.ap_iface = None
        events = []
        saved_emit = state.emit
        state.emit = lambda etype, msg: events.append((etype, msg))
        saved = (linuxutil.hostapd_ok, linuxutil.netdev_exists,
                 linuxutil.ap_capable_uplinks, linuxutil.phy_of,
                 linuxutil.phy_vht, linuxutil.regdom)
        linuxutil.hostapd_ok = lambda: True
        linuxutil.netdev_exists = lambda n: False
        linuxutil.ap_capable_uplinks = lambda: []
        linuxutil.phy_of = lambda n: None
        linuxutil.phy_vht = lambda p: False
        linuxutil.regdom = lambda: ''
        try:
            ok = stk.start_hostapd({
                'portal_mode': 'wpa', 'wpa_psk': 'hunter22!',
                'target_bssid': 'AA:BB:CC:DD:EE:FF', 'clone_bssid': False,
                'wpa3_transition': True, 'target_channel': '6'})
            self.assertFalse(ok)
            self.assertIn('ALERT', [k for k, _ in events])
        finally:
            state.emit = saved_emit
            (linuxutil.hostapd_ok, linuxutil.netdev_exists,
             linuxutil.ap_capable_uplinks, linuxutil.phy_of,
             linuxutil.phy_vht, linuxutil.regdom) = saved


class CrackWordlist(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._old = (config.CRACK_WORDLIST, config.STATE_DIR)
        config.CRACK_WORDLIST = ''
        config.STATE_DIR = self._tmp
        self._saved = (state.read_settings, state._WORDLIST_CANDIDATES)

    def tearDown(self):
        config.CRACK_WORDLIST, config.STATE_DIR = self._old
        (state.read_settings, state._WORDLIST_CANDIDATES) = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_setting_wins_but_must_exist(self):
        state.read_settings = lambda: {'crack_wordlist': '/no/such/file.list'}
        self.assertEqual(state.crack_wordlist(), '')
        p = os.path.join(self._tmp, 'my.list')
        with open(p, 'w') as fh:
            fh.write('x\n')
        state.read_settings = lambda: {'crack_wordlist': p}
        self.assertEqual(state.crack_wordlist(), p)

    def _no_real_wordlists(self):
        """Patch isfile so the real /usr/share/wordlists files never leak in."""
        real_isfile = os.path.isfile

        def isfile(path):
            if 'rockyou' in str(path):
                return False
            return real_isfile(path)
        os.path.isfile = isfile
        self.addCleanup(setattr, os.path, 'isfile', real_isfile)
        return real_isfile

    def test_no_wordlist_returns_empty(self):
        self._no_real_wordlists()
        state.read_settings = lambda: {}
        state._WORDLIST_CANDIDATES = ()
        self.assertEqual(state.crack_wordlist(), '')

    def test_rockyou_gz_extracted_once(self):
        import gzip
        state.read_settings = lambda: {}
        state._WORDLIST_CANDIDATES = ()
        gz_path = os.path.join(self._tmp, 'rockyou.txt.gz')
        with gzip.open(gz_path, 'wb') as fh:
            fh.write(b'dictionnaire\nopensesame\n')
        real_isfile = os.path.isfile

        def isfile(path):
            if path == '/usr/share/wordlists/rockyou.txt.gz':
                return os.path.isfile(gz_path)
            if path == '/usr/share/wordlists/rockyou.txt':
                return False
            return real_isfile(path)
        os.path.isfile = isfile
        try:
            wl = state.crack_wordlist()
            self.assertEqual(wl, os.path.join(self._tmp, 'rockyou.txt'))
            with open(wl, 'rb') as fh:
                self.assertIn(b'opensesame', fh.read())
        finally:
            os.path.isfile = real_isfile


class AutoCrackPipeline(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._saved = (verify.subprocess, state.crack_wordlist)

    def tearDown(self):
        verify.subprocess = self._saved[0]
        state.crack_wordlist = self._saved[1]
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_key_found_parsing(self):
        self.assertEqual(
            verify._KEY_RE.search('KEY FOUND! [ password123 ]').group(1),
            'password123')

    def test_crack_stores_psk_and_patches_handshake(self):
        """Full _crack flow with a faked aircrack: patched handshake entry,
        cracked-store row, CRACK event. Store files are patched to the tmp
        dir so the shared suite state dir stays clean."""
        pcap = os.path.join(self._tmp, 'malstrom-test.pcap')
        with open(pcap, 'wb') as fh:
            fh.write(b'fake')
        wlpath = os.path.join(self._tmp, 'wl.txt')
        with open(wlpath, 'w') as fh:
            fh.write('word1\nword2\n')
        PIPE, STDOUT = object(), object()

        class P(object):
            returncode = 0
            stdout = b'KEY FOUND! [ password123 ]\n'
        # _crack reads subprocess.PIPE/STDOUT on the patched module — they
        # must exist or the bare except swallows the AttributeError.
        fake_sub = type('S', (), {'run': staticmethod(lambda *a, **kw: P()),
                                  'PIPE': PIPE,
                                  'STDOUT': STDOUT})()
        real_hs, real_ck = state.HANDSHAKES_FILE, state.CRACKED_FILE
        real_emit = state.emit
        hs_file = os.path.join(self._tmp, 'handshakes.json')
        ck_file = os.path.join(self._tmp, 'cracked.json')
        events = []
        try:
            verify.subprocess = fake_sub
            state.crack_wordlist = lambda: wlpath
            state.HANDSHAKES_FILE = hs_file
            state.CRACKED_FILE = ck_file
            state.emit = lambda t, m: events.append((t, m))
            state.index_handshake({'bssid': 'AA:BB:CC:DD:EE:FF',
                                   'ssid': 'Corp', 'file': pcap,
                                   'kind': 'handshake'})
            verify.VerifyEngine()._crack(pcap)
            row = state.read_cracked()[-1]
            self.assertEqual(row['psk'], 'password123')
            self.assertEqual(row['ssid'], 'Corp')
            self.assertTrue(any(e.get('cracked') == 'password123'
                                for e in state.read_handshakes()))
            self.assertIn('CRACK', [k for k, _ in events])
        finally:
            state.emit = real_emit
            state.HANDSHAKES_FILE = real_hs
            state.CRACKED_FILE = real_ck


class SamLsaDump(unittest.TestCase):
    LM_NULL = 'aad3b435b51404eeaad3b435b51404ee'   # 32 hex: classic null LM
    NT_A = 'e3b0c44298fc1c149afbf4c8996fb924'
    NT_B = '2d711642b726b04401627ca9fbac32f5'

    def test_netexec_sam_hash_parsing(self):
        out = ('SMB   172.16.52.10   445   DESKTOP   [+] Dumping SAM hashes\n'
               'admin:500:%s:%s:::\n'
               'junk:line without hashes\n'
               'Guest:501:%s:%s:::\n' % (self.LM_NULL, self.NT_A,
                                         self.LM_NULL, self.NT_B))
        lines = lateral._parse_dump_hashes(out)
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith('admin:500:aad3b'))
        self.assertTrue(lines[0].endswith(':::'))

    def test_dump_validates_input(self):
        eng = lateral.LateralEngine()
        self.assertEqual(eng.dump('', '', '').get('ok'), 0)
        r = eng.dump('172.16.52.10', '', '')
        self.assertEqual(r['ok'], 0)
        self.assertIn('no credentials', r['error'])

    def test_dump_lands_nt_hashes_in_vault(self):
        """Full dump worker against a faked netexec: SAM rows land in the
        hash vault tagged kind=nt, job finishes done, HASH event emitted."""
        out = tempfile.mkdtemp()
        class P(object):
            returncode = 0
            stdout = ('SMB  172.16.52.10  445 DESKTOP [+] Dumping SAM hashes\n'
                      'admin:500:%s:%s:::\n' % (
                          SamLsaDump.LM_NULL, SamLsaDump.NT_A))
            stderr = ''
        saved = (lateral.subprocess.run, state.put_scan, state.emit,
                 state.HASHES_FILE, state.HASHES_TXT)
        real_emit = state.emit
        jobs = []
        events = []
        hashes_file = os.path.join(out, 'hashes.json')
        hashes_txt = os.path.join(out, 'hashes.txt')
        try:
            lateral.subprocess.run = lambda *a, **kw: P()
            state.put_scan = lambda j: jobs.append(j)
            state.emit = lambda t, m: events.append((t, m))
            state.HASHES_FILE = hashes_file
            state.HASHES_TXT = hashes_txt
            eng = lateral.LateralEngine()
            r = eng.dump('172.16.52.0/24', 'admin', 'PASS1')
            self.assertEqual(r['ok'], 1)
            deadline = time.time() + 6
            while eng.busy() and time.time() < deadline:
                time.sleep(0.1)
            tok = [h for h in state.read_hashes() if h.get('kind') == 'nt']
            self.assertEqual(len(tok), 1)
            self.assertEqual(tok[-1]['user'], 'admin')
            self.assertTrue(all(j.get('status') in ('done', 'error')
                                for j in jobs))
            self.assertEqual(jobs[-1].get('status'), 'done')
            self.assertIn('HASH', [k for k, _ in events])
        finally:
            (lateral.subprocess.run, state.put_scan, state.emit,
             state.HASHES_FILE, state.HASHES_TXT) = saved
            shutil.rmtree(out, ignore_errors=True)


class Ntlmv2Crack(unittest.TestCase):
    def setUp(self):
        self._saved = (lateral.shutil.which, state.read_hashes,
                       state.read_settings)

    def tearDown(self):
        (lateral.shutil.which, state.read_hashes,
         state.read_settings) = self._saved

    def test_empty_vault_is_honest(self):
        lateral.shutil.which = lambda b: '/usr/bin/hashcat'
        state.read_hashes = lambda: []
        state.read_settings = lambda: {}
        r = lateral.LateralEngine().crack_hashes()
        self.assertEqual(r['ok'], 0)
        self.assertIn('no uncracked hashes', r['error'])

    def test_missing_hashcat_binary_is_honest(self):
        lateral.shutil.which = lambda b: None
        state.read_hashes = lambda: [{'kind': 'ntlmv2',
                                      'token': 'user::dom:aa:bb:cc',
                                      'pass': ''}]
        state.read_settings = lambda: {}
        r = lateral.LateralEngine().crack_hashes()
        self.assertEqual(r['ok'], 0)
        self.assertIn('not installed', r['error'])

    def test_missing_wordlist_is_honest(self):
        lateral.shutil.which = lambda b: '/usr/bin/hashcat'
        state.read_hashes = lambda: [{'kind': 'ntlmv2',
                                      'token': 'user::dom:aa:bb:cc',
                                      'pass': ''}]
        state.read_settings = lambda: {'crack_wordlist': '/no/such.list'}
        r = lateral.LateralEngine().crack_hashes()
        self.assertEqual(r['ok'], 0)
        self.assertIn('wordlist', r['error'])


class ServiceScanKind(unittest.TestCase):
    def setUp(self):
        self._saved = (scan._run_bin, state.put_scan, state.emit)

    def tearDown(self):
        (scan._run_bin, state.put_scan, state.emit) = self._saved

    def test_svc_cmd_includes_version_flag(self):
        eng = scan.ScanEngine()
        started = {}

        def fake_run(args, timeout=120):
            started['args'] = list(args)
            return None, ''
        scan._run_bin = fake_run
        state.put_scan = lambda j: None
        state.emit = lambda *a: None
        r = eng.start_job('svc', '172.16.52.0/24', {'range': '80-500'})
        self.assertEqual(r['ok'], 1)
        deadline = time.time() + 5
        while eng.running() and time.time() < deadline:
            time.sleep(0.1)
        self.assertIn('-sV', ' '.join(started['args']))

    def test_unknown_kind_coerced_to_ports(self):
        eng = scan.ScanEngine()
        started = {}

        def fake_run(args, timeout=120):
            started['args'] = list(args)
            return None, ''
        scan._run_bin = fake_run
        state.put_scan = lambda j: None
        state.emit = lambda *a: None
        r = eng.start_job('bogus', 'h', {'range': '22'})
        self.assertEqual(r['ok'], 1)
        deadline = time.time() + 5
        while eng.running() and time.time() < deadline:
            time.sleep(0.1)
        self.assertNotIn('-sV', ' '.join(started['args']))


class HashcatExport(unittest.TestCase):
    def _mk_handler(self, fname):
        h = object.__new__(web.DashHandler)
        h.result = None
        h.wrote = []

        def q(name, default=''):
            return {'file': fname}.get(name, default)
        h._q = q
        h._json = lambda obj, code=200: setattr(h, 'result', obj)
        h.send_response = lambda *a, **k: None
        h.send_header = lambda *a, **k: None
        h.end_headers = lambda: None
        h.wfile = type('W', (), {'write': lambda s, b: h.wrote.append(b)})()
        return h

    def setUp(self):
        self._tmploot = tempfile.mkdtemp()
        self._old = (config.LOOT_DIR, linuxutil.run, linuxutil.have)
        self._pcap_rel = 'pcaps/x.pcap'
        full = os.path.join(self._tmploot, self._pcap_rel)
        os.makedirs(os.path.dirname(full))
        with open(full, 'wb') as fh:
            fh.write(b'fake-pcap')
        config.LOOT_DIR = self._tmploot

    def tearDown(self):
        config.LOOT_DIR, linuxutil.run, linuxutil.have = self._old
        shutil.rmtree(self._tmploot, ignore_errors=True)

    def test_conversion_streams_22000(self):
        class P(object):
            returncode = 0
            stdout = 'WPA*01*abcdef*hashcat ready\n'
            stderr = ''
        linuxutil.run = lambda argv, timeout=10: P()
        linuxutil.have = lambda b: True
        h = self._mk_handler(self._pcap_rel)
        web.DashHandler._action_hashcat_export(h)
        self.assertIsNone(h.result)                  # success path streams
        body = b''.join(h.wrote).decode('utf-8')
        self.assertIn('hashcat ready', body)
        self.assertIn('WPA*01*', body)
        self.assertTrue(body.endswith('\n'))

    def test_missing_hcx_reports_fixable_error(self):
        class P(object):
            returncode = 1
            stdout = ''
            stderr = 'spawn failed'
        linuxutil.run = lambda argv, timeout=10: P()
        linuxutil.have = lambda b: False
        h = self._mk_handler(self._pcap_rel)
        web.DashHandler._action_hashcat_export(h)
        self.assertEqual(h.result['ok'], 0)
        self.assertIn('hcxtools missing', h.result['error'])

    def test_refuses_paths_outside_loot(self):
        h = self._mk_handler('../../etc/passwd')
        web.DashHandler._action_hashcat_export(h)
        self.assertEqual(h.result['ok'], 0)
        self.assertIn('not found', h.result['error'])


class PortalCert(unittest.TestCase):
    def test_self_signed_cert_generated(self):
        if not linuxutil.have('openssl'):
            self.skipTest('openssl not available')
        cert, key = portal.ensure_portal_cert()
        self.assertTrue(cert and os.path.isfile(cert))
        self.assertTrue(key and os.path.isfile(key))
        with open(cert) as fh:
            self.assertIn('BEGIN CERTIFICATE', fh.read(200))


if __name__ == '__main__':
    unittest.main()
