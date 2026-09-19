"""Tests for the automatic pwnagotchi-style handshake harvester.

No root, no radio required.
"""

import os
import shutil
import tempfile
import time
import unittest

from malstrom import autopwn
from malstrom import config
from malstrom import state


class AutopwnTargeting(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._saved = (state.load_state, state.write_state, state.read_handshakes,
                       state.read_whitelist, state.emit, config.AUTO_SKIP_CAPTURED,
                       config.AUTO_MIN_RSSI, config.AUTO_CHANNELS,
                       config.AUTO_MAX_INTERACTIONS)
        state.emit = lambda *a, **k: None
        config.AUTO_SKIP_CAPTURED = True
        config.AUTO_MIN_RSSI = -80
        config.AUTO_CHANNELS = []
        config.AUTO_MAX_INTERACTIONS = 3
        state.read_handshakes = lambda: []
        state.read_whitelist = lambda: ['00:11:22:33:44:09']
        self.eng = autopwn.AutopwnEngine()
        self.eng._scan_cache = [
            {'ssid': 'OPENNET', 'bssid': '00:11:22:33:44:01', 'channel': 6,
             'signal': -50, 'security': 'OPEN'},
            {'ssid': 'WEPNET', 'bssid': '00:11:22:33:44:02', 'channel': 6,
             'signal': -50, 'security': 'WEP'},
            {'ssid': 'OWENET', 'bssid': '00:11:22:33:44:03', 'channel': 6,
             'signal': -50, 'security': 'OWE'},
            {'ssid': 'WeakNet', 'bssid': '00:11:22:33:44:04', 'channel': 6,
             'signal': -90, 'security': 'WPA2'},
            {'ssid': '[hidden]', 'bssid': '00:11:22:33:44:05', 'channel': 6,
             'signal': -50, 'security': 'WPA2'},
            {'ssid': 'Far5G', 'bssid': '00:11:22:33:44:06', 'channel': 161,
             'signal': -50, 'security': 'WPA2'},
            {'ssid': 'GoodNet', 'bssid': '00:11:22:33:44:07', 'channel': 11,
             'signal': -55, 'security': 'WPA2-CCMP'},
            {'ssid': 'BestNet', 'bssid': '00:11:22:33:44:08', 'channel': 1,
             'signal': -40, 'security': 'WPA3-CCMP'},
            {'ssid': 'Whitelisted', 'bssid': '00:11:22:33:44:09', 'channel': 1,
             'signal': -30, 'security': 'WPA2'},
        ]
        self.eng._last_recon = time.time()

    def tearDown(self):
        (state.load_state, state.write_state, state.read_handshakes,
         state.read_whitelist, state.emit, config.AUTO_SKIP_CAPTURED,
         config.AUTO_MIN_RSSI, config.AUTO_CHANNELS,
         config.AUTO_MAX_INTERACTIONS) = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_picks_strongest_wpa_target(self):
        state.read_handshakes = lambda: []
        ap = self.eng._pick_target({})
        self.assertEqual(ap['ssid'], 'BestNet')
        self.assertEqual(ap['bssid'], '00:11:22:33:44:08')

    def test_skips_open_wep_owe_hidden_weak(self):
        state.read_handshakes = lambda: []
        # Make BestNet and GoodNet vanish by interaction limit.
        self.eng._interactions['00:11:22:33:44:08'] = 3
        self.eng._interactions['00:11:22:33:44:07'] = 3
        ap = self.eng._pick_target({})
        self.assertEqual(ap['ssid'], 'Far5G')

    def test_skips_captured_and_whitelisted(self):
        state.read_handshakes = lambda: [
            {'bssid': '00:11:22:33:44:08', 'valid': True, 'kind': 'handshake'}]
        state.read_whitelist = lambda: ['00:11:22:33:44:09']
        ap = self.eng._pick_target({})
        # BestNet captured, Whitelisted excluded -> Far5G is strongest left
        self.assertEqual(ap['ssid'], 'Far5G')

    def test_honors_channel_allowlist(self):
        config.AUTO_CHANNELS = ['11']
        state.read_handshakes = lambda: []
        ap = self.eng._pick_target({})
        self.assertEqual(ap['ssid'], 'GoodNet')
        self.assertEqual(ap['channel'], 11)


class AutopwnCycle(unittest.TestCase):
    def setUp(self):
        self._saved = (state.load_state, state.write_state, state.read_handshakes,
                       state.emit, config.AUTO_DWELL)
        state.emit = lambda *a, **k: None
        config.AUTO_DWELL = 2
        self.eng = autopwn.AutopwnEngine()

    def tearDown(self):
        (state.load_state, state.write_state, state.read_handshakes,
         state.emit, config.AUTO_DWELL) = self._saved

    def test_arm_writes_auto_state(self):
        wrote = []
        state.load_state = lambda: {'auto_harvest': True}
        state.write_state = wrote.append
        state.read_handshakes = lambda: []
        ap = {'ssid': 'AutoTarget', 'bssid': 'aa:bb:cc:dd:ee:ff',
              'channel': 6, 'signal': -60, 'security': 'WPA2'}
        self.eng._arm(ap)
        self.assertTrue(wrote)
        st = wrote[0]
        self.assertTrue(st['active'])
        self.assertTrue(st['auto_armed'])
        self.assertEqual(st['target_ssid'], 'AutoTarget')
        self.assertEqual(st['target_bssid'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(st['capture_mode'], 'both')
        self.assertEqual(st['deauth_mode'], 'broadcast')

    def test_disarm_clears_auto_armed(self):
        wrote = []
        state.load_state = lambda: {'active': True, 'auto_armed': True,
                                    'target_bssid': 'AA:BB:CC:DD:EE:FF'}
        state.write_state = wrote.append
        self.eng._target = {'bssid': 'AA:BB:CC:DD:EE:FF'}
        self.eng._disarm('test')
        st = wrote[0]
        self.assertFalse(st['active'])
        self.assertFalse(st['auto_armed'])

    def test_check_done_on_capture(self):
        self.eng._target = {'bssid': 'AA:BB:CC:DD:EE:FF'}
        self.eng._armed_at = time.time()
        state.read_handshakes = lambda: [
            {'bssid': 'AA:BB:CC:DD:EE:FF', 'valid': True, 'kind': 'handshake'}]
        self.assertTrue(self.eng._check_done({}))
        self.assertIn('AA:BB:CC:DD:EE:FF', self.eng._seen_bssids)

    def test_check_done_on_dwell_timeout(self):
        self.eng._target = {'bssid': 'AA:BB:CC:DD:EE:FF'}
        self.eng._armed_at = time.time() - 10
        state.read_handshakes = lambda: []
        self.assertTrue(self.eng._check_done({}))

    def test_check_not_done_mid_dwell(self):
        self.eng._target = {'bssid': 'AA:BB:CC:DD:EE:FF'}
        self.eng._armed_at = time.time()
        state.read_handshakes = lambda: []
        self.assertFalse(self.eng._check_done({}))


class AutopwnEapolDetection(unittest.TestCase):
    """Sanity-check that the capture engine still sees Msg1+Msg2."""

    def _frame(self, mtype, ap, sta):
        import struct
        rtap = b'\x00\x00\x08\x00' + b'\x00\x00\x00\x00'
        if mtype in (1, 3):
            fc = 0x0208
            addr1, addr2, addr3 = sta, ap, ap
        else:
            fc = 0x0108
            addr1, addr2, addr3 = ap, sta, ap
        hdr = struct.pack('<HH', fc, 0) + addr1 + addr2 + addr3 + struct.pack('<H', 0x0010)
        llc = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e'
        body = bytearray()
        body.append(0x02)
        if mtype == 1:
            ki = 0x008a
        elif mtype == 2:
            ki = 0x010a
        elif mtype == 3:
            ki = 0x13ca
        else:
            ki = 0x030a
        body += struct.pack('<H', ki)
        body += struct.pack('<H', 16)
        body += b'\x00' * 8
        body += b'\x00' * 32
        body += b'\x00' * 16
        body += b'\x00' * 8
        body += b'\x00' * 8
        body += b'\x00' * 16
        body += struct.pack('<H', 0)
        length = len(body)
        eapol = bytes([0x01, 0x03]) + struct.pack('>H', length) + bytes(body)
        return rtap + hdr + llc + eapol

    def test_msg1_plus_msg2_indexes_handshake(self):
        from malstrom import capture
        ap = bytes.fromhex('112233445566')
        sta = bytes.fromhex('aabbccddeeff')
        eng = capture.CaptureEngine()
        eng.set_cmd(active=True, bssid='11:22:33:44:55:66', ssid='Test',
                    channel=6, mode='handshake')
        eng._ingest(self._frame(1, ap, sta))
        eng._ingest(self._frame(2, ap, sta))
        key = ('11:22:33:44:55:66', 'AA:BB:CC:DD:EE:FF')
        self.assertIn(key, eng._indexed)
        self.assertIn(1, eng._pairs[key]['msg'])
        self.assertIn(2, eng._pairs[key]['msg'])


if __name__ == '__main__':
    unittest.main()
