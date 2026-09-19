"""Tests for the upgraded Wi-Fi recon engine (no root, no radio required).

    MALSTROM_STATE_DIR=/tmp/opencode/ms-state python3 -m pytest tests/ -q

Covers iw-scan parsing (security tags, bands incl. 6 GHz, duplicate-BSS
merge, WPS/hidden flags), OUI vendor lookup from local databases, the
mode-aware scan-interface selection, and honest scan_wifi error surfacing.
"""

import os
import shutil
import tempfile
import unittest

from malstrom import config
from malstrom import linuxutil
from malstrom import recon


IW_DUMP = """
BSS 04:f0:21:11:bf:3b(on wlan0)
	freq: 2437
	capability: ESS Privacy
	signal: -78.00 dBm
	SSID: HomeNet
	DS Parameter set: channel 6
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: PSK
	 * Capabilities: 16-2

BSS 04:f0:21:11:bf:3b(on wlan0) -- associated
	freq: 2437
	capability: ESS Privacy
	signal: -72.00 dBm
	SSID: HomeNet
	DS Parameter set: channel 6
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: PSK

BSS ac:de:48:00:11:22(on wlan0)
	freq: 2462
	capability: ESS
	signal: -45.00 dBm
	SSID: OpenGuest
	DS Param set: channel 11

BSS 00:11:22:33:44:55(on wlan0)
	freq: 5240
	capability: ESS Privacy
	signal: -60.00 dBm
	SSID: Corp-5G
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: 802.1X

BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 6115
	capability: ESS Privacy
	signal: -50.00 dBm
	SSID: Wifi7-Lab
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: SAE

BSS de:ad:be:ef:00:01(on wlan0)
	freq: 2412
	capability: ESS Privacy IBSS
	signal: -85.00 dBm
	SSID: LegacyMesh
	DS Parameter set: channel 1

BSS 12:34:56:78:9a:bc(on wlan0)
	freq: 2412
	capability: ESS Privacy
	signal: -90.00 dBm
	SSID:
	DS Parameter set: channel 1
	WPA:
	 * Version: 1
	 * Group cipher: TKIP
	 * Pairwise ciphers: TKIP CCMP
	 * Authentication suites: PSK
	WPS:
	 * Version: 1.0
"""


def _by_ssid(aps, ssid):
    for ap in aps:
        if ap['ssid'] == ssid:
            return ap
    return None


class FreqMapping(unittest.TestCase):
    def test_channels_across_bands(self):
        self.assertEqual(recon.freq_to_channel(2412), 1)
        self.assertEqual(recon.freq_to_channel(2437), 6)
        self.assertEqual(recon.freq_to_channel(2472), 13)
        self.assertEqual(recon.freq_to_channel(2484), 14)
        self.assertEqual(recon.freq_to_channel(5180), 36)
        self.assertEqual(recon.freq_to_channel(5240), 48)
        self.assertEqual(recon.freq_to_channel(5885), 177)
        self.assertEqual(recon.freq_to_channel(4910), 182)   # JP sub-band
        self.assertEqual(recon.freq_to_channel(5955), 1)     # 6 GHz (6E)
        self.assertEqual(recon.freq_to_channel(6115), 33)
        self.assertEqual(recon.freq_to_channel(7115), 233)
        self.assertEqual(recon.freq_to_channel(9000), 0)

    def test_bands(self):
        self.assertEqual(recon.freq_to_band(2437), '2.4 GHz')
        self.assertEqual(recon.freq_to_band(5240), '5 GHz')
        self.assertEqual(recon.freq_to_band(6115), '6 GHz')
        self.assertEqual(recon.freq_to_band(9000), '')


class IwScanParsing(unittest.TestCase):
    def setUp(self):
        # Keep vendor noise out of the way and restore afterwards.
        self._saved_cache = recon._oui_cache
        recon._oui_cache = {}

    def tearDown(self):
        recon._oui_cache = self._saved_cache

    def test_parses_security_bands_and_flags(self):
        aps = recon.parse_iw_scan(IW_DUMP)
        home = _by_ssid(aps, 'HomeNet')
        self.assertEqual(home['security'], 'WPA2-CCMP')
        self.assertEqual(home['band'], '2.4 GHz')
        self.assertEqual(home['channel'], 6)
        guest = _by_ssid(aps, 'OpenGuest')
        self.assertEqual(guest['security'], 'OPEN')
        self.assertFalse(guest['adhoc'])
        corp = _by_ssid(aps, 'Corp-5G')
        self.assertEqual(corp['security'], 'WPA2-ENT-CCMP')
        self.assertEqual(corp['band'], '5 GHz')
        self.assertEqual(corp['channel'], 48)
        wpa3 = _by_ssid(aps, 'Wifi7-Lab')
        self.assertEqual(wpa3['security'], 'WPA3-CCMP')
        self.assertEqual(wpa3['band'], '6 GHz')
        self.assertEqual(wpa3['channel'], 33)
        legacy = _by_ssid(aps, 'LegacyMesh')
        self.assertEqual(legacy['security'], 'WEP')
        self.assertTrue(legacy['adhoc'])
        hidden = _by_ssid(aps, '[hidden]')
        self.assertEqual(hidden['security'], 'WPA-TKIP')
        self.assertTrue(hidden['wps'])

    def test_duplicate_bss_merged_with_strongest_signal(self):
        aps = recon.parse_iw_scan(IW_DUMP)
        bss = [a for a in aps if a['bssid'] == '04:F0:21:11:BF:3B']
        self.assertEqual(len(bss), 1)
        self.assertEqual(bss[0]['signal'], -72.0)      # stronger block won
        self.assertEqual(bss[0]['ssid'], 'HomeNet')

    def test_sorted_strongest_first(self):
        aps = recon.parse_iw_scan(IW_DUMP)
        sigs = [a['signal'] for a in aps]
        self.assertEqual(sigs, sorted(sigs, reverse=True))
        self.assertEqual(aps[0]['ssid'], 'OpenGuest')

    def test_no_internal_keys_leak(self):
        aps = recon.parse_iw_scan(IW_DUMP)
        for ap in aps:
            for k in list(ap):
                self.assertFalse(k.startswith('_'), k)

    def test_empty_and_garbage_input(self):
        self.assertEqual(recon.parse_iw_scan(''), [])
        self.assertEqual(recon.parse_iw_scan('command failed: -95\n'), [])


class VendorLookup(unittest.TestCase):
    def setUp(self):
        self._saved = (recon._oui_cache, recon._OUI_PATHS)
        recon._oui_cache = None
        self._tmp = tempfile.mkdtemp()
        nmap = os.path.join(self._tmp, 'mac-prefixes')
        with open(nmap, 'w') as fh:
            fh.write('# generated\nF01898 Apple, Inc.\nACDE48 Apple, Inc.\n')
        ieee = os.path.join(self._tmp, 'oui.txt')
        with open(ieee, 'w') as fh:
            fh.write('04-F0-21   (hex)\t\tHomeNet Corp\n'
                     '04F021     (base 16)\t\tHomeNet Corp\n'
                     'Junk line that must be ignored\n')
        recon._OUI_PATHS = (nmap, ieee)

    def tearDown(self):
        recon._oui_cache, recon._OUI_PATHS = self._saved
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_nmap_and_ieee_formats(self):
        self.assertEqual(recon.vendor_of('F0:18:98:11:22:33'), 'Apple, Inc.')
        self.assertEqual(recon.vendor_of('f0:18:98:00:00:00'), 'Apple, Inc.')
        self.assertEqual(recon.vendor_of('AC:DE:48:00:11:22'), 'Apple, Inc.')
        self.assertEqual(recon.vendor_of('04:f0:21:aa:bb:cc'), 'HomeNet Corp')

    def test_unknown_oui_empty(self):
        self.assertEqual(recon.vendor_of('12:34:56:78:9a:bc'), '')
        self.assertEqual(recon.vendor_of(''), '')
        self.assertEqual(recon.vendor_of(None), '')


class ScanIfaceSelection(unittest.TestCase):
    """The scan iface must never be an AP/monitor vif (iw scan fails there)."""

    def setUp(self):
        self._saved_cfg = config.RECON_IFACE
        self._saved = (linuxutil.default_route_iface,
                       linuxutil.ordered_devices,
                       linuxutil.iface_mode,
                       linuxutil.phy_banned,
                       linuxutil.phy_modes)
        config.RECON_IFACE = ''

    def tearDown(self):
        config.RECON_IFACE = self._saved_cfg
        (linuxutil.default_route_iface, linuxutil.ordered_devices,
         linuxutil.iface_mode, linuxutil.phy_banned,
         linuxutil.phy_modes) = self._saved

    def _devices(self, *names):
        return [{'phy': 'phy%d' % i, 'iface': n, 'mac': ''}
                for i, n in enumerate(names)]

    def test_env_override_wins(self):
        config.RECON_IFACE = 'wlanX'
        linuxutil.ordered_devices = lambda: self._devices('wlan0')
        linuxutil.default_route_iface = lambda: 'wlan0'
        linuxutil.iface_mode = lambda n: 'managed'
        self.assertEqual(recon.default_scan_iface(), 'wlanX')

    def test_managed_uplink_preferred(self):
        linuxutil.ordered_devices = lambda: self._devices('wlan0', 'wlan1')
        linuxutil.default_route_iface = lambda: 'wlan1'
        linuxutil.iface_mode = lambda n: 'managed'
        linuxutil.phy_banned = lambda p: False
        linuxutil.phy_modes = lambda p: {'managed', 'AP'}
        self.assertEqual(recon.default_scan_iface(), 'wlan1')

    def test_ap_mode_uplink_skipped_for_managed_spare(self):
        # The operator sacrificed the uplink to hostapd — it is an AP now and
        # `iw scan` would fail on it; a managed spare must be picked instead.
        linuxutil.ordered_devices = lambda: self._devices('wlan0', 'ap0',
                                                          'mon0', 'wlan1')
        linuxutil.default_route_iface = lambda: 'wlan0'
        linuxutil.iface_mode = lambda n: {'wlan0': 'AP', 'ap0': 'AP',
                                          'mon0': 'monitor',
                                          'wlan1': 'managed'}[n]
        linuxutil.phy_banned = lambda p: False
        linuxutil.phy_modes = lambda p: {'managed', 'AP', 'monitor'}
        self.assertEqual(recon.default_scan_iface(), 'wlan1')

    def test_banned_phy_never_scanned(self):
        linuxutil.ordered_devices = lambda: self._devices('wlan0', 'wlan1')
        linuxutil.default_route_iface = lambda: None
        linuxutil.iface_mode = lambda n: 'managed'
        linuxutil.phy_modes = lambda p: {'managed', 'AP'}

        def banned(phy):
            return phy == 'phy0'
        linuxutil.phy_banned = banned
        self.assertEqual(recon.default_scan_iface(), 'wlan1')

    def test_no_wifi_devices_returns_none(self):
        linuxutil.ordered_devices = lambda: []
        linuxutil.default_route_iface = lambda: None
        self.assertIsNone(recon.default_scan_iface())


class ScanWifiDriver(unittest.TestCase):
    def setUp(self):
        self._saved_run = linuxutil.run
        self._saved_iface = recon.default_scan_iface
        self._saved_last = recon._last_aps

    def tearDown(self):
        linuxutil.run = self._saved_run
        recon.default_scan_iface = self._saved_iface
        recon._last_aps = self._saved_last

    def test_happy_path_returns_aps_and_meta(self):
        recon.default_scan_iface = lambda: 'wlan0'
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 0, 'stdout': IW_DUMP, 'stderr': ''})()
        res = recon.scan_wifi()
        self.assertEqual(res['ok'], 1)
        self.assertEqual(res['iface'], 'wlan0')
        self.assertEqual(res['error'], '')
        self.assertIn('ts', res)
        self.assertEqual(len(res['aps']), 6)     # 7 blocks, 6 unique BSSIDs
        self.assertEqual(res['aps'][0]['ssid'], 'OpenGuest')

    def test_scan_aps_legacy_wrapper_keeps_list_contract(self):
        recon.default_scan_iface = lambda: 'wlan0'
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 0, 'stdout': IW_DUMP, 'stderr': ''})()
        aps = recon.scan_aps()
        self.assertIsInstance(aps, list)
        self.assertTrue(aps)

    def test_iw_failure_surfaces_error(self):
        recon.default_scan_iface = lambda: 'wlan0'
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 233, 'stdout': '',
                      'stderr': 'command failed: Operation not supported '
                                '(-95)\nsecond line'})()
        res = recon.scan_wifi()
        self.assertEqual(res['ok'], 0)
        self.assertEqual(res['aps'], [])
        self.assertIn('Operation not supported', res['error'])
        self.assertNotIn('second line', res['error'])   # first line only

    def test_no_iface_surfaces_error(self):
        recon.default_scan_iface = lambda: None
        res = recon.scan_wifi()
        self.assertEqual(res['ok'], 0)
        self.assertEqual(res['aps'], [])
        self.assertIn('no wifi interface', res['error'])

    def test_scan_wifi_publishes_last_fidelity_snapshot(self):
        recon.default_scan_iface = lambda: 'wlan0'
        linuxutil.run = lambda argv, timeout=10: type(
            'R', (), {'returncode': 0, 'stdout': FIDELITY_DUMP, 'stderr': ''})()
        self.assertEqual(recon._last_aps, [])
        res = recon.scan_wifi()
        self.assertEqual(res['ok'], 1)
        self.assertEqual(len(recon._last_aps), 2)
        fast = _by_ssid(res['aps'], 'FastNet')
        self.assertIsNotNone(recon.fidelity_for(fast['bssid']))
        self.assertIsNone(recon.fidelity_for('00:00:00:00:00:00'))


FIDELITY_DUMP = """
BSS 11:22:33:44:55:66(on wlan0)
	freq: 2437
	capability: ESS Privacy
	signal: -62.00 dBm
	SSID: FastNet
	Supported rates: 1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0
	DS Parameter set: channel 6
	HT capabilities:
		Capabilities: 0x1f
		HT20/HT40
		Short GI 20MHz: 1
		Short GI 40MHz: 1
		RX STBC: 1
		LDPC Coding Capability
		Max RX AMPDU length: 65535 bytes
	HT operation:
		* primary channel: 6
		* secondary channel offset: above
		* STA channel width: any
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: PSK
	WMM:
	 * Parameter version 1

BSS de:ad:be:ef:00:99(on wlan0)
	freq: 5240
	capability: ESS Privacy
	signal: -70.00 dBm
	SSID: FiveG
	Extended supported rates: 6.0 9.0 12.0 18.0 24.0 36.0 48.0 54.0
	Beacon interval: 100 TUs
	DTIM period: 3
	VHT capabilities:
		Capabilities: 0x0
	HE capabilities:
		...
	RSN:
	 * Version: 1
	 * Group cipher: CCMP
	 * Pairwise ciphers: CCMP
	 * Authentication suites: PSK
"""


class BeaconFidelityParsing(unittest.TestCase):
    """C7: the recon pass must observe enough of a beacon to replay the
    target's non-identifying phantom (rates, beacon timing, HT profile)."""

    def setUp(self):
        self._saved = recon._last_aps
        recon._last_aps = []

    def tearDown(self):
        recon._last_aps = self._saved

    def test_ht_beacon_fidelity_fields(self):
        aps = recon.parse_iw_scan(FIDELITY_DUMP)
        fast = _by_ssid(aps, 'FastNet')
        self.assertIsNotNone(fast)
        f = fast['fidelity']
        self.assertIn(54, f['rates'])
        self.assertIn(18, f['rates'])
        self.assertIn(5.5, f['rates'])          # observed set kept intact
        self.assertIn(1, f['basic'])
        self.assertNotIn(24, f['basic'])        # only `*`-marked rates are basic
        self.assertIn('ht', f)
        self.assertEqual(f['ht'].get('ht40'), '+')   # secondary channel above
        self.assertTrue(f['ht'].get('short_gi20'))
        self.assertTrue(f['ht'].get('short_gi40'))
        self.assertTrue(f['ht'].get('rx_stbc'))
        self.assertTrue(f['ht'].get('ldpc'))

    def test_vht_he_and_beacon_meta(self):
        aps = recon.parse_iw_scan(FIDELITY_DUMP)
        five = _by_ssid(aps, 'FiveG')
        f = five['fidelity']
        self.assertEqual(f.get('beacon_int'), 100)
        self.assertEqual(f.get('dtim'), 3)
        self.assertIn(54, f['rates'])
        self.assertIn(6, f['rates'])
        self.assertTrue(f['ht'].get('vht'))
        self.assertTrue(f['ht'].get('he'))

    def test_no_private_keys_leak_from_fidelity_dump(self):
        aps = recon.parse_iw_scan(FIDELITY_DUMP)
        for ap in aps:
            for k in list(ap):
                self.assertFalse(k.startswith('_'), k)

    def test_fidelity_for_looks_up_last_scan(self):
        aps = recon.parse_iw_scan(FIDELITY_DUMP)
        recon._last_aps = aps
        fast = _by_ssid(aps, 'FastNet')
        f = recon.fidelity_for(fast['bssid'])
        self.assertIsInstance(f, dict)
        self.assertIn('rates', f)
        self.assertEqual(recon.fidelity_for('00:00:00:00:00:00'), None)
        self.assertEqual(recon.fidelity_for(''), None)


if __name__ == '__main__':
    unittest.main()
