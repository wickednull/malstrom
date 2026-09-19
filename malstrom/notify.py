"""Out-of-band alerting.

When MALSTROM_EXFIL_WEBHOOK is set, every ALERT-class event also gets POSTed
to the configured URL as a small JSON payload — fire-and-forget from a bounded
background queue so the engine's hot paths never block on the network. The
payload carries the event type/timestamp/message only; loot contents are never
included unless MALSTROM_NOTIFY_DETAIL=1. Best-effort: a dead endpoint just
drops the notice; nothing retries or buffers to disk.
"""

import json
import queue
import threading
import time
import urllib.error
import urllib.request

from . import config

_GQI = queue.SimpleQueue()
_thread = None
_lock = threading.Lock()
_last_sent = 0.0
RATE = 5.0  # seconds minimum between webhook writes


def _send(payload):
    body = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(config.EXFIL_WEBHOOK, data=body,
                                 method='POST',
                                 headers={
                                     'Content-Type': 'application/json',
                                     'User-Agent': 'malstrom/2',
                                 })
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


def _run():
    global _last_sent
    while True:
        item = _GQI.get()
        if item is None:
            return
        try:
            wait = RATE - (time.time() - _last_sent)
            if wait > 0:
                time.sleep(wait)
            _send(item)
            _last_sent = time.time()
        except Exception:
            pass


def notify(etype, msg, detail=''):
    """Queue one webhook notice (non-blocking). Safe to call from any thread."""
    if not config.EXFIL_WEBHOOK:
        return False
    payload = {
        'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'type': str(etype)[:32],
        'msg': str(msg)[:512],
    }
    if config.NOTIFY_DETAIL:
        payload['detail'] = (detail or '')[:2048]
    _GQI.put(payload)
    _ensure_thread()
    return True


def _ensure_thread():
    global _thread
    with _lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_run, daemon=True)
            _thread.start()


def stop():
    """Drain the queue and stop the worker (used by app cleanup; tests use
    notify/_send directly)."""
    global _thread
    _GQI.put(None)
    with _lock:
        _thread = None


def reset():
    """For tests: clear queue + thread, reset rate limiter."""
    global _thread
    try:
        while True:
            _GQI.get_nowait()
    except queue.Empty:
        pass
    with _lock:
        _thread = None