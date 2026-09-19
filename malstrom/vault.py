"""At-rest vault for mirrored loot.

On an on-site laptop the operator wants the *mirrored* credential stores on
disk encrypted — the live STATE_DIR copy must stay plaintext so the engine and
dashboard can keep working, but the loot copy (the bit that gets carried off /
synced out) should not be human-readable if the box is seized.

This uses Fernet (AES-128-CBC + HMAC-SHA256, via python3-cryptography) with a
key kept in STATE_DIR/.vault.key (chmod 0600). The key sits beside the data, so
this is protection against a *casual* reader of the seized disk, not against a
targeted attacker already on the box — that gap is covered by the audit trail,
the engagement integrity snapshots and restrictive file modes. When
cryptography is missing the vault degrades to plaintext (never pseudo-crypto):
callers check `available()`. Everything is stdlib + cryptography; tests skip
the encrypted path on hosts without the lib.
"""

import os

from . import config
from . import state

_FERNET = None
_OK = None


def available():
    """True when the encrypted vault can actually be used."""
    global _OK
    if _OK is None:
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            _OK = False
        else:
            _OK = True
    return _OK


def _fernet():
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    from cryptography.fernet import Fernet
    _FERNET = Fernet(_key_bytes())
    return _FERNET


def _key_bytes():
    key = b''
    try:
        with open(state.VAULT_KEY_FILE, 'rb') as fh:
            key = fh.read().strip()
    except IOError:
        pass
    from cryptography.fernet import Fernet
    try:
        Fernet(key)
    except (ValueError, TypeError):
        key = Fernet.generate_key()
        try:
            os.makedirs(config.STATE_DIR, exist_ok=True)
        except OSError:
            pass
        try:
            with open(state.VAULT_KEY_FILE, 'wb') as fh:
                fh.write(key)
            try:
                os.chmod(state.VAULT_KEY_FILE, 0o600)
            except OSError:
                pass
        except OSError:
            return b''
    return key


def encrypt(data):
    """Fernet-encrypt `data` (bytes) — raises if cryptography is missing."""
    return _fernet().encrypt(data)


def decrypt(data):
    """Reverse encrypt(). Raises ValueError on bad payload/key."""
    return _fernet().decrypt(data)


def reload():
    """Drop the cached key/Fernet (for tests pointing VAULT_KEY_FILE elsewhere)."""
    global _FERNET, _OK
    _FERNET = None
    _OK = None