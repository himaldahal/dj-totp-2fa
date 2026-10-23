"""Secret storage: plaintext, Fernet (optional ``cryptography``) or a pair of your own callables.

Stored values carry a short prefix so rows written under one mode stay readable after the mode changes:

* ``p1$<base32>``      plaintext
* ``f1$<fernet token>`` Fernet (first key encrypts, all keys decrypt)
* ``c1$<custom>``      your own encrypt callable
"""
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from . import conf

PLAIN, FERNET, CUSTOM = "p1$", "f1$", "c1$"


class SecretError(Exception):
    """A stored secret cannot be decrypted (wrong or missing key)."""


def cryptography_available():
    try:
        import cryptography.fernet  # noqa: F401
        return True
    except ImportError:
        return False


def _keys():
    keys = conf.get("ENCRYPTION_KEYS") or []
    if isinstance(keys, (str, bytes)):
        keys = [keys]
    return [k.encode() if isinstance(k, str) else k for k in keys]


def _multifernet():
    from cryptography.fernet import Fernet, MultiFernet
    keys = _keys()
    if not keys:
        raise ImproperlyConfigured("ENCRYPTION_KEYS is empty but Fernet encryption is requested.")
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured("ENCRYPTION_KEYS holds an invalid Fernet key: %s" % exc)


def _custom_pair():
    mode = conf.get("SECRET_ENCRYPTION")
    if isinstance(mode, str) and "," in mode:
        mode = [p.strip() for p in mode.split(",")]
    if isinstance(mode, (list, tuple)) and len(mode) == 2:
        enc, dec = mode
        enc = import_string(enc) if isinstance(enc, str) else enc
        dec = import_string(dec) if isinstance(dec, str) else dec
        return enc, dec
    return None


def active_mode():
    """'none', 'fernet' or 'custom' after resolving 'auto'."""
    mode = conf.get("SECRET_ENCRYPTION")
    if _custom_pair():
        return "custom"
    mode = str(mode).lower()
    if mode == "auto":
        return "fernet" if cryptography_available() and _keys() else "none"
    if mode in ("none", "fernet"):
        return mode
    raise ImproperlyConfigured("SECRET_ENCRYPTION must be none, fernet, auto or a pair of callables.")


def encrypt(plain_b32):
    mode = active_mode()
    if mode == "fernet":
        if not cryptography_available():
            raise ImproperlyConfigured("SECRET_ENCRYPTION='fernet' needs the cryptography package (pip install dj-totp-2fa[crypto]).")
        return FERNET + _multifernet().encrypt(plain_b32.encode()).decode()
    if mode == "custom":
        return CUSTOM + _custom_pair()[0](plain_b32)
    return PLAIN + plain_b32


def decrypt(stored):
    if stored.startswith(PLAIN):
        return stored[len(PLAIN):]
    if stored.startswith(FERNET):
        if not cryptography_available():
            raise SecretError("cryptography is not installed but a secret is encrypted.")
        from cryptography.fernet import InvalidToken
        try:
            return _multifernet().decrypt(stored[len(FERNET):].encode()).decode()
        except InvalidToken:
            raise SecretError("No configured key can decrypt this secret.")
    if stored.startswith(CUSTOM):
        pair = _custom_pair()
        if not pair:
            raise SecretError("Custom encryption is not configured.")
        return pair[1](stored[len(CUSTOM):])
    raise SecretError("Unknown secret format.")


def is_current(stored):
    """True when ``stored`` already uses the active mode (and for Fernet, the primary key)."""
    mode = active_mode()
    if mode == "none":
        return stored.startswith(PLAIN)
    if mode == "custom":
        return stored.startswith(CUSTOM)
    if not stored.startswith(FERNET):
        return False
    from cryptography.fernet import Fernet, InvalidToken
    try:
        Fernet(_keys()[0]).decrypt(stored[len(FERNET):].encode())
        return True
    except InvalidToken:
        return False


def generate_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode()
