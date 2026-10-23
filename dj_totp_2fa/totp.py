"""RFC 4226 (HOTP) and RFC 6238 (TOTP) with the standard library only."""
import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}


def generate_secret(num_bytes=20):
    if num_bytes < 16:
        raise ValueError("A TOTP secret needs at least 16 bytes.")
    return secrets.token_bytes(num_bytes)


def b32encode(raw):
    """Base32 without padding, as authenticator apps expect."""
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def b32decode(text):
    cleaned = "".join(str(text).split()).replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(cleaned)
    except (binascii.Error, ValueError):
        raise ValueError("Not a valid base32 secret.")


def hotp(key, counter, digits=6, algorithm="SHA1"):
    """RFC 4226 section 5: HMAC, dynamic truncation, modulo 10**digits."""
    digest = ALGORITHMS[algorithm]
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def time_step(for_time=None, period=30):
    return int((time.time() if for_time is None else for_time) // period)


def totp(key, for_time=None, digits=6, period=30, algorithm="SHA1"):
    return hotp(key, time_step(for_time, period), digits, algorithm)


def clean_code(value):
    """Strip spaces and hyphens. Returns the cleaned string (digits are checked by the caller)."""
    return "".join(ch for ch in str(value or "") if ch not in " -\t\r\n")


def match_steps(key, code, now_step, window, digits=6, algorithm="SHA1"):
    """Compare ``code`` with every step in ``now_step +/- window`` and return the matching steps.

    All candidates are always computed and compared with ``hmac.compare_digest`` (no early exit), so the time taken
    does not reveal which step matched.
    """
    code = clean_code(code)
    well_formed = len(code) == digits and code.isascii() and code.isdigit()
    probe = code if well_formed else "0" * digits
    matches = []
    for offset in range(-window, window + 1):
        step = now_step + offset
        expected = hotp(key, step, digits, algorithm) if step >= 0 else "x" * digits
        if hmac.compare_digest(expected.encode(), probe.encode()) and well_formed:
            matches.append(step)
    return matches


def otpauth_uri(secret_b32, account, issuer="", algorithm="SHA1", digits=6, period=30):
    """Google "Key Uri Format": otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=...&digits=...&period=..."""
    issuer = (issuer or "").replace(":", "").strip()
    account = str(account).replace(":", "").strip()
    label = quote(account, safe="@")
    if issuer:
        label = quote(issuer, safe="") + ":" + label
    query = ["secret=" + quote(secret_b32, safe="")]
    if issuer:
        query.append("issuer=" + quote(issuer, safe=""))
    query += ["algorithm=" + algorithm, "digits=%d" % digits, "period=%d" % period]
    return "otpauth://totp/%s?%s" % (label, "&".join(query))
