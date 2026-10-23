"""Helpers that keep secrets and submitted codes out of logs, reprs and admin pages."""
import logging
import re

_PATTERNS = [
    re.compile(r"(secret=)[A-Za-z0-9=%]+", re.I),
    re.compile(r"(secret['\"]?\s*[:=]\s*['\"]?)[A-Za-z2-7]{16,}", re.I),
    re.compile(r"(code['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9-]{6,12}", re.I),
]


def mask(value, keep=0):
    """'****' for any secret value. Never returns characters of the input unless ``keep`` asks for a prefix."""
    text = str(value or "")
    if not text:
        return ""
    return (text[:keep] if keep else "") + "****"


def scrub(text):
    out = str(text)
    for pattern in _PATTERNS:
        out = pattern.sub(lambda m: m.group(1) + "[redacted]", out)
    return out


class RedactingFilter(logging.Filter):
    def filter(self, record):
        try:
            record.msg = scrub(record.getMessage())
            record.args = ()
        except Exception:  # pragma: no cover - logging must never break the request
            pass
        return True
