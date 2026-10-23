"""Structured logging for the ``dj_totp_2fa`` logger family.

Children: ``.auth``, ``.security``, ``.setup``, ``.admin``. Host ``LOGGING`` entries win; when none configures the
logger we only set its level (never add handlers, so nothing is printed twice).
"""
import json
import logging

from . import conf
from .redact import RedactingFilter, scrub

CHILDREN = ("auth", "security", "setup", "admin")
_filter = RedactingFilter()


class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {"time": self.formatTime(record), "level": record.levelname, "logger": record.name,
                   "message": record.getMessage()}
        extra = getattr(record, "totp", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, default=str)


def logger(child=None):
    base = conf.get("LOGGER_NAME") or "dj_totp_2fa"
    log = logging.getLogger(base + ("." + child if child else ""))
    root = logging.getLogger(base)
    if _filter not in root.filters:
        root.addFilter(_filter)
        root.addHandler(logging.NullHandler())  # library etiquette: no "last resort" stderr output
    if root.level == logging.NOTSET:
        root.setLevel(getattr(logging, str(conf.get("LOG_LEVEL")).upper(), logging.INFO))
    return log


def log_event(child, severity, message, **fields):
    log = logger(child)
    clean = {k: scrub(v) if isinstance(v, str) else v for k, v in fields.items()}
    if conf.get("LOG_FORMAT") == "json":
        text = json.dumps({"event": message, **clean}, default=str)
    else:
        text = message + (" " + " ".join("%s=%s" % kv for kv in clean.items()) if clean else "")
    log.log(severity, "%s", text, extra={"totp": clean})
