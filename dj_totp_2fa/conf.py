"""Layered settings.

Lookup order (first hit wins):

1. the top-level Django setting ``TOTP_<NAME>``
2. the ``DJ_TOTP_2FA`` dict
3. the default in ``settings_registry``

Values are read on every call, so ``override_settings`` works in tests. Dotted strings in callable settings are
imported lazily.
"""
import difflib

from django.conf import settings
from django.utils.module_loading import import_string

from . import settings_registry

DICT_NAME = "DJ_TOTP_2FA"
PREFIX = "TOTP_"
_MISSING = object()


def _resolve(value):
    return import_string(value) if isinstance(value, str) else value


def _convert(name, value):
    kind = settings_registry.import_kind(name)
    if kind is None or value in (None, "", [], ()):
        return value
    if kind == "callable":
        return _resolve(value)
    if kind == "callables":
        return [_resolve(v) for v in value] if isinstance(value, (list, tuple)) else [_resolve(value)]
    if kind == "maybe":
        if isinstance(value, str) and "." in value:
            return import_string(value)
        return value
    return value


def raw(name):
    """The configured value before callables are imported."""
    top = getattr(settings, PREFIX + name, _MISSING)
    if top is not _MISSING:
        return top
    given = getattr(settings, DICT_NAME, None) or {}
    if name in given:
        return given[name]
    return settings_registry.REGISTRY[name].default


def get(name):
    if name not in settings_registry.REGISTRY:
        raise KeyError("Unknown dj_totp_2fa setting %r" % name)
    value = raw(name)
    if name == "NOTIFY" and isinstance(value, dict):
        merged = dict(settings_registry.REGISTRY["NOTIFY"].default)
        merged.update(value)
        return merged
    if name == "ENDPOINT_RATE_LIMITS" and isinstance(value, dict):
        merged = dict(settings_registry.REGISTRY["ENDPOINT_RATE_LIMITS"].default)
        merged.update(value)
        return merged
    return _convert(name, value)


class _Conf:
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return get(name)
        except KeyError:
            raise AttributeError(name)


conf = _Conf()


def int_setting(name, low=None, high=None):
    value = int(get(name))
    if low is not None:
        value = max(low, value)
    if high is not None:
        value = min(high, value)
    return value


def window():
    return int_setting("WINDOW", 0, 2)


def unknown_keys():
    """Names the user configured that the registry does not know: [(where, key, suggestion or None)]."""
    known = set(settings_registry.REGISTRY)
    found = []
    given = getattr(settings, DICT_NAME, None)
    if isinstance(given, dict):
        for key in given:
            if key not in known:
                found.append((DICT_NAME, key, _suggest(key, known)))
    for attr in dir(settings):
        if attr.startswith(PREFIX) and attr.isupper() and attr[len(PREFIX):] not in known:
            found.append(("settings", attr, _suggest(attr[len(PREFIX):], known)))
    return found


def _suggest(key, known):
    close = difflib.get_close_matches(str(key).upper(), list(known), n=1, cutoff=0.6)
    return close[0] if close else None
