from django.contrib.auth import get_user_model
from django.core.management.base import CommandError


def get_user(identifier):
    User = get_user_model()
    manager = User._default_manager
    for lookup in (lambda: manager.get_by_natural_key(identifier), lambda: manager.get(pk=identifier), lambda: manager.get(email__iexact=identifier)):
        try:
            return lookup()
        except Exception:
            continue
    raise CommandError("No user matches %r." % identifier)


def table(rows, headers):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h)) for i, h in enumerate(headers)]
    line = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    for row in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))
    return "\n".join(out)


def require_debug(command, options):
    from django.conf import settings

    from dj_totp_2fa import conf
    if settings.DEBUG or options.get("force") or conf.get("DEBUG_COMMANDS"):
        return
    raise CommandError("%s prints or creates valid codes and only runs with DEBUG=True (or --force, or TOTP_DEBUG_COMMANDS)." % command)
