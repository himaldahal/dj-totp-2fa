"""What the session remembers about two-factor state."""
import time

from . import conf

VERIFIED_KEY = "dj_totp_verified"          # unix time of the first verification in this session
METHOD_KEY = "dj_totp_verified_method"     # totp | recovery | trusted_browser
USER_KEY = "dj_totp_verified_user"         # the user the flag belongs to
FRESH_KEY = "dj_totp_fresh_at"             # unix time of the last explicit code check (step-up)
PENDING_KEY = "dj_totp_pending"
SETUP_KEY = "dj_totp_setup"
NAG_KEY = "dj_totp_nag_at"
ALL_KEYS = (VERIFIED_KEY, METHOD_KEY, USER_KEY, FRESH_KEY)


def mark_verified(request, user, method, fresh=True):
    s = request.session
    now = time.time()
    s[VERIFIED_KEY] = now
    s[METHOD_KEY] = method
    s[USER_KEY] = str(user.pk)
    if fresh:
        s[FRESH_KEY] = now
    else:
        s.pop(FRESH_KEY, None)
    request._dj_totp_verified_cache = True


def mark_fresh(request):
    request.session[FRESH_KEY] = time.time()


def clear(request):
    for key in ALL_KEYS:
        request.session.pop(key, None)
    request._dj_totp_verified_cache = False


def is_verified(request):
    """True when this session passed a second-factor check for the current user (and it has not aged out)."""
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        return False
    session = getattr(request, "session", None)
    if session is None:
        return False
    stamp = session.get(VERIFIED_KEY)
    if stamp is None or session.get(USER_KEY) != str(user.pk):
        return False
    max_age = conf.get("VERIFIED_MAX_AGE")
    if max_age and time.time() - float(stamp) > int(max_age):
        return False
    return True


def verified_method(request):
    return request.session.get(METHOD_KEY) if is_verified(request) else None


def fresh_age(request):
    """Seconds since the last explicit code check, or None when there was none in this session."""
    if not is_verified(request):
        return None
    stamp = request.session.get(FRESH_KEY)
    return None if stamp is None else max(0.0, time.time() - float(stamp))


def is_fresh(request, max_age=None):
    age = fresh_age(request)
    limit = conf.get("FRESH_MAX_AGE") if max_age is None else max_age
    return age is not None and age <= int(limit)
