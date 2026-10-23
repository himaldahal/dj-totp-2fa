from django import template
from django.urls import reverse
from django.utils import timezone

from .. import policy, session as sess

register = template.Library()


@register.filter
def totp_ago(value):
    """'just now', '3 hours ago' ..."""
    from django.utils.timesince import timesince
    from django.utils.translation import gettext as _
    if not value:
        return ""
    if (timezone.now() - value).total_seconds() < 60:
        return _("just now")
    return _("%(when)s ago") % {"when": timesince(value)}


@register.filter
def totp_ago(value):
    """'just now', '3 hours ago' ..."""
    from django.utils.timesince import timesince
    from django.utils.translation import gettext as _
    if not value:
        return ""
    if (timezone.now() - value).total_seconds() < 60:
        return _("just now")
    return _("%(when)s ago") % {"when": timesince(value)}


@register.filter
def group4(value):
    text = str(value or "")
    return " ".join(text[i:i + 4] for i in range(0, len(text), 4))


@register.inclusion_tag("dj_totp_2fa/_banner.html", takes_context=True)
def totp_banner(context):
    """A reminder for required users who are still inside their grace period."""
    request = context.get("request")
    data = {"show": False}
    if request is not None and request.user.is_authenticated and not policy.request_has_device(request):
        if policy.is_required(request.user, request):
            until = policy.grace_until(request.user)
            if until and until > timezone.now():
                data = {"show": True, "days": max(0, (until - timezone.now()).days), "url": reverse("dj_totp_2fa:setup")}
    return data


@register.simple_tag(takes_context=True)
def totp_verified(context):
    request = context.get("request")
    return bool(request and sess.is_verified(request))
