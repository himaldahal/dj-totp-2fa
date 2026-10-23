"""Admin pages. No secret, hash or token is ever displayed; actions are audited and permission checked."""
import csv

from django.contrib import admin, messages
from django.http import HttpResponse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _, ngettext

from . import api, events, ratelimit
from .models import Lockout, RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent, TwoFactorProfile

RESET_PERM = "dj_totp_2fa.reset_two_factor"


def reset_two_factor_for(modeladmin, request, users):
    """Shared by the device admin and the UserAdmin mixin."""
    if not request.user.has_perm(RESET_PERM):
        modeladmin.message_user(request, _("You do not have permission to reset two-factor authentication."), messages.ERROR)
        return 0
    n = 0
    for user in users:
        if api.is_enabled(user) or TrustedBrowser.objects.filter(user=user).exists():
            api.disable(user, request, actor=request.user, event="admin_reset")
            from .notify import alert_staff, notify
            notify(user, "disabled", request)
            alert_staff("admin_reset", {"user": user.pk, "by": request.user.pk})
            n += 1
    modeladmin.message_user(request, ngettext("Two-factor authentication was reset for %d user.",
                                              "Two-factor authentication was reset for %d users.", n) % n, messages.SUCCESS)
    return n


@admin.register(TOTPDevice)
class TOTPDeviceAdmin(admin.ModelAdmin):
    list_display = ("user", "name", "algorithm", "digits", "confirmed", "primary", "last_used_at", "failure_count")
    list_filter = ("confirmed", "algorithm", "primary")
    search_fields = ("user__username", "name")
    readonly_fields = ("user", "algorithm", "digits", "period", "created_at", "confirmed_at", "last_used_at", "last_used_step", "failure_count", "drift_steps")
    fields = ("user", "name", "confirmed", "primary", "window", "algorithm", "digits", "period", "drift_steps",
              "created_at", "confirmed_at", "last_used_at", "last_used_step", "failure_count")
    actions = ["disable_devices", "enable_devices", "reset_users"]

    def has_add_permission(self, request):
        return False

    @admin.action(description=_("Disable selected devices (keep them, stop accepting codes)"))
    def disable_devices(self, request, queryset):
        n = queryset.update(confirmed=False)
        self.message_user(request, _("%d device(s) disabled.") % n, messages.SUCCESS)

    @admin.action(description=_("Re-enable selected devices that were confirmed before"))
    def enable_devices(self, request, queryset):
        n = queryset.filter(confirmed_at__isnull=False).update(confirmed=True)
        self.message_user(request, _("%d device(s) re-enabled.") % n, messages.SUCCESS)

    @admin.action(description=_("Reset 2FA for the users of the selected devices"))
    def reset_users(self, request, queryset):
        users = {d.user for d in queryset.select_related("user")}
        reset_two_factor_for(self, request, users)


@admin.register(RecoveryCode)
class RecoveryCodeAdmin(admin.ModelAdmin):
    list_display = ("user", "state", "created_at", "used_at", "used_ip")
    list_filter = ("used_at",)
    search_fields = ("user__username",)
    fields = ("user", "created_at", "used_at", "used_ip")
    readonly_fields = fields

    @admin.display(description=_("State"))
    def state(self, obj):
        return _("used") if obj.used_at else _("unused")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(TrustedBrowser)
class TrustedBrowserAdmin(admin.ModelAdmin):
    list_display = ("user", "label", "ip", "created_at", "expires_at", "last_seen_at")
    search_fields = ("user__username", "label")
    fields = ("user", "label", "user_agent_summary", "ip", "created_at", "expires_at", "last_seen_at")
    readonly_fields = fields
    actions = ["revoke"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.action(description=_("Revoke selected trusted browsers"))
    def revoke(self, request, queryset):
        for browser in queryset.select_related("user"):
            events.record("trusted_revoked", request, user=browser.user, browser=browser.pk, actor=request.user.pk)
        n = queryset.count()
        queryset.delete()
        self.message_user(request, _("%d trusted browser(s) revoked.") % n, messages.SUCCESS)


@admin.register(TwoFactorEvent)
class TwoFactorEventAdmin(admin.ModelAdmin):
    list_display = ("created_at", "event", "identifier", "ip", "short_details")
    list_filter = ("event", "created_at")
    search_fields = ("identifier", "ip", "event")
    date_hierarchy = "created_at"
    readonly_fields = ("user", "identifier", "event", "ip", "user_agent", "details", "created_at")
    fields = readonly_fields
    actions = ["export_csv"]

    @admin.display(description=_("Details"))
    def short_details(self, obj):
        return ", ".join("%s=%s" % kv for kv in list(obj.details.items())[:4])

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.action(description=_("Export selected events as CSV"))
    def export_csv(self, request, queryset):
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="two-factor-events.csv"'
        writer = csv.writer(response)
        writer.writerow(["time", "event", "user", "ip", "user_agent", "details"])
        for e in queryset.iterator():
            writer.writerow([e.created_at.isoformat(), e.event, e.identifier, e.ip or "", e.user_agent, e.details])
        return response


@admin.register(Lockout)
class LockoutAdmin(admin.ModelAdmin):
    list_display = ("scope", "user", "until", "level", "reason", "is_active")
    list_filter = ("scope",)
    fields = ("scope", "user", "until", "level", "reason", "created_at", "updated_at")
    readonly_fields = fields
    actions = ["clear"]

    @admin.display(boolean=True, description=_("Active"))
    def is_active(self, obj):
        return obj.active

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    @admin.action(description=_("Clear selected lockouts"))
    def clear(self, request, queryset):
        for row in queryset.select_related("user"):
            events.record("lockout_cleared", request, user=row.user, scope=row.scope, actor=request.user.pk)
            if row.user is not None:
                ratelimit.clear_user_counters(row.user)
        n = queryset.count()
        queryset.delete()
        self.message_user(request, _("%d lockout(s) cleared.") % n, messages.SUCCESS)


@admin.register(TwoFactorProfile)
class TwoFactorProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "exempt", "grace_started_at", "grace_until")
    list_filter = ("exempt",)
    search_fields = ("user__username",)
    raw_id_fields = ("user",)


class TwoFactorStatusFilter(admin.SimpleListFilter):
    title = _("two-factor")
    parameter_name = "two_factor"

    def lookups(self, request, model_admin):
        return [("on", _("Enabled")), ("off", _("Not enabled"))]

    def value(self):
        value = super().value()
        return value[-1] if isinstance(value, (list, tuple)) else value

    def queryset(self, request, queryset):
        enabled = TOTPDevice.objects.filter(confirmed=True).values("user_id")
        if self.value() == "on":
            return queryset.filter(pk__in=enabled)
        if self.value() == "off":
            return queryset.exclude(pk__in=enabled)
        return queryset


class TwoFactorUserAdminMixin:
    """Add to your own UserAdmin:  class MyUserAdmin(TwoFactorUserAdminMixin, UserAdmin): ..."""

    def get_list_display(self, request):
        base = list(super().get_list_display(request))
        return base + ["two_factor_status"] if "two_factor_status" not in base else base

    def get_list_filter(self, request):
        base = list(super().get_list_filter(request))
        return base + [TwoFactorStatusFilter] if TwoFactorStatusFilter not in base else base

    def get_actions(self, request):
        actions = super().get_actions(request)
        if request.user.has_perm(RESET_PERM):
            actions["reset_two_factor"] = (type(self).reset_two_factor, "reset_two_factor", type(self).reset_two_factor.short_description)
        return actions

    @admin.display(description=_("2FA"), boolean=True)
    def two_factor_status(self, obj):
        return api.is_enabled(obj)

    def reset_two_factor(self, request, queryset):
        reset_two_factor_for(self, request, list(queryset))

    reset_two_factor.short_description = _("Reset two-factor authentication for selected users")
