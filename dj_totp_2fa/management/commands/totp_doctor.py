import json
import socket
import struct
import sys
import time

from django.conf import settings
from django.contrib.staticfiles import finders
from django.core.cache import caches
from django.core.management.base import BaseCommand
from django.core.checks import run_checks
from django.template.loader import get_template

from dj_totp_2fa import conf, crypto, totp as core
from dj_totp_2fa.models import Lockout, RecoveryCode, TOTPDevice, TrustedBrowser, TwoFactorEvent

TEMPLATES = ["base", "layout", "login", "verify", "setup", "recovery_codes", "overview", "devices", "recovery", "trusted", "disable", "done"]
STATIC = ["css/base.css", "css/themes/clean.css", "css/themes/midnight.css", "css/themes/aurora.css", "js/totp.js", "js/vendor/qrcode.min.js"]
NTP_EPOCH = 2208988800


def ntp_offset(server="pool.ntp.org", timeout=2.0):
    """Seconds the local clock is ahead of NTP (SNTP, one packet). Raises OSError when unreachable."""
    packet = b"\x1b" + 47 * b"\0"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        t0 = time.time()
        s.sendto(packet, (server, 123))
        data, _addr = s.recvfrom(512)
        t1 = time.time()
    seconds, fraction = struct.unpack("!II", data[40:48])
    server_time = seconds - NTP_EPOCH + fraction / 2 ** 32
    return (t0 + t1) / 2 - server_time


class Command(BaseCommand):
    help = "Check configuration, database, cache, middleware, templates, static files and the clock."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--strict", action="store_true", help="Exit non-zero on warnings too.")
        parser.add_argument("--no-network", action="store_true", help="Skip the NTP clock check.")

    def handle(self, *args, **options):
        results = []

        def add(name, status, detail=""):
            results.append({"check": name, "status": status, "detail": detail})

        # known answer test: RFC 6238 SHA1 vector at T=59
        ok = core.totp(b"12345678901234567890", 59, 8, 30, "SHA1") == "94287082"
        add("crypto self-test (RFC 6238 vector)", "ok" if ok else "fail", "" if ok else "TOTP output does not match the RFC")

        issues = run_checks(include_deployment_checks=True)
        mine = [i for i in issues if i.id and i.id.startswith("dj_totp_2fa.")]
        if not mine:
            add("system checks", "ok", "no dj_totp_2fa findings")
        for i in mine:
            add("check " + i.id, "fail" if i.level >= 40 else "warn", i.msg)

        try:
            counts = {"devices": TOTPDevice.objects.count(), "recovery_codes": RecoveryCode.objects.count(),
                      "trusted_browsers": TrustedBrowser.objects.count(), "events": TwoFactorEvent.objects.count(), "lockouts": Lockout.objects.count()}
            add("database tables", "ok", ", ".join("%s=%d" % kv for kv in counts.items()))
        except Exception as exc:
            add("database tables", "fail", "%s (did you run migrate?)" % exc)

        try:
            cache = caches[conf.get("CACHE_ALIAS")]
            cache.set("djtotp:doctor", "1", 5)
            hit = cache.get("djtotp:doctor") == "1"
            cache.incr("djtotp:doctor-n") if cache.add("djtotp:doctor-n", 0, 5) else None
            add("cache (%s)" % conf.get("CACHE_ALIAS"), "ok" if hit else "fail",
                settings.CACHES[conf.get("CACHE_ALIAS")]["BACKEND"].rsplit(".", 1)[-1])
        except Exception as exc:
            add("cache", "fail", str(exc))

        mw = settings.MIDDLEWARE
        add("middleware", "ok" if "dj_totp_2fa.middleware.TwoFactorMiddleware" in mw else "warn",
            "TwoFactorMiddleware installed" if "dj_totp_2fa.middleware.TwoFactorMiddleware" in mw else "TwoFactorMiddleware missing: only the built-in login views enforce 2FA")
        add("messages", "ok" if "django.contrib.messages.middleware.MessageMiddleware" in mw else "warn", "needed for notices and the grace period reminder")

        add("secret storage", "ok" if crypto.active_mode() != "none" else "warn", "mode: " + crypto.active_mode())

        bad = []
        for name in TEMPLATES:
            try:
                get_template("dj_totp_2fa/%s.html" % name)
            except Exception as exc:
                bad.append("%s: %s" % (name, exc))
        try:
            get_template(conf.get("BASE_TEMPLATE"))
        except Exception as exc:
            bad.append("BASE_TEMPLATE: %s" % exc)
        add("templates", "fail" if bad else "ok", "; ".join(bad) or "%d templates load" % (len(TEMPLATES) + 1))

        missing = [p for p in STATIC if not finders.find("dj_totp_2fa/" + p)]
        if not settings.STATIC_URL:
            add("static files", "warn", "STATIC_URL is not set")
        else:
            add("static files", "fail" if missing else "ok", ("missing: " + ", ".join(missing)) if missing else "all assets found")

        if options["no_network"]:
            add("clock (NTP)", "skip", "skipped (--no-network)")
        else:
            try:
                offset = ntp_offset()
                limit = conf.window() * int(conf.get("PERIOD")) or int(conf.get("PERIOD"))
                status = "ok" if abs(offset) < limit / 2 else "warn"
                add("clock (NTP)", status, "server clock is %+.2f s from pool.ntp.org (codes tolerate about %d s)" % (offset, limit))
            except OSError:
                add("clock (NTP)", "warn", "could not reach an NTP server, so clock drift is unverified. Run chrony/ntpd/systemd-timesyncd on every web server; "
                                           "phones sync automatically, so a drifting server is the usual cause of rejected codes.")

        failed = any(r["status"] == "fail" for r in results)
        warned = any(r["status"] == "warn" for r in results)
        if options["json"]:
            self.stdout.write(json.dumps({"ok": not failed and not (options["strict"] and warned), "results": results}, indent=2))
        else:
            for r in results:
                tag = {"ok": self.style.SUCCESS("OK  "), "warn": self.style.WARNING("WARN"), "fail": self.style.ERROR("FAIL"), "skip": "SKIP"}[r["status"]]
                self.stdout.write("%s  %-34s %s" % (tag, r["check"], r["detail"]))
        if failed or (options["strict"] and warned):
            sys.exit(1)
