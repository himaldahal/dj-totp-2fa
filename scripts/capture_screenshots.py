#!/usr/bin/env python
"""Generate docs/screenshots/<theme>/<step>-<desktop|mobile>.png from the real pages.

Usage:  ../.venv/bin/python scripts/capture_screenshots.py [--themes clean,midnight,aurora] [--steps 02-verify,...]

It builds a throwaway sqlite database, seeds a demo user (secret known to this script, so it can produce valid codes
the way the totp_code command does), starts the demo project once per theme and drives headless Chromium.
Nothing here touches a real service.
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"
THEMES = ("clean", "midnight", "aurora")
SIZES = {"desktop": (1280, 800), "mobile": (390, 844)}
BROWSERS = ("/snap/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/chromium", "/usr/bin/google-chrome")
SNAP_DIR = Path.home() / "snap" / "chromium" / "common" / "totp-shots"  # snap browsers may only write under $HOME

# step -> (path, virtual time budget ms, tall window height for desktop or None)
STEPS = {
    "01-login": ("/_shot/logout/?to=/account/2fa/login/", 0),
    "02-verify": ("/_shot/verify/", 1500),
    "03-verify-error": ("/_shot/verify-error/", 1500),
    "04-verify-locked": ("/_shot/verify-locked/", 1500),
    "05-setup-scan": ("/_shot/newbie/?to=/account/2fa/setup/%23step-2", 2500),
    "06-setup-confirm": ("/_shot/newbie/?to=/account/2fa/setup/%23step-3", 2500),
    "07-recovery-codes": ("/_shot/recovery-codes/", 1500),
    "08-overview": ("/_shot/alice/?to=/account/2fa/", 1500),
    "09-devices": ("/_shot/alice/?to=/account/2fa/devices/", 1500),
    "10-trusted-browsers": ("/_shot/alice/?to=/account/2fa/trusted/", 1500),
    "11-disable-confirm": ("/_shot/alice/?to=/account/2fa/disable/", 1500),
    "12-enforced-enrolment": ("/_shot/forced/?to=/", 2500),
    "13-success": ("/_shot/alice/?to=/account/2fa/done/", 1500),
}


def find_browser():
    for path in BROWSERS:
        if os.path.exists(path):
            return path
    sys.exit("No Chromium found (tried: %s)" % ", ".join(BROWSERS))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def seed(db_path):
    os.environ.update(DJANGO_SETTINGS_MODULE="demo.settings", DEMO_DB=str(db_path), DEMO_SHOTS="1")
    sys.path.insert(0, str(ROOT))
    import django
    django.setup()
    from django.conf import settings
    settings.EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"  # keep seeding quiet
    from datetime import timedelta
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.utils import timezone
    from dj_totp_2fa import api, events
    from dj_totp_2fa.models import TOTPDevice, TrustedBrowser, TwoFactorEvent

    call_command("migrate", verbosity=0, interactive=False)
    User = get_user_model()
    alice = User.objects.create_user("alice", "alice@example.com", "demo-pass", first_name="Alice")
    User.objects.create_user("newbie", "newbie@example.com", "demo-pass")
    User.objects.create_user("forced", "forced@example.com", "demo-pass")
    now = timezone.now()
    phone = api.create_device(alice, "Pixel 8")
    TOTPDevice.objects.filter(pk=phone.pk).update(confirmed=True, primary=True, confirmed_at=now - timedelta(days=40),
                                                  created_at=now - timedelta(days=40), last_used_at=now - timedelta(hours=3))
    laptop = api.create_device(alice, "1Password (work laptop)")
    TOTPDevice.objects.filter(pk=laptop.pk).update(confirmed=True, confirmed_at=now - timedelta(days=12),
                                                   created_at=now - timedelta(days=12), last_used_at=now - timedelta(days=2))
    codes = api.generate_recovery_codes(alice)
    for code in codes[:3]:
        api.verify_code(alice, code, method="recovery")
    for label, days, ip in (("Firefox on Linux", 3, "203.0.113.24"), ("Chrome on Windows", 11, "198.51.100.8"), ("Safari on iOS", 20, "192.0.2.77")):
        TrustedBrowser.objects.create(user=alice, token_hash=os.urandom(32).hex(), label=label, ip=ip, created_at=now - timedelta(days=days),
                                      expires_at=now + timedelta(days=30 - days), last_seen_at=now - timedelta(days=1))
    TwoFactorEvent.objects.all().delete()
    for name, ago in (("verified", 3), ("failed", 5), ("failed", 5.1), ("recovery_used", 26), ("device_added", 12 * 24), ("trusted_added", 24 * 11)):
        e = events.record(name, None, user=alice)
        TwoFactorEvent.objects.filter(pk=e.pk).update(created_at=now - timedelta(hours=ago))


def wait_for(port, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/_shot/logout/?to=/account/2fa/login/" % port, timeout=2).read()
            return
        except Exception:
            time.sleep(0.4)
    raise RuntimeError("demo server did not start")


def shoot(browser, url, dest, size, budget, profile):
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SNAP_DIR / dest.name
    tmp.unlink(missing_ok=True)
    cmd = [browser, "--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
           "--user-data-dir=%s" % profile, "--window-size=%d,%d" % size, "--screenshot=%s" % tmp]
    if budget:
        cmd.append("--virtual-time-budget=%d" % budget)
    subprocess.run(cmd + [url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if not tmp.exists():
        raise RuntimeError("screenshot failed: " + url)
    optimise(tmp, dest, size)
    tmp.unlink()


def optimise(src, dest, size):
    from PIL import Image
    img = Image.open(src).convert("RGB")
    if img.size != size:
        img = img.crop((0, 0, min(img.width, size[0]), min(img.height, size[1])))
    dest.parent.mkdir(parents=True, exist_ok=True)
    img.save(dest, optimize=True)
    if dest.stat().st_size > 380_000:
        img.quantize(colors=200, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG).save(dest, optimize=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--themes", default=",".join(THEMES))
    ap.add_argument("--steps", default="", help="comma separated step names (default all)")
    ap.add_argument("--sizes", default=",".join(SIZES))
    args = ap.parse_args()
    browser = find_browser()
    work = Path(tempfile.mkdtemp(prefix="totp-shots-"))
    wanted = [s for s in args.steps.split(",") if s]
    steps = {k: v for k, v in STEPS.items() if not wanted or k in wanted}
    profile = SNAP_DIR / "profile"
    try:
        for theme in args.themes.split(","):
            db = work / ("%s.sqlite3" % theme)
            # seed in a child process so each theme gets a clean database and settings
            env = dict(os.environ, TOTP_THEME=theme, DEMO_DB=str(db), DEMO_SHOTS="1", PYTHONPATH=str(ROOT))
            subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r); sys.argv=['x']; import runpy; "
                            "m = runpy.run_path(%r); m['seed'](%r)" % (str(ROOT), __file__, str(db))], check=True, env=env, cwd=ROOT)
            port = free_port()
            server = subprocess.Popen([sys.executable, "demo/manage.py", "runserver", "127.0.0.1:%d" % port, "--noreload"],
                                      cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_for(port)
                for step, (path, budget) in steps.items():
                    for label in args.sizes.split(","):
                        dest = OUT / theme / ("%s-%s.png" % (step, label))
                        shoot(browser, "http://127.0.0.1:%d%s" % (port, path), dest, SIZES[label], budget, profile)
                        print("%s/%s  %d KB" % (theme, dest.name, dest.stat().st_size // 1024))
            finally:
                server.terminate()
                server.wait(10)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
