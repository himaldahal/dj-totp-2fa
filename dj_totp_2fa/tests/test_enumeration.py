"""No distinguishing messages, equal work, and no user enumeration through the 2FA pages."""
import re
from unittest import mock

from django.contrib.auth.hashers import check_password as real_check_password
from django.test import Client, TestCase
from django.urls import reverse

from dj_totp_2fa import api, session as sess, totp as core
from dj_totp_2fa.models import RecoveryCode

from .base import TotpCase, code_for, enable, login, make_user


def normalise(response):
    text = response.content.decode()
    text = re.sub(r'name="csrfmiddlewaretoken" value="[^"]+"', "csrf", text)
    text = re.sub(r'name="form_token" value="[^"]+"', "token", text)
    text = re.sub(r"\d+ attempts? left", "N attempts left", text)
    return response.status_code, text


class ResponseParityTests(TotpCase):
    def test_all_failure_causes_render_the_same_page(self):
        """Wrong code, replayed code, malformed code and a vetoed attempt are indistinguishable."""
        results = []
        used = code_for(self.device)
        api.verify_code(self.user, used)  # consume the current step so that `used` is a replay
        for attempt in ("000000", used, "abc", "12"):
            client = Client()
            login(client, self.user)
            r = client.post(reverse("dj_totp_2fa:verify"), {"code": attempt})
            results.append(normalise(r))
        self.assertEqual(len(set(results[:2])), 1, "wrong and replayed codes differ")
        self.assertEqual(results[0][0], 200)
        self.assertIn("did not work", results[0][1])

    def test_pending_for_a_missing_user_looks_like_no_pending(self):
        client = Client()
        login(client, self.user)
        no_pending = Client().post(reverse("dj_totp_2fa:verify"), {"code": "000000"})
        self.user.delete()
        gone = client.post(reverse("dj_totp_2fa:verify"), {"code": "000000"})
        self.assertEqual((no_pending.status_code, no_pending["Location"]), (gone.status_code, gone["Location"]))

    def test_unknown_and_known_users_fail_identically_at_the_api(self):
        ghost = make_user("ghost")  # exists but has no device at all
        a = api.verify_code(self.user, "000000")
        b = api.verify_code(ghost, "000000")
        c = api.verify_code(None, "000000")
        self.assertEqual({a.message, b.message, c.message}, {a.message})
        self.assertEqual({a.reason, c.reason}, {"invalid"})

    def test_verify_pages_do_not_name_the_user(self):
        login(self.client, self.user)
        page = self.client.get(reverse("dj_totp_2fa:verify")).content.decode()
        self.assertNotIn(self.user.username, page)
        self.assertNotIn(self.user.email, page)


class EqualWorkTests(TotpCase):
    def count_work(self, user, code, method="totp"):
        calls = {"match": 0, "hash": 0}
        real_match = core.match_steps

        def counting_match(*a, **kw):
            calls["match"] += 1
            return real_match(*a, **kw)

        def counting_hash(*a, **kw):
            calls["hash"] += 1
            return real_check_password(*a, **kw)

        with mock.patch("dj_totp_2fa.totp.match_steps", counting_match), mock.patch("dj_totp_2fa.api.check_password", counting_hash):
            api.verify_code(user, code, method=method)
        return calls

    def test_totp_path_does_the_same_hmac_work_for_every_caller(self):
        ghost = make_user("ghost")
        locked = make_user("locked")
        enable(locked)
        from .test_ratelimit import fail
        fail(locked, n=10)
        baseline = self.count_work(self.user, "000000")
        self.assertEqual(baseline["match"], 1)
        self.assertEqual(self.count_work(ghost, "000000")["match"], 1)
        self.assertEqual(self.count_work(None, "000000")["match"], 1)
        self.assertEqual(self.count_work(locked, "000000")["match"], 1)

    def test_recovery_path_hashes_a_constant_number_of_times(self):
        api.generate_recovery_codes(self.user)
        ghost = make_user("ghost")
        few = make_user("few")
        enable(few)
        api.generate_recovery_codes(few, count=3)
        n = self.count_work(self.user, "AAAAA-BBBBB", "recovery")["hash"]
        self.assertEqual(n, 10)
        self.assertEqual(self.count_work(ghost, "AAAAA-BBBBB", "recovery")["hash"], 10)
        self.assertEqual(self.count_work(few, "AAAAA-BBBBB", "recovery")["hash"], 10)
        self.assertEqual(self.count_work(None, "AAAAA-BBBBB", "recovery")["hash"], 10)

    def test_every_window_candidate_is_computed_without_early_exit(self):
        calls = []
        real = core.hotp

        def spy(*a, **kw):
            calls.append(a[1])
            return real(*a, **kw)

        with mock.patch("dj_totp_2fa.totp.hotp", spy):
            core.match_steps(b"k" * 20, real(b"k" * 20, 100, 6), 100, 2, 6)  
        self.assertEqual(sorted(calls), [98, 99, 100, 101, 102])  # all five, even though step 100 matched

    def test_compare_digest_is_used(self):
        with mock.patch("dj_totp_2fa.totp.hmac.compare_digest", wraps=__import__("hmac").compare_digest) as spy:
            core.match_steps(b"k" * 20, "123456", 5, 1, 6)
        self.assertEqual(spy.call_count, 3)
