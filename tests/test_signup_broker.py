import inspect
import json
from pathlib import Path
import ssl
import sys
from threading import Barrier, Thread
import unittest
from unittest.mock import Mock, call, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    from signup_broker import Refused, SignupBroker, StaticForm, StaticPage
finally:
    sys.path.pop(0)


FIRST = "https://127.0.0.1:24101"
SECOND = "https://127.0.0.1:24102"
ADDRESS = "opaque-canary@fixture.invalid"
FIELD = '<input type="email" name="email">'
FORM = '<form method="post" action="/register">' + FIELD + "</form>"


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.now = 100
        self.browser = Mock(side_effect=lambda value: value)
        with patch.object(ssl.SSLContext, "load_verify_locations") as load_ca:
            self.broker = SignupBroker([FIRST, SECOND], "/synthetic/ca.pem", browser=self.browser, clock=lambda: self.now)
        load_ca.assert_called_once_with(cafile="/synthetic/ca.pem")
        self.assertEqual(self.broker._tls.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(self.broker._tls.check_hostname)
        self.page = StaticPage(FIRST, 24101, "/signup", "/register", b"synthetic-document-digest")
        self.fetch = Mock(return_value=self.page)
        self.submit = Mock(return_value=204)
        self.broker._fetch = self.fetch
        self.broker._submit = self.submit

    def request(self):
        prepared = self.broker.prepare(FIRST + "/signup")
        self.assertEqual(prepared["status"], "pending")
        self.assertRegex(prepared["request_id"], r"^[a-p]{32}$")
        self.assertNotIn(ADDRESS, json.dumps(prepared))
        return prepared["request_id"]

    def test_only_exact_operator_allowlisted_paths_are_prepared(self):
        for destination in (
            "http://127.0.0.1:24101/signup", "https://localhost:24101/signup",
            "https://127.0.0.1:33333/signup", "https://127.0.0.1:24101",
            "https://127.0.0.1:24101/signup?query=yes", "https://127.0.0.1:24101/signup#email",
            "https://127.0.0.1:24101//new-origin/signup", "https://127.0.0.1:24101/../signup",
            "https://127.0.0.1:24101/%2f/signup", "https://u@127.0.0.1:24101/signup",
            "https://127.0.0.1:024101/signup", "https://example.invalid/signup",
        ):
            with self.subTest(destination=destination):
                self.assertEqual(self.broker.prepare(destination), {"status": "denied"})
        self.fetch.assert_not_called()

    def test_approval_binds_to_single_request_and_model_sees_no_value(self):
        request_id = self.request()
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.browser.assert_not_called()
        self.submit.assert_not_called()
        summary = self.broker.pending()
        self.assertEqual(summary, [{
            "request_id": request_id, "origin": FIRST, "path": "/signup", "action": "/register",
            "field": "email", "status": "pending",
        }])
        self.assertEqual(self.broker.approve(request_id, ADDRESS, submit=True), {"status": "approved"})
        self.assertNotIn(ADDRESS, json.dumps(self.broker.describe(request_id)))
        self.assertEqual(self.broker.pending(), [])
        self.assertEqual(self.broker.approve(request_id, "second@fixture.invalid", submit=True), {"status": "denied"})
        self.assertEqual(self.broker.execute(request_id), {"status": "submitted"})
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.assertEqual(self.fetch.call_args_list, [call(FIRST, "/signup")] * 3)
        self.browser.assert_called_once_with(ADDRESS)
        self.submit.assert_called_once_with(self.page, ADDRESS)
        self.assertEqual(list(inspect.signature(self.broker.execute).parameters), ["request_id"])

    def test_fill_only_never_submits(self):
        request_id = self.request()
        self.assertEqual(self.broker.approve(request_id, ADDRESS), {"status": "approved"})
        self.assertEqual(self.broker.execute(request_id), {"status": "filled"})
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.browser.assert_called_once_with(ADDRESS)
        self.submit.assert_not_called()

    def test_expired_or_cancelled_authorization_cannot_fill(self):
        request_id = self.request()
        self.broker.approve(request_id, ADDRESS, submit=True)
        self.now += 120
        self.assertEqual(self.broker.execute(request_id), {"status": "expired"})
        request_id = self.request()
        self.assertEqual(self.broker.cancel(request_id), {"status": "cancelled"})
        self.assertEqual(self.broker.approve(request_id, ADDRESS), {"status": "denied"})
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.browser.assert_not_called()
        self.submit.assert_not_called()

    def test_revalidated_document_action_and_origin_must_match(self):
        for modified in (
            StaticPage(FIRST, 24101, "/signup", "/changed-action", self.page.digest),
            StaticPage(FIRST, 24101, "/signup", "/register", b"changed-document"),
            StaticPage(SECOND, 24102, "/signup", "/register", self.page.digest),
        ):
            request_id = self.request()
            self.broker.approve(request_id, ADDRESS, submit=True)
            self.fetch.return_value = modified
            self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
            self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
            self.fetch.return_value = self.page
        self.browser.assert_not_called()
        self.submit.assert_not_called()

    def test_concurrent_execution_only_performs_one_action(self):
        request_id = self.request()
        self.broker.approve(request_id, ADDRESS, submit=True)
        barrier = Barrier(2)
        outcomes = []

        def run():
            barrier.wait(timeout=5)
            outcomes.append(self.broker.execute(request_id)["status"])

        callers = [Thread(target=run) for _ in range(2)]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join(timeout=5)
        self.assertCountEqual(outcomes, ["submitted", "denied"])
        self.browser.assert_called_once_with(ADDRESS)
        self.submit.assert_called_once_with(self.page, ADDRESS)

    def test_changed_form_after_browser_fill_is_denied_before_post(self):
        request_id = self.request()
        self.broker.approve(request_id, ADDRESS, submit=True)

        def fill_then_change(email):
            self.fetch.return_value = StaticPage(FIRST, 24101, "/signup", "/modified", b"changed")
            return email

        self.browser.side_effect = fill_then_change
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.browser.assert_called_once_with(ADDRESS)
        self.submit.assert_not_called()

    def test_error_and_redirect_unknown_results_are_not_retried_or_echoed(self):
        for status in (200, 307, OSError(ADDRESS)):
            request_id = self.request()
            self.broker.approve(request_id, ADDRESS, submit=True)
            if isinstance(status, OSError):
                self.submit.side_effect = status
            else:
                self.submit.return_value = status
            result = self.broker.execute(request_id)
            self.assertEqual(result, {"status": "unknown"})
            self.assertNotIn(ADDRESS, json.dumps(result))
            self.assertEqual(self.broker.execute(request_id), {"status": "denied"})
        self.assertEqual(self.submit.call_count, 3)

    def test_only_synthetic_input_and_literal_submit_option_are_accepted(self):
        request_id = self.request()
        for invalid in ("not-an-email", "demo@example.com", "a\n@fixture.invalid"):
            self.assertEqual(self.broker.approve(request_id, invalid, submit=True), {"status": "denied"})
        self.assertEqual(self.broker.approve(request_id, ADDRESS, submit="true"), {"status": "denied"})
        self.browser.assert_not_called()

    def test_post_request_is_fixed_field_and_never_follows_redirect(self):
        del self.broker._submit
        connection = Mock()
        connection.getresponse.return_value.status = 307
        with patch.object(self.broker, "_connection", return_value=connection) as connect:
            result = self.broker._submit(self.page, ADDRESS)
        self.assertEqual(result, 307)
        connect.assert_called_once_with(24101)
        connection.request.assert_called_once_with(
            "POST", "/register", body=b"email=opaque-canary%40fixture.invalid",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        connection.close.assert_called_once()


class StaticFormTests(unittest.TestCase):
    @staticmethod
    def parse(source):
        parser = StaticForm()
        parser.feed(source)
        return parser.checked_action()

    def test_accepts_only_static_bound_form(self):
        document = ('<!doctype html><html><head><meta charset="UTF-8"></head><body>'
                    '<form method="POST" action="/register"><label for="email">Email</label>'
                    '<input type="email" name="email" id="email" required/>'
                    '<button type="submit">Continue</button></form></body></html>')
        self.assertEqual(self.parse(document), "/register")

    def test_rejects_publishers_forms_and_field_swaps_outside_scope(self):
        for source in (
            FORM.replace('action="/register"', f'action="{SECOND}/register"'),
            FORM.replace('action="/register"', 'action="//127.0.0.1:24102/register"'),
            FORM.replace('method="post"', 'method'),
            FORM.replace('method="post"', 'method="get"'),
            FORM.replace(FIELD, '<input type="text" name="email">'),
            FORM.replace(FIELD, '<input type="email" name="alternate">'),
            FORM.replace(FIELD, '<input type="email" name="email" value="already-filled">'),
            FORM.replace(FIELD, '<input type="email" name="email" name="other">'),
            FORM.replace(FIELD, FIELD * 2),
            FORM.replace("</form>", '<button formaction="/alternate">go</button></form>'),
            FORM.replace("</form>", '<input type="hidden" name="redirect"></form>'),
            '<script>alert(1)</script>' + FORM,
            '<iframe></iframe>' + FORM,
            '<html><head><title>' + FORM + '</title></head></html>',
            FORM.removesuffix("</form>"),
        ):
            with self.subTest(source=source), self.assertRaises(Refused):
                self.parse(source)


if __name__ == "__main__":
    unittest.main()
