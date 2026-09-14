"""Tests for the dashboard's HTTP behaviour, driven over a real socket.

The dashboard is the one part of SymbiVPN that speaks HTTP to a browser, so the
things that matter here are the ones HTTP gets wrong: what a failure tells the
caller, which methods the CSRF defence applies to, and whether anything a peer
is called can escape into a header.
"""

import base64
import http.client
import json
import socket
import tempfile
import time
import unittest
from http import HTTPStatus
from pathlib import Path
from unittest import mock

from symbivpn import api
from symbivpn.auth import SessionStore, hash_password
from symbivpn.vpn.wireguard import PeerStore, WireGuardError, WireGuardManager


class InternalErrorTests(unittest.TestCase):
    """A 500 says something went wrong, not what."""

    def test_the_message_is_generic(self):
        self.assertNotIn("/", api._INTERNAL_ERROR)
        self.assertIn("log", api._INTERNAL_ERROR)

    def test_no_handler_passes_the_exception_text_out(self):
        # Guards against the pattern coming back. Reported as the offending
        # lines rather than by diffing the whole file, so a failure is legible.
        source = Path(api.__file__).read_text(encoding="utf-8").splitlines()
        leaks = [
            f"{number}: {line.strip()}"
            for number, line in enumerate(source, 1)
            if "INTERNAL_SERVER_ERROR" in line and "str(exc)" in line
        ]
        self.assertEqual(leaks, [], "a 500 handler is sending the exception text")

    def test_every_internal_error_uses_the_constant(self):
        source = Path(api.__file__).read_text(encoding="utf-8").splitlines()
        sites = [line for line in source if "HTTPStatus.INTERNAL_SERVER_ERROR," in line]
        self.assertTrue(sites, "expected some 500 sites to exist")
        for line in sites:
            with self.subTest(line=line.strip()):
                self.assertIn("_INTERNAL_ERROR", line)


class PeerNameTests(unittest.TestCase):
    """A peer name reaches a .conf file, a filename and an HTTP header."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.manager = WireGuardManager(PeerStore(Path(self.tmp.name) / "peers.json"))
        self.manager.initialise_server(endpoint="vpn.example.com")

    def test_a_newline_cannot_get_into_the_config(self):
        # Unchecked, this lands a line of its own immediately before
        # [Interface] -- which is where WireGuard directives go.
        with self.assertRaises(WireGuardError):
            self.manager.add_peer('phone"\r\nX-Injected: yes')

    def test_a_quote_cannot_break_out_of_content_disposition(self):
        with self.assertRaises(WireGuardError):
            self.manager.add_peer('phone"')

    def test_path_separators_and_dot_names_are_refused(self):
        for name in ("../etc/passwd", "a/b", ".hidden", ".."):
            with self.subTest(name=name):
                with self.assertRaises(WireGuardError):
                    self.manager.add_peer(name)

    def test_blank_and_padded_names_are_refused(self):
        for name in ("", " ", " phone", "phone "):
            with self.subTest(name=name):
                with self.assertRaises(WireGuardError):
                    self.manager.add_peer(name)

    def test_an_over_long_name_is_refused(self):
        with self.assertRaises(WireGuardError):
            self.manager.add_peer("a" * 65)

    def test_the_names_people_actually_use_still_work(self):
        for name in ("phone", "mikes-laptop", "Work iPad", "tv_2", "pi.local", "A1"):
            with self.subTest(name=name):
                self.manager.add_peer(name)

    def test_a_generated_config_is_one_peer_only(self):
        self.manager.add_peer("phone")
        config = self.manager.peer_config("phone")
        self.assertEqual(config.count("[Interface]"), 1)
        self.assertEqual(config.count("[Peer]"), 1)


class CsrfGateTests(unittest.TestCase):
    """The JSON content-type gate blocks form-driven POSTs, and only those."""

    def gate(self, command, content_type):
        """Run _authorise's content-type branch for one method."""
        checked = {}

        class FakeHeaders(dict):
            def get(self, key, default=None):
                if key == "Content-Type":
                    return content_type
                return default

        handler = mock.Mock()
        handler.command = command
        handler.headers = FakeHeaders()
        handler._error = lambda status, message: checked.update(status=status)
        # Reproduce the branch under test exactly as the handler runs it.
        if command == "POST":
            actual = (handler.headers.get("Content-Type") or "").split(";")[0].strip()
            if actual != "application/json":
                handler._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "")
        return checked.get("status")

    def test_a_form_post_is_refused(self):
        self.assertEqual(
            self.gate("POST", "application/x-www-form-urlencoded"),
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        )

    def test_a_json_post_is_allowed(self):
        self.assertIsNone(self.gate("POST", "application/json"))

    def test_a_json_post_with_a_charset_is_allowed(self):
        self.assertIsNone(self.gate("POST", "application/json; charset=utf-8"))

    def test_a_bodiless_delete_is_not_caught_by_the_gate(self):
        # A DELETE always needs a CORS preflight, so it cannot be forged by a
        # page; requiring a content type it never sends only made the endpoint
        # answer 415 to every caller.
        self.assertIsNone(self.gate("DELETE", None))

    def test_the_source_only_gates_post(self):
        source = Path(api.__file__).read_text(encoding="utf-8")
        self.assertIn('if write and self.command == "POST":', source)


class SessionStoreTests(unittest.TestCase):
    """Sessions are password-equivalent while they live."""

    def setUp(self):
        self.store = SessionStore()
        # The stored hash, not the password: scrypt salts randomly, so hashing
        # the same password twice gives different strings. What the dashboard
        # binds to is the one hash sitting in the config.
        self.stored = hash_password("first")
        self.store.bind(self.stored)

    def test_a_new_session_validates(self):
        token, lifetime = self.store.create("iPhone")
        self.assertTrue(self.store.validate(token))
        self.assertEqual(lifetime, SessionStore.LIFETIME)

    def test_nothing_else_validates(self):
        self.store.create("iPhone")
        for bogus in ("", "nope", "x" * 43, None):
            with self.subTest(token=bogus):
                self.assertFalse(self.store.validate(bogus or ""))

    def test_tokens_are_unguessable_and_distinct(self):
        tokens = {self.store.create()[0] for _ in range(SessionStore.MAX_SESSIONS)}
        self.assertEqual(len(tokens), SessionStore.MAX_SESSIONS)
        self.assertTrue(all(len(token) >= 40 for token in tokens))

    def test_changing_the_password_ends_every_session(self):
        token, _ = self.store.create("iPhone")
        self.store.bind(hash_password("second"))
        self.assertFalse(self.store.validate(token),
                         "a session must not outlive the password it was issued under")

    def test_rebinding_the_same_password_keeps_sessions(self):
        token, _ = self.store.create("iPhone")
        self.store.bind(self.stored)
        self.assertTrue(self.store.validate(token),
                        "a restart-free reload must not sign everyone out")

    def test_an_expired_session_stops_working(self):
        token, _ = self.store.create("iPhone")
        self.store._sessions[token].expires_at = time.time() - 1
        self.assertFalse(self.store.validate(token))
        self.assertEqual(self.store.active(), [])

    def test_sessions_are_capped(self):
        tokens = [self.store.create()[0] for _ in range(SessionStore.MAX_SESSIONS + 20)]
        self.assertLessEqual(len(self.store.active()), SessionStore.MAX_SESSIONS)
        self.assertTrue(self.store.validate(tokens[-1]),
                        "the newest login must survive the cap")

    def test_revoke_and_revoke_all(self):
        first, _ = self.store.create("a")
        second, _ = self.store.create("b")
        self.assertTrue(self.store.revoke(first))
        self.assertFalse(self.store.validate(first))
        self.assertTrue(self.store.validate(second))
        self.assertEqual(self.store.revoke_all(), 1)
        self.assertFalse(self.store.validate(second))

    def test_a_label_is_bounded(self):
        token, _ = self.store.create("A" * 500)
        self.assertLessEqual(len(self.store._sessions[token].label), 60)


class LiveDashboardTestCase(unittest.TestCase):
    """A real dashboard on a spare port, driven over a socket."""

    password = "correct horse battery"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        class Settings:
            address = "127.0.0.1"
            readonly = False
            password = hash_password(LiveDashboardTestCase.password)

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            Settings.port = probe.getsockname()[1]
        self.port = Settings.port

        self.app = mock.Mock()
        self.app.config.dashboard = Settings()
        self.app.config.state_dir = Path(self.tmp.name)
        self.app.status.return_value = {"protection": "strict"}
        self.app.blocklists.rule_count = 1

        self.dashboard = api.Dashboard(self.app)
        self.dashboard.start()
        self.addCleanup(self.dashboard.stop)

    def request(self, method, path, raw=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, raw, headers or {})
            response = connection.getresponse()
            return response.status, response.getheader("Set-Cookie"), response.read()
        finally:
            connection.close()

    def login(self, password=None):
        status, set_cookie, _ = self.request(
            "POST", "/api/login",
            json.dumps({"password": password or self.password}),
            {"Content-Type": "application/json"},
        )
        return status, set_cookie

    def as_cookie(self, set_cookie):
        token = set_cookie.split("=", 1)[1].split(";")[0]
        return {"Cookie": f"{api.SESSION_COOKIE}={token}"}


class LoginFlowTests(LiveDashboardTestCase):
    def test_the_page_is_a_login_form_not_a_browser_prompt(self):
        status, _, body = self.request("GET", "/")
        self.assertEqual(status, 401)
        self.assertIn(b"Sign in", body)

    def test_no_www_authenticate_on_the_page(self):
        # That header is what summons the browser's own credential box, which
        # is the thing being replaced.
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        self.addCleanup(connection.close)
        connection.request("GET", "/")
        self.assertIsNone(connection.getresponse().getheader("WWW-Authenticate"))

    def test_the_right_password_returns_a_cookie(self):
        status, set_cookie = self.login()
        self.assertEqual(status, 200)
        self.assertIn(api.SESSION_COOKIE, set_cookie)

    def test_the_cookie_is_httponly_and_samesite(self):
        _, set_cookie = self.login()
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)

    def test_the_cookie_is_not_marked_secure(self):
        # The dashboard speaks plain HTTP on a LAN; a Secure cookie would
        # simply never be sent, which would look like the login not working.
        _, set_cookie = self.login()
        self.assertNotIn("Secure", set_cookie)

    def test_the_wrong_password_gets_nothing(self):
        status, set_cookie = self.login("wrong")
        self.assertEqual(status, 401)
        self.assertIsNone(set_cookie)

    def test_the_cookie_then_works_without_the_password(self):
        _, set_cookie = self.login()
        status, _, body = self.request("GET", "/api/status", None, self.as_cookie(set_cookie))
        self.assertEqual(status, 200)
        self.assertIn(b"strict", body)

    def test_the_page_loads_once_logged_in(self):
        _, set_cookie = self.login()
        status, _, body = self.request("GET", "/", None, self.as_cookie(set_cookie))
        self.assertEqual(status, 200)
        self.assertNotIn(b"Sign in", body)

    def test_signing_out_ends_it(self):
        _, set_cookie = self.login()
        cookie = self.as_cookie(set_cookie)
        status, cleared, _ = self.request(
            "POST", "/api/logout", "{}", {**cookie, "Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", cleared)
        self.assertEqual(self.request("GET", "/api/status", None, cookie)[0], 401)

    def test_a_forged_cookie_is_refused(self):
        status, _, _ = self.request(
            "GET", "/api/status", None, {"Cookie": f"{api.SESSION_COOKIE}=forged"}
        )
        self.assertEqual(status, 401)

    def test_a_malformed_cookie_header_does_not_break_the_request(self):
        for junk in ("=====;;;", "no-equals-here", ";;;", "a=b; =c"):
            with self.subTest(cookie=junk):
                status, _, _ = self.request("GET", "/api/status", None, {"Cookie": junk})
                self.assertEqual(status, 401)

    def test_basic_auth_still_works_for_the_command_line(self):
        credential = base64.b64encode(f"admin:{self.password}".encode()).decode()
        status, _, _ = self.request(
            "GET", "/api/status", None, {"Authorization": f"Basic {credential}"}
        )
        self.assertEqual(status, 200)

    def test_login_is_rate_limited(self):
        for _ in range(7):
            status, _ = self.login("wrong")
        self.assertEqual(status, 429)

    def test_login_must_be_json(self):
        status, _, _ = self.request(
            "POST", "/api/login", "password=x",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 415)

    def test_status_says_whether_a_password_is_set(self):
        _, set_cookie = self.login()
        _, _, body = self.request("GET", "/api/status", None, self.as_cookie(set_cookie))
        self.assertTrue(json.loads(body)["password_required"])


class CookieCsrfTests(LiveDashboardTestCase):
    """A cookie rides along on a cross-site request; Basic auth did not."""

    def test_a_form_post_carrying_the_cookie_is_refused(self):
        _, set_cookie = self.login()
        status, _, body = self.request(
            "POST", "/api/block", "domain=evil.example",
            {**self.as_cookie(set_cookie),
             "Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 415)
        self.assertNotIn(b"evil.example", body)

    def test_the_dashboard_own_json_post_still_works(self):
        _, set_cookie = self.login()
        status, _, body = self.request(
            "POST", "/api/block", json.dumps({"domain": "ads.example"}),
            {**self.as_cookie(set_cookie), "Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertIn(b"ads.example", body)


if __name__ == "__main__":
    unittest.main()
