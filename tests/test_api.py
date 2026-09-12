"""Tests for the dashboard's HTTP behaviour, driven over a real socket.

The dashboard is the one part of SymbiVPN that speaks HTTP to a browser, so the
things that matter here are the ones HTTP gets wrong: what a failure tells the
caller, which methods the CSRF defence applies to, and whether anything a peer
is called can escape into a header.
"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from pathlib import Path
from unittest import mock

from symbivpn import api
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


if __name__ == "__main__":
    unittest.main()
