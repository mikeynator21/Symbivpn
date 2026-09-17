"""Tests for upstream transports, failover and response validation."""

import socket
import threading
import time
import unittest
from unittest import mock

from symbivpn import dnsmsg
from symbivpn.resolver import (
    DoHUpstream,
    DoTUpstream,
    PlainUpstream,
    ResolutionError,
    UpstreamPool,
    _validate_response,
    apply_0x20,
    build_upstream,
    parse_dot_target,
    pin_hostname,
    split_host_port,
)


class StubResolver:
    """A UDP resolver that answers, or misbehaves on demand."""

    def __init__(self, answer="1.2.3.4", corrupt=False, silent=False):
        self.answer = answer
        self.corrupt = corrupt
        self.silent = silent
        self.queries = 0
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.3)
        self.port = self._socket.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def spec(self):
        return f"udp://127.0.0.1:{self.port}"

    def _serve(self):
        while not self._stop.is_set():
            try:
                payload, peer = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            self.queries += 1
            if self.silent:
                continue
            if self.corrupt:
                # Answer a different name than the one asked for.
                forged = dnsmsg.build_query("attacker.example", dnsmsg.TYPE_A)
                reply = dnsmsg.build_address_response(
                    forged, dnsmsg.TYPE_A, self.answer, 60
                )
                reply = dnsmsg.set_message_id(reply, dnsmsg.parse_header(payload).id)
            else:
                reply = dnsmsg.build_address_response(
                    payload, dnsmsg.TYPE_A, self.answer, 60
                )
            try:
                self._socket.sendto(reply, peer)
            except OSError:
                return

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._socket.close()


class UpstreamFactoryTests(unittest.TestCase):
    def test_scheme_selects_transport(self):
        self.assertIsInstance(build_upstream("https://dns.example/dns-query"), DoHUpstream)
        self.assertIsInstance(build_upstream("tls://dns.example@1.2.3.4"), DoTUpstream)
        self.assertIsInstance(build_upstream("udp://192.168.1.1"), PlainUpstream)
        self.assertIsInstance(build_upstream("192.168.1.1"), PlainUpstream)

    def test_encrypted_flags(self):
        self.assertTrue(build_upstream("https://dns.example/dns-query").encrypted)
        self.assertTrue(build_upstream("tls://dns.example@1.2.3.4").encrypted)
        self.assertFalse(build_upstream("192.168.1.1").encrypted)

    def test_dot_address_pinning(self):
        upstream = build_upstream("tls://dns.quad9.net@9.9.9.9")
        self.assertEqual(upstream.hostname, "dns.quad9.net")
        self.assertEqual(upstream.address, "9.9.9.9")
        self.assertEqual(upstream.port, 853)

    def test_dot_custom_port(self):
        self.assertEqual(build_upstream("tls://dns.example@1.2.3.4:8853").port, 8853)

    def test_plain_custom_port(self):
        self.assertEqual(build_upstream("udp://192.168.1.1:5353").port, 5353)

    def test_https_required_for_doh(self):
        with self.assertRaises(ValueError):
            DoHUpstream("http://insecure.example/dns-query")


class PoolTests(unittest.TestCase):
    def test_plaintext_rejected_in_strict_mode(self):
        with self.assertRaises(ValueError) as ctx:
            UpstreamPool(["192.168.1.1"], require_encrypted=True)
        self.assertIn("plaintext", str(ctx.exception))

    def test_empty_pool_rejected(self):
        with self.assertRaises(ValueError):
            UpstreamPool([])

    def test_resolves_through_a_working_upstream(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2)
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["1.2.3.4"])

    def test_fails_over_to_a_working_upstream(self):
        """A connection that cannot be established must not escape the pool.

        Regression test: an unreachable resolver used to raise OSError out of
        the connection factory, past the failover logic, so the second
        upstream was never tried.
        """
        dead = StubResolver(silent=True)
        alive = StubResolver(answer="5.6.7.8")
        self.addCleanup(dead.stop)
        self.addCleanup(alive.stop)

        pool = UpstreamPool(
            [dead.spec, alive.spec], require_encrypted=False, timeout=0.4
        )
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["5.6.7.8"])

    def test_unreachable_tls_upstream_fails_over(self):
        """A refused TCP connection is an upstream failure, not an exception."""
        alive = StubResolver(answer="9.9.9.9")
        self.addCleanup(alive.stop)

        # Port 1 is reserved and refuses instantly on every platform.
        pool = UpstreamPool(
            ["tls://nowhere.invalid@127.0.0.1:1", alive.spec],
            require_encrypted=False,
            timeout=0.4,
        )
        self.addCleanup(pool.close)

        reply = pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertEqual(dnsmsg.answer_addresses(reply), ["9.9.9.9"])

    def test_all_upstreams_failing_raises_resolution_error(self):
        pool = UpstreamPool(
            ["udp://127.0.0.1:1", "tls://nowhere.invalid@127.0.0.1:1"],
            require_encrypted=False,
            timeout=0.3,
        )
        self.addCleanup(pool.close)
        with self.assertRaises(ResolutionError):
            pool.resolve("example.com", dnsmsg.TYPE_A)

    def test_spoofed_answer_rejected(self):
        """An upstream answering a different name must not be believed."""
        liar = StubResolver(corrupt=True)
        self.addCleanup(liar.stop)
        pool = UpstreamPool([liar.spec], require_encrypted=False, timeout=0.5, use_0x20=False)
        self.addCleanup(pool.close)

        with self.assertRaises(ResolutionError):
            pool.resolve("example.com", dnsmsg.TYPE_A)

    def test_health_recorded(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2)
        self.addCleanup(pool.close)

        pool.resolve("example.com", dnsmsg.TYPE_A)
        status = pool.status()[0]
        self.assertTrue(status["available"])
        self.assertEqual(status["queries"], 1)
        self.assertEqual(status["errors"], 0)

    def test_failed_upstream_is_benched(self):
        pool = UpstreamPool(["udp://127.0.0.1:1"], require_encrypted=False, timeout=0.2)
        self.addCleanup(pool.close)
        for _ in range(3):
            with self.assertRaises(ResolutionError):
                pool.resolve("example.com", dnsmsg.TYPE_A)
        self.assertFalse(pool.upstreams[0].health.available)

    def test_question_normalised_to_lowercase(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        pool = UpstreamPool([stub.spec], require_encrypted=False, timeout=2, use_0x20=True)
        self.addCleanup(pool.close)

        reply = pool.resolve("Example.COM", dnsmsg.TYPE_A)
        # 0x20 randomisation must not leak into what we cache and serve.
        self.assertEqual(dnsmsg.first_question(reply).name, "example.com")


class ZeroXTwentyTests(unittest.TestCase):
    def test_case_is_randomised_but_name_preserved(self):
        name = "some-long-example-name.com"
        variants = {apply_0x20(name) for _ in range(50)}
        self.assertGreater(len(variants), 1)
        for variant in variants:
            self.assertEqual(variant.lower(), name)


class ValidationTests(unittest.TestCase):
    def _pair(self, name="example.com", qtype=dnsmsg.TYPE_A):
        query = dnsmsg.build_query(name, qtype)
        reply = dnsmsg.build_address_response(query, qtype, "1.2.3.4", 60)
        return query, reply

    def test_matching_response_accepted(self):
        query, reply = self._pair()
        _validate_response(reply, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_id_rejected(self):
        query, reply = self._pair()
        reply = dnsmsg.set_message_id(reply, 0xBEEF)
        with self.assertRaises(ResolutionError):
            _validate_response(reply, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_name_rejected(self):
        query, _ = self._pair()
        _, other = self._pair("different.com")
        other = dnsmsg.set_message_id(other, dnsmsg.parse_header(query).id)
        with self.assertRaises(ResolutionError):
            _validate_response(other, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)

    def test_wrong_type_rejected(self):
        query, reply = self._pair()
        with self.assertRaises(ResolutionError):
            _validate_response(reply, query, "example.com", dnsmsg.TYPE_AAAA, 1, strict_case=False)

    def test_query_masquerading_as_response_rejected(self):
        query, _ = self._pair()
        with self.assertRaises(ResolutionError):
            _validate_response(query, query, "example.com", dnsmsg.TYPE_A, 1, strict_case=False)


class Case0x20Tests(unittest.TestCase):
    """The case pattern is a secret shared with the upstream for one query."""

    def test_the_name_is_unchanged_apart_from_case(self):
        for _ in range(50):
            self.assertEqual(apply_0x20("example.com").lower(), "example.com")

    def test_the_pattern_varies(self):
        patterns = {apply_0x20("a-fairly-long-name.example.com") for _ in range(200)}
        self.assertGreater(len(patterns), 150, "the pattern must not be predictable")

    def test_digits_and_punctuation_are_left_alone(self):
        self.assertTrue(all(
            character in "0123456789.-" or character.isalpha()
            for character in apply_0x20("s3-1.example.com")
        ))
        for _ in range(50):
            randomised = apply_0x20("s3-1.example.com")
            self.assertEqual(randomised[1:5], "3-1.")

    def test_it_does_not_come_from_the_seedable_generator(self):
        import random

        random.seed(99)
        first = apply_0x20("example.com")
        random.seed(99)
        second = apply_0x20("example.com")
        # A predictable generator would give the same pattern twice; with 11
        # letters the chance of a genuine collision is about one in 2048.
        self.assertNotEqual(first, second)

    def test_an_empty_name_is_handled(self):
        self.assertEqual(apply_0x20(""), "")


if __name__ == "__main__":
    unittest.main()


class HostPortParsingTests(unittest.TestCase):
    """Address parsing, including the IPv6 forms people actually paste."""

    def test_plain_forms(self):
        self.assertEqual(split_host_port("9.9.9.9", 53), ("9.9.9.9", 53))
        self.assertEqual(split_host_port("9.9.9.9:5353", 53), ("9.9.9.9", 5353))
        self.assertEqual(split_host_port("router.lan", 53), ("router.lan", 53))

    def test_bare_ipv6_is_not_mistaken_for_a_port(self):
        self.assertEqual(split_host_port("2620:fe::fe", 53), ("2620:fe::fe", 53))

    def test_bracketed_ipv6_loses_its_brackets(self):
        # Read as a hostname, "[2620:fe::fe]" resolves to nothing at all, so a
        # resolver written the way its own documentation writes it would simply
        # never answer.
        self.assertEqual(split_host_port("[2620:fe::fe]", 53), ("2620:fe::fe", 53))
        self.assertEqual(
            split_host_port("[2620:fe::fe]:8853", 53), ("2620:fe::fe", 8853)
        )

    def test_bracketed_ipv6_resolves(self):
        host, _ = split_host_port("[::1]:853", 53)
        socket.getaddrinfo(host, 853, type=socket.SOCK_STREAM)

    def test_malformed_targets_are_refused(self):
        for bad in ("[2620:fe::fe", "[2620:fe::fe]junk", "9.9.9.9:nope", "9.9.9.9:0"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    split_host_port(bad, 53)

    def test_dot_specs(self):
        self.assertEqual(
            parse_dot_target("tls://dns.quad9.net@9.9.9.9"),
            ("dns.quad9.net", "9.9.9.9", 853),
        )
        self.assertEqual(
            parse_dot_target("tls://dns.quad9.net@[2620:fe::fe]:8853"),
            ("dns.quad9.net", "2620:fe::fe", 8853),
        )
        self.assertEqual(
            parse_dot_target("tls://dns.quad9.net"),
            ("dns.quad9.net", "dns.quad9.net", 853),
        )

    def test_pin_hostname_is_the_certificate_name(self):
        self.assertEqual(pin_hostname("https://dns.quad9.net/dns-query"), "dns.quad9.net")
        self.assertEqual(pin_hostname("tls://dns.quad9.net@9.9.9.9"), "dns.quad9.net")
        # An unencrypted upstream has no certificate, so nothing to pin.
        self.assertIsNone(pin_hostname("udp://192.168.1.1"))
        self.assertIsNone(pin_hostname("192.168.1.1"))


class NamedPlainUpstreamTests(unittest.TestCase):
    """A plain upstream named rather than numbered must still be usable.

    Names are the normal way to reach a resolver on a local network --
    `router.lan`, `fritz.box` -- and they bring two problems a numeric address
    does not: the reply arrives from an address that is not the name, and a
    name can resolve to several addresses of which only some work.
    """

    def stub(self):
        stub = StubResolver()
        self.addCleanup(stub.stop)
        return stub

    @staticmethod
    def _addresses(*addresses):
        """A getaddrinfo that returns exactly these, in this order."""
        def fake(host, port, *args, **kwargs):
            out = []
            for family, address in addresses:
                if family == socket.AF_INET6:
                    out.append((family, socket.SOCK_DGRAM, 17, "", (address, port, 0, 0)))
                else:
                    out.append((family, socket.SOCK_DGRAM, 17, "", (address, port)))
            return out
        return fake

    def test_answer_from_a_named_resolver_is_accepted(self):
        # The reply arrives from 127.0.0.1 while the upstream was written as
        # "localhost". Comparing those as strings discards a perfectly good
        # answer and burns the whole timeout on every query.
        stub = self.stub()
        upstream = PlainUpstream(f"localhost:{stub.port}", timeout=5.0, use_0x20=False)
        started = time.monotonic()
        reply = upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))
        self.assertTrue(reply)
        self.assertLess(time.monotonic() - started, 4.0)

    def test_a_name_whose_first_address_is_dead_still_resolves(self):
        # What a dual-stack host does with "localhost": ::1 first, and nothing
        # listening there. Taking only the first address makes a resolver that
        # answers perfectly well over IPv4 look dead -- and the cache pins that
        # verdict for a minute.
        stub = self.stub()
        upstream = PlainUpstream(f"localhost:{stub.port}", timeout=5.0, use_0x20=False)
        fake = self._addresses(
            (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")
        )
        with mock.patch("socket.getaddrinfo", fake):
            reply = upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))
        self.assertTrue(reply)

    def test_the_address_that_answered_is_tried_first_next_time(self):
        stub = self.stub()
        upstream = PlainUpstream(f"localhost:{stub.port}", timeout=5.0, use_0x20=False)
        fake = self._addresses(
            (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")
        )
        query = dnsmsg.build_query("example.com", dnsmsg.TYPE_A)
        with mock.patch("socket.getaddrinfo", fake):
            upstream.resolve(query)
            self.assertEqual(upstream._working[0], socket.AF_INET)
            self.assertEqual(upstream.endpoints()[0], upstream._working)
            started = time.monotonic()
            upstream.resolve(query)
        # The dead address is not paid for again.
        self.assertLess(time.monotonic() - started, 1.0)

    def test_when_no_address_works_it_is_a_resolution_error(self):
        # Not a bare OSError: the pool routes around a ResolutionError and
        # would otherwise let an unexpected exception escape to the caller.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            dead = probe.getsockname()[1]
        upstream = PlainUpstream(f"localhost:{dead}", timeout=1.0, use_0x20=False)
        fake = self._addresses(
            (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")
        )
        with mock.patch("socket.getaddrinfo", fake):
            with self.assertRaises(ResolutionError):
                upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))

    def test_an_unsupported_address_family_is_just_another_dead_address(self):
        # A host with IPv6 switched off answers an AF_INET6 socket with
        # EAFNOSUPPORT before anything is sent. That has to be skipped, not
        # raised: a name with an AAAA record is perfectly ordinary there.
        stub = self.stub()
        upstream = PlainUpstream(f"localhost:{stub.port}", timeout=5.0, use_0x20=False)
        fake = self._addresses(
            (socket.AF_INET6, "::1"), (socket.AF_INET, "127.0.0.1")
        )
        real_socket = socket.socket

        def refuse_ipv6(family, *args, **kwargs):
            if family == socket.AF_INET6:
                raise OSError(97, "Address family not supported by protocol")
            return real_socket(family, *args, **kwargs)

        with mock.patch("socket.getaddrinfo", fake), \
             mock.patch("socket.socket", refuse_ipv6):
            reply = upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))
        self.assertTrue(reply)

    def test_a_reply_from_a_different_address_is_ignored(self):
        # The anti-spoofing check still has to work now that the comparison is
        # made against the resolved address rather than the spelling.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.2", 0))
        except OSError:  # pragma: no cover - not every host routes all of 127/8
            self.skipTest("127.0.0.2 is not usable here")

        listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listener.bind(("0.0.0.0", 0))
        port = listener.getsockname()[1]
        self.addCleanup(listener.close)

        impostor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        impostor.bind(("127.0.0.2", 0))
        self.addCleanup(impostor.close)

        def answer_from_elsewhere():
            try:
                payload, peer = listener.recvfrom(4096)
            except OSError:
                return
            reply = dnsmsg.build_address_response(payload, dnsmsg.TYPE_A, "1.2.3.4", 60)
            try:
                impostor.sendto(reply, peer)   # source is 127.0.0.2, not .0.1
            except OSError:
                pass

        threading.Thread(target=answer_from_elsewhere, daemon=True).start()

        upstream = PlainUpstream(f"127.0.0.1:{port}", timeout=1.0, use_0x20=False)
        with self.assertRaises(ResolutionError):
            upstream.resolve(dnsmsg.build_query("example.com", dnsmsg.TYPE_A))
