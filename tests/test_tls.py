"""Tests for the TLS policy and SPKI pinning that guard every outbound query.

Pinning is the only check that notices an interception whose CA the machine
already trusts, so these cover not just that a correct pin passes but that a
pin which would never be consulted is refused before it can give false comfort.
"""

import base64
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from symbivpn import tlsutil
from symbivpn.config import Config, ConfigError, _validate

OPENSSL = shutil.which("openssl")
requires_openssl = unittest.skipUnless(OPENSSL, "openssl is not installed")


def _make_cert(directory: Path, name: str, keyspec: str) -> tuple[Path, Path]:
    """A throwaway self-signed certificate, and its key."""
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"
    subprocess.run(
        [
            OPENSSL, "req", "-x509", "-newkey", keyspec, "-keyout", str(key),
            "-out", str(cert), "-days", "2", "-nodes", "-subj", f"/CN={name}.example",
        ],
        check=True, capture_output=True,
    )
    return cert, key


def _openssl_pin(cert: Path) -> str:
    """The pin as openssl computes it, which is what a person would paste in."""
    pubkey = subprocess.run(
        [OPENSSL, "x509", "-in", str(cert), "-pubkey", "-noout"],
        check=True, capture_output=True,
    ).stdout
    der = subprocess.run(
        [OPENSSL, "pkey", "-pubin", "-outform", "der"],
        input=pubkey, check=True, capture_output=True,
    ).stdout
    digest = subprocess.run(
        [OPENSSL, "dgst", "-sha256", "-binary"],
        input=der, check=True, capture_output=True,
    ).stdout
    return base64.b64encode(digest).decode("ascii")


@requires_openssl
class SPKIExtractionTests(unittest.TestCase):
    """The DER walker must find exactly the bytes openssl would hash.

    A pin computed over the wrong span of the certificate would still be a
    stable 32 bytes, so it would match itself and look like it worked -- right
    up until it had to reject a forged certificate, which it never would.
    """

    def _check(self, name, keyspec):
        with tempfile.TemporaryDirectory() as tmp:
            cert, _ = _make_cert(Path(tmp), name, keyspec)
            der = ssl.PEM_cert_to_DER_cert(cert.read_text())
            self.assertEqual(tlsutil.spki_pin(der), _openssl_pin(cert))

    def test_rsa(self):
        self._check("rsa", "rsa:2048")

    def test_ecdsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            params = Path(tmp) / "p.pem"
            params.write_bytes(subprocess.run(
                [OPENSSL, "ecparam", "-name", "prime256v1"],
                check=True, capture_output=True).stdout)
            cert, _ = _make_cert(Path(tmp), "ec", f"ec:{params}")
            der = ssl.PEM_cert_to_DER_cert(cert.read_text())
            self.assertEqual(tlsutil.spki_pin(der), _openssl_pin(cert))

    def test_ed25519(self):
        self._check("ed", "ed25519")

    def test_v1_certificate_without_a_version_field(self):
        # A v1 certificate omits the [0] version element entirely, which is the
        # branch the walker skips conditionally -- miscount it and every field
        # after it is read as the public key.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            _, key = _make_cert(tmp, "seed", "rsa:2048")
            csr, cert = tmp / "v1.csr", tmp / "v1.pem"
            subprocess.run([OPENSSL, "req", "-new", "-key", str(key), "-out",
                            str(csr), "-subj", "/CN=v1.example"],
                           check=True, capture_output=True)
            subprocess.run([OPENSSL, "x509", "-req", "-in", str(csr), "-signkey",
                            str(key), "-days", "2", "-out", str(cert)],
                           check=True, capture_output=True)
            der = ssl.PEM_cert_to_DER_cert(cert.read_text())
            self.assertEqual(tlsutil.spki_pin(der), _openssl_pin(cert))

    def test_garbage_is_rejected_rather_than_hashed(self):
        for bad in (b"", b"\x30", b"\x30\x82\xff\xff", b"not a certificate"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    tlsutil.spki_pin(bad)


class ProfileTests(unittest.TestCase):
    """Each profile must actually give up something the one below it allows."""

    def _suites(self, profile):
        context = tlsutil.build_context(tlsutil.TLSPolicy(profile=profile))
        return context, {c["name"] for c in context.get_ciphers()}

    def test_paranoid_requires_tls13(self):
        context, _ = self._suites("paranoid")
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)

    def test_compatible_and_strict_still_refuse_tls11(self):
        for profile in ("compatible", "strict"):
            context, _ = self._suites(profile)
            self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_strict_drops_finite_field_diffie_hellman(self):
        # In TLS 1.2 the client cannot negotiate the DH group; declining DHE is
        # the only way to keep that choice on this side of the connection.
        _, compatible = self._suites("compatible")
        _, strict = self._suites("strict")
        self.assertTrue({name for name in compatible if name.startswith("DHE")})
        self.assertFalse({name for name in strict if name.startswith("DHE")})
        self.assertTrue(strict < compatible)

    def test_every_profile_is_aead_only(self):
        for profile in ("compatible", "strict", "paranoid"):
            _, suites = self._suites(profile)
            for name in suites:
                with self.subTest(profile=profile, cipher=name):
                    self.assertFalse(name.endswith(("-SHA", "-SHA256", "-SHA384"))
                                     and "GCM" not in name and "CHACHA" not in name)


class PinNormalisationTests(unittest.TestCase):
    """A pin must be checked whichever way a person reasonably spells it."""

    PIN = base64.b64encode(bytes(range(32))).decode("ascii")

    def test_hostname_lookup_ignores_case_and_a_trailing_dot(self):
        policy = tlsutil.TLSPolicy(pins={"DNS.Quad9.Net.": [self.PIN]})
        for spelling in ("dns.quad9.net", "DNS.QUAD9.NET", "dns.quad9.net.", " dns.quad9.net "):
            with self.subTest(spelling=spelling):
                self.assertEqual(policy.pins_for(spelling), [self.PIN])

    def test_an_unpinned_host_reports_no_pins(self):
        policy = tlsutil.TLSPolicy(pins={"dns.quad9.net": [self.PIN]})
        self.assertEqual(policy.pins_for("dns.google"), [])

    def test_hpkp_header_spelling_is_accepted(self):
        policy = tlsutil.TLSPolicy(pins={"dns.quad9.net": [f'pin-sha256="{self.PIN}"']})
        self.assertEqual(policy.pins_for("dns.quad9.net"), [self.PIN])

    def test_parse_pin_requires_a_sha256_digest(self):
        self.assertEqual(len(tlsutil.parse_pin(self.PIN)), 32)
        for bad in ("", "not base64!", base64.b64encode(b"short").decode()):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    tlsutil.parse_pin(bad)


@requires_openssl
class LivePinningTests(unittest.TestCase):
    """Pinning checked against a real handshake, not a mocked one."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = Path(cls._tmp.name)
        cls.cert, key = _make_cert(root, "served", "rsa:2048")
        other, _ = _make_cert(root, "other", "rsa:2048")
        cls.served_pin = _openssl_pin(cls.cert)
        cls.other_pin = _openssl_pin(other)

        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(cls.cert, key)
        cls._listener = socket.socket()
        cls._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls._listener.bind(("127.0.0.1", 0))
        cls._listener.listen(8)
        cls.port = cls._listener.getsockname()[1]

        def serve():
            while True:
                try:
                    raw, _ = cls._listener.accept()
                except OSError:
                    return
                try:
                    server.wrap_socket(raw, server_side=True).close()
                except OSError:
                    raw.close()

        cls._thread = threading.Thread(target=serve, daemon=True)
        cls._thread.start()

    @classmethod
    def tearDownClass(cls):
        cls._listener.close()
        cls._tmp.cleanup()

    def _connect(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context.wrap_socket(socket.create_connection(("127.0.0.1", self.port)))

    def _check(self, pins, hostname):
        connection = self._connect()
        try:
            tlsutil.verify_pin(connection, hostname, tlsutil.TLSPolicy(pins=pins))
        finally:
            connection.close()

    def test_the_right_pin_passes(self):
        self._check({"served.example": [self.served_pin]}, "served.example")

    def test_a_wrong_pin_is_refused(self):
        with self.assertRaises(tlsutil.PinMismatch):
            self._check({"served.example": [self.other_pin]}, "served.example")

    def test_one_matching_pin_among_several_is_enough(self):
        # Resolvers publish a backup pin so a key rotation does not take the
        # network down; either must be accepted.
        self._check({"served.example": [self.other_pin, self.served_pin]}, "served.example")

    def test_a_pin_keyed_on_another_name_does_not_apply(self):
        # This is the fail-open that config validation exists to prevent: the
        # connection is allowed, because as far as the policy is concerned this
        # host was never pinned at all.
        self._check({"dns.google": [self.other_pin]}, "8.8.8.8")


class PinConfigurationTests(unittest.TestCase):
    """A pin that could never be checked is refused when the config loads."""

    GOOD = base64.b64encode(bytes(range(32))).decode("ascii")

    def _validated(self, **pins):
        config = Config()
        config.upstream.pins = dict(pins)
        _validate(config)
        return config

    def test_a_pin_on_a_configured_resolver_is_accepted(self):
        self._validated(**{"dns.quad9.net": [self.GOOD]})

    def test_spelling_of_the_key_does_not_matter(self):
        self._validated(**{"DNS.Quad9.Net.": [self.GOOD]})

    def test_a_typo_in_the_hostname_is_refused(self):
        with self.assertRaises(ConfigError) as caught:
            self._validated(**{"dns.qaud9.net": [self.GOOD]})
        self.assertIn("never be checked", str(caught.exception))
        # The message has to say what the valid names are, or the person is
        # left guessing at the spelling that would have worked.
        self.assertIn("dns.quad9.net", str(caught.exception))

    def test_pinning_an_ip_when_the_certificate_name_was_wanted_is_refused(self):
        with self.assertRaises(ConfigError):
            self._validated(**{"9.9.9.9": [self.GOOD]})

    def test_an_empty_pin_list_is_refused(self):
        with self.assertRaises(ConfigError):
            self._validated(**{"dns.quad9.net": []})

    def test_a_malformed_pin_is_refused(self):
        for bad in ("not a pin", "YWJj"):
            with self.subTest(bad=bad):
                with self.assertRaises(ConfigError):
                    self._validated(**{"dns.quad9.net": [bad]})

    def test_a_malformed_upstream_is_refused_at_load_rather_than_at_query_time(self):
        for spec in ("udp://[2620:fe::fe", "tls://dns.quad9.net@9.9.9.9:0",
                     "udp://192.168.1.1:notaport"):
            with self.subTest(spec=spec):
                config = Config()
                config.upstream.servers = [spec]
                with self.assertRaises(ConfigError):
                    _validate(config)

    def test_an_ipv6_resolver_in_bracket_form_is_accepted(self):
        config = Config()
        config.upstream.servers = ["udp://[2620:fe::fe]:53"]
        _validate(config)
