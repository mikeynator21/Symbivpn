"""Tests for X25519 key generation and the QR encoder."""

import random
import string
import tempfile
import unittest
from pathlib import Path

from symbivpn.vpn import crypto, qr
from symbivpn.vpn.wireguard import PeerStore, WireGuardManager
from tests import qrdecode


class X25519Tests(unittest.TestCase):
    """RFC 7748 section 6.1 test vectors."""

    ALICE_PRIVATE = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    BOB_PRIVATE = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def test_alice_public_key(self):
        public = crypto.public_key(bytes.fromhex(self.ALICE_PRIVATE))
        self.assertEqual(public.hex(), self.ALICE_PUBLIC)

    def test_bob_public_key(self):
        public = crypto.public_key(bytes.fromhex(self.BOB_PRIVATE))
        self.assertEqual(public.hex(), self.BOB_PUBLIC)

    def test_shared_secret_agrees_both_ways(self):
        alice = bytes.fromhex(self.ALICE_PRIVATE)
        bob = bytes.fromhex(self.BOB_PRIVATE)
        self.assertEqual(
            crypto.x25519(alice, crypto.public_key(bob)).hex(), self.SHARED
        )
        self.assertEqual(
            crypto.x25519(bob, crypto.public_key(alice)).hex(), self.SHARED
        )

    def test_rfc_7748_scalar_vector(self):
        # Section 5.2: a direct X25519(k, u) vector.
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        point = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        self.assertEqual(crypto.x25519(scalar, point).hex(), expected)

    def test_generated_keys_are_clamped(self):
        private = crypto.generate_private_key()
        self.assertEqual(len(private), 32)
        self.assertEqual(private[0] & 0b111, 0)
        self.assertEqual(private[31] & 0b1000_0000, 0)
        self.assertEqual(private[31] & 0b0100_0000, 0b0100_0000)

    def test_keys_are_distinct(self):
        keys = {crypto.generate_private_key() for _ in range(20)}
        self.assertEqual(len(keys), 20)

    def test_encode_decode_round_trip(self):
        private = crypto.generate_private_key()
        self.assertEqual(crypto.decode_key(crypto.encode_key(private)), private)

    def test_derive_public_key_from_encoded(self):
        private = crypto.generate_private_key()
        derived = crypto.derive_public_key(crypto.encode_key(private))
        self.assertEqual(derived, crypto.encode_key(crypto.public_key(private)))

    def test_decode_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            crypto.decode_key("c2hvcnQ=")

    def test_preshared_key_length(self):
        self.assertEqual(len(crypto.generate_preshared_key()), 32)


class FormatInformationTests(unittest.TestCase):
    """The 32 format strings are published in the QR standard, table C.1."""

    EXPECTED = {
        ("L", 0): "111011111000100", ("L", 1): "111001011110011",
        ("L", 2): "111110110101010", ("L", 3): "111100010011101",
        ("L", 4): "110011000101111", ("L", 5): "110001100011000",
        ("L", 6): "110110001000001", ("L", 7): "110100101110110",
        ("M", 0): "101010000010010", ("M", 1): "101000100100101",
        ("M", 2): "101111001111100", ("M", 3): "101101101001011",
        ("M", 4): "100010111111001", ("M", 5): "100000011001110",
        ("M", 6): "100111110010111", ("M", 7): "100101010100000",
        ("Q", 0): "011010101011111", ("Q", 1): "011000001101000",
        ("Q", 2): "011111100110001", ("Q", 3): "011101000000110",
        ("Q", 4): "010010010110100", ("Q", 5): "010000110000011",
        ("Q", 6): "010111011011010", ("Q", 7): "010101111101101",
        ("H", 0): "001011010001001", ("H", 1): "001001110111110",
        ("H", 2): "001110011100111", ("H", 3): "001100111010000",
        ("H", 4): "000011101100010", ("H", 5): "000001001010101",
        ("H", 6): "000110100001100", ("H", 7): "000100000111011",
    }

    def test_all_thirty_two(self):
        for (level, mask), expected in self.EXPECTED.items():
            with self.subTest(level=level, mask=mask):
                actual = format(qr.format_information(level, mask), "015b")
                self.assertEqual(actual, expected)


class QRStructureTests(unittest.TestCase):
    def test_tables_match_matrix_geometry(self):
        """An independent cross-check on the block tables.

        The codeword count in the table must equal the number of free modules
        the matrix actually has, so a mistranscribed row cannot go unnoticed.
        """
        for version in range(1, qr.MAX_VERSION + 1):
            free = qr.free_module_count(version)
            for level in ("L", "M", "Q", "H"):
                with self.subTest(version=version, level=level):
                    self.assertEqual(free // 8, qr.total_codewords(version, level))

    def test_matrix_size(self):
        for version in (1, 5, 10, 20):
            code = qr.encode("x", version=version)
            self.assertEqual(code.size, version * 4 + 17)

    def test_finder_patterns_present(self):
        code = qr.encode("hello")
        size = code.size
        for row, column in ((0, 0), (0, size - 7), (size - 7, 0)):
            with self.subTest(corner=(row, column)):
                # A finder pattern's outer ring is dark and its centre is dark.
                self.assertTrue(code.modules[row][column])
                self.assertTrue(code.modules[row + 3][column + 3])
                self.assertFalse(code.modules[row + 1][column + 1])

    def test_timing_patterns_alternate(self):
        code = qr.encode("hello")
        for position in range(8, code.size - 8):
            self.assertEqual(code.modules[6][position], position % 2 == 0)
            self.assertEqual(code.modules[position][6], position % 2 == 0)

    def test_dark_module_is_set(self):
        code = qr.encode("hello")
        self.assertTrue(code.modules[code.size - 8][8])

    def test_version_chosen_by_length(self):
        self.assertLess(qr.choose_version(b"x" * 10, "M"), qr.choose_version(b"x" * 500, "M"))

    def test_oversized_payload_rejected(self):
        with self.assertRaises(qr.QRError):
            qr.encode("x" * 5000)

    def test_invalid_level_rejected(self):
        with self.assertRaises(qr.QRError):
            qr.encode("hello", ec_level="Z")

    def test_reed_solomon_length(self):
        self.assertEqual(len(qr.reed_solomon(b"hello world", 10)), 10)

    def test_reed_solomon_is_deterministic(self):
        self.assertEqual(qr.reed_solomon(b"abc", 7), qr.reed_solomon(b"abc", 7))

    def test_mask_chosen_from_all_eight(self):
        self.assertIn(qr.encode("symbivpn test payload").mask, range(8))

    def test_wireguard_config_fits(self):
        config = (
            "[Interface]\nPrivateKey = " + "A" * 44 + "\nAddress = 10.9.0.2/32\n"
            "DNS = 10.9.0.1\nMTU = 1280\n\n[Peer]\nPublicKey = " + "B" * 44 +
            "\nPresharedKey = " + "C" * 44 + "\nAllowedIPs = 0.0.0.0/0, ::/0\n"
            "Endpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n"
        )
        code = qr.encode(config)
        self.assertLessEqual(code.version, qr.MAX_VERSION)


class QRRenderTests(unittest.TestCase):
    def test_png_has_valid_signature(self):
        png = qr.encode("hello").to_png()
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", png[:32])
        self.assertTrue(png.endswith(b"IEND\xaeB`\x82"))

    def test_svg_is_well_formed(self):
        svg = qr.encode("hello").to_svg()
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))

    def test_text_render_has_quiet_zone(self):
        text = qr.encode("hello").to_text(quiet_zone=2)
        self.assertGreater(len(text.splitlines()), 10)


class X25519DepthTests(unittest.TestCase):
    """The checks a single multiplication happens to survive.

    Every WireGuard key on the network comes out of this. A subtly wrong
    implementation does not look broken -- it produces keys that are simply
    weaker than they appear, or that no other implementation agrees with.
    """

    def test_rfc_7748_iterated_vector(self):
        # Section 5.2: iterate k, u = X25519(k, u), k. This is the vector that
        # catches carry propagation and reduction bugs; the single-shot ones
        # can pass with arithmetic that is wrong in the general case.
        k = u = bytes.fromhex(
            "0900000000000000000000000000000000000000000000000000000000000000"
        )
        expected = {
            1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        }
        for iteration in range(1, 1001):
            k, u = crypto.x25519(k, u), k
            if iteration in expected:
                self.assertEqual(k.hex(), expected[iteration],
                                 f"diverged after {iteration} iterations")

    def test_the_high_bit_of_u_is_ignored(self):
        # RFC 7748 requires masking bit 255 of the u-coordinate. Without it a
        # non-canonical encoding gives a different answer from every other
        # implementation, which shows up as a peer that will not connect.
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        point = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        non_canonical = point[:31] + bytes([point[31] | 0x80])
        self.assertEqual(crypto.x25519(scalar, point),
                         crypto.x25519(scalar, non_canonical))

    def test_small_order_points_give_nothing_away(self):
        scalar = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        for point in (
            "00" * 32,
            "01" + "00" * 31,
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        ):
            with self.subTest(point=point[:16]):
                self.assertEqual(
                    crypto.x25519(scalar, bytes.fromhex(point)), bytes(32),
                    "a small-order point must produce an all-zero secret",
                )


class WireGuardInteropTests(unittest.TestCase):
    """Keys are only useful if the other end agrees what they are."""

    def setUp(self):
        import shutil

        if shutil.which("wg") is None:
            self.skipTest("the wg tool is not installed")

    def _wg_pubkey(self, private_b64: str) -> str:
        import subprocess

        return subprocess.run(
            ["wg", "pubkey"], input=private_b64,
            capture_output=True, text=True, check=True,
        ).stdout.strip()

    def test_our_public_keys_match_wg(self):
        # The fallback path, used on any machine without the wg tool. If it
        # disagreed, peers created there would silently never connect.
        for _ in range(10):
            private = crypto.generate_private_key()
            self.assertEqual(
                crypto.encode_key(crypto.public_key(private)),
                self._wg_pubkey(crypto.encode_key(private)),
            )

    def test_we_derive_wg_generated_keys_identically(self):
        import subprocess

        for _ in range(10):
            private = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True, check=True
            ).stdout.strip()
            self.assertEqual(
                crypto.encode_key(crypto.public_key(crypto.decode_key(private))),
                self._wg_pubkey(private),
            )


if __name__ == "__main__":
    unittest.main()


class QRReadBackTests(unittest.TestCase):
    """Read the payload back out, which no structural test can do.

    Finder patterns, timing rows and matrix sizes can all be right while the
    data is placed wrongly, masked wrongly, or described by a format field that
    names the wrong mask. Every one of those produces a code a phone cannot
    read, and every one passes the tests above. The only check that catches
    them is reading the thing back.
    """

    def round_trip(self, payload, level="M", mask=None):
        code = qr.encode(payload, level, mask=mask)
        return code, qrdecode.decode(code.modules).decode()

    def test_a_short_payload(self):
        code, back = self.round_trip("hello world")
        self.assertEqual(back, "hello world")

    def test_the_format_field_names_what_was_used(self):
        for level in ("L", "M", "Q", "H"):
            for mask in range(8):
                with self.subTest(level=level, mask=mask):
                    code = qr.encode("format field check", level, mask=mask)
                    read_level, read_mask = qrdecode.read_format(code.modules)
                    self.assertEqual(read_level, level)
                    self.assertEqual(read_mask, mask)

    def test_every_mask_pattern_survives_a_round_trip(self):
        payload = "SymbiVPN mask coverage " * 12
        for mask in range(8):
            for level in ("L", "M", "Q", "H"):
                with self.subTest(mask=mask, level=level):
                    _, back = self.round_trip(payload, level, mask=mask)
                    self.assertEqual(back, payload)

    def test_every_version_at_its_maximum_payload(self):
        # The largest payload each version can hold, which is where an
        # off-by-one in capacity, padding or interleaving shows up.
        random.seed(20260917)
        checked = 0
        for level in ("L", "M", "Q", "H"):
            for version in range(1, qr.MAX_VERSION + 1):
                overhead = 1 + (1 if version <= 9 else 2)
                capacity = qr._capacity_bits(version, level) // 8 - overhead
                payload = "".join(
                    random.choice(string.ascii_letters) for _ in range(capacity)
                )
                code = qr.encode(payload, level)
                if code.version != version:
                    continue
                with self.subTest(level=level, version=version):
                    self.assertEqual(qrdecode.decode(code.modules).decode(), payload)
                checked += 1
        # Versions 1 to 20 at four levels; if this collapses, the loop above
        # stopped exercising what it claims to.
        self.assertGreaterEqual(checked, 60)

    def test_a_multi_block_version_is_de_interleaved_correctly(self):
        # Above a certain size the codewords are split across several
        # Reed-Solomon blocks and interleaved. Getting that wrong scrambles the
        # payload while leaving the matrix looking perfectly well formed.
        version = 17
        _, (blocks1, _), (blocks2, _) = qr._BLOCK_TABLE[(version, "M")]
        self.assertGreater(blocks1 + blocks2, 1)
        payload = "block interleaving " * 25
        code = qr.encode(payload, "M")
        self.assertEqual(code.version, version)
        self.assertEqual(qrdecode.decode(code.modules).decode(), payload)

    def test_a_real_peer_configuration_reads_back_exactly(self):
        # The path a person actually uses: scan this and the phone is on the
        # VPN. A single wrong module here and it simply will not scan.
        with tempfile.TemporaryDirectory() as tmp:
            manager = WireGuardManager(PeerStore(Path(tmp) / "peers.json"))
            manager.initialise_server(endpoint="vpn.example.com")
            manager.add_peer("phone")
            config = manager.peer_config("phone")
            code = manager.peer_qr("phone")
            self.assertEqual(qrdecode.decode(code.modules).decode(), config)
            self.assertIn("PrivateKey", config)

    def test_a_mask_that_disagrees_with_the_format_field_is_caught(self):
        # The exact shape of an encoder bug this suite could not previously
        # see: the matrix is masked with one pattern and advertises another.
        payload = "SymbiVPN teeth check " * 8
        level, version = "M", qr.encode(payload, "M").version
        size = version * 4 + 17
        base = qr._Matrix(size)
        qr._place_finder(base, 0, 0)
        qr._place_finder(base, 0, size - 7)
        qr._place_finder(base, size - 7, 0)
        qr._place_alignment(base, version)
        qr._place_timing(base)
        qr._reserve_format_areas(base, version)
        qr._place_data(
            base,
            qr._interleave(
                qr._encode_payload(payload.encode(), version, level), version, level
            ),
        )
        masked = qr._apply_mask(base, 3)
        qr._write_format_information(masked, level, 5)   # advertises the wrong one
        qr._write_version_information(masked, version)

        try:
            self.assertNotEqual(qrdecode.decode(masked.modules), payload.encode())
        except qrdecode.DecodeError:
            pass    # Refusing to decode it is the other correct outcome.

    def test_damage_to_the_payload_is_not_silently_repaired(self):
        # No error correction here on purpose: the reader must report what is
        # in the matrix, not what it could be recovered to, or it would hide
        # the faults it exists to find.
        payload = "SymbiVPN damage check " * 8
        code = qr.encode(payload, "M")
        flipped = [row[:] for row in code.modules]
        # The first data module the zigzag reads is in the bottom-right corner.
        flipped[code.size - 1][code.size - 1] = not flipped[code.size - 1][code.size - 1]
        try:
            self.assertNotEqual(qrdecode.decode(flipped), payload.encode())
        except qrdecode.DecodeError:
            pass
