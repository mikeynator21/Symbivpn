"""Tests for AES-256-GCM and the vault built on it.

The cipher is written here rather than imported, so it is tested against the
standards' own numbers rather than against itself: a wrong implementation that
round-trips with itself is exactly the failure mode to guard against.
"""

import secrets
import subprocess
import tempfile
import unittest
from pathlib import Path

from symbivpn import aesgcm, vault
from symbivpn.aesgcm import InvalidTag, decrypt, encrypt, encrypt_block, expand_key


def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", ""))


class KnownAnswerTests(unittest.TestCase):
    """Numbers from FIPS-197 and NIST SP 800-38D."""

    def test_sbox_matches_fips_197(self):
        # Figure 7's first row, and the property that makes it an S-box.
        self.assertEqual(aesgcm.SBOX[:8], h("637c777bf26b6fc5"))
        self.assertEqual(len(set(aesgcm.SBOX)), 256)

    def test_fips_197_appendix_c3(self):
        key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        block = h("00112233445566778899aabbccddeeff")
        self.assertEqual(
            encrypt_block(expand_key(key), block).hex(),
            "8ea2b7ca516745bfeafc49904b496089",
        )

    def test_gcm_case_13_empty(self):
        ct, tag = encrypt(h("00" * 32), h("00" * 12), b"", b"")
        self.assertEqual(ct, b"")
        self.assertEqual(tag.hex(), "530f8afbc74536b9a963b4f1c4cb738b")

    def test_gcm_case_14_single_block(self):
        ct, tag = encrypt(h("00" * 32), h("00" * 12), h("00" * 16), b"")
        self.assertEqual(ct.hex(), "cea7403d4d606b6e074ec5d3baf39d18")
        self.assertEqual(tag.hex(), "d0d1c8a799996bf0265b98b5d48ab919")

    def test_gcm_case_15_long_plaintext(self):
        ct, tag = encrypt(
            h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
            h("cafebabefacedbaddecaf888"),
            h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"),
        )
        self.assertEqual(
            ct.hex(),
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        )
        self.assertEqual(tag.hex(), "b094dac5d93471bdec1a502270e3cc6c")

    def test_gcm_case_16_with_associated_data(self):
        ct, tag = encrypt(
            h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
            h("cafebabefacedbaddecaf888"),
            h("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"),
            h("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        )
        self.assertEqual(tag.hex(), "76fc6ece0f4e1768cddf8853bb2d551b")


class AgainstOpenSSLTests(unittest.TestCase):
    """An independent implementation, for the block cipher itself."""

    def setUp(self):
        import shutil

        if shutil.which("openssl") is None:
            self.skipTest("openssl is not installed")

    def test_random_blocks_match_openssl(self):
        for _ in range(25):
            key = secrets.token_bytes(32)
            block = secrets.token_bytes(16)
            result = subprocess.run(
                ["openssl", "enc", "-aes-256-ecb", "-nopad", "-K", key.hex()],
                input=block, capture_output=True, check=True,
            )
            self.assertEqual(encrypt_block(expand_key(key), block), result.stdout[:16])


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.nonce = secrets.token_bytes(12)

    def test_lengths_around_the_block_boundary(self):
        for size in (0, 1, 15, 16, 17, 31, 32, 33, 1000):
            with self.subTest(size=size):
                message = secrets.token_bytes(size)
                ct, tag = encrypt(self.key, self.nonce, message, b"aad")
                self.assertEqual(len(ct), size, "GCM must not change the length")
                self.assertEqual(decrypt(self.key, self.nonce, ct, tag, b"aad"), message)

    def test_a_wrong_key_length_is_refused(self):
        for size in (0, 16, 31, 33):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    encrypt(secrets.token_bytes(size), self.nonce, b"x")

    def test_a_wrong_nonce_length_is_refused(self):
        for size in (0, 8, 11, 13, 16):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    encrypt(self.key, secrets.token_bytes(size), b"x")

    def test_the_same_plaintext_twice_differs(self):
        # Different nonces, so identical input must not give identical output.
        first, _ = encrypt(self.key, secrets.token_bytes(12), b"same")
        second, _ = encrypt(self.key, secrets.token_bytes(12), b"same")
        self.assertNotEqual(first, second)


class TamperTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)
        self.nonce = secrets.token_bytes(12)
        self.ct, self.tag = encrypt(self.key, self.nonce, b"peer private keys", b"peers")

    def opened(self, **overrides):
        args = dict(key=self.key, nonce=self.nonce, ciphertext=self.ct,
                    tag=self.tag, aad=b"peers")
        args.update(overrides)
        return decrypt(args["key"], args["nonce"], args["ciphertext"],
                       args["tag"], args["aad"])

    def test_a_flipped_ciphertext_bit(self):
        with self.assertRaises(InvalidTag):
            self.opened(ciphertext=bytes([self.ct[0] ^ 1]) + self.ct[1:])

    def test_a_flipped_tag_bit(self):
        with self.assertRaises(InvalidTag):
            self.opened(tag=bytes([self.tag[0] ^ 1]) + self.tag[1:])

    def test_altered_associated_data(self):
        with self.assertRaises(InvalidTag):
            self.opened(aad=b"other")

    def test_the_wrong_key(self):
        with self.assertRaises(InvalidTag):
            self.opened(key=secrets.token_bytes(32))

    def test_the_wrong_nonce(self):
        with self.assertRaises(InvalidTag):
            self.opened(nonce=secrets.token_bytes(12))

    def test_a_truncated_ciphertext(self):
        with self.assertRaises(InvalidTag):
            self.opened(ciphertext=self.ct[:-1])

    def test_a_short_tag_is_refused(self):
        with self.assertRaises(InvalidTag):
            self.opened(tag=self.tag[:8])


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_a_key_is_created_once_and_reused(self):
        first = vault.local_key(self.dir)
        self.assertEqual(len(first), 32)
        self.assertEqual(vault.local_key(self.dir), first)

    def test_the_key_file_is_owner_only(self):
        vault.local_key(self.dir)
        mode = (self.dir / vault.KEYFILE).stat().st_mode
        self.assertEqual(mode & 0o077, 0, "nobody but the owner may read the key")

    def test_seal_and_unseal(self):
        key = vault.local_key(self.dir)
        blob = vault.seal(key, b"secret", context=b"peers")
        self.assertTrue(vault.looks_sealed(blob))
        self.assertNotIn(b"secret", blob)
        self.assertEqual(vault.unseal(key, blob, context=b"peers"), b"secret")

    def test_the_context_is_authenticated(self):
        key = vault.local_key(self.dir)
        blob = vault.seal(key, b"secret", context=b"peers")
        with self.assertRaises(vault.VaultError):
            vault.unseal(key, blob, context=b"something-else")

    def test_a_truncated_vault_is_refused(self):
        key = vault.local_key(self.dir)
        blob = vault.seal(key, b"secret")
        for cut in (1, 10, len(blob) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(vault.VaultError):
                    vault.unseal(key, blob[:cut])

    def test_plaintext_is_not_mistaken_for_a_vault(self):
        self.assertFalse(vault.looks_sealed(b'{"peers": []}'))


class PortableBundleTests(unittest.TestCase):
    def test_a_bundle_round_trips_on_another_machine(self):
        # No shared state: only the passphrase and the file cross over.
        blob = vault.export_bundle("a good passphrase", {"state_key": "ab" * 32})
        self.assertEqual(
            vault.import_bundle("a good passphrase", blob)["state_key"], "ab" * 32
        )

    def test_the_wrong_passphrase_is_refused(self):
        blob = vault.export_bundle("a good passphrase", {"state_key": "00"})
        with self.assertRaises(vault.VaultError):
            vault.import_bundle("not it", blob)

    def test_the_message_does_not_say_which_was_wrong(self):
        # Telling a guesser "right passphrase, altered file" is a free hint.
        blob = vault.export_bundle("a good passphrase", {"state_key": "00"})
        altered = blob[:-1] + bytes([blob[-1] ^ 1])
        wrong = str(self.assertRaises(vault.VaultError))
        try:
            vault.import_bundle("not it", blob)
        except vault.VaultError as exc:
            wrong = str(exc)
        try:
            vault.import_bundle("a good passphrase", altered)
        except vault.VaultError as exc:
            self.assertEqual(str(exc), wrong)

    def test_a_foreign_file_is_refused(self):
        with self.assertRaises(vault.VaultError):
            vault.import_bundle("x" * 10, b"not a symbivpn export at all")

    def test_an_empty_passphrase_is_refused(self):
        with self.assertRaises(vault.VaultError):
            vault.export_bundle("", {"state_key": "00"})


class PairingTests(unittest.TestCase):
    """The key on the connector, not on the machine it protects."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.store_path = self.dir / "peers.json"

    def gateway_with_peers(self):
        from symbivpn.vpn.wireguard import PeerStore, WireGuardManager

        key = vault.local_key(self.dir)
        manager = WireGuardManager(PeerStore(self.store_path, key=key))
        manager.initialise_server(endpoint="vpn.example.com")
        manager.add_peer("phone")
        return key, manager

    def test_private_keys_are_not_on_disk_in_the_clear(self):
        key, manager = self.gateway_with_peers()
        raw = self.store_path.read_bytes()
        self.assertTrue(vault.looks_sealed(raw))
        self.assertNotIn(manager.store.server.private_key.encode(), raw)

    def test_pairing_removes_the_key(self):
        self.gateway_with_peers()
        vault.pair(self.dir)
        self.assertFalse((self.dir / vault.KEYFILE).exists())
        self.assertTrue(vault.is_paired(self.dir))

    def test_a_paired_machine_does_not_quietly_make_a_new_key(self):
        # Which would re-key the state and strand the peers for good.
        self.gateway_with_peers()
        vault.pair(self.dir)
        with self.assertRaises(vault.Locked):
            vault.local_key(self.dir)

    def test_a_locked_store_still_constructs(self):
        # Losing a phone must not stop the resolver from starting.
        from symbivpn.vpn.wireguard import PeerStore

        self.gateway_with_peers()
        vault.pair(self.dir)
        store = PeerStore(self.store_path, key=None)
        self.assertTrue(store.locked)
        self.assertEqual(store.peers, {})

    def test_a_locked_store_refuses_to_write(self):
        # The one unrecoverable mistake: an empty store over sealed peers.
        from symbivpn.vpn.wireguard import PeerStore, WireGuardError

        self.gateway_with_peers()
        vault.pair(self.dir)
        store = PeerStore(self.store_path, key=None)
        before = self.store_path.read_bytes()
        with self.assertRaises(WireGuardError):
            store.save()
        self.assertEqual(self.store_path.read_bytes(), before)

    def test_the_connector_key_unlocks_it(self):
        from symbivpn.vpn.wireguard import PeerStore

        key, _ = self.gateway_with_peers()
        bundle = vault.export_bundle("carry me", {"state_key": key.hex()})
        vault.pair(self.dir)

        store = PeerStore(self.store_path, key=None)
        recovered = bytes.fromhex(
            vault.import_bundle("carry me", bundle)["state_key"]
        )
        store.unlock(recovered)
        self.assertFalse(store.locked)
        self.assertEqual(sorted(store.peers), ["phone"])

    def test_a_wrong_key_does_not_unlock_or_clobber(self):
        from symbivpn.vpn.wireguard import PeerStore, WireGuardError

        self.gateway_with_peers()
        vault.pair(self.dir)
        store = PeerStore(self.store_path, key=None)
        before = self.store_path.read_bytes()

        with self.assertRaises(WireGuardError):
            store.unlock(secrets.token_bytes(32))
        self.assertTrue(store.locked, "a failed unlock must leave it locked")
        self.assertEqual(self.store_path.read_bytes(), before)

    def test_restoring_the_key_makes_it_self_sufficient_again(self):
        from symbivpn.vpn.wireguard import PeerStore

        key, _ = self.gateway_with_peers()
        vault.pair(self.dir)
        vault.unpair(self.dir, key)
        self.assertFalse(vault.is_paired(self.dir))
        store = PeerStore(self.store_path, key=vault.local_key(self.dir))
        self.assertFalse(store.locked)
        self.assertEqual(sorted(store.peers), ["phone"])

    def test_an_older_plaintext_store_is_read_and_converted(self):
        from symbivpn.vpn.wireguard import PeerStore, WireGuardManager

        # An install from before any of this existed.
        plain = WireGuardManager(PeerStore(self.store_path, key=None))
        plain.initialise_server(endpoint="vpn.example.com")
        plain.add_peer("phone")
        self.assertFalse(vault.looks_sealed(self.store_path.read_bytes()))

        key = vault.local_key(self.dir)
        reopened = PeerStore(self.store_path, key=key)
        self.assertTrue(reopened.needs_sealing)
        self.assertEqual(sorted(reopened.peers), ["phone"])
        reopened.save()
        self.assertTrue(vault.looks_sealed(self.store_path.read_bytes()))


if __name__ == "__main__":
    unittest.main()
