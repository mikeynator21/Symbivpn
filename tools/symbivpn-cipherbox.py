#!/usr/bin/env python3
"""SymbiVPN cipher box -- open an encrypted SymbiVPN file, anywhere.

This is a single file with no dependencies and nothing to install. Download
it, run it with Python 3.11 or newer, and it will open what SymbiVPN wrote.

It exists for the case that matters: the gateway is gone. A drowned Pi, a
wiped disk, a laptop that will not boot. Your peers are encrypted and the only
thing that could read them was on the machine that died -- unless you kept
this file and the exported key, which is the whole idea.

    python3 symbivpn-cipherbox.py key       symbivpn.key
    python3 symbivpn-cipherbox.py peers     peers.json --key-file symbivpn.key
    python3 symbivpn-cipherbox.py configs   peers.json --key-file symbivpn.key --out ./recovered

DO NOT EDIT. Generated from symbivpn/aesgcm.py and symbivpn/vault.py by
tools/build_cipherbox.py; a test fails if this copy falls behind them.
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import json
import logging
import os
import secrets
import stat
import struct
import sys
import types
from pathlib import Path

log = logging.getLogger("cipherbox")

# ---- from symbivpn/aesgcm.py, verbatim ----

BLOCK = 16
KEY_BYTES = 32          # AES-256
ROUNDS = 14             # AES-256
NONCE_BYTES = 12        # The 96-bit IV GCM is specified around.
TAG_BYTES = 16


def _build_sbox() -> tuple[bytes, list[int]]:
    """The AES S-box, constructed rather than pasted.

    Each entry is the multiplicative inverse in GF(2^8) put through the affine
    transform of FIPS-197 section 5.1.1. Building it is a dozen lines and can
    be checked by eye against the standard's first row; a 256-entry literal
    can only be checked by trusting whoever typed it.
    """
    # Log and antilog tables over the generator 3, used for the inverse.
    antilog = [0] * 256
    log = [0] * 256
    value = 1
    for exponent in range(255):
        antilog[exponent] = value
        log[value] = exponent
        # Multiply by 3: value ^ xtime(value).
        value ^= ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF
    antilog[255] = antilog[0]

    sbox = bytearray(256)
    for byte in range(256):
        inverse = 0 if byte == 0 else antilog[255 - log[byte]]
        result = inverse
        for _ in range(4):
            inverse = ((inverse << 1) | (inverse >> 7)) & 0xFF
            result ^= inverse
        sbox[byte] = result ^ 0x63
    return bytes(sbox), log


SBOX, _LOG = _build_sbox()
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(byte: int) -> int:
    """Multiply by x in GF(2^8), reducing by the AES polynomial."""
    return ((byte << 1) ^ 0x1B) & 0xFF if byte & 0x80 else byte << 1


def expand_key(key: bytes) -> list[list[int]]:
    """Expand a 256-bit key into the 15 round keys AES-256 uses."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"AES-256 needs a {KEY_BYTES}-byte key, got {len(key)}")

    words = [list(key[i : i + 4]) for i in range(0, KEY_BYTES, 4)]
    for index in range(8, 4 * (ROUNDS + 1)):
        word = list(words[index - 1])
        if index % 8 == 0:
            word = word[1:] + word[:1]                      # RotWord
            word = [SBOX[b] for b in word]                  # SubWord
            word[0] ^= RCON[index // 8 - 1]
        elif index % 8 == 4:
            word = [SBOX[b] for b in word]                  # SubWord only
        words.append([a ^ b for a, b in zip(words[index - 8], word)])

    return [
        [byte for word in words[round_ * 4 : round_ * 4 + 4] for byte in word]
        for round_ in range(ROUNDS + 1)
    ]


def encrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    """One AES-256 block encryption. The only direction GCM needs."""
    state = [b ^ k for b, k in zip(block, round_keys[0])]

    for round_ in range(1, ROUNDS + 1):
        state = [SBOX[b] for b in state]                    # SubBytes

        # ShiftRows: the state is column-major, so row r shifts left by r.
        state = [
            state[0], state[5], state[10], state[15],
            state[4], state[9], state[14], state[3],
            state[8], state[13], state[2], state[7],
            state[12], state[1], state[6], state[11],
        ]

        if round_ != ROUNDS:                                # MixColumns
            mixed = []
            for column in range(0, 16, 4):
                a0, a1, a2, a3 = state[column : column + 4]
                total = a0 ^ a1 ^ a2 ^ a3
                mixed += [
                    a0 ^ total ^ _xtime(a0 ^ a1),
                    a1 ^ total ^ _xtime(a1 ^ a2),
                    a2 ^ total ^ _xtime(a2 ^ a3),
                    a3 ^ total ^ _xtime(a3 ^ a0),
                ]
            state = mixed

        state = [b ^ k for b, k in zip(state, round_keys[round_])]

    return bytes(state)


def _ghash(subkey: int, data: bytes) -> int:
    """GHASH: the GF(2^128) hash GCM authenticates with.

    The field is GF(2) modulo x^128 + x^7 + x^2 + x + 1, with GCM's bit
    ordering -- which is why the reduction constant reads 0xE1 followed by
    zeros rather than the polynomial written the usual way round.
    """
    accumulator = 0
    for offset in range(0, len(data), BLOCK):
        chunk = data[offset : offset + BLOCK].ljust(BLOCK, b"\0")
        accumulator ^= int.from_bytes(chunk, "big")

        product = 0
        value = accumulator
        for bit in range(127, -1, -1):
            if (subkey >> bit) & 1:
                product ^= value
            carry = value & 1
            value >>= 1
            if carry:
                value ^= 0xE1 << 120
        accumulator = product
    return accumulator


def _gctr(round_keys, counter: bytes, data: bytes) -> bytes:
    """GCM's counter mode: encrypt the counter, XOR, increment the low word."""
    if not data:
        return b""
    prefix = counter[:12]
    block_number = int.from_bytes(counter[12:], "big")
    out = bytearray()
    for offset in range(0, len(data), BLOCK):
        keystream = encrypt_block(
            round_keys, prefix + block_number.to_bytes(4, "big")
        )
        chunk = data[offset : offset + BLOCK]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        block_number = (block_number + 1) & 0xFFFFFFFF
    return bytes(out)


def _lengths(aad: bytes, ciphertext: bytes) -> bytes:
    return struct.pack("!QQ", len(aad) * 8, len(ciphertext) * 8)


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt and authenticate. Returns (ciphertext, tag)."""
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"GCM wants a {NONCE_BYTES}-byte nonce, got {len(nonce)}")

    round_keys = expand_key(key)
    subkey = int.from_bytes(encrypt_block(round_keys, b"\0" * BLOCK), "big")
    counter_zero = nonce + b"\0\0\0\1"

    ciphertext = _gctr(round_keys, nonce + b"\0\0\0\2", plaintext)

    padded_aad = aad + b"\0" * (-len(aad) % BLOCK)
    padded_ct = ciphertext + b"\0" * (-len(ciphertext) % BLOCK)
    digest = _ghash(subkey, padded_aad + padded_ct + _lengths(aad, ciphertext))
    tag = _gctr(round_keys, counter_zero, digest.to_bytes(BLOCK, "big"))
    return ciphertext, tag


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Verify and decrypt. Raises InvalidTag if anything was altered."""
    if len(tag) != TAG_BYTES:
        raise InvalidTag(f"a GCM tag is {TAG_BYTES} bytes, got {len(tag)}")

    round_keys = expand_key(key)
    subkey = int.from_bytes(encrypt_block(round_keys, b"\0" * BLOCK), "big")

    padded_aad = aad + b"\0" * (-len(aad) % BLOCK)
    padded_ct = ciphertext + b"\0" * (-len(ciphertext) % BLOCK)
    digest = _ghash(subkey, padded_aad + padded_ct + _lengths(aad, ciphertext))
    expected = _gctr(round_keys, nonce + b"\0\0\0\1", digest.to_bytes(BLOCK, "big"))

    # Compared in constant time, and *before* anything is returned: releasing
    # unverified plaintext is how AEAD gets undone in practice.
    if not hmac.compare_digest(expected, tag):
        raise InvalidTag("the data has been altered, or the key is wrong")

    return _gctr(round_keys, nonce + b"\0\0\0\2", ciphertext)


class InvalidTag(ValueError):
    """The ciphertext did not authenticate."""


# The embedded vault code below refers to `aesgcm.X`, exactly as it does in
# the package. Here that module is this file, so the name is bound to a view
# of it rather than the import being rewritten -- which keeps the embedded
# source byte-identical to the original, and that is what makes the drift
# test meaningful.
aesgcm = types.SimpleNamespace(
    KEY_BYTES=KEY_BYTES,
    NONCE_BYTES=NONCE_BYTES,
    TAG_BYTES=TAG_BYTES,
    BLOCK=BLOCK,
    encrypt=encrypt,
    decrypt=decrypt,
    InvalidTag=InvalidTag,
)

# ---- from symbivpn/vault.py, verbatim ----

log = logging.getLogger(__name__)

#: Identifies the format and the parameters, and is authenticated as
#: associated data -- so downgrading the header is not a way in.
MAGIC = b"SBVPN-VAULT-1"
KEYFILE = "state.key"
#: Written when the key has deliberately been moved to a connector device.
#: Without it, a missing key just means "first run" and a new one is made --
#: which would quietly undo the pairing and re-key the state.
PAIRED_MARKER = "state.paired"

# scrypt, matching the dashboard password hashing: memory-hard, so a stolen
# file cannot be attacked at GPU speed.
SCRYPT_N = 1 << 15          # Higher than the login path: this runs rarely.
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16


class VaultError(Exception):
    """The vault could not be opened."""


class Locked(VaultError):
    """The state is encrypted and the key is not on this machine.

    Not a failure to be recovered from by re-keying: the key is on the
    connector, which is the point. Everything that does not need the peer keys
    carries on regardless -- losing a phone must not take DNS down with it.
    """


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Turn a passphrase into a 256-bit key."""
    import hashlib

    if not passphrase:
        raise VaultError("a passphrase is required")
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=aesgcm.KEY_BYTES,
        maxmem=256 * 1024 * 1024,
    )


def seal(key: bytes, plaintext: bytes, context: bytes = b"") -> bytes:
    """Encrypt to a self-describing blob."""
    if len(key) != aesgcm.KEY_BYTES:
        raise VaultError(f"the key must be {aesgcm.KEY_BYTES} bytes")
    nonce = secrets.token_bytes(aesgcm.NONCE_BYTES)
    header = MAGIC + struct.pack("!H", len(context)) + context
    ciphertext, tag = aesgcm.encrypt(key, nonce, plaintext, aad=header)
    return header + nonce + tag + ciphertext


def unseal(key: bytes, blob: bytes, context: bytes = b"") -> bytes:
    """Decrypt a blob written by `seal`, or raise."""
    header = MAGIC + struct.pack("!H", len(context)) + context
    if not blob.startswith(header):
        raise VaultError("this is not a SymbiVPN vault, or it is a different version")
    body = blob[len(header):]
    if len(body) < aesgcm.NONCE_BYTES + aesgcm.TAG_BYTES:
        raise VaultError("the vault file is truncated")
    nonce = body[: aesgcm.NONCE_BYTES]
    tag = body[aesgcm.NONCE_BYTES : aesgcm.NONCE_BYTES + aesgcm.TAG_BYTES]
    ciphertext = body[aesgcm.NONCE_BYTES + aesgcm.TAG_BYTES :]
    try:
        return aesgcm.decrypt(key, nonce, ciphertext, tag, aad=header)
    except aesgcm.InvalidTag as exc:
        raise VaultError(str(exc)) from exc


# -- the unattended key beside the data -----------------------------------


def local_key(state_dir: Path | str, *, create: bool = True) -> bytes | None:
    """The machine's own state key, created on first use.

    Beside the data on purpose: the service has to start without anyone
    present. See this module's docstring for exactly what that does and does
    not protect.
    """
    directory = Path(state_dir)
    path = directory / KEYFILE
    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        if (directory / PAIRED_MARKER).exists():
            raise Locked(
                "the state key is held on the connector device. Unlock with "
                "`symbivpn unlock`, or from the dashboard on that device."
            )
        existing = b""
    except OSError as exc:
        raise VaultError(f"could not read {path}: {exc}") from exc

    if len(existing) == aesgcm.KEY_BYTES:
        _warn_if_readable(path)
        return existing
    if existing:
        raise VaultError(
            f"{path} is not a {aesgcm.KEY_BYTES}-byte key. Move it aside and "
            f"SymbiVPN will make a new one -- but anything encrypted with the "
            f"old key is then unreadable, so keep it until you are sure."
        )
    if not create:
        return None

    key = secrets.token_bytes(aesgcm.KEY_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written 0600 from the start rather than chmodded afterwards: between
    # create and chmod is a window, and this is the one file that matters.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, key)
    finally:
        os.close(descriptor)
    log.info("created the state encryption key at %s", path)
    return key


def _warn_if_readable(path: Path) -> None:
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        log.warning(
            "%s is readable by more than its owner, which makes encrypting "
            "the state pointless. Fix it: chmod 600 %s", path, path,
        )


def seal_file(path: Path, key: bytes, payload: bytes, context: bytes = b"") -> None:
    """Write an encrypted file, atomically and 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, seal(key, payload, context))
    finally:
        os.close(descriptor)
    temporary.replace(path)


def unseal_file(path: Path, key: bytes, context: bytes = b"") -> bytes | None:
    """Read an encrypted file, or None if it is not there."""
    try:
        blob = path.read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise VaultError(f"could not read {path}: {exc}") from exc
    return unseal(key, blob, context)


def looks_sealed(blob: bytes) -> bool:
    """Whether these bytes are a vault, as opposed to the plaintext we used to write."""
    return blob.startswith(MAGIC)


# -- the portable, passphrase-locked copy ---------------------------------


def export_bundle(passphrase: str, payload: dict) -> bytes:
    """Lock a dictionary with a passphrase, for carrying elsewhere."""
    salt = secrets.token_bytes(SALT_BYTES)
    key = derive_key(passphrase, salt)
    body = seal(key, json.dumps(payload).encode("utf-8"), context=b"export")
    # The salt travels with it -- it is not secret, and without it the
    # passphrase cannot reproduce the key on another machine.
    return b"SBVPN-EXPORT-1" + salt + body


def import_bundle(passphrase: str, blob: bytes) -> dict:
    """Open a bundle written by `export_bundle`."""
    prefix = b"SBVPN-EXPORT-1"
    if not blob.startswith(prefix):
        raise VaultError("this is not a SymbiVPN export file")
    salt = blob[len(prefix) : len(prefix) + SALT_BYTES]
    if len(salt) != SALT_BYTES:
        raise VaultError("the export file is truncated")
    key = derive_key(passphrase, salt)
    try:
        opened = unseal(key, blob[len(prefix) + SALT_BYTES :], context=b"export")
    except VaultError:
        # One message for both, because which of the two it was is exactly
        # what an attacker guessing passphrases would like to be told.
        raise VaultError("wrong passphrase, or the file has been altered") from None
    try:
        payload = json.loads(opened)
    except ValueError as exc:
        raise VaultError(f"the export file does not contain valid data: {exc}") from exc
    if not isinstance(payload, dict):
        raise VaultError("the export file does not contain valid data")
    return payload


# -- pairing the key to a connector ---------------------------------------


def is_paired(state_dir: Path | str) -> bool:
    """Whether this machine has handed its key to a connector device."""
    return (Path(state_dir) / PAIRED_MARKER).exists()


def pair(state_dir: Path | str) -> None:
    """Remove the local key, leaving the state openable only by the connector.

    The caller must already have exported the key somewhere safe. There is no
    copy left here afterwards, which is the whole point and also the whole
    risk: lose the connector and the peers are gone.
    """
    directory = Path(state_dir)
    marker = directory / PAIRED_MARKER
    descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, b"the state key lives on a connector device\n")
    finally:
        os.close(descriptor)

    key_path = directory / KEYFILE
    try:
        # Overwritten before unlinking. On a journalling filesystem this is not
        # a guarantee -- the old blocks may survive -- so it raises the cost
        # rather than settling the question.
        size = key_path.stat().st_size
        with open(key_path, "r+b") as handle:
            handle.write(secrets.token_bytes(size))
            handle.flush()
            os.fsync(handle.fileno())
        key_path.unlink()
    except FileNotFoundError:
        pass
    log.warning(
        "the state key has been removed from this machine. Without the "
        "connector device the VPN peers cannot be read."
    )


def unpair(state_dir: Path | str, key: bytes) -> None:
    """Put a key back on this machine, so it can start on its own again."""
    directory = Path(state_dir)
    if len(key) != aesgcm.KEY_BYTES:
        raise VaultError(f"the key must be {aesgcm.KEY_BYTES} bytes")
    directory.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(directory / KEYFILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, key)
    finally:
        os.close(descriptor)
    (directory / PAIRED_MARKER).unlink(missing_ok=True)
    log.info("the state key is on this machine again")


# -- the command line -----------------------------------------------------


def _read_key(args) -> bytes:
    """The 32-byte state key, from an exported bundle or straight hex."""
    if args.key_hex:
        key = bytes.fromhex(args.key_hex.strip())
        if len(key) != aesgcm.KEY_BYTES:
            raise SystemExit(f"a state key is {aesgcm.KEY_BYTES} bytes, got {len(key)}")
        return key

    path = Path(args.key_file)
    try:
        blob = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"could not read {path}: {exc}") from exc

    passphrase = getpass.getpass("  passphrase for the exported key: ")
    try:
        payload = import_bundle(passphrase, blob)
        return bytes.fromhex(payload["state_key"])
    except (VaultError, KeyError, ValueError) as exc:
        raise SystemExit(f"could not open {path}: {exc}") from exc


def _open_peers(path: Path, key: bytes) -> dict:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"could not read {path}: {exc}") from exc

    if looks_sealed(raw):
        try:
            raw = unseal(key, raw, context=b"peers")
        except VaultError as exc:
            raise SystemExit(f"could not decrypt {path}: {exc}") from exc
    else:
        print(f"note: {path} is not encrypted; reading it as it is.", file=sys.stderr)

    try:
        return json.loads(raw)
    except ValueError as exc:
        raise SystemExit(f"{path} does not contain SymbiVPN peers: {exc}") from exc


def _peer_config(server: dict, peer: dict) -> str:
    """Rebuild a peer's WireGuard configuration from the stored fields."""
    lines = [
        f"# SymbiVPN :: {peer.get('name', 'peer')}  (recovered by the cipher box)",
        "[Interface]",
        f"PrivateKey = {peer.get('private_key', '')}",
        f"Address = {peer.get('address', '')}/32",
    ]
    resolver = server.get("dns_address") or server.get("address", "")
    if resolver:
        lines.append(f"DNS = {resolver}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server.get('public_key', '')}",
    ]
    if peer.get("preshared_key"):
        lines.append(f"PresharedKey = {peer['preshared_key']}")
    allowed = peer.get("allowed_ips") or "0.0.0.0/0, ::/0"
    lines += [
        f"AllowedIPs = {allowed}",
        f"Endpoint = {server.get('endpoint', '')}:{server.get('listen_port', 51820)}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="symbivpn-cipherbox",
        description=(
            "Open an encrypted SymbiVPN file on a machine with nothing installed."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    def key_source(p):
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("--key-file", help="an exported key file (asks for the passphrase)")
        group.add_argument("--key-hex", help="the 32-byte state key as hex")

    show = sub.add_parser("key", help="open an exported key file and print the key")
    show.add_argument("path", help="the exported key file")

    peers = sub.add_parser("peers", help="decrypt a peers file and print it")
    peers.add_argument("path", help="peers.json from the state directory")
    key_source(peers)

    configs = sub.add_parser("configs", help="write each peer's WireGuard config")
    configs.add_argument("path", help="peers.json from the state directory")
    configs.add_argument("--out", default=".", help="directory to write into")
    key_source(configs)

    args = parser.parse_args(argv)

    if args.command == "key":
        blob = Path(args.path).read_bytes()
        passphrase = getpass.getpass("  passphrase for the exported key: ")
        try:
            payload = import_bundle(passphrase, blob)
        except VaultError as exc:
            raise SystemExit(str(exc)) from exc
        print(payload["state_key"])
        return 0

    key = _read_key(args)
    payload = _open_peers(Path(args.path), key)

    if args.command == "peers":
        print(json.dumps(payload, indent=2))
        return 0

    server = payload.get("server") or {}
    written = 0
    directory = Path(args.out)
    directory.mkdir(parents=True, exist_ok=True)
    for peer in payload.get("peers", []):
        name = str(peer.get("name", "peer"))
        safe = "".join(c for c in name if c.isalnum() or c in "-_. ") or "peer"
        destination = directory / f"{safe}.conf"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(descriptor, _peer_config(server, peer).encode("utf-8"))
        finally:
            os.close(descriptor)
        written += 1
        print(f"  wrote {destination}")
    print(f"\n{written} configuration(s) recovered. They contain private keys: mode 600.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
