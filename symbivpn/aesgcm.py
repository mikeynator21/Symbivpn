"""AES-256-GCM, from FIPS-197 and NIST SP 800-38D.

Python's standard library has no symmetric cipher. Adding one as a dependency
would cost the thing that makes this project installable on a Raspberry Pi or
under Termux -- no compiler, no package index -- so the cipher is built here,
the same way this project already builds X25519, QR encoding and the DNS wire
format from their specifications.

GCM needs only the forward direction of AES: both encryption and decryption
run the block cipher over a counter and XOR the result, so there is no inverse
cipher here to get wrong.

**This is not constant-time.** It is table-driven and written in Python, so it
leaks timing and cache behaviour to anything that can measure them. That is an
acceptable trade for encrypting a state file at rest, where the attacker has
to be on the machine already and reading memory is easier than timing it. It
would not be acceptable for a network-facing protocol, and nothing here uses
it that way: the tunnel is WireGuard and the resolver channel is TLS, both of
which bring their own vetted implementations.
"""

from __future__ import annotations

import hmac
import struct

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
