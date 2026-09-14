"""Encrypting what SymbiVPN keeps on disk, with AES-256-GCM.

The state directory holds the WireGuard private keys for every peer. They are
kept rather than discarded so a phone's QR code can be shown again later, which
is worth it -- and it means a backup, a decommissioned SD card or a snapshot of
the filesystem carries every key on the network.

Two different jobs, deliberately kept apart, because they have different
threat models and conflating them is how people end up trusting the wrong one:

**At rest, unattended.** The service starts on boot with nobody to type a
passphrase, so the key lives beside the data in a 0600 file. That protects a
disk that leaves the building: a backup, a stolen Pi, a sold drive. It does
*not* protect against someone who already has root on the running machine --
they can read the key file exactly as the service does. Anyone who tells you
otherwise is selling something.

**Portable, with a passphrase.** Moving a gateway to new hardware, or keeping
an off-site copy, needs a file that is safe somewhere you do not control. That
one is locked with a passphrase through scrypt, and the machine it came from
is not required to open it.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import stat
import struct
from pathlib import Path

from . import aesgcm

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
