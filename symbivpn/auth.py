"""Password handling for the dashboard.

The dashboard can add VPN peers and switch filtering off, so reaching it is
close to owning the network it protects. Two things follow from that: it must
not be reachable from the network without a password, and the password must not
sit in a config file in the clear.

Hashing uses scrypt from the standard library, which is memory-hard -- a
stolen hash cannot be attacked at GPU speed the way a plain SHA-256 can.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import threading
import time

log = logging.getLogger(__name__)

#: scrypt parameters. n=16384 costs roughly 16MB and a few tens of
#: milliseconds, which is nothing per login and a great deal per guess.
SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32

PREFIX = "scrypt$"


def hash_password(password: str) -> str:
    """Hash a password for storage in the config file."""
    if not password:
        raise ValueError("a password is required")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES,
    )
    return f"{PREFIX}{salt.hex()}${derived.hex()}"


def is_hashed(stored: str) -> bool:
    return stored.startswith(PREFIX) and stored.count("$") == 2


def verify_password(supplied: str, stored: str) -> bool:
    """Check a password against a stored value, hashed or not.

    A plaintext value in the config still works, so an existing install does
    not break on upgrade -- but it is compared in constant time all the same,
    and the caller warns about it.
    """
    if not stored:
        return False

    if not is_hashed(stored):
        # Encoded first: compare_digest refuses non-ASCII str outright, so
        # comparing them directly would raise rather than return False.
        return hmac.compare_digest(supplied.encode("utf-8"), stored.encode("utf-8"))

    try:
        _, salt_hex, expected_hex = stored.split("$", 2)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except (ValueError, TypeError):
        return False

    derived = hashlib.scrypt(
        supplied.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=len(expected) or KEY_BYTES,
    )
    return hmac.compare_digest(derived, expected)


class AttemptLimiter:
    """Slows down password guessing, per client address.

    scrypt already makes each guess expensive; this stops a client tying up
    the server making them, and turns a distributed guessing attempt into a
    visible one.
    """

    #: Most clients tracked at once. Both maps are keyed by address, and a
    #: client on a local network can usually pick its own -- an IPv6 /64 gives
    #: it more addresses than there are grains of sand. Without a ceiling the
    #: bookkeeping meant to slow guessing becomes a way to exhaust memory in
    #: the process that is also answering the network's DNS.
    MAX_TRACKED = 4096

    #: Seconds between full sweeps of the two maps.
    SWEEP_INTERVAL = 1.0

    def __init__(self, limit: int = 5, window: float = 300.0, lockout: float = 300.0) -> None:
        self.limit = limit
        self.window = window
        self.lockout = lockout
        self._failures: dict[str, list[float]] = {}
        self._locked: dict[str, float] = {}
        self._lock = threading.Lock()
        self._next_sweep = 0.0

    def _prune(self, now: float) -> None:
        """Forget what has expired, and cap what has not. Caller holds the lock.

        Nothing ever revisits a locked-out client that simply stops trying, so
        without this its entry stays for the life of the process.

        A sweep walks both maps, so it is rate-limited rather than run on every
        attempt: at a few thousand tracked clients, sweeping per failed login
        would hand an attacker a way to spend the gateway's CPU by getting the
        password wrong quickly, which is the opposite of the point.
        """
        over_capacity = (
            len(self._locked) > self.MAX_TRACKED or len(self._failures) > self.MAX_TRACKED
        )
        if now < self._next_sweep and not over_capacity:
            return
        self._next_sweep = now + self.SWEEP_INTERVAL

        for client, until in list(self._locked.items()):
            if now >= until:
                del self._locked[client]
                self._failures.pop(client, None)

        for client, times in list(self._failures.items()):
            if not times or now - times[-1] >= self.window:
                del self._failures[client]

        # If everything tracked is still live, drop what expires soonest. An
        # attacker able to reach this point has enough addresses that per-
        # address lockout was not going to stop it anyway, and a bounded map
        # matters more than holding the last few entries.
        #
        # Trimmed to below the ceiling rather than exactly to it, so the next
        # entry does not put the map over again and force another sweep. That
        # is what makes the cost amortised instead of per-attempt.
        floor = self.MAX_TRACKED * 7 // 8
        if len(self._locked) > self.MAX_TRACKED:
            ordered = sorted(self._locked, key=self._locked.__getitem__)
            for client in ordered[: len(self._locked) - floor]:
                del self._locked[client]
        if len(self._failures) > self.MAX_TRACKED:
            ordered = sorted(self._failures, key=lambda key: self._failures[key][-1])
            for client in ordered[: len(self._failures) - floor]:
                del self._failures[client]

    def locked_out(self, client: str) -> float:
        """Seconds remaining on a lockout, or 0 if the client may try."""
        now = time.monotonic()
        with self._lock:
            until = self._locked.get(client)
            if until is None:
                return 0.0
            if now >= until:
                del self._locked[client]
                self._failures.pop(client, None)
                return 0.0
            return until - now

    def record_failure(self, client: str) -> bool:
        """Note a failed attempt. Returns True if the client is now locked out."""
        now = time.monotonic()
        with self._lock:
            attempts = [t for t in self._failures.get(client, []) if now - t < self.window]
            attempts.append(now)
            self._failures[client] = attempts

            locked = len(attempts) >= self.limit
            if locked:
                self._locked[client] = now + self.lockout

            # Housekeeping runs on the failure path, which is the only one an
            # attacker controls, and where the maps actually grow.
            self._prune(now)
            return locked

    def record_success(self, client: str) -> None:
        with self._lock:
            self._failures.pop(client, None)
            self._locked.pop(client, None)

    def status(self) -> dict[str, int]:
        with self._lock:
            # Reporting is not the hot path, so it always sweeps first and
            # reports what is actually still live.
            self._next_sweep = 0.0
            self._prune(time.monotonic())
            return {
                "clients_with_failures": len(self._failures),
                "locked_out": len(self._locked),
            }


class AdminToken:
    """A secret shared between the daemon and the CLI on the same machine.

    Hashing the dashboard password is right for a human typing it, and wrong
    for the CLI: it has only the hash, and a hash is not a password. Rather
    than weaken the hashing or make `symbivpn status` prompt, the daemon
    writes a token that anyone who could already read the config can read --
    which is the same trust boundary, expressed honestly.
    """

    FILENAME = "admin.token"

    def __init__(self, state_dir) -> None:
        from pathlib import Path

        self.path = Path(state_dir) / self.FILENAME
        #: Held once the daemon has loaded it. Comparing against this rather
        #: than re-reading the file means tampering with the file does not
        #: grant access -- it only breaks the CLI until the next restart.
        self._value = ""

    def load_or_create(self, password: str = "") -> str:
        """Read the token, issuing a new one if it is missing or stale.

        A token is bound to the password that was configured when it was
        issued. Changing the password is how someone revokes access, so a
        token that outlived the password it was issued under would quietly
        defeat that.
        """
        import os
        import stat

        wanted = self.fingerprint(password)
        existing = self.read()
        if existing and self.issued_for() == wanted:
            self._value = existing
            return existing

        if existing:
            log.info(
                "the dashboard password changed, so the local admin token has "
                "been reissued; any copy of the old one no longer works"
            )

        token = secrets.token_urlsafe(32)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Written before the mode is set, so create it closed rather than
        # widening it afterwards.
        handle = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(handle, "w", encoding="utf-8") as file:
            file.write(f"{token}\n{wanted}")
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        self._value = token
        return token

    def read(self) -> str:
        """The stored token, or "" if there is not a usable one.

        Anything unreadable -- missing, truncated, not text -- reads as absent
        so that `load_or_create` replaces it. Raising here would take the
        daemon down at start-up over a corrupt file it can simply rewrite.
        """
        try:
            payload = self.path.read_text(encoding="utf-8").strip()
        except (OSError, ValueError, UnicodeDecodeError):
            return ""

        token, _, _ = payload.partition("\n")
        token = token.strip()
        return token if len(token) >= 20 else ""

    def issued_for(self) -> str:
        """The password fingerprint this token was issued against."""
        try:
            payload = self.path.read_text(encoding="utf-8")
        except (OSError, ValueError, UnicodeDecodeError):
            return ""
        _, _, fingerprint = payload.partition("\n")
        return fingerprint.strip()

    @staticmethod
    def fingerprint(password: str) -> str:
        """A short, non-reversible marker for "which password is configured".

        Stored beside the token so that changing the password invalidates it.
        """
        if not password:
            return ""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()[:32]

    def matches(self, supplied: str) -> bool:
        """Compare against the token held in memory since start-up.

        Deliberately not a fresh read: otherwise anyone able to write the file
        could choose the secret, and "can write this file" is a weaker
        condition than "was here when the service started".
        """
        if not self._value:
            return False
        # Encoded for the same reason as above: this runs before the password
        # check, so a non-ASCII password would otherwise raise here and never
        # reach the code that can verify it.
        return hmac.compare_digest(supplied.encode("utf-8"), self._value.encode("utf-8"))


def looks_local(address: str) -> bool:
    """Whether an address means "this machine only"."""
    return address in ("127.0.0.1", "::1", "localhost", "")


class Session:
    """One logged-in browser."""

    __slots__ = ("token", "created_at", "expires_at", "label")

    def __init__(self, token: str, created_at: float, expires_at: float, label: str) -> None:
        self.token = token
        self.created_at = created_at
        self.expires_at = expires_at
        self.label = label

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "created_at": self.created_at,
            "expires_in": max(0, int(self.expires_at - time.time())),
        }


class SessionStore:
    """Browser sessions for the dashboard.

    HTTP Basic authentication is what a command-line client wants and what a
    phone handles worst: the browser re-asks whenever it feels like it, there
    is no way to log out, and the password rides on every single request. A
    session cookie is the right shape for a person on a phone -- log in once,
    stay logged in, log out when you mean to -- and it keeps the password off
    every request after the first.

    Sessions are held in memory and nowhere else. Restarting the service logs
    everyone out, which is the honest trade for never writing anything
    password-equivalent to disk; a gateway restarts rarely, and logging in
    again is a few seconds.
    """

    #: How long a session lasts without being used. Long, deliberately: the
    #: whole point is not being asked again on a phone.
    LIFETIME = 30 * 86_400
    #: Ceiling on concurrent sessions, so a login loop cannot grow this.
    MAX_SESSIONS = 32

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._issued_for = ""

    def bind(self, password: str) -> None:
        """Tie sessions to the configured password.

        Changing the password is how someone revokes access, so sessions
        issued under the old one must not outlive it -- the same rule the
        local admin token follows.
        """
        fingerprint = AdminToken.fingerprint(password)
        with self._lock:
            ended = len(self._sessions)
            if self._issued_for and self._issued_for != fingerprint and ended:
                self._sessions.clear()
                log.info(
                    "the dashboard password changed, so %d browser session(s) were ended",
                    ended,
                )
            self._issued_for = fingerprint

    def create(self, label: str = "") -> tuple[str, int]:
        """Start a session. Returns (token, lifetime-in-seconds)."""
        now = time.time()
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(now)
            if len(self._sessions) >= self.MAX_SESSIONS:
                # Drop the one that will expire first rather than refuse the
                # login: being unable to log in is a worse failure than
                # signing out the oldest device.
                oldest = min(self._sessions.values(), key=lambda s: s.expires_at)
                del self._sessions[oldest.token]
            self._sessions[token] = Session(token, now, now + self.LIFETIME, label[:60])
        return token, self.LIFETIME

    def validate(self, token: str) -> bool:
        """Whether this token names a live session."""
        if not token:
            return False
        now = time.time()
        with self._lock:
            self._prune(now)
            # Compared one by one rather than by dictionary lookup: `==` on
            # strings stops at the first wrong byte, and there is no reason to
            # answer a guess in a time that depends on how close it was.
            for session in self._sessions.values():
                if hmac.compare_digest(session.token, token):
                    return True
        return False

    def revoke(self, token: str) -> bool:
        with self._lock:
            for session in list(self._sessions.values()):
                if hmac.compare_digest(session.token, token):
                    del self._sessions[session.token]
                    return True
        return False

    def revoke_all(self) -> int:
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
        return count

    def active(self) -> list[dict[str, object]]:
        now = time.time()
        with self._lock:
            self._prune(now)
            return [session.as_dict() for session in self._sessions.values()]

    def _prune(self, now: float) -> None:
        """Drop expired sessions. Caller holds the lock."""
        for token, session in list(self._sessions.items()):
            if now >= session.expires_at:
                del self._sessions[token]
