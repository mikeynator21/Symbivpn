"""The dashboard and its JSON API.

A single-file HTTP server on the standard library. The dashboard is the honest
answer to "is this thing working, and why did it break that site?" -- so the
query log, the block reason for any name, and the per-source rule counts are all
one click away.

The API binds to localhost by default. Exposing it to the hotspot is a
deliberate choice, and setting a password is required before any write is
accepted from off-host.
"""

from __future__ import annotations

import base64
import hmac
import http.cookies
import json
import logging
import mimetypes
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from .auth import (
    AdminToken,
    AttemptLimiter,
    SessionStore,
    is_hashed,
    looks_local,
    verify_password,
)
from .vpn import qr
from .vpn.wireguard import WireGuardError

if TYPE_CHECKING:  # pragma: no cover
    from .app import Application

log = logging.getLogger(__name__)

WEB_ROOT = Path(__file__).parent / "web"
MAX_BODY = 256 * 1024

#: What an unexpected failure tells the caller. The real message goes to the
#: log, where the operator can read it: exception text routinely carries file
#: paths and configuration values, and the caller has no use for either.
_INTERNAL_ERROR = "internal error; see the service log"

#: The session cookie. Not `Secure`: the dashboard speaks plain HTTP on the
#: local network, and a Secure cookie would simply never be sent. `SameSite`
#: is what carries the weight instead -- the browser will not attach this to a
#: request another site caused, which is what a cookie reintroduces and Basic
#: authentication did not have.
SESSION_COOKIE = "symbivpn_session"
COOKIE_ATTRIBUTES = "HttpOnly; SameSite=Strict; Path=/"


class Dashboard:
    """Runs the HTTP server for one application instance."""

    def __init__(self, application: "Application") -> None:
        self.app = application
        self.config = application.config.dashboard
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._limiter = AttemptLimiter()
        #: Logged-in browsers, so a phone is asked once rather than every time.
        self.sessions = SessionStore()
        # Lets the CLI on this machine authenticate without the password,
        # which it only has the hash of.
        self._token = AdminToken(application.config.state_dir)

    def start(self) -> None:
        if self.config.password:
            # Bound to the password, so changing the password revokes the token
            # and ends every browser session issued under the old one.
            self._token.load_or_create(self.config.password)
            self.sessions.bind(self.config.password)
        handler = _make_handler(self)
        try:
            self._server = ThreadingHTTPServer((self.config.address, self.config.port), handler)
        except OSError as exc:
            raise OSError(
                f"could not bind the dashboard to {self.config.address}:{self.config.port}: {exc}"
            ) from exc
        self._server.daemon_threads = True

        self._thread = threading.Thread(
            target=self._server.serve_forever, name="dashboard", daemon=True
        )
        self._thread.start()

        if not looks_local(self.config.address) and not self.config.password:
            # Configuration validation refuses this unless it was opted into,
            # so reaching here means the operator asked for it explicitly.
            log.warning(
                "the dashboard is reachable from the network at %s:%d with NO PASSWORD. "
                "Anyone who can reach it can switch filtering off or add a VPN peer.",
                self.config.address, self.config.port,
            )
        elif self.config.password and not is_hashed(self.config.password):
            log.warning(
                "dashboard.password is stored in the clear. Replace it with a hash: "
                "run `symbivpn passwd` and paste the result into the config."
            )
        log.info("dashboard on http://%s:%d", self.config.address, self.config.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # -- authentication ---------------------------------------------------

    def authorised(
        self, header: str | None, client: str = "", cookie: str = ""
    ) -> tuple[bool, str]:
        """Check credentials. Returns (allowed, reason-if-not)."""
        if not self.config.password:
            return True, ""

        # A live session first: it is the common case for a browser, and it
        # costs a comparison rather than a deliberately slow password hash.
        if cookie and self.sessions.validate(cookie):
            return True, ""

        remaining = self._limiter.locked_out(client) if client else 0.0
        if remaining:
            return False, f"too many failed attempts; try again in {int(remaining)}s"

        supplied = _extract_credential(header)
        if supplied is None:
            return False, "authentication required"

        # The local admin token, used by the CLI. Checked first because it is
        # a cheap comparison and the common case for automated callers.
        if self._token.matches(supplied):
            if client:
                self._limiter.record_success(client)
            return True, ""

        if verify_password(supplied, self.config.password):
            if client:
                self._limiter.record_success(client)
            return True, ""

        if client and self._limiter.record_failure(client):
            log.warning("locking out %s after repeated failed dashboard logins", client)
        return False, "authentication required"


def _make_handler(dashboard: Dashboard) -> type[BaseHTTPRequestHandler]:
    application = dashboard.app

    class Handler(BaseHTTPRequestHandler):
        server_version = "SymbiVPN"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        # -- plumbing -----------------------------------------------------

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s - %s", self.address_string(), fmt % args)

        def _send(
            self,
            status: HTTPStatus,
            body: bytes,
            content_type: str = "application/json",
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            # The dashboard loads nothing from anywhere else, so lock it down.
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            )
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
            self._send(status, json.dumps(payload, default=str).encode("utf-8"))

        def _error(self, status: HTTPStatus, message: str) -> None:
            self._json({"error": message, "status": int(status)}, status)

        def _body(self) -> dict[str, Any]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return {}
            if length <= 0:
                return {}
            if length > MAX_BODY:
                raise ValueError(f"request body is too large ({length} bytes)")
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"request body is not valid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _session_cookie(self) -> str:
            """The session token this request carries, if any."""
            raw = self.headers.get("Cookie")
            if not raw:
                return ""
            try:
                jar = http.cookies.SimpleCookie()
                jar.load(raw)
            except http.cookies.CookieError:
                # A malformed Cookie header is not a reason to fail the
                # request; it just means there is no session in it.
                return ""
            morsel = jar.get(SESSION_COOKIE)
            return morsel.value if morsel else ""

        def _logged_in(self) -> bool:
            """Whether this request is already authorised, without answering it."""
            allowed, _ = dashboard.authorised(
                self.headers.get("Authorization"),
                self.client_address[0],
                self._session_cookie(),
            )
            return allowed

        def _authorise(self, *, write: bool) -> bool:
            if write and dashboard.config.readonly:
                self._error(HTTPStatus.FORBIDDEN, "the dashboard is in read-only mode")
                return False

            if write and self.command == "POST":
                # A state-changing POST must be JSON. A form can only ever send
                # the three "simple" content types, and anything else needs a
                # CORS preflight, which nothing here answers -- so a page on the
                # local network cannot make a logged-in browser change settings
                # on its behalf.
                #
                # Only POST, because only POST can be a simple request. DELETE
                # always needs a preflight, so it is already safe -- and a
                # bodiless DELETE sends no Content-Type at all, which made the
                # peer-removal endpoint answer 415 to every caller.
                content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
                if content_type != "application/json":
                    self._error(
                        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                        "writes must be sent as application/json",
                    )
                    return False

            allowed, reason = dashboard.authorised(
                self.headers.get("Authorization"),
                self.client_address[0],
                self._session_cookie(),
            )
            if allowed:
                return True

            status = (
                HTTPStatus.TOO_MANY_REQUESTS
                if "failed attempts" in reason
                else HTTPStatus.UNAUTHORIZED
            )
            extra = {} if status == HTTPStatus.TOO_MANY_REQUESTS else {
                "WWW-Authenticate": 'Basic realm="SymbiVPN"'
            }
            self._send(status, json.dumps({"error": reason}).encode(), extra=extra)
            return False

        # -- routing ------------------------------------------------------

        def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = urllib.parse.parse_qs(parsed.query)

            try:
                if not path.startswith("/api"):
                    # The page is behind the same authentication as the API,
                    # but a browser gets a form rather than the Basic prompt:
                    # the prompt reappears at the browser's whim, cannot be
                    # logged out of, and sends the password on every request.
                    if not self._logged_in():
                        self._serve_login()
                        return
                    self._serve_static(path)
                    return
                if not self._authorise(write=False):
                    return
                handler = self._route_get(path)
                if handler is None:
                    self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
                    return
                handler(query)
            except BrokenPipeError:
                return
            except Exception:  # noqa: BLE001 - never leak internals to the caller
                log.exception("dashboard GET %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, _INTERNAL_ERROR)

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_POST(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            try:
                # Logging in is the one write that cannot require being logged
                # in. It is still rate-limited, and still has to be JSON.
                if path == "/api/login":
                    self._post_login()
                    return
                if not self._authorise(write=True):
                    return
                body = self._body()
                handler = self._route_post(path)
                if handler is None:
                    self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
                    return
                handler(body)
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
            except WireGuardError as exc:
                self._error(HTTPStatus.CONFLICT, str(exc))
            except BrokenPipeError:
                return
            except Exception:  # noqa: BLE001
                log.exception("dashboard POST %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, _INTERNAL_ERROR)

        def do_DELETE(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            try:
                if not self._authorise(write=True):
                    return
                if path.startswith("/api/vpn/peers/"):
                    name = urllib.parse.unquote(path.rsplit("/", 1)[-1])
                    application.vpn.remove_peer(name)
                    self._sync_vpn()
                    self._json({"removed": name})
                    return
                self._error(HTTPStatus.NOT_FOUND, f"no such endpoint: {path}")
            except WireGuardError as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
            except Exception:  # noqa: BLE001
                log.exception("dashboard DELETE %s failed", path)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, _INTERNAL_ERROR)

        def _route_get(self, path: str) -> Callable[[dict], None] | None:
            routes: dict[str, Callable[[dict], None]] = {
                "/api/status": self._get_status,
                "/api/savings": self._get_savings,
                "/api/queries": self._get_queries,
                "/api/top": self._get_top,
                "/api/history": self._get_history,
                "/api/clients": self._get_clients,
                "/api/check": self._get_check,
                "/api/cache": self._get_cache,
                "/api/gateway": self._get_gateway,
                "/api/vpn/peers": self._get_peers,
                "/api/search": self._get_search,
            }
            if path in routes:
                return routes[path]
            if path.startswith("/api/vpn/peers/"):
                return self._get_peer_detail
            return None

        def _route_post(self, path: str) -> Callable[[dict], None] | None:
            return {
                "/api/allow": self._post_allow,
                "/api/block": self._post_block,
                "/api/blocklists/refresh": self._post_refresh,
                "/api/cache/flush": self._post_flush,
                "/api/vpn/peers": self._post_peer,
                "/api/logout": self._post_logout,
            }.get(path)

        # -- sessions -----------------------------------------------------

        def _post_login(self) -> None:
            """Exchange the password for a session cookie."""
            client = self.client_address[0]
            if not dashboard.config.password:
                # Nothing to log in to; the dashboard is open by configuration.
                self._json({"logged_in": True, "password_required": False})
                return

            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if content_type != "application/json":
                self._error(
                    HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "send the password as application/json"
                )
                return

            remaining = dashboard._limiter.locked_out(client)
            if remaining:
                self._error(
                    HTTPStatus.TOO_MANY_REQUESTS,
                    f"too many failed attempts; try again in {int(remaining)}s",
                )
                return

            try:
                body = self._body()
            except ValueError as exc:
                self._error(HTTPStatus.BAD_REQUEST, str(exc))
                return

            password = str(body.get("password", ""))
            if not password or not verify_password(password, dashboard.config.password):
                if dashboard._limiter.record_failure(client):
                    log.warning("locking out %s after repeated failed dashboard logins", client)
                self._error(HTTPStatus.UNAUTHORIZED, "wrong password")
                return

            dashboard._limiter.record_success(client)
            token, lifetime = dashboard.sessions.create(
                (self.headers.get("User-Agent") or "").strip()
            )
            self._send(
                HTTPStatus.OK,
                json.dumps({"logged_in": True}).encode(),
                extra={
                    "Set-Cookie": (
                        f"{SESSION_COOKIE}={token}; Max-Age={lifetime}; {COOKIE_ATTRIBUTES}"
                    )
                },
            )

        def _post_logout(self, _body: dict) -> None:
            """End this browser's session, and clear the cookie."""
            dashboard.sessions.revoke(self._session_cookie())
            self._send(
                HTTPStatus.OK,
                json.dumps({"logged_in": False}).encode(),
                extra={"Set-Cookie": f"{SESSION_COOKIE}=; Max-Age=0; {COOKIE_ATTRIBUTES}"},
            )

        def _serve_login(self) -> None:
            """The login form. 401, so a script still sees a refusal."""
            try:
                page = (WEB_ROOT / "login.html").read_bytes()
            except OSError:
                page = b"<h1>SymbiVPN</h1><p>A password is required.</p>"
            # No WWW-Authenticate header: that is what summons the browser's
            # own credential box, which is the thing being replaced.
            self._send(
                HTTPStatus.UNAUTHORIZED, page, "text/html; charset=utf-8",
                extra={"Cache-Control": "no-store"},
            )

        # -- static -------------------------------------------------------

        def _serve_static(self, path: str) -> None:
            name = "dashboard.html" if path == "/" else path.lstrip("/")
            target = (WEB_ROOT / name).resolve()
            try:
                # Refuse anything that escapes the web root.
                target.relative_to(WEB_ROOT.resolve())
            except ValueError:
                self._error(HTTPStatus.FORBIDDEN, "forbidden")
                return
            if not target.is_file():
                self._error(HTTPStatus.NOT_FOUND, "not found")
                return
            content_type, _ = mimetypes.guess_type(target.name)
            self._send(
                HTTPStatus.OK,
                target.read_bytes(),
                content_type or "application/octet-stream",
                extra={"Cache-Control": "no-cache"},
            )

        # -- read endpoints -----------------------------------------------

        def _get_status(self, _query: dict) -> None:
            # `password_required` is what tells the page whether to offer a
            # sign-out: with no password there is no session to end.
            self._json({
                **application.status(),
                "password_required": bool(dashboard.config.password),
            })

        def _get_savings(self, _query: dict) -> None:
            self._json(application.savings())

        def _get_queries(self, query: dict) -> None:
            self._json(
                {
                    "queries": application.query_log.recent_queries(
                        limit=_int(query, "limit", 100, maximum=1000),
                        client=_first(query, "client"),
                        action=_first(query, "action"),
                    )
                }
            )

        def _get_search(self, query: dict) -> None:
            term = _first(query, "q")
            if not term:
                self._error(HTTPStatus.BAD_REQUEST, "the `q` parameter is required")
                return
            self._json({"results": application.query_log.search(term, _int(query, "limit", 100, maximum=1000))})

        def _get_top(self, query: dict) -> None:
            action = _first(query, "action") or "block"
            self._json({"action": action, "top": application.query_log.top(action, _int(query, "limit", 20, maximum=200))})

        def _get_history(self, query: dict) -> None:
            self._json({"history": application.query_log.history(hours=_int(query, "hours", 24, maximum=720))})

        def _get_clients(self, _query: dict) -> None:
            payload = {"clients": application.query_log.clients()}
            if application.gateway is not None and application.gateway.dhcp is not None:
                payload["leases"] = [
                    lease.as_dict() for lease in application.gateway.dhcp.active_leases()
                ]
            self._json(payload)

        def _get_check(self, query: dict) -> None:
            name = _first(query, "name")
            if not name:
                self._error(HTTPStatus.BAD_REQUEST, "the `name` parameter is required")
                return
            self._json(application.engine.check(name, _first(query, "client") or "0.0.0.0"))

        def _get_cache(self, query: dict) -> None:
            limit = _int(query, "limit", 100, maximum=2000)
            self._json(
                {
                    "stats": {**application.cache.stats.as_dict(), "entries": len(application.cache)},
                    "entries": application.cache.snapshot()[:limit],
                }
            )

        def _get_gateway(self, _query: dict) -> None:
            if application.gateway is None:
                self._json({"enabled": False})
                return
            self._json({"enabled": True, **application.gateway.status()})

        def _get_peers(self, _query: dict) -> None:
            self._json({"peers": application.vpn.status()})

        def _get_peer_detail(self, query: dict) -> None:
            parts = self.path.split("?")[0].rstrip("/").split("/")
            name = urllib.parse.unquote(parts[4]) if len(parts) > 4 else ""
            fmt = parts[5] if len(parts) > 5 else "config"
            try:
                if fmt in ("config", "conf"):
                    self._send(
                        HTTPStatus.OK,
                        application.vpn.peer_config(name).encode("utf-8"),
                        "text/plain; charset=utf-8",
                        extra={"Content-Disposition": f'attachment; filename="{name}.conf"'},
                    )
                elif fmt == "qr.png":
                    self._send(HTTPStatus.OK, application.vpn.peer_qr(name).to_png(), "image/png")
                elif fmt == "qr.svg":
                    self._send(
                        HTTPStatus.OK,
                        application.vpn.peer_qr(name).to_svg().encode("utf-8"),
                        "image/svg+xml",
                    )
                else:
                    self._error(HTTPStatus.NOT_FOUND, f"unknown format {fmt!r}")
            except WireGuardError as exc:
                self._error(HTTPStatus.NOT_FOUND, str(exc))
            except qr.QRError:
                log.exception("could not render a QR code for peer %r", name)
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, _INTERNAL_ERROR)

        # -- write endpoints ----------------------------------------------

        def _post_allow(self, body: dict) -> None:
            domain = _domain(body)
            application.add_local_rule(domain, allow=True)
            self._json({"allowed": domain, "rules": application.blocklists.rule_count})

        def _post_block(self, body: dict) -> None:
            domain = _domain(body)
            application.add_local_rule(domain, allow=False)
            self._json({"blocked": domain, "rules": application.blocklists.rule_count})

        def _post_refresh(self, _body: dict) -> None:
            started = time.time()
            application.load_blocklists(refresh=True)
            self._json(
                {
                    "rules": application.blocklists.rule_count,
                    "sources": len(application.blocklists.sources),
                    "elapsed_seconds": round(time.time() - started, 2),
                }
            )

        def _post_flush(self, _body: dict) -> None:
            name = _first_value(_body_domain(_body))
            dropped = application.cache.invalidate(name)
            self._json({"flushed": dropped, "name": name or "*"})

        def _post_peer(self, body: dict) -> None:
            name = str(body.get("name", "")).strip()
            if not name:
                raise ValueError("`name` is required")
            peer = application.vpn.add_peer(
                name,
                profile=body.get("profile", "full"),
                preshared=bool(body.get("preshared", True)),
                mobile=bool(body.get("mobile", False)),
                tether_subnet=str(body.get("tether_subnet", "")),
                note=str(body.get("note", "")),
            )
            self._sync_vpn()
            self._json({"peer": peer.public_view()}, HTTPStatus.CREATED)

        def _sync_vpn(self) -> None:
            """Push the peer list to the live interface, if there is one."""
            try:
                application.vpn.apply(Path(application.config.vpn.config_path))
            except WireGuardError as exc:
                log.warning("could not reload the WireGuard interface: %s", exc)

    return Handler


def _extract_credential(header: str | None) -> str | None:
    """Pull the secret out of a Basic or Bearer authorization header."""
    if not header:
        return None
    try:
        scheme, _, value = header.partition(" ")
        if scheme.lower() == "basic":
            decoded = base64.b64decode(value).decode("utf-8")
            _, _, supplied = decoded.partition(":")
            return supplied
        if scheme.lower() == "bearer":
            return value
    except (ValueError, UnicodeDecodeError):
        return None
    return None


def _first(query: dict, key: str) -> str:
    values = query.get(key)
    return values[0].strip() if values else ""


def _int(query: dict, key: str, default: int, *, maximum: int | None = None) -> int:
    raw = _first(query, key)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"`{key}` must be a number, got {raw!r}") from exc
    if value < 1:
        raise ValueError(f"`{key}` must be positive, got {value}")
    return min(value, maximum) if maximum else value


def _domain(body: dict) -> str:
    domain = str(body.get("domain", "")).strip().lower().strip(".")
    if not domain:
        raise ValueError("`domain` is required")
    if "/" in domain or " " in domain:
        raise ValueError(f"{domain!r} is not a valid domain")
    return domain


def _body_domain(body: dict) -> str:
    return str(body.get("domain", "")).strip().lower().strip(".")


def _first_value(value: str) -> str | None:
    return value or None
