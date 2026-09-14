# Security

What SymbiVPN protects, how, and — as importantly — what it does not.

## The cryptography

### The tunnel

WireGuard, using its own primitives, which are not configurable and should not
be: ChaCha20-Poly1305 for data, Curve25519 for key agreement, BLAKE2s for
hashing, HKDF for derivation, in a Noise IKpsk2 handshake that rekeys every two
minutes.

The one meaningful choice is the optional pre-shared key, and SymbiVPN sets
one on **every peer by default**. It costs nothing and adds a layer of
symmetric secrecy on top of the X25519 handshake: traffic recorded today stays
unreadable to an attacker who breaks Curve25519 later, which is the practical
shape of the "harvest now, decrypt later" concern.

Keys are generated with `wg` when it is installed. When it is not, the
pure-Python X25519 in `symbivpn/vpn/crypto.py` is used instead, checked
against the RFC 7748 test vectors in the test suite. That implementation is
used only to generate keys from fresh randomness — never to process
attacker-supplied points — because Python's integers are not constant-time.

### The resolver channel

DNS-over-HTTPS and DNS-over-TLS on pooled, long-lived connections:

- TLS 1.3 preferred, 1.2 the floor, 1.3 required under `protection = "paranoid"`.
- AEAD ciphers only, with forward secrecy — ECDHE/DHE with AES-GCM or
  ChaCha20-Poly1305. No static RSA, no CBC, no RC4, no 3DES.
- Certificate verification and hostname checking always on. There is no
  option to disable them.
- TLS compression off (CRIME).
- Optional public-key pinning, per host.

Queries are **rebuilt** rather than forwarded, which strips EDNS Client Subnet
and any other identifying option the client attached, and normalises the
question so cache entries collapse.

On DNSSEC: SymbiVPN does not request DNSSEC records. Asking for them would
inflate every response with signatures it would then have to validate.
Instead it requires an authenticated channel to a validating resolver and reads
the AD bit — the same guarantee, at a fraction of the bytes. If you want
end-to-end validation on this host, run a validating resolver locally and point
SymbiVPN at it.

### Certificate pinning

Opt-in, because a stale pin breaks resolution for the whole network:

```bash
symbivpn tls pin dns.quad9.net
```

```toml
[upstream.pins]
"dns.quad9.net" = ["base64-sha256-of-the-spki"]
```

Pins are on the SubjectPublicKeyInfo, not the certificate, so a resolver
rotating its certificate while keeping its key does not break. Capture pins
from a network you trust.

### The access point

WPA3-SAE where the client supports it, WPA2 where it does not, on one SSID.
SAE replaces WPA2's pre-shared-key handshake with a password-authenticated key
exchange, so a captured handshake cannot be attacked offline with a wordlist —
the difference between a weak passphrase being a risk and being an
inconvenience. Management-frame protection is required for SAE clients, which
blocks deauthentication attacks. Only CCMP; TKIP is not offered. Group keys
rotate every ten minutes.

`wpa3_only = true` drops WPA2 entirely. Stronger, but older devices cannot join.

### Between nodes

Cluster messages are authenticated with HMAC-SHA256 over a shared secret, which
is **required** — without it anything that can reach the port could inject
cache entries, which is a DNS-poisoning primitive. Shared cache entries are
re-validated against their own question on arrival, so a compromised node
cannot inject an answer for a name it did not send.

## Attacks this defends against

**Cache poisoning.** Responses are checked for transaction ID, question name,
type and class. On any plaintext upstream, 0x20 case randomisation is applied
and the echoed case is verified, which raises the cost of blind spoofing
considerably. Both the transaction ID and the case pattern come from the
system CSPRNG — drawn from an ordinary seedable generator, a few observed
queries would give away every one that followed, and neither measure would be
worth anything. Encrypted upstreams make it moot.

An answer fetched with the CD bit set — a client saying it will do its own
DNSSEC validation — is never cached or shared, because it arrives unvalidated
and handing it to a device that did not ask for that would downgrade DNSSEC on
that device's behalf.

**DNS rebinding.** A public name resolving into a private address range is
rejected. This is the DNS half of an attack where a page loaded from the
internet is handed a local address and can then talk to your router from inside
the browser's origin.

**Amplification.** ANY queries are refused. Queries from outside the allowed
private networks are ignored entirely — not refused, ignored, because replying
at all confirms the port is open. Per-client token-bucket rate limiting is on
by default.

**The joined network reaching back in.** Every port SymbiVPN opens — the
resolver, the dashboard, DHCP, the time server, the cluster listener — is
dropped on the uplink interface. Only SymbiVPN's own ports are named, so
whatever else the machine runs (ssh, say) keeps working; the point is that
nothing *we* opened answers the hotel LAN. Clients on the hotspot reach the
internet through that network without reaching the hosts on it.

**The dashboard as an attack surface.** Signing in exchanges the password for
a session cookie, so it is sent once rather than on every request. The cookie
is `HttpOnly` (script cannot read it) and `SameSite=Strict` (the browser will
not attach it to a request another site caused). It is deliberately *not*
`Secure`: the dashboard speaks plain HTTP on the local network, and a Secure
cookie would simply never be sent — `SameSite` is what carries the weight.
Sessions live in memory only, are capped, expire, and are all ended the moment
the password changes; a restart signs everyone out, which is the trade for
never writing anything password-equivalent to disk. Basic authentication still
works, for the CLI and for `curl`.

A state-changing POST must be
`application/json`, which a form cannot send and which needs a CORS preflight
nothing here answers — so a page on your network cannot make a logged-in
browser change settings on its behalf. Failed logins are rate-limited per
client and lock out. An unexpected failure tells the caller only that one
happened; the detail goes to the log, because exception text routinely carries
file paths and configuration values. Static files are served only from within
the web root, checked after resolving symlinks.

**A peer name as an injection vector.** The name a VPN peer is given is not
just a label: it goes into the generated `.conf`, into the filename that config
downloads as, and into a `Content-Disposition` header. A newline in it would
place a line of its own directly above `[Interface]`. Names are therefore
restricted to letters, digits, spaces and `. _ -`, validated once where peers
are created, which is what keeps all three uses safe.

**A guest device flooding the network it was separated from.** Reflection
copies each discovery packet onto every other network, so it is a multiplier
by design. Deduplication only catches an identical packet — changing one byte
defeats it — so reflection is rate-limited per source address, with a burst
allowance for the flurry a device sends when it joins.

**Resource exhaustion by a device on your own network.** A DNS-over-TCP
connection stays open between queries, so TCP has its own workers and its own
ceiling — in total and per client. Without that, a handful of connections
opened and left silent would hold every worker until they timed out, and UDP
resolution, which is very nearly all real traffic, would stop for everyone.
Background cache refreshes are capped the same way.

**Filter bypass.** Covered in the README under "Holding the line".

**Local network attack, on a hostile LAN.** In gateway mode, clients may route
through the network the laptop joined but cannot reach hosts on it. The rule
drops traffic to the uplink's current subnet and is ordered ahead of the accept
that would otherwise match first — rule order being the whole of the control,
since nftables takes the first match. The integration testbed asserts both the
ordering and the resulting behaviour.

## What it does not protect against

Being straight about this matters more than the list above.

**It is DNS-level filtering.** An ad served from the same domain as the content
— YouTube's own ads, Facebook's in-feed ads, Twitch's stitched pre-rolls —
cannot be blocked without blocking the service. No DNS blocker can do this,
whatever it claims. Use a content blocker in the browser as well.

**A device that ignores the network's DNS entirely.** The measures in "Holding
the line" cover the common cases and are genuinely effective, but an
application that ships its own resolver over HTTPS to an address not on the
block list will bypass filtering. The firewall rules narrow this considerably;
they do not close it.

**Traffic content.** SymbiVPN sees names, not payloads. It is not a firewall,
an IDS, or an antivirus.

**A compromised device on your network.** Filtering DNS does not contain a
device that is already owned.

**Your ISP seeing where you connect.** Encrypted DNS hides the *lookups*. The
IP addresses you then connect to, and the SNI in your TLS handshakes, remain
visible unless traffic goes through the VPN with a `full` profile.

**A malicious upstream resolver.** You are trusting whoever you point at. The
defaults (Quad9, Cloudflare) are chosen for stated no-log policies and
malware filtering at the resolver, which is not the same as being able to
verify them.

## Reaching the dashboard

The dashboard can add VPN peers and switch filtering off, so reaching it is
close to owning the network it protects. Accordingly:

- Binding it anywhere but localhost **requires a password**. This is refused at
  configuration load, not warned about, and waiving it takes an explicit
  `dashboard.allow_insecure = true`.
- The password is stored as an **scrypt hash** (n=16384, r=8) — memory-hard, so
  a stolen config cannot be attacked at GPU speed. `symbivpn passwd` generates
  one. A plaintext value still works so upgrades do not break, and is warned
  about at start-up.
- Five failures in five minutes **locks that client out** for five minutes.
  scrypt already makes each guess expensive; this stops a client tying up the
  server making them.
- Writes must be `application/json`. A browser cannot send that content type
  cross-origin without a CORS preflight that nothing here answers, so a page on
  your LAN cannot make a logged-in browser change your settings.

## Trusting the blocklists

Downloading rules from someone else is a supply chain, and it is treated as one.

**Exception rules from downloads are ignored.** An `@@||domain^` rule switches
protection off for a name. Honouring one from a source that could be hijacked
would let it un-block whatever it liked with nothing looking wrong.
Allowlisting is a local decision; `blocklists.trust_remote_allow_rules` turns
this off if you need it.

**Regex rules from downloads are refused.** A `/pattern/` line in a list is
compiled and then run against every name the network looks up. `/(a+)+b$/` is
the classic: measured, one lookup of a 32-character name took 21 seconds, and
doubles for every two characters added. That is not a bad rule — it is DNS
stopped for every device at once, from one line in a list nobody reads.
Community DNS lists do not use the syntax, so a list that starts to is worth
the warning this logs. Regexes in `blocklists.regex` in your own config are
unaffected; `blocklists.trust_remote_regex_rules` turns the refusal off if you
have read the list and want it.

**A list cannot be a decompression bomb.** Lists are fetched with
`Accept-Encoding: gzip`, and gzip reaches about 1000:1 — so a megabyte on the
wire expands to a gigabyte, on a gateway that is often a Raspberry Pi. Both the
download and its expansion are bounded at 64MB, the expansion through a
bounded read rather than a whole decompress. An oversized list is skipped and
the cached copy kept.

**A collapsed source is refused.** If a list that had 80,000 rules comes back
with 12, that is a broken source or a hijacked one. The update is rejected and
the previous copy kept. Local files are exempt — a file shrinking is its owner
editing it.

Neither replaces reading what you subscribe to. They bound the damage from a
source that goes bad after you did.

## Auditing an install

```bash
symbivpn harden
```

Reports weak settings by severity with the fix for each, and exits non-zero on
anything high so it can go in a check script. It covers exposure, open-resolver
risk, plaintext upstreams, missing pins, blocklist trust, rebinding,
amplification, gateway isolation and log retention.

## Handling of secrets

- `peers.json` holds WireGuard private keys. Mode 0600, and written atomically.
- Generated hostapd configs contain the passphrase. Mode 0600, in a temporary
  file, unlinked on shutdown.
- Query logs record what your household looks up. Retention is bounded (7 days
  by default, 1 under `paranoid`), and `log_queries = false` keeps the counters
  while recording no names at all.
- The dashboard binds to localhost by default. Binding it to the network
  without setting `dashboard.password` logs a warning.

Private keys for peers are stored so that a QR code can be shown again later.
That is a deliberate trade-off for a home tool — being able to re-add a phone
without regenerating every key is worth more than never holding the key — and
it is why the state directory is mode 0700.

## Reviewing it yourself

The whole thing is standard-library Python with no dependencies, which means
there is no supply chain to audit and the source is the artefact. The parts
worth reading first:

| | |
|---|---|
| `symbivpn/engine.py` | Every filtering decision, in the order they are made |
| `symbivpn/resolver.py` | Upstream transports and response validation |
| `symbivpn/tlsutil.py` | TLS hardening and pinning |
| `symbivpn/gateway/firewall.py` | The complete nftables ruleset |
| `symbivpn/vpn/crypto.py` | X25519 |

To see the exact firewall rules on a running gateway:

```bash
sudo symbivpn gateway rules
```

And to watch the controls above being enforced by a real kernel against real
clients, rather than taking this page's word for it:

```bash
sudo ./tests/integration/run.sh
```
