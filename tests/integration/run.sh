#!/usr/bin/env bash
# Convenience wrapper: check prerequisites, then run the integration testbed.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "needs root: sudo $0" >&2; exit 1; }

missing=()
for tool in ip ss nft dig openssl; do
    command -v "$tool" >/dev/null || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "missing: ${missing[*]}" >&2
    echo "on Debian/Ubuntu: apt install iproute2 nftables dnsutils openssl" >&2
    exit 1
fi

CERT_DIR=/tmp/symbivpn-testbed-certs
mkdir -p "$CERT_DIR"
# Regenerate when the certificate is missing OR already expired. It is
# deliberately short-lived and it is cached between runs, so checking only for
# the file meant the DoH tests quietly started failing two days after anyone's
# first run -- and failing as "got ''", which points at DNS-over-HTTPS rather
# than at the expired certificate that actually caused it. `-checkend` is true
# when the certificate is still good an hour from now.
if [[ ! -f "$CERT_DIR/cert.pem" ]] \
   || ! openssl x509 -in "$CERT_DIR/cert.pem" -checkend 3600 >/dev/null 2>&1; then
    rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -days 2 -nodes -subj "/CN=testbed-resolver" \
        -addext "subjectAltName=IP:10.200.0.2" >/dev/null 2>&1
fi

exec python3 "$(dirname "$0")/run_testbed.py" "$@"
