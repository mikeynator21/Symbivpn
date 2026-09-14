#!/usr/bin/env python3
"""Generate the standalone cipher box from the real modules.

The point of the cipher box is that it works when SymbiVPN does not -- on a
laptop with nothing installed, when the gateway it came from is dead. That
means it has to carry its own copy of the cipher, and a second copy of a
cipher is a second thing to get wrong.

So it is generated, never hand-written: `symbivpn/aesgcm.py` and
`symbivpn/vault.py` go in verbatim, and a test regenerates and compares, so
the two cannot drift without something failing.

    python3 tools/build_cipherbox.py          # write it
    python3 tools/build_cipherbox.py --check   # is it current?
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "tools" / "symbivpn-cipherbox.py"

HEADER = '''#!/usr/bin/env python3
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

__IMPORTS__

log = logging.getLogger("cipherbox")

'''

BRIDGE = '''

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

'''

CLI = '''

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
    return "\\n".join(lines) + "\\n"


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
    print(f"\\n{written} configuration(s) recovered. They contain private keys: mode 600.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _strip_module_preamble(source: str) -> tuple[str, list[str]]:
    """Split a module into (body, its module-level imports).

    The imports are returned rather than discarded so the generated file can
    re-emit exactly what the sources needed. A hand-maintained import list in
    the template is how this broke twice: the file parsed, looked complete,
    and died at the first call that reached for a name nobody had listed.
    """
    lines = source.splitlines()
    out: list[str] = []
    imports: list[str] = []
    in_docstring = False
    docstring_done = False
    for line in lines:
        stripped = line.strip()
        if not docstring_done:
            if not in_docstring and stripped.startswith('"""'):
                in_docstring = True
                if stripped.endswith('"""') and len(stripped) > 3:
                    in_docstring, docstring_done = False, True
                continue
            if in_docstring:
                if stripped.endswith('"""'):
                    in_docstring, docstring_done = False, True
                continue
            if not stripped:
                continue
            docstring_done = True
        # Only module-level imports. An indented one is inside a function and
        # is part of that function's behaviour -- stripping those silently
        # produced a file that parsed, imported nothing, and died at the first
        # call that needed the name.
        if line.startswith(("import ", "from ")) and "(" not in stripped:
            # Not __future__ (the header states it first, as it must be), and
            # not package-relative imports -- inside one file there is no
            # package, and the bridge below supplies those names instead.
            if stripped != "from __future__ import annotations" and not stripped.startswith(
                ("from .", "from symbivpn")
            ):
                imports.append(stripped)
            continue
        out.append(line)
    return "\n".join(out).strip("\n"), imports


#: What the command line itself needs, on top of whatever the sources import.
CLI_IMPORTS = ("import argparse", "import getpass", "import sys", "import types")


def render() -> str:
    aesgcm_source, aesgcm_imports = _strip_module_preamble(
        (ROOT / "symbivpn" / "aesgcm.py").read_text()
    )
    vault_source, vault_imports = _strip_module_preamble(
        (ROOT / "symbivpn" / "vault.py").read_text()
    )

    # Whatever the sources imported, plus the CLI's own. Sorted so the output
    # is stable and the drift check compares like with like.
    collected = sorted(set(aesgcm_imports) | set(vault_imports) | set(CLI_IMPORTS))
    plain = [line for line in collected if line.startswith("import ")]
    froms = [line for line in collected if line.startswith("from ")]
    imports = "\n".join(plain + froms)

    return (
        HEADER.replace("__IMPORTS__", imports)
        + "# ---- from symbivpn/aesgcm.py, verbatim ----\n\n"
        + aesgcm_source
        + "\n"
        + BRIDGE
        + "# ---- from symbivpn/vault.py, verbatim ----\n\n"
        + vault_source
        + "\n"
        + CLI
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="only report whether it is current")
    args = parser.parse_args()

    wanted = render()
    current = OUTPUT.read_text() if OUTPUT.exists() else ""

    if args.check:
        if current == wanted:
            print(f"{OUTPUT.name} is current.")
            return 0
        print(
            f"{OUTPUT.name} is out of date. Regenerate it:\n"
            f"    python3 tools/build_cipherbox.py",
            file=sys.stderr,
        )
        return 1

    OUTPUT.write_text(wanted)
    OUTPUT.chmod(0o755)
    print(f"Wrote {OUTPUT} ({len(wanted.splitlines())} lines).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
