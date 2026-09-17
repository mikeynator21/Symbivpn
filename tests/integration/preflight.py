#!/usr/bin/env python3
"""Can this machine actually run the testbed?

The testbed builds a bridge in a network namespace and expects a DHCP
broadcast to cross it. That is ordinary Linux networking, and it works on an
ordinary Linux box -- but "ordinary" is doing some work in that sentence, and
when it does not hold every check downstream fails saying "network
unreachable", which points nowhere near the cause.

This isolates the networking the testbed depends on and nothing else, in two
shapes:

* a *forgiving* shape, where the client has an address of its own -- three
  cases that narrow down which part of "a broadcast crossing a bridge" is
  missing, if any;
* the *exact* shape the testbed uses -- a client with no address at all, the
  veth brought up before it is enslaved, and the real DHCP ports. A client
  before DHCP has no address and therefore no routes, so reaching
  255.255.255.255 rests entirely on SO_BINDTODEVICE. That is a stronger
  assumption than the forgiving shape makes, and it is the one that matters.

When a case fails it prints where the packet stopped -- left the client, or
reached the bridge port, or neither -- because "no answer" on its own points
nowhere.

Run it directly:  sudo python3 tests/integration/preflight.py
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time

NS_A = "sbvpn-pre-a"          # stands in for the gateway
NS_B = "sbvpn-pre-b"          # stands in for the phone
BRIDGE = "pre-br0"
ADDRESS = "10.244.0.1"
CLIENT_ADDRESS = "10.244.0.50"
PORT = 6767
#: The real DHCP ports, for the case that mirrors the testbed. Privileged
#: ports behave no differently, but using them removes one more difference.
SERVER_PORT = 67
CLIENT_PORT = 68


def run(*command: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=check)


def ns(namespace: str, *command: str, check: bool = False):
    return run("ip", "netns", "exec", namespace, *command, check=check)


def build(*, client_address: bool, enslave_before_up: bool) -> None:
    """Wire up the two namespaces.

    `client_address` and `enslave_before_up` are the two places the forgiving
    shape and the testbed's own shape differ, so they are switches rather than
    two copies of the same code that could drift apart.
    """
    teardown()
    run("ip", "netns", "add", NS_A, check=True)
    run("ip", "netns", "add", NS_B, check=True)
    ns(NS_A, "ip", "link", "add", BRIDGE, "type", "bridge", check=True)
    ns(NS_A, "ip", "link", "set", BRIDGE, "up", check=True)
    ns(NS_A, "ip", "addr", "add", f"{ADDRESS}/24", "dev", BRIDGE, check=True)

    run("ip", "link", "add", "pre-gw", "type", "veth", "peer", "name", "pre-cl", check=True)
    run("ip", "link", "set", "pre-gw", "netns", NS_A, check=True)
    run("ip", "link", "set", "pre-cl", "netns", NS_B, check=True)

    if enslave_before_up:
        ns(NS_A, "ip", "link", "set", "pre-gw", "master", BRIDGE, check=True)
        ns(NS_A, "ip", "link", "set", "pre-gw", "up", check=True)
    else:
        # What the testbed does: the veth is up before it joins the bridge.
        ns(NS_A, "ip", "link", "set", "pre-gw", "up", check=True)
        ns(NS_A, "ip", "link", "set", "pre-gw", "master", BRIDGE, check=True)

    ns(NS_B, "ip", "link", "set", "pre-cl", "up", check=True)
    if client_address:
        ns(NS_B, "ip", "addr", "add", f"{CLIENT_ADDRESS}/24", "dev", "pre-cl", check=True)
    ns(NS_B, "ip", "link", "set", "lo", "up", check=True)
    time.sleep(0.5)           # let the bridge port settle


def teardown() -> None:
    for namespace in (NS_A, NS_B):
        run("ip", "netns", "del", namespace)


LISTENER = r"""
import socket, sys
bind_to_device = sys.argv[1] == "yes"
port = int(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
if bind_to_device:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"%s\0")
sock.bind(("", port))
sock.settimeout(6)
print("READY", flush=True)
try:
    payload, peer = sock.recvfrom(2048)
    print("GOT", payload.decode(), flush=True)
except socket.timeout:
    print("NOTHING", flush=True)
""" % BRIDGE.encode().decode()

SENDER = r"""
import socket, sys
target, port, source_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# Bound to the device, which is what a client with no address must do to send
# anything at all -- and what the testbed's DHCP client does.
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"pre-cl\0")
sock.bind(("", source_port))
for _ in range(3):
    try:
        sock.sendto(b"hello", (target, port))
    except OSError as exc:
        print("SENDFAIL", exc, flush=True)
        raise SystemExit(1)
print("SENT", flush=True)
"""


def _packets(namespace: str, interface: str) -> tuple[int, int]:
    """(received, transmitted) packet counts for one interface.

    Read from /proc/net/dev rather than parsed out of `ip -s link`: the
    columns there are fixed and have been for decades, where `ip`'s layout
    varies with the flags and the version. A diagnostic that misparses is
    worse than none, because it is believed.
    """
    result = ns(namespace, "cat", "/proc/net/dev")
    for line in result.stdout.splitlines():
        name, _, rest = line.partition(":")
        if name.strip() != interface:
            continue
        fields = rest.split()
        if len(fields) < 10:
            break
        return int(fields[1]), int(fields[9])
    return -1, -1


def _explain_where_it_stopped(sent_ok: bool) -> None:
    """Say which hop the packet failed to make, rather than only that it did."""
    _, client_tx = _packets(NS_B, "pre-cl")
    port_rx, _ = _packets(NS_A, "pre-gw")
    bridge_rx, _ = _packets(NS_A, BRIDGE)
    print(f"         send call {'succeeded' if sent_ok else 'failed'}; "
          f"client tx={client_tx}, bridge port rx={port_rx}, bridge rx={bridge_rx}")
    if not sent_ok:
        print("         -- the send itself failed, so this is routing, not the bridge")
    elif client_tx <= 0:
        print("         -- the send was accepted but nothing left the client: "
              "the packet was dropped on the way out of the stack")
    elif port_rx <= 0:
        print("         -- it never reached the bridge port: the veth or the link is the problem")
    elif bridge_rx <= 0:
        print("         -- it reached the port but not the bridge: bridge forwarding is the problem")
    else:
        print("         -- it reached the bridge but not the socket: the bind is the problem")
    state = ns(NS_A, "bridge", "-o", "link", "show").stdout.strip()
    print(f"         bridge ports: {state or '(none reported)'}")


def attempt(
    label: str,
    *,
    bind_to_device: bool,
    target: str,
    port: int = PORT,
    source_port: int = 6868,
) -> bool:
    listener = subprocess.Popen(
        ["ip", "netns", "exec", NS_A, "python3", "-c", LISTENER,
         "yes" if bind_to_device else "no", str(port)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    assert listener.stdout is not None
    if listener.stdout.readline().strip() != "READY":
        print(f"  [FAIL] {label}: the listener did not start")
        listener.kill()
        return False

    sender = ns(NS_B, "python3", "-c", SENDER, target, str(port), str(source_port))
    sent_ok = "SENT" in sender.stdout

    outcome = listener.stdout.readline().strip()
    listener.wait(timeout=10)

    arrived = outcome.startswith("GOT")
    print(f"  [{'ok  ' if arrived else 'FAIL'}] {label}")
    if not arrived:
        if sender.stdout.strip() and not sent_ok:
            print(f"         sender said: {sender.stdout.strip()}")
        _explain_where_it_stopped(sent_ok)
    return arrived


def main() -> int:
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("needs root: sudo python3 tests/integration/preflight.py", file=sys.stderr)
        return 2

    results: dict[str, bool] = {}
    try:
        print("Can a broadcast cross a bridge into a socket on this machine?\n")
        build(client_address=True, enslave_before_up=True)
        results["unicast to the bridge address (the control)"] = attempt(
            "unicast to the bridge address (the control)",
            bind_to_device=False, target=ADDRESS)
        results["broadcast, socket bound to the bridge device"] = attempt(
            "broadcast, socket bound to the bridge device",
            bind_to_device=True, target="255.255.255.255")
        results["broadcast, socket not bound to any device"] = attempt(
            "broadcast, socket not bound to any device",
            bind_to_device=False, target="255.255.255.255")

        print("\nAnd under the testbed's own conditions -- a client with no\n"
              "address, the veth up before it joins the bridge, real DHCP ports?\n")
        build(client_address=False, enslave_before_up=False)
        results["the testbed's exact conditions"] = attempt(
            "the testbed's exact conditions",
            bind_to_device=True, target="255.255.255.255",
            port=SERVER_PORT, source_port=CLIENT_PORT)
    finally:
        teardown()

    print()
    if all(results.values()):
        print("This machine can run the testbed.")
        return 0

    if not results.get("unicast to the bridge address (the control)"):
        print("Even unicast does not cross the bridge here, so the testbed\n"
              "cannot work on this machine at all.")
    elif not results.get("broadcast, socket bound to the bridge device") and \
            results.get("broadcast, socket not bound to any device"):
        print("Broadcasts cross, but a socket bound to the bridge with\n"
              "SO_BINDTODEVICE does not see them. That is what breaks DHCP\n"
              "here: the server binds to the access-point interface.")
    elif not results.get("the testbed's exact conditions"):
        print("A broadcast crosses when the client has an address of its own,\n"
              "and does not under the conditions the testbed actually uses. A\n"
              "client before DHCP has no address and so no routes, so the send\n"
              "rests entirely on SO_BINDTODEVICE -- and that is the difference\n"
              "this machine does not tolerate. The line above says which hop\n"
              "the packet failed to make.")
    else:
        print("Broadcasts do not cross the bridge on this machine.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
