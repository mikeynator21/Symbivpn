#!/usr/bin/env python3
"""Can this machine actually run the testbed?

The testbed builds a bridge in a network namespace and expects a DHCP
broadcast to cross it. That is ordinary Linux networking, and it works on an
ordinary Linux box -- but "ordinary" is doing some work in that sentence, and
when it does not hold every check downstream fails saying "network
unreachable", which points nowhere near the cause.

This isolates the one thing the testbed depends on and nothing else: a UDP
broadcast, sent from one namespace, arriving at a socket bound to a bridge in
another. It tests it twice, with and without SO_BINDTODEVICE, because that is
the difference between "broadcasts do not cross" and "they cross but the
server cannot see them" -- and those have different answers.

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
PORT = 6767


def run(*command: str, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=check)


def ns(namespace: str, *command: str, check: bool = False):
    return run("ip", "netns", "exec", namespace, *command, check=check)


def build() -> None:
    teardown()
    run("ip", "netns", "add", NS_A, check=True)
    run("ip", "netns", "add", NS_B, check=True)
    ns(NS_A, "ip", "link", "add", BRIDGE, "type", "bridge", check=True)
    ns(NS_A, "ip", "link", "set", BRIDGE, "up", check=True)
    ns(NS_A, "ip", "addr", "add", f"{ADDRESS}/24", "dev", BRIDGE, check=True)

    # A veth pair with the gateway end on the bridge, exactly as the testbed
    # wires a client in.
    run("ip", "link", "add", "pre-gw", "type", "veth", "peer", "name", "pre-cl", check=True)
    run("ip", "link", "set", "pre-gw", "netns", NS_A, check=True)
    run("ip", "link", "set", "pre-cl", "netns", NS_B, check=True)
    ns(NS_A, "ip", "link", "set", "pre-gw", "master", BRIDGE, check=True)
    ns(NS_A, "ip", "link", "set", "pre-gw", "up", check=True)
    ns(NS_B, "ip", "link", "set", "pre-cl", "up", check=True)
    # The control needs an address to send unicast from; the broadcast cases
    # deliberately do not use it, because a phone has none before DHCP.
    ns(NS_B, "ip", "addr", "add", "10.244.0.50/24", "dev", "pre-cl", check=True)
    ns(NS_B, "ip", "link", "set", "lo", "up", check=True)
    time.sleep(0.5)           # let the bridge port settle


def teardown() -> None:
    for namespace in (NS_A, NS_B):
        run("ip", "netns", "del", namespace)


LISTENER = r"""
import socket, sys
bind_to_device = sys.argv[1] == "yes"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
if bind_to_device:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"%s\0")
sock.bind(("", %d))
sock.settimeout(6)
print("READY", flush=True)
try:
    payload, peer = sock.recvfrom(2048)
    print("GOT", payload.decode(), flush=True)
except socket.timeout:
    print("NOTHING", flush=True)
""" % (BRIDGE.encode().decode(), PORT)

SENDER = r"""
import socket, sys
target = sys.argv[1]
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# Bound to the device, which is what a client with no address must do to send
# anything at all -- and what the testbed's DHCP client does.
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"pre-cl\0")
sock.bind(("", 6868))
for _ in range(3):
    sock.sendto(b"hello", (target, %d))
""" % PORT


def attempt(label: str, *, bind_to_device: bool, target: str) -> bool:
    listener = subprocess.Popen(
        ["ip", "netns", "exec", NS_A, "python3", "-c", LISTENER,
         "yes" if bind_to_device else "no"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    assert listener.stdout is not None
    if listener.stdout.readline().strip() != "READY":
        print(f"  [fail] {label}: the listener did not start")
        listener.kill()
        return False

    ns(NS_B, "python3", "-c", SENDER, target)
    outcome = listener.stdout.readline().strip()
    listener.wait(timeout=10)

    arrived = outcome.startswith("GOT")
    print(f"  [{'ok  ' if arrived else 'FAIL'}] {label}")
    return arrived


def main() -> int:
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() != "0":
        print("needs root: sudo python3 tests/integration/preflight.py", file=sys.stderr)
        return 2

    print("Can a broadcast cross a bridge into a socket on this machine?\n")
    try:
        build()
        results = {
            "unicast to the bridge address (the control)":
                attempt("unicast to the bridge address (the control)",
                        bind_to_device=False, target=ADDRESS),
            "broadcast, socket bound to the bridge device":
                attempt("broadcast, socket bound to the bridge device",
                        bind_to_device=True, target="255.255.255.255"),
            "broadcast, socket not bound to any device":
                attempt("broadcast, socket not bound to any device",
                        bind_to_device=False, target="255.255.255.255"),
        }
    finally:
        teardown()

    print()
    if all(results.values()):
        print("This machine can run the testbed.")
        return 0

    if not results["unicast to the bridge address (the control)"]:
        print("Even unicast does not cross the bridge here, so the testbed\n"
              "cannot work on this machine at all.")
    elif not results["broadcast, socket bound to the bridge device"] and \
            results["broadcast, socket not bound to any device"]:
        print("Broadcasts cross, but a socket bound to the bridge with\n"
              "SO_BINDTODEVICE does not see them. That is what breaks DHCP\n"
              "here: the server binds to the access-point interface.")
    else:
        print("Broadcasts do not cross the bridge on this machine.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
