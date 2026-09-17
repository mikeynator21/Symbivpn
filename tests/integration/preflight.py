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


def _snapshot() -> dict[str, tuple[int, int]]:
    """Packet counts at every hop, to be differenced across one attempt.

    Totals are not usable on their own: bringing an interface up generates
    IPv6 multicast of its own, so a hop that carried nothing during the test
    can still show a non-zero count and read as success.
    """
    return {
        "client": _packets(NS_B, "pre-cl"),
        "port": _packets(NS_A, "pre-gw"),
        "bridge": _packets(NS_A, BRIDGE),
    }


def _moved(before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]],
           hop: str, index: int) -> int:
    """How many packets crossed one hop during the attempt."""
    return max(0, after[hop][index] - before[hop][index])


def _explain_where_it_stopped(sent_ok: bool, before: dict, after: dict) -> None:
    """Say which hop the packet failed to make, rather than only that it did."""
    client_tx = _moved(before, after, "client", 1)
    port_rx = _moved(before, after, "port", 0)
    bridge_rx = _moved(before, after, "bridge", 0)
    print(f"         send call {'succeeded' if sent_ok else 'failed'}; during the "
          f"attempt: client tx={client_tx}, bridge port rx={port_rx}, "
          f"bridge rx={bridge_rx}")
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

    before = _snapshot()
    sender = ns(NS_B, "python3", "-c", SENDER, target, str(port), str(source_port))
    sent_ok = "SENT" in sender.stdout

    outcome = listener.stdout.readline().strip()
    listener.wait(timeout=10)
    after = _snapshot()

    arrived = outcome.startswith("GOT")
    print(f"  [{'ok  ' if arrived else 'FAIL'}] {label}")
    if not arrived:
        if sender.stdout.strip() and not sent_ok:
            print(f"         sender said: {sender.stdout.strip()}")
        _explain_where_it_stopped(sent_ok, before, after)
    return arrived


# Read off a packet socket, exactly as the testbed's DHCP client does and as
# every real one does. A UDP socket is the wrong instrument here: the reply is
# broadcast to a client with no address and therefore no route back to the
# sender, which is the case reverse path filtering drops, so on a host with it
# on the packet reaches the interface and no socket ever sees it. Testing the
# reply over UDP would report a fault on every such machine while the thing it
# stands in for works perfectly well.
REPLY_LISTENER = r"""
import socket, struct, sys
port = int(sys.argv[1])
ETH_P_IP = 0x0800
sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP))
# Not htons() on the bind: Python swaps the protocol itself there.
sock.bind(("pre-cl", ETH_P_IP))
sock.settimeout(6)
print("READY", flush=True)
deadline = __import__("time").monotonic() + 6
while True:
    remaining = deadline - __import__("time").monotonic()
    if remaining <= 0:
        print("NOTHING", flush=True)
        break
    sock.settimeout(remaining)
    try:
        packet = sock.recv(2048)
    except socket.timeout:
        print("NOTHING", flush=True)
        break
    if len(packet) < 28 or packet[0] >> 4 != 4:
        continue
    header_length = (packet[0] & 0x0F) * 4
    if packet[9] != socket.IPPROTO_UDP or len(packet) < header_length + 8:
        continue
    udp = packet[header_length:header_length + 8]
    if struct.unpack("!H", udp[2:4])[0] != port:
        continue
    length = struct.unpack("!H", udp[6:8])[0]
    print("GOT", packet[header_length + 8:header_length + length].decode(), flush=True)
    break
"""

REPLY_SENDER = r"""
import socket, sys
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
# Exactly how the DHCP server is bound: to the bridge, on the server port.
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"%s\0")
sock.bind(("", %d))
for _ in range(3):
    try:
        sock.sendto(b"offer", ("255.255.255.255", port))
    except OSError as exc:
        print("SENDFAIL", exc, flush=True)
        raise SystemExit(1)
print("SENT", flush=True)
""" % (BRIDGE.encode().decode(), SERVER_PORT)


def attempt_reply(label: str) -> bool:
    """The server's answer, going the other way.

    Every case above sends client to server. A DHCPOFFER goes the other way,
    from a socket bound to the bridge out to a client that still has no
    address, and nothing here tested that direction -- so a machine where the
    request arrives and the answer does not would have passed preflight and
    failed the testbed, saying only that no lease arrived.
    """
    listener = subprocess.Popen(
        ["ip", "netns", "exec", NS_B, "python3", "-c", REPLY_LISTENER, str(CLIENT_PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    assert listener.stdout is not None
    if listener.stdout.readline().strip() != "READY":
        print(f"  [FAIL] {label}: the listener did not start")
        listener.kill()
        return False

    before = _snapshot()
    sender = ns(NS_A, "python3", "-c", REPLY_SENDER, str(CLIENT_PORT))
    sent_ok = "SENT" in sender.stdout
    outcome = listener.stdout.readline().strip()
    listener.wait(timeout=10)
    after = _snapshot()

    arrived = outcome.startswith("GOT")
    print(f"  [{'ok  ' if arrived else 'FAIL'}] {label}")
    if not arrived:
        if sender.stdout.strip() and not sent_ok:
            print(f"         sender said: {sender.stdout.strip()}")
        bridge_tx = _moved(before, after, "bridge", 1)
        port_tx = _moved(before, after, "port", 1)
        client_rx = _moved(before, after, "client", 0)
        print(f"         send call {'succeeded' if sent_ok else 'failed'}; during the "
              f"attempt: bridge tx={bridge_tx}, bridge port tx={port_tx}, "
              f"client rx={client_rx}")
        if not sent_ok:
            print("         -- the send itself failed: the server cannot broadcast "
                  "out of a socket bound to the bridge")
        elif bridge_tx <= 0:
            print("         -- nothing left the bridge: the broadcast was dropped "
                  "on the way out of the gateway's stack")
        elif client_rx <= 0:
            print("         -- it left the bridge and never reached the client")
        else:
            print("         -- it reached the client's interface and was not read: "
                  "the packet socket is not seeing what the interface received")
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
        results["the answer coming back the other way"] = attempt_reply(
            "the answer coming back the other way")
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
    elif not results.get("the answer coming back the other way"):
        print("The request crosses the bridge and the answer does not. A\n"
              "DHCPOFFER is broadcast from a socket bound to the bridge out to\n"
              "a client that still has no address, and that direction is the\n"
              "one this machine does not carry -- which looks from the client\n"
              "exactly like a request that never arrived. The line above says\n"
              "which hop the answer failed to make.")
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
