"""A minimal DHCP client, written from RFC 2131.

Deliberately independent of SymbiVPN's DHCP code: if the server were tested
with its own parser, a shared misunderstanding of the protocol would pass. This
builds the packets by hand and reads the reply by hand.

Prints the lease it obtained as JSON, and configures the interface.
"""

from __future__ import annotations

import json
import random
import socket
import struct
import subprocess
import sys
import time

MAGIC = b"\x63\x82\x53\x63"
DISCOVER, OFFER, REQUEST, ACK, NAK = 1, 2, 3, 5, 6


def mac_of(interface: str) -> bytes:
    with open(f"/sys/class/net/{interface}/address") as handle:
        return bytes.fromhex(handle.read().strip().replace(":", ""))


def build(message_type: int, mac: bytes, xid: bytes, requested=None, server=None) -> bytes:
    packet = bytearray()
    packet += struct.pack("!BBBB", 1, 1, 6, 0)     # BOOTREQUEST, ethernet
    packet += xid
    packet += struct.pack("!HH", 0, 0x8000)        # secs, broadcast
    packet += b"\x00" * 16                         # ciaddr/yiaddr/siaddr/giaddr
    packet += mac + b"\x00" * 10                   # chaddr
    packet += b"\x00" * 192                        # sname + file
    packet += MAGIC
    packet += bytes([53, 1, message_type])
    packet += bytes([12, 5]) + b"phone"            # hostname
    packet += bytes([55, 4, 1, 3, 6, 15])          # request mask, router, DNS, domain
    if requested:
        packet += bytes([50, 4]) + socket.inet_aton(requested)
    if server:
        packet += bytes([54, 4]) + socket.inet_aton(server)
    packet += bytes([255])
    return bytes(packet)


def parse(payload: bytes) -> dict | None:
    if len(payload) < 240 or payload[236:240] != MAGIC:
        return None
    options = {}
    cursor = 240
    while cursor < len(payload):
        code = payload[cursor]
        if code == 255:
            break
        if code == 0:
            cursor += 1
            continue
        length = payload[cursor + 1]
        options[code] = payload[cursor + 2 : cursor + 2 + length]
        cursor += 2 + length
    return {
        "xid": payload[4:8],
        "yiaddr": socket.inet_ntoa(payload[16:20]),
        "options": options,
    }


def addresses(raw: bytes) -> list[str]:
    return [socket.inet_ntoa(raw[i : i + 4]) for i in range(0, len(raw) - 3, 4)]


ETH_P_IP = 0x0800


class ReplyReader:
    """Reads DHCP replies the way a real client does: off a packet socket.

    A UDP socket cannot be relied on here. The reply is broadcast to a client
    that has no address yet and therefore no routes, so a host with reverse
    path filtering turned on drops it before any socket sees it -- the packet
    reaches the interface and goes no further. That is not a quirk: it is why
    dhclient, dhcpcd, Android and iOS all receive over AF_PACKET instead.

    Measured, on a machine with rp_filter switched on for the client: the
    bridge sent four frames, the client's interface received four, and a UDP
    socket bound to that interface with SO_BINDTODEVICE saw none of them.

    SOCK_DGRAM at the packet level means the kernel strips the Ethernet header,
    so this parses IP and UDP and nothing lower.
    """

    def __init__(self, interface: str) -> None:
        self.socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)
        )
        # Not htons() here, unlike the constructor: Python byte-swaps the
        # protocol itself for an AF_PACKET bind, so passing a swapped value
        # binds to protocol 8 rather than 0x0800 and matches nothing. The
        # socket comes up, reads block, and nothing says why.
        self.socket.bind((interface, ETH_P_IP))

    def settimeout(self, timeout: float) -> None:
        self.socket.settimeout(timeout)

    def read(self) -> bytes | None:
        """The next UDP payload addressed to the DHCP client port, if any."""
        packet = self.socket.recv(2048)
        if len(packet) < 20:
            return None
        version_and_length = packet[0]
        if version_and_length >> 4 != 4:
            return None
        header_length = (version_and_length & 0x0F) * 4
        if header_length < 20 or len(packet) < header_length + 8:
            return None
        if packet[9] != socket.IPPROTO_UDP:
            return None
        # A fragment other than the first carries no UDP header to read.
        if packet[6] & 0x1F or packet[7]:
            return None
        udp = packet[header_length : header_length + 8]
        destination_port = struct.unpack("!H", udp[2:4])[0]
        if destination_port != 68:
            return None
        length = struct.unpack("!H", udp[6:8])[0]
        if length < 8:
            return None
        return packet[header_length + 8 : header_length + length]

    def close(self) -> None:
        self.socket.close()


def main() -> int:
    interface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    mac = mac_of(interface)
    xid = bytes(random.getrandbits(8) for _ in range(4))

    # Sent over UDP, which works from an unconfigured interface as long as the
    # socket names the device; received over a packet socket, which is the
    # only way to see a reply the routing layer will not deliver.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
    sock.bind(("", 68))
    replies = ReplyReader(interface)

    def exchange(message_type, **kwargs):
        """Send, and keep sending until answered or out of attempts.

        RFC 2131 has the client retransmit with backoff, and every real client
        does -- dhclient, Android and iOS all retry several times. A single
        datagram going missing is ordinary, especially on a bridge whose ports
        were brought up moments ago. Sending once and calling silence a failure
        made this less robust than any device it stands in for, and turned an
        unremarkable lost packet into a testbed that fails.
        """
        packet = build(message_type, mac, xid, **kwargs)
        for attempt in range(4):
            sock.sendto(packet, ("255.255.255.255", 67))
            deadline = time.time() + 0.5 * (2 ** attempt)
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                replies.settimeout(remaining)
                try:
                    payload = replies.read()
                except socket.timeout:
                    break
                if payload is None:
                    continue
                reply = parse(payload)
                if reply and reply["xid"] == xid:
                    return reply
        return None

    offer = exchange(DISCOVER)
    if offer is None:
        print(json.dumps({"error": "no DHCPOFFER received"}))
        return 1

    server_id = socket.inet_ntoa(offer["options"].get(54, b"\x00" * 4))
    ack = exchange(REQUEST, requested=offer["yiaddr"], server=server_id)
    if ack is None or ack["options"].get(53, b"\x00")[0] != ACK:
        print(json.dumps({"error": "no DHCPACK received", "offered": offer["yiaddr"]}))
        return 1

    options = ack["options"]
    lease = {
        "address": ack["yiaddr"],
        "netmask": socket.inet_ntoa(options[1]) if 1 in options else "",
        "router": addresses(options.get(3, b"")),
        "dns": addresses(options.get(6, b"")),
        "domain": options.get(15, b"").decode("ascii", "replace").strip("\x00"),
        "lease_seconds": struct.unpack("!I", options[51])[0] if 51 in options else 0,
        "server_id": server_id,
    }
    sock.close()

    # Apply it, so the rest of the test uses a genuinely DHCP-configured host.
    prefix = sum(bin(int(part)).count("1") for part in lease["netmask"].split(".")) if lease["netmask"] else 24
    subprocess.run(
        ["ip", "addr", "add", f"{lease['address']}/{prefix}", "dev", interface],
        capture_output=True, check=False,
    )
    if lease["router"]:
        subprocess.run(
            ["ip", "route", "add", "default", "via", lease["router"][0]],
            capture_output=True, check=False,
        )

    print(json.dumps(lease))
    return 0


if __name__ == "__main__":
    sys.exit(main())
