#!/usr/bin/env python3
"""A relay agent in a few lines, for the option 82 rows of the DHCP lab.

It sends one client's exchange to the node as a relay agent would: DISCOVER, REQUEST and
optionally a renewal and a RELEASE, with giaddr set to its own address and option 82 with
a circuit-id and, when asked, the link selection sub-option (RFC 3527) or option 118 (RFC
3011). It checks that the OFFER and the ACK carry an address of the expected network and
option 82 back unchanged (RFC 3046 section 2.2), and prints one line per step:

    offer 192.0.2.160 echo=ok
    ack 192.0.2.160 echo=ok lease=60
    renew 192.0.2.160
    release 192.0.2.160

WP8.4: with --vendor-class, --user-class and --arch it sends options 60, 77 and 93 (RFC
4578) as a boot client does; --expect-file and --expect-vendor check the boot file in the
`file` field and option 60 of the OFFER and the ACK (UEFI HTTP boot, PXE); --proxy-port
sends the boot server discovery of PXE after the ACK: a REQUEST from the leased address to
the server's proxy DHCP port, whose ACK must carry no address and the expected boot file:

    proxy 0.0.0.0 file=ipxe.efi

The exit status is 0 when every step passed, 1 otherwise. Written against RFC 2131 only;
it shares no code with Tenko. Run as root in the tools container (port 67).
"""

import argparse
import ipaddress
import os
import socket
import struct
import sys

COOKIE = b"\x63\x82\x53\x63"
DISCOVER, OFFER, REQUEST, ACK, NAK, RELEASE = 1, 2, 3, 5, 6, 7


def option(code, data):
    return bytes([code, len(data)]) + data


def message(kind, xid, mac, giaddr, ciaddr, options):
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1, 1, 6, 1, xid, 0, 0,
        ipaddress.IPv4Address(ciaddr).packed,
        b"\0" * 4, b"\0" * 4,
        ipaddress.IPv4Address(giaddr).packed,
        mac + b"\0" * 10, b"\0" * 64, b"\0" * 128,
    )
    body = option(53, bytes([kind])) + b"".join(options) + b"\xff"
    return header + COOKIE + body


def parse(data):
    """The header fields and the options of a reply (the options field only)."""
    if len(data) < 240 or data[236:240] != COOKIE:
        return None
    xid = struct.unpack("!I", data[4:8])[0]
    yiaddr = str(ipaddress.IPv4Address(data[16:20]))
    # WP8.4: the next server and the boot file of a boot reply.
    siaddr = str(ipaddress.IPv4Address(data[20:24]))
    boot_file = data[108:236].split(b"\0", 1)[0].decode("ascii", "replace")
    options, pos = {}, 240
    while pos < len(data):
        code = data[pos]
        if code == 0:
            pos += 1
            continue
        if code == 255 or pos + 1 >= len(data):
            break
        length = data[pos + 1]
        options[code] = options.get(code, b"") + data[pos + 2 : pos + 2 + length]
        pos += 2 + length
    return {"xid": xid, "yiaddr": yiaddr, "siaddr": siaddr, "file": boot_file,
            "options": options}


def exchange(sock, server, packet, xid, want):
    sock.sendto(packet, (server, 67))
    while True:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None
        reply = parse(data)
        if reply and reply["xid"] == xid and reply["options"].get(53, b"\0")[0] in want:
            return reply


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True)
    ap.add_argument("--giaddr", required=True, help="this host's address, the relay's")
    ap.add_argument("--mac", required=True)
    ap.add_argument("--expect", required=True, help="the network the address must be in")
    ap.add_argument("--circuit", default="relay-test")
    ap.add_argument("--link", help="link selection sub-option (RFC 3527)")
    ap.add_argument("--subnet-selection", help="option 118 (RFC 3011)")
    ap.add_argument("--renew", action="store_true")
    ap.add_argument("--release", action="store_true")
    ap.add_argument("--timeout", type=float, default=5.0)
    # WP8.4: a boot client's options and the checks of a boot reply.
    ap.add_argument("--vendor-class", help="option 60")
    ap.add_argument("--user-class", help="option 77, as plain text")
    ap.add_argument("--arch", type=int, help="option 93, one architecture type")
    ap.add_argument("--expect-file", help="the boot file the replies carry in `file`")
    ap.add_argument("--expect-vendor", help="the option 60 the replies carry")
    ap.add_argument("--proxy-port", type=int, help="the server's proxy DHCP port (4011)")
    args = ap.parse_args()

    mac = bytes.fromhex(args.mac.replace(":", ""))
    expect = ipaddress.IPv4Network(args.expect)
    agent = option(1, args.circuit.encode())
    if args.link:
        agent += option(5, ipaddress.IPv4Address(args.link).packed)
    relay_info = option(82, agent)
    extra = [option(55, bytes([1, 3, 6, 15, 42, 51, 54]))]
    if args.subnet_selection:
        extra.append(option(118, ipaddress.IPv4Address(args.subnet_selection).packed))
    # WP8.4: the boot client's options.
    if args.vendor_class:
        extra.append(option(60, args.vendor_class.encode()))
    if args.user_class:
        extra.append(option(77, args.user_class.encode()))
    if args.arch is not None:
        extra.append(option(93, struct.pack("!H", args.arch)))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.giaddr, 67))
    sock.settimeout(args.timeout)
    xid = int.from_bytes(os.urandom(4), "big")
    ok = True

    def check(step, reply, addr=None):
        nonlocal ok
        if reply is None:
            print(f"{step} timeout")
            ok = False
            return None
        kind = reply["options"].get(53, b"\0")[0]
        if kind == NAK:
            print(f"{step} nak")
            ok = False
            return None
        yiaddr = reply["yiaddr"]
        inside = ipaddress.IPv4Address(yiaddr) in expect
        echo = reply["options"].get(82) == agent
        lease = reply["options"].get(51)
        lease = struct.unpack("!I", lease)[0] if lease and len(lease) == 4 else "-"
        good = inside and echo and (addr is None or addr == yiaddr)
        # WP8.4: the boot file and option 60 of a boot reply.
        boot = ""
        if args.expect_file is not None:
            good = good and reply["file"] == args.expect_file
            boot += f" file={reply['file'] or '-'}"
        if args.expect_vendor is not None:
            vendor = reply["options"].get(60, b"").decode("ascii", "replace")
            good = good and vendor == args.expect_vendor
            boot += f" vendor={vendor or '-'}"
        print(f"{step} {yiaddr} echo={'ok' if echo else 'missing'} lease={lease}"
              + ("" if inside else f" outside={expect}") + boot)
        ok = ok and good
        return reply if good else None

    offer = check("offer", exchange(
        sock, args.server, message(DISCOVER, xid, mac, args.giaddr, "0.0.0.0", extra + [relay_info]),
        xid, (OFFER,)))
    if offer is None:
        return 1
    addr = offer["yiaddr"]
    server_id = offer["options"].get(54, ipaddress.IPv4Address(args.server).packed)
    request = extra + [option(50, ipaddress.IPv4Address(addr).packed), option(54, server_id), relay_info]
    ack = check("ack", exchange(
        sock, args.server, message(REQUEST, xid, mac, args.giaddr, "0.0.0.0", request),
        xid, (ACK, NAK)), addr)
    if ack is None:
        return 1
    # WP8.4: the boot server discovery on the proxy DHCP port, from the leased address.
    if args.proxy_port:
        xid += 1
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind((args.giaddr, 0))
        probe.settimeout(args.timeout)
        probe.sendto(message(REQUEST, xid, mac, "0.0.0.0", addr, extra), (args.server, args.proxy_port))
        reply = None
        while reply is None:
            try:
                data, _ = probe.recvfrom(4096)
            except socket.timeout:
                break
            parsed = parse(data)
            if parsed and parsed["xid"] == xid:
                reply = parsed
        if reply is None:
            print("proxy timeout")
            ok = False
        else:
            kind = reply["options"].get(53, b"\0")[0]
            good = kind == ACK and reply["yiaddr"] == "0.0.0.0"
            if args.expect_file is not None:
                good = good and reply["file"] == args.expect_file
            print(f"proxy {reply['yiaddr']} file={reply['file'] or '-'}"
                  + ("" if kind == ACK else f" type={kind}"))
            ok = ok and good
    if args.renew:
        xid += 1
        check("renew", exchange(
            sock, args.server, message(REQUEST, xid, mac, args.giaddr, addr, extra + [relay_info]),
            xid, (ACK, NAK)), addr)
    if args.release:
        xid += 1
        sock.sendto(message(RELEASE, xid, mac, args.giaddr, addr, [option(54, server_id), relay_info]),
                    (args.server, 67))
        print(f"release {addr}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
