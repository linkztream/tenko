#!/usr/bin/env python3
"""A DHCPv6 relay agent in a few lines, for the rows of the round dhcp6 of the DHCP lab.

It sends one client's exchange to the node as a relay agent would (RFC 8415 sections 19
and 20): a SOLICIT and then a REQUEST for the advertised address, each inside a RELAY-FORW
with the link address of --link, from the address --bind on port 547 (the node answers to
the source address and port of the RELAY-FORW). With --two-deep the client's message goes
through a lightweight relay first (RFC 6221): an inner RELAY-FORW with the link address
`::` and, with --interface-id, an Interface-Id, then the outer RELAY-FORW with --link.
With --mac the innermost RELAY-FORW carries the Client Link-Layer Address option (RFC
6939). It checks that the RELAY-REPL chain has the same depth as the RELAY-FORW chain, that
the Interface-Id comes back in the layer that sent it, and that the answer is an ADVERTISE
and then a REPLY with an address (and, with --rapid-commit, a REPLY with the Rapid Commit
option to the SOLICIT, without a REQUEST). It prints one line per step:

    advertise 2001:db8:101::1abc depth=1 iid=ok
    reply 2001:db8:101::1abc depth=1 iid=ok lifetimes=120/60 fqdn=host6.example.test flags=0x01
    address 2001:db8:101::1abc
    release 2001:db8:101::1abc status=0

The exit status is 0 when every step passed, 1 otherwise. Written against RFC 8415 with the
standard library only; it shares no code with Tenko. Run as root in the tools container
(port 547).
"""

import argparse
import ipaddress
import os
import socket
import struct
import sys

SOLICIT, ADVERTISE, REQUEST, REPLY, RELEASE, RELAY_FORW, RELAY_REPL = 1, 2, 3, 7, 8, 12, 13
OPT_CLIENTID, OPT_SERVERID, OPT_IA_NA, OPT_IAADDR, OPT_ORO = 1, 2, 3, 5, 6
OPT_ELAPSED, OPT_RELAY_MSG, OPT_STATUS, OPT_RAPID_COMMIT = 8, 9, 13, 14
OPT_INTERFACE_ID, OPT_FQDN, OPT_LINKLAYER = 18, 39, 79
# The enterprise number for documentation (RFC 5612 section 8's example, IANA 32473).
ENTERPRISE = 32473


def option(code, data):
    return struct.pack("!HH", code, len(data)) + data


def options_of(data):
    """The options of an area as {code: [data, ...]}; a truncated option ends the walk."""
    found, pos = {}, 0
    while pos + 4 <= len(data):
        code, length = struct.unpack("!HH", data[pos : pos + 4])
        if pos + 4 + length > len(data):
            break
        found.setdefault(code, []).append(data[pos + 4 : pos + 4 + length])
        pos += 4 + length
    return found


def fqdn_option(name):
    """Option 39 (RFC 4704) with the S flag: the name in wire format, a partial name (no
    trailing dot) without the root label."""
    full = name.endswith(".")
    labels = [label for label in name.rstrip(".").split(".") if label]
    wire = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
    return option(OPT_FQDN, b"\x01" + wire + (b"\0" if full else b""))


def fqdn_text(data):
    flags, wire, labels, pos = data[0], data[1:], [], 0
    while pos < len(wire) and wire[pos]:
        labels.append(wire[pos + 1 : pos + 1 + wire[pos]].decode("ascii", "replace"))
        pos += 1 + wire[pos]
    return ".".join(labels), flags


def relay_forw(inner, link, peer, hops, interface_id=None, mac=None):
    body = option(OPT_RELAY_MSG, inner)
    if interface_id is not None:
        body += option(OPT_INTERFACE_ID, interface_id.encode())
    if mac is not None:
        # Link-layer type 1, Ethernet (RFC 6939 section 4).
        body += option(OPT_LINKLAYER, struct.pack("!H", 1) + mac)
    return (struct.pack("!BB", RELAY_FORW, hops) + ipaddress.IPv6Address(link).packed
            + ipaddress.IPv6Address(peer).packed + body)


def unwrap(data):
    """The RELAY-REPL layers of an answer from the outside in: (hops, link, peer,
    interface id or None) per layer, and the client message at the bottom."""
    layers = []
    while data and data[0] == RELAY_REPL and len(data) >= 34:
        found = options_of(data[34:])
        iid = found.get(OPT_INTERFACE_ID, [None])[0]
        layers.append((data[1], str(ipaddress.IPv6Address(data[2:18])),
                       str(ipaddress.IPv6Address(data[18:34])), iid))
        if OPT_RELAY_MSG not in found:
            return layers, b""
        data = found[OPT_RELAY_MSG][0]
    return layers, data


def ia_na_address(found):
    """The first address of the first IA_NA of a client message's options, with its
    lifetimes and the status inside the IA address, if any."""
    for ia in found.get(OPT_IA_NA, []):
        inner = options_of(ia[12:])
        for addr in inner.get(OPT_IAADDR, []):
            if len(addr) >= 24:
                preferred, valid = struct.unpack("!II", addr[16:24])
                status = options_of(addr[24:]).get(OPT_STATUS, [b"\0\0"])[0]
                return str(ipaddress.IPv6Address(addr[:16])), preferred, valid, \
                    struct.unpack("!H", status[:2])[0]
    return None


def status_of(found):
    """The status code of a client message's top level, or inside its first IA_NA."""
    if OPT_STATUS in found:
        return struct.unpack("!H", found[OPT_STATUS][0][:2])[0]
    for ia in found.get(OPT_IA_NA, []):
        inner = options_of(ia[12:])
        if OPT_STATUS in inner:
            return struct.unpack("!H", inner[OPT_STATUS][0][:2])[0]
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", required=True, help="the node's IPv6 address")
    ap.add_argument("--bind", required=True, help="this host's address, the relay's")
    ap.add_argument("--link", default="2001:db8:101::1",
                    help="link address of the outermost relay (the link of the client)")
    ap.add_argument("--duid", help="the client's DUID in hex; default: a DUID-EN")
    ap.add_argument("--iaid", type=int, default=1)
    ap.add_argument("--mac", help="the client's MAC: adds option 79 (RFC 6939)")
    ap.add_argument("--interface-id", help="Interface-Id (option 18) of the innermost relay")
    ap.add_argument("--two-deep", action="store_true",
                    help="a lightweight relay (RFC 6221) inside the outer relay")
    ap.add_argument("--fqdn", help="Client FQDN (option 39) with the S flag")
    ap.add_argument("--rapid-commit", action="store_true",
                    help="SOLICIT with Rapid Commit, a REPLY expected; no REQUEST")
    ap.add_argument("--release", action="store_true", help="release the address at the end")
    ap.add_argument("--expect", help="the prefix the address must be in")
    ap.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args()

    mac = bytes.fromhex(args.mac.replace(":", "")) if args.mac else None
    if args.duid:
        duid = bytes.fromhex(args.duid.replace(":", ""))
    else:
        tail = (mac + b"\0\0") if mac else os.urandom(8)
        duid = struct.pack("!HI", 2, ENTERPRISE) + tail[:8]
    expect = ipaddress.IPv6Network(args.expect) if args.expect else None
    # The client's link-local address as the relay sees it (RFC 8415 section 9).
    peer = "fe80::5e:1"
    if mac:
        peer = "fe80::" + ":".join(f"{mac[i] << 8 | mac[i + 1]:x}" for i in (0, 2, 4))
    depth = 2 if args.two_deep else 1

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, 547))
    sock.settimeout(args.timeout)
    server = (args.server, 547)
    ok = True

    def wrap(client_message):
        """The client's message inside the relay chain."""
        if args.two_deep:
            inner = relay_forw(client_message, "::", peer, 0, args.interface_id, mac)
            return relay_forw(inner, args.link, "fe80::5e:ffff", 1)
        return relay_forw(client_message, args.link, peer, 0, args.interface_id, mac)

    def exchange(client_message, xid, want):
        """Sends the wrapped message and returns (layers, type, options) of the answer
        whose transaction id matches, or None on a timeout."""
        packet = wrap(client_message)
        for _ in range(2):
            sock.sendto(packet, server)
            while True:
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    break
                layers, message = unwrap(data)
                if len(message) >= 4 and message[1:4] == xid and message[0] in want:
                    return layers, message[0], options_of(message[4:])
        return None

    def chain_ok(layers):
        """The RELAY-REPL chain is as deep as the RELAY-FORW chain and the Interface-Id
        comes back in the layer that sent it (the innermost) and nowhere else."""
        if len(layers) != depth:
            return False, f"depth={len(layers)}"
        want = args.interface_id.encode() if args.interface_id else None
        echoed = [layer[3] for layer in layers]
        good = echoed[-1] == want and all(e is None for e in echoed[:-1])
        return good, "iid=" + ("ok" if good else f"wrong({echoed})")

    def lifetimes(found):
        found_addr = ia_na_address(found)
        return f"lifetimes={found_addr[2]}/{found_addr[1]}" if found_addr else "lifetimes=-"

    def client_options():
        found = option(OPT_CLIENTID, duid) + option(OPT_ELAPSED, b"\0\0")
        found += option(OPT_ORO, struct.pack("!HHH", 23, 24, 56))
        if args.fqdn:
            found += fqdn_option(args.fqdn)
        return found

    def ia_na(address=None):
        body = struct.pack("!III", args.iaid, 0, 0)
        if address:
            body += option(OPT_IAADDR, ipaddress.IPv6Address(address).packed
                           + struct.pack("!II", 0, 0))
        return option(OPT_IA_NA, body)

    def report(step, layers, found):
        nonlocal ok
        good, chain = chain_ok(layers)
        taken = ia_na_address(found)
        status = status_of(found)
        line = f"{step} {taken[0] if taken else '-'} {'depth=' + str(len(layers))} {chain}"
        if taken and taken[3]:
            status = status or taken[3]
        if status:
            line += f" status={status}"
        good = good and taken is not None and status == 0
        if taken and expect and ipaddress.IPv6Address(taken[0]) not in expect:
            line += f" outside={expect}"
            good = False
        line += " " + lifetimes(found)
        if OPT_FQDN in found:
            name, flags = fqdn_text(found[OPT_FQDN][0])
            line += f" fqdn={name or '-'} flags=0x{flags:02x}"
        print(line)
        ok = ok and good
        return taken[0] if taken and good else None

    xid = os.urandom(3)
    solicit = bytes([SOLICIT]) + xid + client_options() + ia_na()
    if args.rapid_commit:
        solicit += option(OPT_RAPID_COMMIT, b"")
    answer = exchange(solicit, xid, (REPLY,) if args.rapid_commit else (ADVERTISE,))
    if answer is None:
        print("solicit timeout")
        return 1
    layers, kind, found = answer
    address = report("reply" if args.rapid_commit else "advertise", layers, found)
    if args.rapid_commit and OPT_RAPID_COMMIT not in found:
        print("reply without the Rapid Commit option")
        ok = False
    if address is None:
        return 1
    if not args.rapid_commit:
        server_id = found.get(OPT_SERVERID, [b""])[0]
        xid = os.urandom(3)
        request = bytes([REQUEST]) + xid + client_options() + option(OPT_SERVERID, server_id) \
            + ia_na(address)
        answer = exchange(request, xid, (REPLY,))
        if answer is None:
            print("request timeout")
            return 1
        layers, kind, found = answer
        taken = report("reply", layers, found)
        if taken is None:
            return 1
        if taken != address:
            print(f"reply gave {taken}, not the advertised {address}")
            ok = False
    else:
        server_id = found.get(OPT_SERVERID, [b""])[0]
    print(f"address {address}")
    if args.release:
        xid = os.urandom(3)
        release = bytes([RELEASE]) + xid + option(OPT_CLIENTID, duid) \
            + option(OPT_SERVERID, server_id) + option(OPT_ELAPSED, b"\0\0") + ia_na(address)
        answer = exchange(release, xid, (REPLY,))
        if answer is None:
            print("release timeout")
            return 1
        layers, kind, found = answer
        status = status_of(found)
        good, chain = chain_ok(layers)
        print(f"release {address} status={status} depth={len(layers)} {chain}")
        ok = ok and good and status == 0
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
