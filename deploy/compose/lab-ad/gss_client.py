#!/usr/bin/env python3
"""A GSS-TSIG client of the AD lab (E43), over the MIT GSSAPI of the client container.

It negotiates a security context with TKEY (RFC 2930, RFC 3645) over TCP and signs dynamic
updates (RFC 2136) with GSS-TSIG itself, so that the rows nsupdate cannot steer can run: a
signature dated outside the fudge (BADTIME), the same signed update sent twice (a replay), a
key name the server never negotiated (BADKEY), a context the server let expire (BADKEY), and
a TKEY offer of NTLM alone. It also checks, on MIT's side, what nsupdate checks silently:
mutual authentication and the signature of every answer, the TKEY answer's digest covering
no request MAC ([MS-GSSA] section 3.1.5.1).

Each command prints one line `key=value ...` for the round script to read. Run it in the
client container with a ticket in the credential cache (kinit first):

    python3 /lab/gss_client.py negotiate
    python3 /lab/gss_client.py update NAME ADDRESS [--tcp] [--skew SECS] [--twice]
        [--key-name NAME] [--wait SECS]
    python3 /lab/gss_client.py ntlm

The lab only: the server, zone and service name are the lab's fixed values.
"""

import argparse
import os
import socket
import struct
import sys
import time

import gssapi

SERVER = "198.51.100.3"
ZONE = "lab.example.test"
SERVICE = "DNS@ns1.lab.example.test"
GSS_TSIG = "gss-tsig"
FUDGE = 300
TYPE_TKEY, TYPE_TSIG, TYPE_SOA, TYPE_A = 249, 250, 6, 1
CLASS_IN, CLASS_ANY = 1, 255
# SPNEGO offering NTLM alone, with the start of an NTLM negotiate message.
NTLM_ONLY = bytes.fromhex(
    "602c06062b0601050502a0223020a00e300c060a2b06010401823702020a"
    "a20e040c4e544c4d5353500001000000"
)


def wire_name(text):
    out = b""
    for label in text.rstrip(".").lower().split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def read_name(data, pos):
    """Skips a name (compressed or not); returns the position after it."""
    while True:
        length = data[pos]
        if length == 0:
            return pos + 1
        if length >= 0xC0:
            return pos + 2
        pos += 1 + length


def records(data):
    """The records of a message: (type, start, rdata start, rdata end) per record."""
    qd, an, ns, ar = struct.unpack("!4H", data[4:12])
    pos = 12
    for _ in range(qd):
        pos = read_name(data, pos) + 4
    out = []
    for _ in range(an + ns + ar):
        start = pos
        pos = read_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        out.append((rtype, start, pos + 10, pos + 10 + rdlen))
        pos += 10 + rdlen
    return out


def tsig_variables(key_name, time_signed, error=0, other=b""):
    return (
        wire_name(key_name)
        + struct.pack("!HI", CLASS_ANY, 0)
        + wire_name(GSS_TSIG)
        + struct.pack("!Q", time_signed)[2:]
        + struct.pack("!HH", FUDGE, error)
        + struct.pack("!H", len(other))
        + other
    )


def sign(message, ctx, key_name, time_signed):
    """Appends a GSS-TSIG record to `message`; returns the signed message and its MAC."""
    digest = message + tsig_variables(key_name, time_signed)
    mac = ctx.get_signature(digest)
    rdata = (
        wire_name(GSS_TSIG)
        + struct.pack("!Q", time_signed)[2:]
        + struct.pack("!HH", FUDGE, len(mac))
        + mac
        + message[0:2]
        + struct.pack("!HH", 0, 0)
    )
    signed = bytearray(message)
    arcount = struct.unpack("!H", signed[10:12])[0] + 1
    signed[10:12] = struct.pack("!H", arcount)
    rr = wire_name(key_name) + struct.pack("!HHIH", TYPE_TSIG, CLASS_ANY, 0, len(rdata)) + rdata
    return bytes(signed) + rr, mac


def tsig_of(answer):
    """The TSIG of an answer: (record start, time signed, MAC, error), or None."""
    for rtype, start, rdata, end in records(answer):
        if rtype == TYPE_TSIG:
            pos = read_name(answer, rdata)
            time_signed = struct.unpack("!Q", b"\x00\x00" + answer[pos : pos + 6])[0]
            mac_len = struct.unpack("!H", answer[pos + 8 : pos + 10])[0]
            mac = answer[pos + 10 : pos + 10 + mac_len]
            error = struct.unpack("!H", answer[pos + 12 + mac_len : pos + 14 + mac_len])[0]
            other_len = struct.unpack("!H", answer[pos + 14 + mac_len : pos + 16 + mac_len])[0]
            other = answer[pos + 16 + mac_len : pos + 16 + mac_len + other_len]
            return start, time_signed, mac, error, other
    return None


def verify_answer(answer, ctx, key_name, request_mac):
    """Whether the answer's GSS-TSIG verifies at the client; None when it has none."""
    tsig = tsig_of(answer)
    if tsig is None:
        return None
    start, time_signed, mac, error, other = tsig
    if not mac:
        return False
    body = bytearray(answer[:start])
    body[10:12] = struct.pack("!H", struct.unpack("!H", body[10:12])[0] - 1)
    prior = b"" if request_mac is None else struct.pack("!H", len(request_mac)) + request_mac
    digest = prior + bytes(body) + tsig_variables(key_name, time_signed, error, other)
    try:
        ctx.verify_signature(digest, mac)
    except gssapi.exceptions.GSSError:
        return False
    return True


def exchange_tcp(message):
    with socket.create_connection((SERVER, 53), timeout=10) as sock:
        sock.sendall(struct.pack("!H", len(message)) + message)
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
        return recv_exact(sock, length)


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("the server closed the connection")
        data += chunk
    return data


def exchange_udp(message):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(message, (SERVER, 53))
        return sock.recv(65535)


def tkey_query(key_name, token, mode=3):
    now = int(time.time())
    name = wire_name(key_name)
    rdata = (
        wire_name(GSS_TSIG)
        + struct.pack("!IIHHH", now, now + 3600, mode, 0, len(token))
        + token
        + struct.pack("!H", 0)
    )
    header = struct.pack("!6H", int.from_bytes(os.urandom(2), "big"), 0, 1, 0, 0, 1)
    return (
        header
        + name
        + struct.pack("!HH", TYPE_TKEY, CLASS_ANY)
        + name
        + struct.pack("!HHIH", TYPE_TKEY, CLASS_ANY, 0, len(rdata))
        + rdata
    )


def tkey_of(answer):
    """The TKEY of an answer: (error, key data), or None."""
    for rtype, _start, rdata, _end in records(answer):
        if rtype == TYPE_TKEY:
            pos = read_name(answer, rdata)
            _inc, _exp, _mode, error, key_len = struct.unpack("!IIHHH", answer[pos : pos + 14])
            return error, answer[pos + 14 : pos + 14 + key_len]
    return None


def negotiate(key_name, mech=None):
    name = gssapi.Name(SERVICE, gssapi.NameType.hostbased_service)
    flags = [
        gssapi.RequirementFlag.mutual_authentication,
        gssapi.RequirementFlag.replay_detection,
        gssapi.RequirementFlag.out_of_sequence_detection,
        gssapi.RequirementFlag.integrity,
    ]
    ctx = gssapi.SecurityContext(name=name, flags=flags, mech=mech, usage="initiate")
    token = ctx.step()
    answer = None
    legs = 0
    while token:
        legs += 1
        answer = exchange_tcp(tkey_query(key_name, token))
        rcode = answer[3] & 0x0F
        tkey = tkey_of(answer)
        if rcode != 0 or tkey is None or tkey[0] != 0:
            raise RuntimeError(f"rcode={rcode} tkey_error={None if tkey is None else tkey[0]}")
        token = None if ctx.complete or not tkey[1] else ctx.step(tkey[1])
    if not ctx.complete:
        raise RuntimeError("the negotiation ended before the context was complete")
    mutual = gssapi.RequirementFlag.mutual_authentication in ctx.actual_flags
    verified = verify_answer(answer, ctx, key_name, None)
    return ctx, legs, mutual, verified


def update_message(name, address):
    msg_id = int.from_bytes(os.urandom(2), "big")
    header = struct.pack("!6H", msg_id, 5 << 11, 1, 0, 1, 0)
    zone = wire_name(ZONE) + struct.pack("!HH", TYPE_SOA, CLASS_IN)
    rdata = socket.inet_aton(address)
    rr = wire_name(name) + struct.pack("!HHIH", TYPE_A, CLASS_IN, 60, len(rdata)) + rdata
    return header + zone + rr


def result(answer, ctx, key_name, request_mac):
    tsig = tsig_of(answer)
    verified = verify_answer(answer, ctx, key_name, request_mac)
    return (
        f"rcode={answer[3] & 0x0F} tsig_error={'none' if tsig is None else tsig[3]} "
        f"verified={'none' if verified is None else int(verified)}"
    )


def key_name_of():
    return f"lab-{os.urandom(4).hex()}.{ZONE}"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("negotiate")
    update = sub.add_parser("update")
    update.add_argument("name")
    update.add_argument("address")
    update.add_argument("--tcp", action="store_true")
    update.add_argument("--skew", type=int, default=0)
    update.add_argument("--twice", action="store_true")
    update.add_argument("--key-name")
    update.add_argument("--wait", type=int, default=0)
    sub.add_parser("ntlm")
    args = parser.parse_args()

    if args.command == "ntlm":
        answer = exchange_tcp(tkey_query(key_name_of(), NTLM_ONLY))
        tkey = tkey_of(answer)
        print(f"rcode={answer[3] & 0x0F} tkey_error={'none' if tkey is None else tkey[0]}")
        return 0

    key_name = key_name_of()
    try:
        ctx, legs, mutual, verified = negotiate(key_name)
    except (RuntimeError, gssapi.exceptions.GSSError, OSError) as error:
        print(f"established=0 error={str(error).replace(' ', '_')}")
        return 1
    if args.command == "negotiate":
        print(f"established=1 legs={legs} mutual={int(mutual)} verified={int(bool(verified))}")
        return 0
    if args.wait:
        time.sleep(args.wait)
    signing_name = args.key_name or key_name
    message = update_message(args.name, args.address)
    signed, mac = sign(message, ctx, signing_name, int(time.time()) + args.skew)
    exchange = exchange_tcp if args.tcp else exchange_udp
    lines = [result(exchange(signed), ctx, signing_name, mac)]
    if args.twice:
        lines.append(result(exchange(signed), ctx, signing_name, mac))
    print(" | ".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
