#!/usr/bin/env python3
"""The DNS-over-the-wire mutator of the security round's row `fuzz.dns_wire`
(deploy/security/README.md). Python standard library only.

It sends mutations of the DNS seeds to one UDP and one TCP port of the node under test at a
bounded rate for a fixed time, while a probe asks a known name once a second. It never
reaches past the node it is given: the target address and the two ports are its arguments
and default to loopback.

    dnswire.py --seeds fuzz/seeds/dns_codec --duration 600 --rate 200 \
        --host 127.0.0.1 --udp 53 --tcp 53 \
        --probe-name probe.security.example.test --probe-type A --probe-expect 192.0.2.53 \
        --report out/dnswire.json

The probe uses the same UDP and TCP ports. A probe that is not answered within one second,
or whose answer is not the expected address, is recorded; the caller (fuzz.sh) decides the
row from the report together with NRestarts and resident memory. Exit status is 0 when every
probe was answered correctly and non-zero when any probe failed, so the row can also key off
the exit status.

The malformed traffic is this program's own mutations of the committed seeds; it carries no
real names or addresses and is sent only to the node under test.
"""

import argparse
import json
import os
import random
import socket
import struct
import sys
import time


def load_seeds(path):
    seeds = []
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            if os.path.isfile(full):
                with open(full, "rb") as f:
                    seeds.append(f.read())
    elif os.path.isfile(path):
        with open(path, "rb") as f:
            seeds.append(f.read())
    # A minimal well-formed query, so the mutator has something even without seeds.
    if not seeds:
        seeds.append(build_query("probe.example.test", 1))
    return seeds


def build_query(name, qtype, txid=0x1234):
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".") if label)
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + q


def mutate(rng, seed):
    data = bytearray(seed)
    if not data:
        data = bytearray(b"\x00")
    choice = rng.randint(0, 4)
    if choice == 0 and data:  # flip some bits
        for _ in range(rng.randint(1, 8)):
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randint(0, 7)
    elif choice == 1:  # truncate
        data = data[: rng.randint(0, len(data))]
    elif choice == 2:  # append junk
        data += bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
    elif choice == 3 and len(data) >= 2:  # overwrite the counts with large values
        data[4:12] = bytes(rng.getrandbits(8) for _ in range(min(8, len(data) - 4)))
    else:  # duplicate
        data += bytes(data[: rng.randint(0, len(data))])
    return bytes(data)


def send_udp(host, port, payload, timeout=0.3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(payload, (host, port))
        try:
            s.recvfrom(4096)
        except socket.timeout:
            pass
    except OSError:
        pass
    finally:
        s.close()


def send_tcp(host, port, payload, timeout=0.3):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return
    try:
        s.settimeout(timeout)
        framed = struct.pack(">H", min(len(payload), 0xFFFF)) + payload
        s.sendall(framed)
        try:
            s.recv(4096)
        except socket.timeout:
            pass
    except OSError:
        pass
    finally:
        s.close()


def probe(host, udp, tcp, name, qtype, expect):
    """Ask over UDP and over TCP, both within one second, and check each answer holds
    `expect`. The row fails when either transport stops answering (a listener that a flood
    of malformed packets or an exhausted descriptor table knocked over), so both must
    succeed. Returns (ok, detail)."""
    query = build_query(name, qtype, txid=random.randint(0, 0xFFFF))
    details = []
    ok = True
    for proto, port in (("udp", udp), ("tcp", tcp)):
        try:
            if proto == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                data = None
                # Two attempts within the one-second budget: a lossy path (and some
                # virtual network stacks) can drop a datagram, and a UDP probe retries.
                for _ in range(2):
                    try:
                        s.sendto(query, (host, port))
                        data, _ = s.recvfrom(4096)
                        break
                    except socket.timeout:
                        continue
                s.close()
                if data is None:
                    raise OSError("timed out")
            else:
                s = socket.create_connection((host, port), timeout=1.0)
                s.settimeout(1.0)
                s.sendall(struct.pack(">H", len(query)) + query)
                length = struct.unpack(">H", recv_exact(s, 2))[0]
                data = recv_exact(s, length)
                s.close()
        except OSError as exc:
            ok = False
            details.append(f"{proto}: {exc}")
            continue
        if expect is None:
            details.append(f"{proto}: answered")
        elif expect.encode() in data or contains_a(data, expect):
            details.append(f"{proto}: {expect}")
        else:
            ok = False
            details.append(f"{proto}: answer did not hold {expect}")
    return ok, "; ".join(details)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def contains_a(data, address):
    try:
        octets = bytes(int(x) for x in address.split("."))
    except ValueError:
        return False
    return octets in data


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seeds", required=True)
    ap.add_argument("--duration", type=float, default=600)
    ap.add_argument("--rate", type=float, default=200, help="datagrams per second, both transports")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--udp", type=int, default=53)
    ap.add_argument("--tcp", type=int, default=53)
    ap.add_argument("--probe-name", default="probe.security.example.test")
    ap.add_argument("--probe-type", type=int, default=1)
    ap.add_argument("--probe-expect", default=None)
    ap.add_argument("--report", required=True)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    seeds = load_seeds(args.seeds)
    interval = 1.0 / args.rate if args.rate > 0 else 0
    end = time.time() + args.duration
    next_probe = time.time()
    sent = 0
    probes_ok = 0
    probes_failed = []

    while time.time() < end:
        payload = mutate(rng, rng.choice(seeds))
        if rng.random() < 0.5:
            send_udp(args.host, args.udp, payload)
        else:
            send_tcp(args.host, args.tcp, payload)
        sent += 1
        now = time.time()
        if now >= next_probe:
            ok, detail = probe(args.host, args.udp, args.tcp, args.probe_name, args.probe_type, args.probe_expect)
            if ok:
                probes_ok += 1
            else:
                probes_failed.append({"at": round(now, 3), "detail": detail})
            next_probe = now + 1.0
        if interval:
            time.sleep(interval)

    report = {
        "sent": sent,
        "probes_ok": probes_ok,
        "probes_failed": probes_failed,
        "duration": args.duration,
        "rate": args.rate,
        "target": {"host": args.host, "udp": args.udp, "tcp": args.tcp},
    }
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(report, f)
    print(json.dumps({k: report[k] for k in ("sent", "probes_ok")} | {"probes_failed": len(probes_failed)}))
    sys.exit(1 if probes_failed else 0)


if __name__ == "__main__":
    main()
