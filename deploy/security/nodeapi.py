#!/usr/bin/env python3
"""The security round's client of the node's API (deploy/security/README.md).

Python standard library only. It completes first-run setup with a fresh administrator
(and, where the profile requires a second factor for administrators, enrols an
authenticator and signs in again with it), then sends the few requests the rows need with
the session it keeps in a state file.

    nodeapi.py --state S --url https://tenko.example.test:8443 --connect 127.0.0.1 \
        --ca ca-root.pem setup --token-file F --profile standard
    nodeapi.py --state S get /nodes/enrolments
    nodeapi.py --state S post /nodes/enrolments '{"roles": ["probe"]}'
    nodeapi.py --state S delete /nodes/enrolments/<id>

The connection goes to --connect while TLS and the Origin name the host of --url, so the
certificate is checked for the configured host name. The state file holds the session
cookie, the administrator's password and the authenticator's seed of this run: it is
written with mode 0600 and never belongs in the evidence bundle. Exit status: 0 for a 2xx
answer, 1 for another answer (the status and the body on standard error), 2 for usage.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import uuid

API = "/api/v1"


class Node(http.client.HTTPSConnection):
    """An HTTPS connection to `connect` that speaks TLS and HTTP for `host`."""

    def __init__(self, host, port, connect, context, timeout=30):
        super().__init__(host, port, context=context, timeout=timeout)
        self._connect_to = connect
        self._ctx = context

    def connect(self):
        raw = socket.create_connection((self._connect_to, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(raw, server_hostname=self.host)


def load_state(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(path, state):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f)


def totp_code(secret_b32, params, at=None):
    """RFC 6238 with the enrolment's parameters."""
    secret = base64.b32decode(secret_b32.strip().upper() + "=" * (-len(secret_b32.strip()) % 8))
    period = int(params.get("period", 30))
    digits = int(params.get("digits", 6))
    digest = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha512": hashlib.sha512}[
        params.get("algorithm", "sha1")
    ]
    step = int((time.time() if at is None else at) // period)
    mac = hmac.new(secret, struct.pack(">Q", step), digest).digest()
    offset = mac[-1] & 0x0F
    value = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits), step


class Client:
    def __init__(self, state_path):
        self.state_path = state_path
        self.state = load_state(state_path)

    def configure(self, url, connect, ca):
        if url:
            self.state["url"] = url
        if connect:
            self.state["connect"] = connect
        if ca:
            self.state["ca"] = os.path.abspath(ca)
        for key in ("url", "connect", "ca"):
            if key not in self.state:
                sys.exit(f"nodeapi: --{key} is needed once (it is kept in the state file)")
        self.save()

    def save(self):
        save_state(self.state_path, self.state)

    def request(self, method, path, body=None, keyed=True):
        url = urllib.parse.urlsplit(self.state["url"])
        ctx = ssl.create_default_context(cafile=self.state["ca"])
        conn = Node(url.hostname, url.port or 443, self.state["connect"], ctx)
        origin = f"{url.scheme}://{url.netloc}"
        headers = {"Origin": origin, "Accept": "application/json"}
        if keyed and method != "GET":
            headers["Idempotency-Key"] = str(uuid.uuid4())
        if method in ("DELETE", "PATCH", "PUT"):
            headers.setdefault("If-Match", "*")
        if self.state.get("cookie"):
            headers["Cookie"] = self.state["cookie"]
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, API + path, body=data, headers=headers)
        reply = conn.getresponse()
        raw = reply.read()
        for name, value in reply.getheaders():
            if name.lower() == "set-cookie" and value.startswith("tenko_session="):
                pair = value.split(";", 1)[0]
                self.state["cookie"] = pair if pair != "tenko_session=" else None
        conn.close()
        try:
            doc = json.loads(raw) if raw else None
        except ValueError:
            doc = raw.decode(errors="replace")
        return reply.status, doc

    def checked(self, method, path, body=None, keyed=True):
        status, doc = self.request(method, path, body, keyed)
        if not 200 <= status < 300:
            sys.stderr.write(f"nodeapi: {method} {path}: HTTP {status}: {json.dumps(doc)[:600]}\n")
            sys.exit(1)
        return doc

    def totp(self):
        """A code of a step not used yet (the server refuses a replayed step)."""
        while True:
            code, step = totp_code(self.state["totp_secret"], self.state["totp_params"])
            if step > self.state.get("totp_last_step", -1):
                self.state["totp_last_step"] = step
                self.save()
                return code
            time.sleep(1)

    def login(self):
        first = self.checked(
            "POST",
            "/auth/login/password",
            {"user_name": self.state["admin"], "password": self.state["password"]},
            keyed=False,
        )
        if first.get("status") == "authenticated":
            self.save()
            return first["session"]
        done = self.checked(
            "POST",
            "/auth/login/totp",
            {"challenge_id": first["challenge_id"], "code": self.totp()},
            keyed=False,
        )
        self.save()
        return done["session"]

    def setup(self, token, profile, admin, host_name):
        # The Standard preset asks for at least 12 characters, the Hardened one for 16; a
        # random password of 32 characters meets both (and the Lab and Home PIN presets do
        # not apply to the profiles this round uses).
        self.state.update({"admin": admin, "password": secrets.token_urlsafe(24), "cookie": None})
        self.save()
        session = self.checked(
            "POST",
            "/setup",
            {
                "setup_token": token,
                "profile": profile,
                "admin": {"name": admin, "display_name": "Security round", "password": self.state["password"]},
                "host_name": host_name,
                "language": "en",
            },
            keyed=False,
        )
        self.save()
        if session.get("flags", {}).get("mfa_enrolment_required"):
            start = self.checked("POST", "/auth/totp/enroll/start", {}, keyed=False)
            self.state["totp_secret"] = start["secret"]
            self.state["totp_params"] = start.get("params", {})
            self.save()
            self.checked(
                "POST",
                "/auth/totp/enroll/finish",
                {"enrolment_id": start["enrolment_id"], "code": self.totp()},
                keyed=False,
            )
            self.checked("POST", "/auth/logout", {}, keyed=False)
            self.state["cookie"] = None
            session = self.login()
        return {
            "profile": session.get("profile"),
            "strength": session.get("strength"),
            "required_strength": session.get("required_strength"),
        }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--state", required=True)
    ap.add_argument("--url")
    ap.add_argument("--connect")
    ap.add_argument("--ca")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup")
    s.add_argument("--token-file", required=True)
    s.add_argument("--profile", default="standard")
    s.add_argument("--admin", default="secround")
    s.add_argument("--host-name", default="tenko.example.test")
    sub.add_parser("login")
    for name in ("get", "delete"):
        p = sub.add_parser(name)
        p.add_argument("path")
    for name in ("post", "put", "patch"):
        p = sub.add_parser(name)
        p.add_argument("path")
        p.add_argument("body")
    args = ap.parse_args()

    client = Client(args.state)
    client.configure(args.url, args.connect, args.ca)
    if args.cmd == "setup":
        with open(args.token_file, encoding="utf-8") as f:
            token = f.read().strip()
        print(json.dumps(client.setup(token, args.profile, args.admin, args.host_name)))
    elif args.cmd == "login":
        client.login()
    else:
        body = json.loads(args.body) if hasattr(args, "body") else None
        doc = client.checked(args.cmd.upper(), args.path, body)
        if doc is not None:
            print(json.dumps(doc))


if __name__ == "__main__":
    main()
