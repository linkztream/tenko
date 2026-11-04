#!/usr/bin/env python3
"""The security round's client of the node's API (deploy/security/README.md).

Python standard library only. It completes first-run setup with a fresh administrator
(and, where the profile requires a second factor for administrators, enrolls an
authenticator and signs in again with it), then sends the few requests the rows need with
the session it keeps in a state file.

    nodeapi.py --state S --url https://tenko.example.test:8443 --connect 127.0.0.1 \
        --ca ca-root.pem setup --token-file F --profile standard
    nodeapi.py --state S get /nodes/enrollments
    nodeapi.py --state S post /nodes/enrollments '{"roles": ["probe"]}'
    nodeapi.py --state S delete /nodes/enrollments/<id>
    nodeapi.py --state S unauth --public rules/public-operations.txt --out unauth.jsonl         --findings unauth-findings.json --document-out openapi.served.json
    nodeapi.py --state S scan-access --dir DIR
    nodeapi.py --state S scan-revoke --dir DIR

The connection goes to --connect while TLS and the Origin name the host of --url, so the
certificate is checked for the configured host name. The state file holds the session
cookie, the administrator's password and the authenticator's seed of this run: it is
written with mode 0600 and never belongs in the evidence bundle. Exit status: 0 for a 2xx
answer, 1 for another answer (the status and the body on standard error), 2 for usage.

The web rows (deploy/security/web.sh) use three more commands:

- `unauth` walks every operation of the OpenAPI document the node serves and sends each one
  that the public list does not name (and each `setup-only` entry, since setup is complete)
  without a session or a token; it passes when every such operation answers 401 or 403, or
  is not served because its module is off, and the operations the document declares public
  are exactly the list.
- `scan-access` creates what the scanners use: an account with the global role `viewer`
  and a session of it (for the web interface), and a scoped token of the administrator with
  one grant of the role `viewer` (for the API), the narrowest roles that read the
  inventory (ADR 0015). The secrets go into files of mode 0600 in DIR, which is the round's
  private work directory and never the bundle; the identifiers go to standard output.
- `scan-revoke` revokes the token, ends the session, deletes the account and the secret
  files, and checks that the token is refused afterwards.
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

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

# A path parameter that names an object gets an identifier no object has; a resource that
# exists is not needed, since an operation must refuse an unauthenticated caller before it
# looks anything up.
PLACEHOLDER_UUID = "00000000-0000-4000-8000-000000000000"

# The answers of the router itself for an operation that is not mounted: the routes of a
# module the node was installed without (deploy/security/install-node.sh: ipam and dns) are
# absent, while the document the node serves lists every module's operations.
NOT_SERVED = {(404, "sys.route_not_found"), (405, "sys.method_not_allowed")}

# Requests per second of the walk: below the per-address limit of the API (20 per second,
# a burst of 100), so the walk measures authentication and not the rate limiter.
UNAUTH_RATE = 15


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
    """RFC 6238 with the enrollment's parameters."""
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

    def send(self, method, full_path, headers, data=None, timeout=30, max_body=None):
        """One request to `full_path` (with its /api/v1 prefix). Returns the reply and its
        body; with `max_body`, the body is read only when its declared length is at most
        that many bytes (an event stream or a large answer is never waited for)."""
        url = urllib.parse.urlsplit(self.state["url"])
        ctx = ssl.create_default_context(cafile=self.state["ca"])
        conn = Node(url.hostname, url.port or 443, self.state["connect"], ctx, timeout=timeout)
        try:
            conn.request(method, full_path, body=data, headers=headers)
            reply = conn.getresponse()
            if max_body is None:
                raw = reply.read()
            else:
                length = reply.getheader("Content-Length")
                raw = reply.read() if length and length.isdigit() and int(length) <= max_body else b""
            return reply, raw
        finally:
            conn.close()

    def request(self, method, path, body=None, keyed=True):
        url = urllib.parse.urlsplit(self.state["url"])
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
        reply, raw = self.send(method, API + path, headers, data)
        for name, value in reply.getheaders():
            if name.lower() == "set-cookie" and value.startswith("tenko_session="):
                pair = value.split(";", 1)[0]
                self.state["cookie"] = pair if pair != "tenko_session=" else None
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
        if session.get("flags", {}).get("mfa_enrollment_required"):
            start = self.checked("POST", "/auth/totp/enroll/start", {}, keyed=False)
            self.state["totp_secret"] = start["secret"]
            self.state["totp_params"] = start.get("params", {})
            self.save()
            self.checked(
                "POST",
                "/auth/totp/enroll/finish",
                {"enrollment_id": start["enrollment_id"], "code": self.totp()},
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

    # ── The web rows ─────────────────────────────────────────────────────────────────────

    def admin_call(self, method, path, body=None, keyed=True):
        """A request of the administrator that signs in again once when the session has
        ended or is not recent enough for the operation (auth.step_up_required)."""
        status, doc = self.request(method, path, body, keyed)
        code = doc.get("code") if isinstance(doc, dict) else None
        if status == 401 or (status == 403 and code == "auth.step_up_required"):
            self.login()
            status, doc = self.request(method, path, body, keyed)
        return status, doc

    def scan_access(self, out_dir, user_name):
        # A fresh sign-in first: creating an account and a token asks for a recent one.
        self.login()
        password = secrets.token_urlsafe(24)
        status, user = self.admin_call(
            "POST",
            "/users",
            {"name": user_name, "display_name": "Security round scan", "roles": ["viewer"], "password": password},
        )
        if status != 201:
            fail(f"POST /users: HTTP {status}: {json.dumps(user)[:600]}")
        access = {"user_id": user["id"], "user_name": user_name}
        write_private(os.path.join(out_dir, "access.json"), json.dumps(access))

        # The token: a scoped token of the administrator with one grant of the role viewer,
        # so it acts with the intersection of that grant and the administrator's roles
        # (IAM-10): reads, never a change. One day is the shortest lifetime the API takes.
        status, created = self.admin_call(
            "POST",
            "/auth/tokens",
            {"name": "security-round-scan", "grants": [{"role": "viewer"}], "expires_in_days": 1},
            keyed=False,
        )
        if status != 201:
            fail(f"POST /auth/tokens: HTTP {status}: {json.dumps(created)[:600]}")
        access["token_id"] = created["info"]["id"]
        write_private(os.path.join(out_dir, "token"), created["token"])
        write_private(os.path.join(out_dir, "access.json"), json.dumps(access))

        # The session: the viewer account signs in with its own state file. The initial
        # password must be changed at the first sign-in; the Standard profile asks a second
        # factor of administrators only (TGL-02), so a viewer signs in with the password.
        viewer = Client(os.path.join(out_dir, "viewer-state.json"))
        viewer.state.update({key: self.state[key] for key in ("url", "connect", "ca")})
        viewer.state.update({"admin": user_name, "password": password, "cookie": None})
        viewer.save()
        first = viewer.checked(
            "POST", "/auth/login/password", {"user_name": user_name, "password": password}, keyed=False
        )
        if first.get("status") != "authenticated":
            fail("the viewer account was asked for a second factor; the scan session needs a password sign-in")
        session = first["session"]
        if session.get("flags", {}).get("password_change_required"):
            new_password = secrets.token_urlsafe(24)
            viewer.checked(
                "POST",
                "/auth/password",
                {"current_password": password, "new_password": new_password},
                keyed=False,
            )
            viewer.state["password"] = new_password
            viewer.save()
            session = viewer.checked("GET", "/auth/session")
        if not viewer.state.get("cookie"):
            fail("the viewer's sign-in set no session cookie")
        access["session_id"] = session.get("session_id")
        write_private(os.path.join(out_dir, "cookie"), viewer.state["cookie"])
        write_private(os.path.join(out_dir, "access.json"), json.dumps(access))
        return {
            "user_id": access["user_id"],
            "token_id": access["token_id"],
            "session_id": access["session_id"],
            "session_roles": session.get("roles"),
        }

    def scan_revoke(self, out_dir):
        """Revoke what scan_access created. Every step is tried; the result names each."""
        result = {}
        try:
            with open(os.path.join(out_dir, "access.json"), encoding="utf-8") as f:
                access = json.load(f)
        except FileNotFoundError:
            return {"nothing_to_revoke": True}
        token = None
        try:
            with open(os.path.join(out_dir, "token"), encoding="utf-8") as f:
                token = f.read().strip()
        except FileNotFoundError:
            pass
        if access.get("token_id"):
            status, _ = self.admin_call("DELETE", f"/auth/tokens/{access['token_id']}")
            result["token_revoked"] = status in (204, 404)
        viewer_state = os.path.join(out_dir, "viewer-state.json")
        if os.path.exists(viewer_state):
            viewer = Client(viewer_state)
            if viewer.state.get("cookie"):
                status, _ = viewer.request("POST", "/auth/logout", {}, keyed=False)
                result["session_ended"] = status in (204, 401)
        if access.get("user_id"):
            status, _ = self.admin_call("DELETE", f"/users/{access['user_id']}")
            result["account_deleted"] = status in (204, 404)
        # The proof: the token is refused now.
        if token:
            reply, _ = self.send(
                "GET", API + "/auth/session", {"Accept": "application/json", "Authorization": f"Bearer {token}"}
            )
            result["token_refused_after"] = reply.status == 401
        for name in ("token", "cookie", "viewer-state.json", "access.json"):
            try:
                os.remove(os.path.join(out_dir, name))
            except FileNotFoundError:
                pass
        return result

    def unauth(self, public_path, out_path, findings_path, document_out, fallback):
        """The walk of web.unauth. Returns True when it passes."""
        public = load_public(public_path)
        reply, raw = self.send("GET", API + "/openapi.json", {"Accept": "application/json"})
        source = "served by the node"
        if reply.status == 200:
            doc = json.loads(raw)
            with open(document_out, "wb") as f:
                f.write(raw)
        elif fallback:
            print(f"the node did not serve its OpenAPI document (HTTP {reply.status}); walking {fallback}")
            with open(fallback, encoding="utf-8") as f:
                doc = json.load(f)
            source = fallback
        else:
            fail(f"GET /openapi.json: HTTP {reply.status}")

        default_security = doc.get("security", [])
        operations = []
        for path, item in sorted(doc.get("paths", {}).items()):
            shared = item.get("parameters", [])
            for method in HTTP_METHODS:
                op = item.get(method)
                if op is None:
                    continue
                security = op.get("security", default_security)
                declared_public = not security or any(not requirement for requirement in security)
                operations.append((method.upper(), path, op, shared, declared_public))

        findings, problems = [], []
        in_document = {(method, path) for method, path, *_ in operations}
        declared = {(method, path) for method, path, _, _, is_public in operations if is_public}
        for key in sorted(declared - set(public)):
            problems.append(f"declared public by the document but not in the list: {key[0]} {key[1]}")
            findings.append(
                unauth_finding("not-listed", key, "the document declares the operation public; the public list does not name it")
            )
        for key in sorted(set(public) - declared):
            if not key[1].startswith(API + "/"):
                continue  # served outside the API (the web interface's files): not an operation
            if key in in_document:
                problems.append(f"in the list but the document requires authentication: {key[0]} {key[1]}")
                findings.append(
                    unauth_finding("stale-entry", key, "the public list names an operation the document secures, so the walk skips it")
                )
            else:
                problems.append(f"in the list but not an operation of the document: {key[0]} {key[1]}")
                findings.append(unauth_finding("stale-entry", key, "the public list names an operation the document does not have"))

        # A `setup-only` entry is public while first-run setup is open; the round tests a node
        # after setup, so the walk sends it as well and expects a refusal.
        counts = {"refused": 0, "not served": 0, "answered": 0, "public": 0}
        with open(out_path, "w", encoding="utf-8") as out:
            for method, path, op, shared, _ in operations:
                if (method, path) in public and "setup-only" not in public[(method, path)]:
                    counts["public"] += 1
                    continue
                target, headers, data = unauth_request(doc, method, path, op, shared)
                status, code = None, None
                for _attempt in range(6):
                    time.sleep(1 / UNAUTH_RATE)
                    try:
                        reply, raw = self.send(method, target, dict(headers), data, timeout=10, max_body=65536)
                    except (OSError, http.client.HTTPException) as error:
                        status, code = None, f"no answer: {error.__class__.__name__}"
                        break
                    status = reply.status
                    try:
                        code = json.loads(raw).get("code") if raw else None
                    except (ValueError, AttributeError):
                        code = None
                    if status != 429:
                        break
                    retry = reply.getheader("Retry-After", "1") or "1"
                    time.sleep(min(max(int(retry) if retry.isdigit() else 1, 1), 30))
                if status in (401, 403):
                    verdict = "refused"
                elif (status, code) in NOT_SERVED:
                    verdict = "not served"
                else:
                    verdict = "answered"
                    shown = status if status is not None else code
                    problems.append(f"{method} {path} answered {shown} ({code or 'no code'}) without credentials")
                    findings.append(unauth_finding("answers", (method, path), f"answers {shown} without a session or a token"))
                counts[verdict] += 1
                record = {"method": method, "path": path, "request": target, "status": status, "code": code, "verdict": verdict}
                out.write(json.dumps(record) + "\n")

        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=1)
        print(
            f"document {source}: {len(operations)} operations; {counts['public']} public by the list, "
            f"{counts['refused']} refused with 401 or 403, {counts['not served']} not served (a module the node "
            f"was installed without), {counts['answered']} answered"
        )
        for problem in problems:
            print(f"FAIL {problem}")
        return not problems


def fail(message):
    sys.stderr.write(f"nodeapi: {message}\n")
    sys.exit(1)


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def load_public(path):
    """The public list: `METHOD /path [setup-only]` per line, the path as the document writes
    it; text after '#' is a comment (the reason of the entry). Returns a map from (method,
    path) to the entry's flags."""
    entries = {}
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            text = line.split("#", 1)[0].strip()
            if not text:
                continue
            parts = text.split()
            flags = set(parts[2:])
            if (
                len(parts) < 2
                or parts[0].lower() not in HTTP_METHODS
                or not parts[1].startswith("/")
                or not flags <= {"setup-only"}
            ):
                sys.stderr.write(f"nodeapi: {path}:{number}: expected `METHOD /path [setup-only]`, got {text!r}\n")
                sys.exit(2)
            entries[(parts[0].upper(), parts[1])] = flags
    return entries


def unauth_finding(rule, key, title):
    return {
        "tool": "unauth",
        "rule": rule,
        "location": f"{key[0]} {key[1]}",
        "severity": "High",
        "title": f"{key[0]} {key[1]}: {title}",
    }


def resolve(doc, schema):
    """Follow the local `$ref`s of a schema or a parameter."""
    for _ in range(10):
        if not isinstance(schema, dict) or not str(schema.get("$ref", "")).startswith("#/"):
            break
        node = doc
        for part in schema["$ref"][2:].split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        schema = node
    return schema if isinstance(schema, dict) else {}


def placeholder(doc, param):
    """A value of the parameter's type that names nothing."""
    schema = resolve(doc, param.get("schema", {}))
    if schema.get("enum"):
        return str(schema["enum"][0])
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), None)
    name = param.get("name", "")
    if kind in ("integer", "number"):
        return "1"
    if kind == "boolean":
        return "false"
    if schema.get("format") == "uuid" or name in ("id", "token") or name.endswith("_id"):
        return PLACEHOLDER_UUID
    if name == "addr":
        return "192.0.2.1"
    return "placeholder"


def unauth_request(doc, method, path, op, shared):
    """The request of one operation without credentials: the path parameters and the
    required query parameters filled with placeholders, a body of the declared media type."""
    params = {}
    for param in [resolve(doc, p) for p in shared] + [resolve(doc, p) for p in op.get("parameters", [])]:
        params[(param.get("in"), param.get("name"))] = param
    target = path
    for (where, name), param in params.items():
        if where == "path":
            target = target.replace("{" + name + "}", urllib.parse.quote(placeholder(doc, param), safe=""))
    while "{" in target and "}" in target[target.index("{") :]:
        start = target.index("{")
        target = target[:start] + "placeholder" + target[target.index("}", start) + 1 :]
    query = [
        (name, placeholder(doc, param))
        for (where, name), param in params.items()
        if where == "query" and param.get("required")
    ]
    if query:
        target += "?" + urllib.parse.urlencode(query)
    headers = {"Accept": "application/json"}
    data = None
    content = resolve(doc, op.get("requestBody", {})).get("content", {})
    if content:
        if "application/json" in content:
            headers["Content-Type"], data = "application/json", b"{}"
        elif "multipart/form-data" in content:
            headers["Content-Type"] = "multipart/form-data; boundary=tenkosec"
            data = b"--tenkosec--\r\n"
        else:
            headers["Content-Type"], data = next(iter(content)), b""
    return target, headers, data


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
    u = sub.add_parser("unauth")
    u.add_argument("--public", required=True)
    u.add_argument("--out", required=True)
    u.add_argument("--findings", required=True)
    u.add_argument("--document-out", required=True)
    u.add_argument("--fallback")
    for name in ("scan-access", "scan-revoke"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
        if name == "scan-access":
            p.add_argument("--user", default="secround-scan")
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
    elif args.cmd == "unauth":
        ok = client.unauth(args.public, args.out, args.findings, args.document_out, args.fallback)
        sys.exit(0 if ok else 1)
    elif args.cmd == "scan-access":
        print(json.dumps(client.scan_access(args.dir, args.user)))
    elif args.cmd == "scan-revoke":
        result = client.scan_revoke(args.dir)
        print(json.dumps(result))
        if result.get("token_revoked") is False or result.get("token_refused_after") is False:
            sys.exit(1)
    else:
        body = json.loads(args.body) if hasattr(args, "body") else None
        doc = client.checked(args.cmd.upper(), args.path, body)
        if doc is not None:
            print(json.dumps(doc))


if __name__ == "__main__":
    main()
