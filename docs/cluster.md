# Cluster: nodes, enrolment and the node transport

This page describes how Tenko DDI connects its data-plane nodes to its controllers: how an administrator enrols a node with a single-use token, which certificates the internal CA issues and how they renew, how a node is revoked, the gRPC protocol the two sides speak and how its version is negotiated, how heartbeats show the health of a node, how the observations of a probe travel through a disk buffer that survives outages, and which ports and settings an installation needs. It also describes how several controllers form one cluster that replicates the store. It is for an administrator who adds a probe to a site or a controller to an installation, and for a developer who works on the transport. It describes the behaviour of the `tenko-cluster` crate, of `tenko node`, `tenko cluster` and the node process of `tenko serve` in the `tenko` crate, of the Raft store in `tenko-store`, and of the `/nodes` and `/cluster` routes in `tenko-api`; where this page and the code differ, the code is right. The requirements are OPS-03, OPS-04, OPS-08 and OPS-28 in [REQUIREMENTS.md](REQUIREMENTS.md). The messages are defined in the `.proto` files in [`crates/tenko-cluster/proto/tenko/cluster/v1/`](../crates/tenko-cluster/proto/tenko/cluster/v1/), package `tenko.cluster.v1`; their comments are part of the contract.

Controllers run the API, the web UI and the store. Data-plane nodes run `probe` today and `dns` and `dhcp` later. Controllers and nodes talk gRPC over mutual TLS on the cluster port (OPS-04), with certificates from the internal CA of the installation. The mechanism is the same for native, Docker and LXC installations. mTLS is structural: no security profile turns it off, and the transport speaks TLS 1.3 only. Nodes negotiate the protocol version with the controller (OPS-08) and keep working across controller outages (OPS-28): a probe keeps its observations on disk and sends them when a controller is back. Slice 2 (WP2.2) brought the traffic from nodes to controllers: the handshake, heartbeats, certificate renewal and probe observations. Slice 3 (WP3.1a) adds the traffic between controllers on the same port: Raft, joining, forwarded writes and the transfer of the key encryption keys (section 12). Section 13 lists what comes next.

Terms used below: a **controller** is an installation that runs the `controller` role. A **node** is an enrolled data-plane installation with the roles `probe`, `dns` or `dhcp`. The **cluster port** is the TCP port on which controllers accept nodes and each other (8444 by default). The **internal CA** is the certificate authority of the installation; its key lives in the vault of the controllers. An **enrolment token** is a single-use, time-limited secret that lets one node obtain its first certificate.

Contents:

1. [Enrolment](#1-enrolment)
2. [Certificates and renewal](#2-certificates-and-renewal)
3. [Revocation](#3-revocation)
4. [The protocol and its versioning rule](#4-the-protocol-and-its-versioning-rule)
5. [Heartbeats and health](#5-heartbeats-and-health)
6. [Observations and the buffer](#6-observations-and-the-buffer)
7. [Ports and firewall](#7-ports-and-firewall)
8. [Configuration](#8-configuration)
9. [API](#9-api)
10. [Audit actions](#10-audit-actions)
11. [Error codes](#11-error-codes)
12. [The controller cluster](#12-the-controller-cluster)
13. [What comes next](#13-what-comes-next)

## 1. Enrolment

Enrolment gives a node its id, its certificate and the CA root it trusts. It needs a token from an administrator and runs once per node.

### 1.1 Creating a token

An administrator creates a token with `POST /api/v1/nodes/enrolments`, or with the command below, which uses the credentials of `tenko login`:

```
tenko node enrol-token --roles probe --name probe-dmz --expires-in 3600
```

```json
{"roles": ["probe"], "name": "probe-dmz", "vrf": "<vrf id>", "expires_in_secs": 3600}
```

Every field is optional. The command line flags are `--roles` (comma-separated), `--name`, `--vrf` and `--expires-in`.

| Field | Meaning | Default |
|---|---|---|
| `roles` | The roles the node may take: `probe`, `dns`, `dhcp`; or `controller` alone, for a controller that joins the cluster (section 12.1; beside another role 422 `cluster.enrolment.roles`). Only an administrator who signed in within the last five minutes creates a controller token (403 `auth.step_up_required`; a personal API token cannot) | `["probe"]` |
| `name` | The name the node gets. It must be unique among nodes and has 1 to 63 letters, digits, dots, hyphens and underscores, starting with a letter or digit | The node chooses one, its host name |
| `vrf` | The VRF, by id, of the node's observations when a batch names none (section 6) | The default VRF |
| `expires_in_secs` | Seconds until the token expires, 60 to 604,800 (seven days); at most 3,600 for a controller token | 3,600, or `[cluster] enrolment_ttl_secs` (at most 3,600 for a controller token) |

The answer shows the token once and carries `Cache-Control: no-store`. It holds the stored token record, the SHA-256 fingerprint of the CA root and the command line to run on the node. `tenko node enrol-token` prints the token on standard output and the other lines as notes, so a script can capture the token. The controller keeps only a digest, SHA-256 over a fixed label, the token id and the secret, so a copy of its store reveals no token.

The token text has the form `tnk1.<id>.<secret>`: the prefix `tnk1`, the id of the token record as 32 hexadecimal digits, and the secret as 43 characters of unpadded base64url. Creating a token opens the cluster port when it starts on demand (section 7.2).

`GET /api/v1/nodes/enrolments` lists the tokens, newest first, with the state `pending`, `used` or `expired` and the node a used token enrolled; it never shows the token text. Used and expired tokens stay listed for seven days. `DELETE /api/v1/nodes/enrolments/{id}` withdraws a token, whatever its state.

### 1.2 Enrolling the node

On the node, run the command that the token answer printed:

```
tenko node enrol --controller https://ddi.example.net:8443 --token <token> \
  --ca-fingerprint <sha256> --name probe-dmz --address 192.0.2.20
```

| Option | Meaning |
|---|---|
| `--controller URL` | Required. The URL of the controller as administrators open it. A plain `http://` URL needs `--ca-fingerprint`, because nothing else protects the token |
| `--token`, `--token-file`, `TENKO_ENROL_TOKEN` | The token, or a file whose first line is the token, or the environment variable |
| `--ca-fingerprint` | The SHA-256 of the CA root, hexadecimal, colons allowed. The controller prints it at start (TLS mode a) and shows it with every token |
| `--name` | The node name; the name of the token wins when it has one. Default: the host name |
| `--roles` | The roles the node runs; each must be allowed by the token. Default: the roles of the token |
| `--address` | The address the controller shows for the node. Default: the address the controller sees the request come from |
| `--data-dir`, `--config` | Where the node keeps its files |
| `--force` | Enrols a node that is enrolled already. It replaces the files on the node only; the old node stays registered until an administrator revokes it |

The steps:

1. The command checks the form of the token.
2. It fetches `GET /api/v1/system/ca-root` without trusting the server yet and compares the SHA-256 of the root with `--ca-fingerprint`. Without the option it trusts the root on first use and prints a warning with the fingerprint, which the administrator should compare with the one the controller printed. From then on the API connection trusts only that root. When the API certificate is imported or TLS ends at a reverse proxy, that route answers 404 and the system roots verify the API connection instead; the fingerprint is then checked against the CA root in the answer of step 4.
3. The node generates an ECDSA P-256 key, which never leaves the node, and sends a PKCS#10 certificate request with the token, its name, roles, address, software version and the protocol majors it implements to `POST /api/v1/nodes/enrol`. The route is public: the token is the credential.
4. The controller answers with the node id, the certificate, the CA root, the cluster endpoints and the heartbeat interval. The node checks the root against the fingerprint and against the root of step 2 once more and writes its files (section 1.4). If this last check fails, the node is registered on the controller but not set up on the node; the command says so, and the administrator revokes the node.

Then `tenko serve --roles probe --data-dir <dir>` starts the node process. In Phase 1 only the `probe` role runs without the controller role; a node enrolled for `dns` or `dhcp` is registered, but its process refuses to start until those engines exist. A node needs neither the store nor the vault.

The command exits with status 9 when a fingerprint does not match, 6 when the controller refuses the token (401), 5 for other refusals of the API, 7 when the controller cannot be reached and 2 when the node is enrolled already.

### 1.3 What the controller checks

| Check | Error code |
|---|---|
| The token has the right form, its id exists and its secret matches. A wrong secret and an unknown id give the same answer | `cluster.enrolment.invalid_token` |
| The token is unused | `cluster.enrolment.used` |
| The token has not expired | `cluster.enrolment.expired` |
| Every requested role is allowed by the token | `cluster.enrolment.roles` |
| The node and the controller share a protocol major | `cluster.protocol.unsupported` |
| The node name follows the rule of section 1.1 and no other node has it | `cluster.node.name`, `cluster.node.name_taken` |
| The address is an IP address or a host name | `cluster.node.address` |
| The certificate request is valid, signed with its own key, and over an ECDSA P-256 key | `cluster.ca.invalid_csr` |

Only the key of the request counts. The name, the roles and the validity come from the controller, so a request cannot ask for a certificate it was not granted.

Using the token and creating the node commit in one write, with preconditions on the token record, the id counter and the name. A token therefore works exactly once, even when two nodes race with it: the loser gets `cluster.enrolment.used`, `cluster.node.name_taken` or `cluster.enrolment.conflict`. Node ids start at 1001, grow, and are never reused; a controller keeps the `[node] id` of its configuration. The node record holds the id, name, roles, address, VRF, the newest certificate, the serial and expiry of every unexpired certificate, who enrolled the node and when, the last renewal, `last_seen`, the software version and the protocol state.

Every enrolment, and every refused attempt, is audited as `cluster.node.enrol`. A refusal is a failed record with the error code, the id of the token when it was recognised and the source address; it names no node. A refusal that has no code of its own in the table above, such as a bad name or address, is recorded as `cluster.enrolment.refused`.

### 1.4 Files on the node

The files are in `<data_dir>/node/`.

| File | Contents |
|---|---|
| `identity.json` | Node id, name, roles, the controller URL, the cluster endpoints, the heartbeat interval, the enrolment time and the SHA-256 of the CA root |
| `ca-root.pem` | The CA root that the node trusts on the cluster port |
| `node-cert.pem` | The node certificate, leaf first |
| `node-key.pem` (Unix) or `node-key.dpapi` (Windows) | The private key. On Unix the directory is `0700` and the files are `0600`. On Windows the key is sealed with DPAPI in the machine scope, so a copied data directory does not carry a usable key |
| `status.json` | What the running node process last saw (section 5) |
| `buffer/` | The observation buffer (section 6) |

In a container the data directory must be a volume that survives the container, or the node loses its identity with it.

### 1.5 Example: a probe in the DMZ

The controller is `ddi.example.net`; the probe runs on `probe-dmz.example.net` at `192.0.2.20`. An administrator signs in and creates the token on any machine that reaches the controller:

```
tenko login --url https://ddi.example.net:8443 --user alice
tenko node enrol-token --roles probe --name probe-dmz
```

On the probe, with the token and the fingerprint from the answer, enrol once and start the node process:

```
tenko node enrol --controller https://ddi.example.net:8443 --token <token> \
  --ca-fingerprint <sha256> --address 192.0.2.20 --data-dir /var/lib/tenko
tenko serve --roles probe --data-dir /var/lib/tenko
tenko node status --check --data-dir /var/lib/tenko
```

The firewall lets `192.0.2.20` reach the controller on 8443/TCP for the enrolment and on 8444/TCP from then on (section 7).

## 2. Certificates and renewal

All certificates come from the internal CA, an ECDSA P-256 root with a validity of ten years.

| Certificate | Held by | Lifetime | Contents |
|---|---|---|---|
| CA root | The installation | 10 years | Self-signed. The key is a system secret in the vault |
| Node certificate | Each node | 1 year | The URI subject alternative names `urn:tenko:node:<id>` and `urn:tenko:role:<role>`, one per role; server and client authentication |
| Cluster port certificate | Each controller | 1 year | The same form, with the role `controller` |

Host names play no part. A node accepts a server only when its certificate chains to the CA root of its enrolment and carries the role `controller`; the controller accepts a client only when its certificate chains to the same root, names a node and is not revoked. A controller of another installation is refused (`cluster.tls.foreign_ca`).

A controller keeps its certificate for the cluster port and its key in the vault. It checks them daily and issues new ones 30 days before expiry (audit action `cluster.node.controller_cert`); the cluster port uses the new certificate for the next connection. A controller in a cluster of controllers keeps its certificate and key under `<data_dir>/node/` instead, like a node (section 12.1). It checks them every six hours, renews them by the rule of a node below and presents the new pair to nodes and peers.

A node renews its certificate over the mutual TLS channel (`Node.Renew`). It generates a new key and sends a certificate request; the controller issues a certificate with the same node id and roles. The renewal is due when less than a third of the lifetime or fewer than 30 days remain, which for a one-year certificate is about 122 days before expiry. The node checks this with every heartbeat and tries again hourly while a renewal fails; the controller also asks for one in the answer to a heartbeat once fewer than 30 days remain. `tenko node renew` renews at once, also beside a running node process, which loads the new pair for its next connection.

The old certificate stays valid until it expires. Both serials are in the node record, and both are revoked with the node (section 3). The node swaps its files with `.new` and `.old` copies of the certificate and the key, so a crash never leaves a broken pair: when the current pair does not load, the node falls back to the `.old` pair. The renewal is audited as `cluster.node.renew`.

## 3. Revocation

`DELETE /api/v1/nodes/{id}` (administrators) revokes a node. The controller removes the node record and its name, and puts every unexpired certificate serial of the node on the revocation list, the table `cluster.revocations`. The TLS verifier of the cluster port checks that list at every handshake; a revoked certificate fails it with the alert `certificate_revoked`. The heartbeat stream of the node gets a directive that says it was revoked, and its connections close about 0.3 s later. The node then reports the state `revoked` (`cluster.node.revoked`) and tries again every five minutes, which fails the same way. The node's own bookkeeping (`last_seen` on connect, on disconnect and every five minutes, and the agreed protocol) writes the same record, so a revocation or a renewal can find it changed between reading and writing it; the controller then reads the record again and plans the change anew, up to three times, so a heartbeat never makes an administrator see `cluster.node.conflict`.

A revoked node does not come back by itself. It needs a new token and gets a new id; its name becomes free again. An entry leaves the revocation list after the expiry of its certificate, when the hourly maintenance pass finds it. The revocation is audited as `cluster.node.revoke`.

A controller reads the revocation list from the store at start, every hour and whenever the table changes. In a cluster of controllers the list replicates with the store, so a revocation made on one controller takes effect on every other within a moment (section 12.6).

## 4. The protocol and its versioning rule

The protocol is the package `tenko.cluster.v1`. Like the plugin protocol of [plugins.md](plugins.md) it is compiled at build time from the `.proto` files, without `protoc`. Every call needs a client certificate of an enrolled node that still holds that certificate (`cluster.node.unknown`, `cluster.node.certificate_unknown`). A refused call carries the metadata entry `tenko-error-code` with a stable code.

| Service | Method | Purpose |
|---|---|---|
| `Handshake` | `Hello` | Agrees on the protocol major. Frozen across majors |
| `Node` | `Heartbeat` | A bidirectional stream: a beat from the node, a directive from the controller for every beat, and directives the controller pushes (a revocation) |
| `Node` | `Renew` | Issues a new certificate for the key of a certificate request |
| `Observations` | `Ingest` | Hands one batch of the buffer of a probe to the reconciler. Needs the role `probe` (`cluster.node.role`) |
| `Raft`, `Cluster` | | Between controllers only; section 12.5 |

### 4.1 Version negotiation (OPS-08)

The node offers every major it implements in `Hello`, with its software version and its roles. The controller answers with the highest major both sides implement, together with its own majors, its version, the node id it knows the certificate by, the heartbeat interval, its clock and the cluster ports of every controller of the cluster (`endpoints`, its own first). When the sides share no major, the controller refuses with gRPC `FAILED_PRECONDITION`, the metadata entry `tenko-error-code: cluster.protocol.unsupported` and the entry `tenko-majors` with its own majors, for example `1, 2`. `Hello` and its two messages are frozen: every later major serves them unchanged, so two nodes of different majors can always find out what they share. Enrolment applies the same rule before it issues a certificate (section 1.3).

The controller records a refusal on the node (`protocol.mismatch` in the node record: the majors on both sides, the time and the version of the node), audits it as `cluster.node.version_mismatch` at most once an hour per node and offer, and `GET /api/v1/system/status` shows a `cluster.protocol.mismatch` warning until the node connects with a common major. The node reports the state `protocol_mismatch` and retries every five minutes.

### 4.2 Evolution and rolling upgrades

Within a major every change is additive. New fields take new numbers; no field, enum value or method is removed, renamed or renumbered; both sides ignore fields they do not know. A breaking change is a new package, `tenko.cluster.v2`, and a new major in the handshake.

Upgrade controllers first. A controller that introduces a new major keeps the previous one for one release, so nodes that are not upgraded yet can follow; the release after that drops it.

| Controller majors | Node majors | Outcome |
|---|---|---|
| 1 | 1 | Major 1 |
| 1, 2 | 1 | Major 1: the controller was upgraded first and still speaks the old major |
| 1, 2 | 1, 2 | Major 2 |
| 2 | 1 | Refused: upgrade the node |
| 1 | 2 | Refused: upgrade the controller |

Today only major 1 exists.

## 5. Heartbeats and health

The node sends a beat every `heartbeat_secs` seconds (default 10). The controller names the interval in the handshake, so a change of `[cluster] heartbeat_secs` takes effect at the next connection of each node. A beat carries the software version, the roles, the agreed major, the number and size of the batches in the buffer, the batches dropped since the process started, the expiry of the certificate and the node's clock. The controller answers every beat with a directive that asks for a renewal when one is due. HTTP/2 keepalive pings in both directions close a dead connection after about 40 s. A node that sees a controller clock more than five minutes away logs a warning.

A node counts as connected while its heartbeat stream is open. The controller holds this in memory, and writes `last_seen` to the store at connect, at disconnect and at most every five minutes in between, so a quiet cluster does not write on every beat. `GET /api/v1/nodes` and `GET /api/v1/nodes/{id}` show `connected` and the live `connection`: since when, the address the controller sees, the major, the version, the last beat, the buffer and the certificate expiry as the node reports them. In a cluster of controllers each controller also records which nodes are connected to it (section 12.6), so every controller shows the same `connected` view; `connection.controller` names the controller that holds the connection, and only that controller knows the last beat and the buffer.

`GET /api/v1/system/status` has a `cluster` object: the addresses the cluster port listens on, the majors of the controller, the number of nodes and of connected nodes, the software versions of the connected nodes with their counts, and the number of nodes whose handshake was refused. The object is refreshed as soon as anything under `cluster.*` is written (a node enrols, connects, disconnects, is revoked or has its handshake refused) and every five seconds otherwise; a new summary is announced with an event of the `cluster` topic (`kind` `cluster.status`, no revision), so a client reads the status again. Nodes with a refused handshake also produce the warning `cluster.protocol.mismatch`.

On the node, `tenko node status [--check] [--json]` shows the identity, the certificate (with the days left and whether a renewal is due), the CA fingerprint and the state of the node process from `status.json`. With `--check` it also connects and says hello, which tests the certificate, the CA and the protocol versions; it exits with status 7 when that fails. The states of the node process:

| State | Meaning |
|---|---|
| `connecting` | Dialling a controller |
| `connected` | The handshake succeeded and heartbeats flow |
| `disconnected` | Not connected; a retry follows after a pause |
| `protocol_mismatch` | The node and the controller share no protocol major |
| `refused` | The controller does not know the node or its certificate, or the certificate of the controller is not from the CA of the node or not a controller's |
| `revoked` | The node was revoked; enrol it again |
| `stopped` | The node process ended |

A broken connection is retried after 1 s, with the pause doubling up to 60 s and varying by a quarter in either direction, so many nodes do not reconnect at the same moment; a connection that got past the handshake starts the pause at 1 s again. A refusal that a quick retry does not fix (unknown node, foreign CA, no common major, revocation) is retried every five minutes. A node with several cluster endpoints tries them in turn.

## 6. Observations and the buffer

A probe hands its findings to the node transport as batches. A batch has one method, whether it is complete, the time the probe finished collecting, an optional VRF and the sightings.

| Part of a batch | Meaning |
|---|---|
| `method` | `arp`, `nd`, `mdns`, `lldp`, `icmp`, `tcp_syn`, `os_fingerprint`, `snmp`, `tcp_connect`, `reverse_dns`, `llmnr` or `arp_sweep` |
| `complete` | The batch is the whole picture of the probe for this method |
| `collected_at` | When the probe finished collecting |
| `vrf` | The VRF of the addresses; optional |
| `sightings` | Each has `observed_at`, an optional `ttl_secs` and one subject: `address` (IP address, optional MAC address), `services` (IP address, open TCP ports, and `tls_tcp`, the open ports that answered a TLS handshake), `os` (IP address, OS guess, confidence), `link` (two ends and a kind), `attachment` (MAC address, device, port, VLAN), `name` (IP address, name) or `vendor` (MAC address, vendor) |

The methods of the scanner and what each one reports are described in [scanning.md](scanning.md). The controller files the sightings under the source `probe:<node>:<method>`. A complete batch therefore expires only what that method of that node reported before; the sources and the rules of expiry are in [reconciliation.md](reconciliation.md). The VRF is the one of the batch, else the one of the enrolment token of the node, else the default VRF. Until first-run setup has created the default VRF, the controller answers 503 `cluster.probe.no_vrf` and the node keeps the batch. A sighting that is malformed is counted as skipped. The answer to `Ingest` carries the sequence of the batch and the counts of new, changed, refreshed, unchanged, gone and skipped facts.

A batch that fails as a whole (no known method, no collection time, a bad VRF, or more than 250,000 sightings) is refused with `cluster.probe.invalid_batch`. The node logs it and drops it, because sending it again cannot help. Any other failure leaves the batch in the buffer.

### 6.1 The buffer

The buffer in `<data_dir>/node/buffer/` keeps every batch on disk until the controller has confirmed it. It sends the oldest batch first and one at a time, survives restarts of the node and of the controller, and replays in order when a connection is back. Delivery is at least once. Each batch has a sequence within the epoch of the buffer, a UUID that changes only when its epoch file is lost. The controller remembers the epoch and the highest sequence it ingested for each node, and answers a batch sent again after a lost answer with `duplicate` set, without ingesting it a second time. That memory lives in the store (`cluster.ingest_cursors`), so it survives a restart of the controller and a batch resent to another controller is recognised there too; see `node-sync.md`.

| Bound | Value |
|---|---|
| Size of the buffer | `[cluster] buffer_mib`, default 64 MiB |
| Batches | 10,000 |
| One batch | 16 MiB, or the size of the buffer when that is smaller |
| One `Ingest` message on the cluster port | 32 MiB |

When the buffer is full, the oldest batches go first and are counted as dropped. The counter is in the heartbeats and in `status.json`. The newest batch always stays, so the controller gets the latest picture of the segment after an outage.

Each batch is one file with a header of the magic `TKB1`, the length and the SHA-256 of the payload, written atomically. A file that fails the check when it reaches the head of the queue is set aside as `<sequence>.corrupt` and counted.

Other processes on the host hand batches to the node by dropping files into `buffer/incoming/`: the payload is the protobuf form of an `IngestRequest` with an empty epoch and sequence, written to a `.tmp` file and renamed to `.batch`. The node process adopts them within a second, in the order of their names. The scanner of the probe writes into the same buffer, and so does `tenko node scan run` (see [scanning.md](scanning.md#72-on-demand-runs)).

### 6.2 Injecting a batch

`tenko node inject --file batch.json` queues a batch from a JSON file. It is a diagnostic and hidden from the help: it proves the path from a probe to the reconciler before the scanner runs. The running node process sends the batch like one of its own.

```json
{
  "method": "arp",
  "complete": false,
  "collected_at": "2026-10-10T08:00:05Z",
  "sightings": [
    {"observed_at": "2026-10-10T08:00:01Z",
     "subject": {"type": "address", "data": {"ip": "192.0.2.30", "mac": "00:00:5e:00:53:30"}}}
  ]
}
```

## 7. Ports and firewall

### 7.1 Ports

| Port | On | Used for | Direction |
|---|---|---|---|
| 8443/TCP | Controller | API and UI, also the CA root and the enrolment of a node | Administrators and, once at enrolment, the node, to the controller |
| 8444/TCP | Controller | The cluster port: gRPC over mutual TLS | Nodes to the controllers, and controllers to each other |
| none | Node | A node opens no port | |

Nodes connect out to the controller. Allow 8444/TCP from the node networks to the controllers, and from no other source; the cluster port is not meant for administrators or clients. A probe in a DMZ needs only that outbound path in normal operation, and 8443/TCP to the controller once, while it enrols. The mutual TLS must reach the controller: a layer 4 forwarder in between works, a proxy that terminates TLS does not. In a cluster of controllers, also allow 8444/TCP between every pair of controllers.

### 7.2 When the cluster port is open

| `[cluster] listen` | Behaviour |
|---|---|
| Not set | `0.0.0.0:8444`. The port opens at start when a node is enrolled or a token is waiting, and else when the first token is created. A member of a cluster of controllers opens it at once, in start step 3 (section 12.2) |
| A list of addresses | The port is always open on those addresses. The server does not start when one cannot be bound (`cluster.listen`) |
| `[]` | The port is never open. A member of a cluster of controllers does not start with it (`cluster.member.port_off`) |

`[cluster] advertise` is a list of `host:port` endpoints that the controller tells nodes at enrolment. Use it for NAT, for a port other than 8444, or for a name that nodes resolve and administrators do not. When it is empty, the node uses the host name it enrolled through together with the port of the first listening address of the controller (`ddi.example.net:8444` for the example above). The node keeps the endpoints in `identity.json`.

### 7.3 Docker and LXC

A container publishes 8444 as well as 8443. Bridge networking is fine for the cluster port; DHCP and DNS need host or macvlan networking, see `deploy/`. A probe in a container keeps `/var/lib/tenko` on a volume, enrols once with `tenko node enrol` in that volume and then runs `tenko serve --roles probe`. LXC needs no special capability for the transport; the capabilities that the raw-socket methods of the probe need are described in [scanning.md](scanning.md#9-raw-socket-methods).

## 8. Configuration

The `[cluster]` section of `tenko.toml`, with the example in `deploy/tenko.example.toml`. A key is also set by the environment variable `TENKO_CLUSTER__` plus the key in upper case; a list is given as a TOML array, for example `TENKO_CLUSTER__LISTEN='["0.0.0.0:8444"]'`, and `TENKO_CLUSTER__LISTEN='[]'` keeps the port closed.

| Key | Environment variable | Applies to | Default | Meaning |
|---|---|---|---|---|
| `listen` | `TENKO_CLUSTER__LISTEN` | Controller | Not set | Socket addresses of the cluster port (section 7.2) |
| `advertise` | `TENKO_CLUSTER__ADVERTISE` | Controller | Empty | Endpoints (`host:port`) that nodes are told at enrolment |
| `heartbeat_secs` | `TENKO_CLUSTER__HEARTBEAT_SECS` | Controller | 10 | Seconds between two heartbeats of a node, 1 to 300 |
| `enrolment_ttl_secs` | `TENKO_CLUSTER__ENROLMENT_TTL_SECS` | Controller | 3600 | Lifetime of a token whose request names none, 60 to 604,800 |
| `buffer_mib` | `TENKO_CLUSTER__BUFFER_MIB` | Node | 64 | Size of the observation buffer in MiB, 1 to 4,096 |
| `isolation_after_ms` | `TENKO_CLUSTER__ISOLATION_AFTER_MS` | Controller | 3000 | Milliseconds without contact to a quorum after which a controller counts as isolated, 500 to 60,000 (section 12.4) |
| `catch_up_timeout_secs` | `TENKO_CLUSTER__CATCH_UP_TIMEOUT_SECS` | Controller | 120 | Seconds a starting member waits to catch up with the leader before it starts isolated, 5 to 3,600 (section 12.2) |
| `auto_promote` | `TENKO_CLUSTER__AUTO_PROMOTE` | Controller | `true` | The leader promotes caught-up learners to voters (section 12.3) |
| `promote_lag_entries` | `TENKO_CLUSTER__PROMOTE_LAG_ENTRIES` | Controller | 100 | How many log entries a learner may lag and still count as caught up, 1 to 1,000,000 |
| `peer_address_map` | `TENKO_CLUSTER__PEER_ADDRESS_MAP` | Controller | Empty | A table from the cluster port a peer advertises (`host:port`, its `[node] address`) to the `host:port` this controller dials instead, for split-horizon setups and labs (section 12.2); as a variable an inline table, `'{ "controller-2.example.test:8444" = "192.0.2.12:8444" }'`. Both sides are `host:port`, and an entry may not map an address to itself |

An invalid value stops the start with `config.invalid`. A node reads `buffer_mib` from its own configuration, like the data directory.

Two keys of the `[node]` section matter to a cluster of controllers. `id` is the node id of the controller, which is also its Raft id: 1 for the first controller (the default), the id of its enrolment for a joined one. `address` is the cluster port as the other controllers reach it (`host:port`); without it the first controller names the first `[cluster] advertise` endpoint, else the address the first join arrived at. `tenko cluster join` writes both (section 12.1).

## 9. API

| Endpoint | Operation id | Authorization |
|---|---|---|
| `GET /api/v1/nodes` | `list_nodes` | `read` on nodes: viewers, operators, administrators. A page by node id, like every list |
| `GET /api/v1/nodes/{id}` | `get_node` | `read` on nodes; returns an `ETag` |
| `DELETE /api/v1/nodes/{id}` | `revoke_node` | Administrators |
| `POST /api/v1/nodes/enrolments` | `create_enrolment` | Administrators |
| `GET /api/v1/nodes/enrolments` | `list_enrolments` | Administrators |
| `DELETE /api/v1/nodes/enrolments/{id}` | `delete_enrolment` | Administrators |
| `POST /api/v1/nodes/enrol` | `enrol_node` | Public; the token is the credential. The answer carries `Cache-Control: no-store` |
| `GET /api/v1/cluster/members` | `list_cluster_members` | `read` on nodes. The controllers of the cluster (section 12.3) |
| `POST /api/v1/cluster/members/{id}/promote` | `promote_cluster_member` | `update` on the node: administrators. Body `{"force": false, "replace": <node id>}`, both optional |
| `DELETE /api/v1/cluster/members/{id}` | `remove_cluster_member` | `delete` on the node: administrators |
| `POST /api/v1/cluster/step-down` | `step_down_cluster_leader` | `update` on nodes: administrators |
| `GET /api/v1/cluster/digests` | `get_cluster_digests` | `read` on nodes. `?revision=` names the revision (section 12.7) |

The edits (creating and deleting a token, enrolment, renewal, revocation) run as inline jobs of the kind `cluster.edit`, with the step `cluster.write`; a promotion or removal of a controller is a job of the same kind with the step `cluster.member`. The change, the job record and the audit record commit as one write. Changes of the tables of the `cluster` namespace are events of the `cluster` topic of the event stream. Like every event they carry references, not bodies, so a client fetches again what it shows.

## 10. Audit actions

| Action | Written when | By |
|---|---|---|
| `cluster.enrolment.create` | A token was created; records its id, roles and expiry, never the token | The administrator |
| `cluster.enrolment.delete` | A token was deleted; records its id and state | The administrator |
| `cluster.node.enrol` | A node enrolled, or a request was refused with its error code | The new node, or the cluster component for a refusal |
| `cluster.node.renew` | A node renewed its certificate; records the new and the previous serial | The node |
| `cluster.node.revoke` | A node was revoked; records the revoked serials | The administrator |
| `cluster.node.version_mismatch` | A handshake was refused for want of a common major; at most once an hour per node and offer | The cluster component |
| `cluster.node.controller_cert` | A controller issued a certificate for its cluster port | The cluster component |
| `cluster.member.join` | A controller joined the cluster as a learner, or the first controller recorded itself as a member | The cluster component |
| `cluster.member.announce` | A controller reported a new binary in its member record after a start; records the version, the previous version and the newest data format the binary knows | The cluster component |
| `cluster.member.promote` | Learners became voters, by the leader or by an administrator; records the voters afterwards, `force` and a replaced voter | The administrator, or the cluster component for an automatic promotion |
| `cluster.member.remove` | A controller left the cluster; its certificates were revoked | The administrator |
| `cluster.member.step_down` | The leader handed leadership over; records the new leader | The administrator |
| `vault.kek.transfer` | A controller handed the key encryption keys to a joining controller (`purpose` `join`) or to a member that lacked generations (`purpose` `fetch`); records the generation ids, never the keys | The cluster component |

The certificate authority itself writes `cluster.ca.create` and `cluster.tls.issue`.

## 11. Error codes

A code is stable. The API answers with the HTTP status; on the cluster port the status maps to gRPC (400, 413 and 422 to `INVALID_ARGUMENT`, 401 to `UNAUTHENTICATED`, 403 to `PERMISSION_DENIED`, 404 to `NOT_FOUND`, 409 to `FAILED_PRECONDITION`, 503 to `UNAVAILABLE`) and the code travels in the metadata entry `tenko-error-code`.

### 11.1 Answers of the controller

| Code | Status | Meaning |
|---|---|---|
| `cluster.enrolment.invalid_token` | 401 | The token is malformed, unknown or has a wrong secret |
| `cluster.enrolment.used` | 401 | The token was used already |
| `cluster.enrolment.expired` | 401 | The token expired |
| `cluster.enrolment.roles` | 403 at enrolment, 422 at creation | The token does not allow a requested role; a token for `controller` is refused |
| `cluster.enrolment.lifetime` | 422 | `expires_in_secs` is outside 60 to 604,800 |
| `cluster.enrolment.not_found` | 404 | No such token |
| `cluster.enrolment.conflict` | 409 | Another enrolment happened at the same time; try again |
| `cluster.enrolment.random` | 500 | The system random number generator failed |
| `cluster.node.not_found` | 404 | No enrolled node has that id |
| `cluster.node.name` | 422 | The node name breaks the rule of section 1.1 |
| `cluster.node.name_taken` | 409 | Another node has the name |
| `cluster.node.address` | 422 | The address is neither an IP address nor a host name |
| `cluster.node.conflict` | 409 | The node changed during its revocation three times in a row; try again |
| `cluster.node.unknown` | 403 | The certificate is valid but its node is not enrolled, for example after a revocation |
| `cluster.node.certificate_unknown` | 403 | The certificate is not one the node was issued, or it expired |
| `cluster.node.role` | 403 | The node lacks the role the call needs (`Ingest` needs `probe`) |
| `cluster.ca.invalid_csr` | 422 | The certificate request is unusable |
| `cluster.protocol.unsupported` | 409 | The two sides share no protocol major |
| `cluster.tls.no_peer` | 401 | A call did not arrive over the mutual TLS of the cluster port |
| `cluster.tls.not_a_node` | 403 | The client certificate names no Tenko node |
| `cluster.probe.invalid_batch` | 400 | The batch cannot be ingested; the node drops it |
| `cluster.probe.no_vrf` | 503 | The default VRF does not exist yet; the node keeps the batch |
| `cluster.listen` | 500 | The cluster port cannot listen on an address |
| `cluster.join.request` | 400 | A join names no node or no cluster port as `host:port` |
| `cluster.join.not_controller` | 403 | The joining node was not enrolled with a controller token |
| `cluster.join.format_newer` | 409 | The cluster's data is in a format the joining binary does not know; upgrade the joining host |
| `cluster.member.not_found` | 404 | The node is not a member of the cluster |
| `cluster.member.even_voters` | 409 | A promotion would leave an even number of voters; join another learner first, or use `force` |
| `cluster.member.not_caught_up` | 409 | The learner lags or is out of contact; wait, or use `force` |
| `cluster.member.last_voter` | 409 | The cluster cannot lose its last voter |
| `cluster.member.is_leader` | 409 | The member leads; step it down first |
| `cluster.member.changing` | 409 | Another membership change is in progress |
| `cluster.member.no_successor` | 409 | No other voter is in contact to take over leadership |
| `cluster.member.no_address` | 409 | The first controller does not know its own cluster port; set `[node] address` |
| `cluster.member.not_leader` | 503 | No leader is known to take the change; try again after the election |
| `cluster.member.starting` | 503 | The controller is still starting |
| `cluster.member.step_down_timeout` | 504 | Leadership did not move in time; the leader keeps leading |
| `cluster.single` | 409 | The controller is not part of a cluster of controllers |
| `cluster.port.starting` | 503 | A member's node services are not ready yet; the node retries |
| `cluster.peer.not_controller` | 403 | A caller of `Raft` or `Cluster` has no `controller` role |
| `cluster.peer.impersonation` | 403 | A Raft message speaks for another node than its sender |
| `cluster.peer.unreachable`, `cluster.peer.no_endpoint`, `cluster.peer.no_credentials`, `cluster.peer.call` | 503 | Another controller cannot be reached: no connection, no known cluster port, no certificate of this controller yet, or a failed call |
| `cluster.forward.not_leader` | 503 | The controller asked to take a forwarded write does not lead; nothing was queued and the write goes to the leader it names |
| `cluster.forward.no_answer` | 504 | A forwarded write got no answer; it may have committed |
| `cluster.forward.wire` | 409 | A peer sent a payload in another encoding; upgrade the older controller |
| `cluster.wire.payload` | 400 | A payload between controllers does not decode |
| `cluster.snapshot.empty`, `.digest`, `.offset`, `.chunk`, `.truncated` | 400 | A snapshot stream is incomplete, out of order, has chunks over 1 MiB or a wrong SHA-256; the leader sends it again |
| `cluster.raft.stopped` | 503 | The Raft node of the controller stopped |
| `vault.kek.transfer.token` | 400, 403 | The join token id is malformed, is not the one the caller enrolled with, or a fetch came from a controller that is not a member |
| `vault.kek.transfer.key` | 400 | The one-time public key is not 32 bytes |
| `vault.kek.transfer.used` | 409 | The keys were transferred with this join token already |
| `vault.kek.transfer.unavailable` | 503 | The controller cannot hand over keys yet |

Start step 3 of `tenko serve` stops with `cluster.member.identity` (the cluster identity under `<data_dir>/node/` belongs to another node id than `[node] id`), `cluster.member.no_identity` (a member without a cluster identity), `cluster.member.port_off` (a member with `[cluster] listen = []`) or `cluster.config.batch_limit` (the store's batch and entry limits allow a Raft entry larger than an append request between controllers).

### 11.2 Reported on the node

These codes appear in `status.json`, in the output of `tenko node` and in the log of the node process.

| Code | Meaning |
|---|---|
| `cluster.node.not_enrolled` | The node has no identity; run `tenko node enrol` |
| `cluster.node.revoked` | The controller refused the certificate as revoked, or said so in a directive |
| `cluster.node.renew` | A renewal failed |
| `cluster.node.endpoint` | The node knows no usable cluster endpoint |
| `cluster.node.files`, `cluster.node.key` | A file of the node is unreadable, or the key file holds no key |
| `cluster.node.enrol_answer` | The answer to an enrolment is unusable |
| `cluster.tls.foreign_ca` | The certificate of the controller is not from the CA of the node: another installation, or a CA that was created again |
| `cluster.tls.not_a_controller` | The server on the cluster port has no `controller` role |
| `cluster.tls.refused` | The controller refused the certificate of the node |
| `cluster.tls`, `cluster.tls.config`, `cluster.tls.key`, `cluster.tls.invalid_root` | The TLS handshake or its configuration failed |
| `cluster.connect`, `cluster.heartbeat`, `cluster.call` | The controller cannot be reached, the heartbeat stream closed, or a call failed without a code |
| `cluster.buffer.io` | A file of the buffer cannot be read or written (500) |
| `cluster.buffer.too_large` | A batch is larger than the limit of one batch (413) |
| `cluster.buffer.config` | The limits of the buffer are unusable (500) |

## 12. The controller cluster

Several controllers form one cluster (OPS-03): one Raft group replicates the store (ADR 0002), so every controller serves the API, the UI and the nodes from the same data, and the cluster keeps accepting writes while a majority of its voters is up. Three controllers survive the loss of one. The decisions behind this section are in [ADR 0014](adr/0014-controller-cluster.md).

Terms: a **member** is a controller in the Raft group. A **voter** counts for the majority; a **learner** replicates without voting (a controller catching up). The **leader** is the voter that orders the writes; the other members are **followers**.

### 12.1 Growing from one controller to three

The first controller is an ordinary installation. Each further controller joins it, on its own host and with an empty data directory:

1. An administrator who signed in within the last five minutes creates a controller token on any controller (the token lets a host receive the installation's key encryption keys), with the API: `POST /api/v1/nodes/enrolments` with `{"roles": ["controller"]}`. The token carries the role `controller` alone and lives at most an hour. A personal API token cannot create it (403 `auth.step_up_required`). The answer shows the command to run, with the token and the CA fingerprint filled in.
2. On the new host:

   ```sh
   tenko cluster join --controller https://ddi.example.test:8443 \
     --token tnk1.… --ca-fingerprint 3f9a… \
     --address controller-2.example.test:8444 --data-dir /var/lib/tenko \
     --config /etc/tenko/tenko.toml
   ```

   The command enrols the host as a node with the role `controller` (node id 1001 and up, which is also its Raft id; the key is generated and sealed on the host, as for a probe), receives the key encryption keys and seals them with its own KEK provider, opens an empty store and its cluster port, asks to join, and waits until it has copied the cluster's data, from the log or as a snapshot (at most `--timeout-secs`, default 600). Then it writes `[node] id` and `address` and `[cluster] listen` into the configuration file, the one of `--config` or else `tenko.toml` in the data directory: a new file, or appended to one without `[node]` and `[cluster]` tables. When the file has such a table already, the command exits with status 2 and prints the lines to set there. `--address` is the cluster port as the other controllers reach it; `--listen` overrides where the port listens (default all addresses on that port). The default name is the host and port of `--address`, joined by a hyphen.
3. Start it with `tenko serve --config …`. It starts as a learner; the leader promotes it to a voter once it stays caught up (section 12.3).
4. Repeat for the third controller. With one voter and one caught-up learner the leader waits; when the second learner has caught up, both become voters together, so the cluster goes from one voter straight to three.

Nothing in the first controller's data directory changes format: the cluster is state in the store (the Raft membership and the member records). When the first peer joins, the first controller records itself as a member and moves its cluster identity from the vault to `<data_dir>/node/`, like the identity of a joined controller.

A join refuses a cluster whose data is in a format the joining binary does not know (`cluster.join.format_newer`, exit status 11): upgrade the joining host first. A store directory remembers its node id (the file `node-id` in it); a configuration with another `[node] id` does not start. A store directory that a join prepared is never initialized as a cluster of its own: run the join again, or start over with an empty directory. With the `file` key provider the key file must exist before the join, as a container's mounted secret does: the join seals the received keys under the generation directory (`[kek] dir`, default `<data_dir>/kek`) with it, and unlike `tenko serve` it does not create a missing key file.

### 12.2 Starting a member

`tenko serve` brings the cluster up in start step 3, before the vault:

- A single controller has nothing to join; its cluster port opens in step 10 as before, with the controller services beside the node services, ready for the first join.
- A member opens its cluster port at once with the identity under `<data_dir>/node/`, so its peers replicate to it while it starts. The node services answer `UNAVAILABLE` (`cluster.port.starting`) until step 10; a node retries.
- The member waits until it has applied what the leader committed (a linearizable read through the leader), at most `[cluster] catch_up_timeout_secs` (default 120). After that it starts isolated and catches up in the background.
- It fetches key generations it lacks (an online rotation while it was stopped) from another member, before the vault opens them.

A controller dials each peer at the cluster port of the peer's member record, its `[node] address`. Where that address does not work from every controller, for example a name that resolves to an inside address at one site and is unreachable from another, or the fault proxy of the cluster lab (section 12.10), `[cluster] peer_address_map` names the address this controller dials instead: `peer_address_map = { "controller-2.example.test:8444" = "192.0.2.12:8444" }`. The map applies to the controllers this one dials, after the member record is read; the advertised address in the record stays the same for everyone else, and nodes never use the map. The mutual TLS is the same either way: the certificate of the peer is checked against the installation's CA, not against the address dialled.

### 12.3 Membership

`GET /api/v1/cluster/members` and `tenko cluster members` show each member with its role, whether it leads, its cluster port, version and data format, and, from the leader, the log index it matched, how far it lags and when the leader last heard from it. `tenko cluster status` shows the leader, the term and the quorum state.

| Change | How | Rule |
|---|---|---|
| Promotion | Automatic, or `tenko cluster promote <id>` (`POST /cluster/members/{id}/promote`) | A learner that stayed within `[cluster] promote_lag_entries` (default 100) of the leader and in contact for 10 seconds is promoted when `[cluster] auto_promote` is on, and only to an odd number of voters. By hand the same rules apply (`cluster.member.even_voters`, `cluster.member.not_caught_up`) unless `--force` |
| Replacement | `tenko cluster promote <new> --replace <dead>` | One joint change removes the dead voter and adds the learner, so the cluster never has two or four voters; the dead voter's certificates are revoked |
| Removal | `tenko cluster remove <id> --yes` (`DELETE /cluster/members/{id}`) | The member leaves the Raft group, its member record goes and its certificates are revoked. The leader cannot remove itself (`cluster.member.is_leader`): step it down first |
| Step-down | `tenko cluster step-down` (`POST /cluster/step-down`) | Before a planned restart of the leader: new writes wait, the most caught-up voter in contact receives every entry and campaigns, and the command answers when it leads (`cluster.member.no_successor` without one) |

Any controller takes these requests; a follower hands them to the leader. A promotion or removal is an inline job `cluster.edit` (step `cluster.member`) on the controller that took the request, and its answer carries the job id (`job_id`). The changes are audited as `cluster.member.promote`, `.remove` and `.step_down`. They need the rights of an administrator (`update` and `delete` on nodes), which the token of `tenko login` carries. To restart every controller in turn, step the leader down first and restart the followers one at a time, waiting for each to be caught up again.

### 12.4 Writes, reads and quorum

A write on a follower goes to the leader over the cluster port and returns once the follower has applied it, so the controller that answered shows the change at once (read-your-writes). A write that reaches no leader within five seconds fails with 503 `sys.store.no_quorum`; one whose answer was lost fails with 503 `sys.store.timeout`, and the idempotency key of the request or its precondition makes a retry safe. Reads are served from the local copy; a linearizable read on a follower asks the leader how far to catch up first.

Each controller knows whether it reaches a quorum:

| State | Meaning |
|---|---|
| `single` | The only voter |
| `healthy` | In contact with a quorum |
| `electing` | No leader known; since when |
| `isolated` | No contact with a quorum for `[cluster] isolation_after_ms` (default 3,000): reads serve the local copy, writes are refused; since when, the last contact and the revision applied |

The state is in `GET /api/v1/cluster/members` (`quorum`) and `GET /api/v1/system/status`; every change is an event of the `cluster` topic with the kind `cluster.quorum` and the parameters `state`, `since`, `last_contact` and `applied`. How an isolated controller treats writes and queued changes is in [partitions.md](partitions.md).

### 12.5 The controller services

Controllers talk to each other on the cluster port with two services of `tenko.cluster.v1`:

| Service | Methods | Purpose |
|---|---|---|
| `Raft` | `AppendEntries`, `Vote`, `InstallSnapshot` | Consensus. Payloads are openraft 0.9 types in CBOR, tagged `openraft-0.9/cbor-1`. An append request stays below 30 MiB; a larger one is cut and sent in parts. A snapshot streams in chunks of 1 MiB, the first carrying the vote, the metadata and the SHA-256 of the file; the receiver installs only a complete stream whose digest matches, building every index aside (a broken transfer starts again) |
| `Cluster` | `Join`, `Propose`, `ReadIndex`, `Members`, `Digest`, `TransferKek`, `Campaign`, `Change` | Joining, forwarded writes (`tenko-batch/cbor-1`) and read indexes, the member list, state digests, the key transfer, the hand-over of leadership and forwarded membership changes (`tenko-cluster/cbor-1`) |

Every caller presents a certificate of the installation's CA with the role `controller`; a probe gets `cluster.peer.not_controller`, and another installation's CA fails the handshake. `Cluster` also needs the caller's node record holding the certificate. `Raft` accepts a controller whose record this member has not replicated yet (a learner catching up from an empty store knows nobody), and refuses a message that speaks for another node than its sender (`cluster.peer.impersonation`). A payload in another encoding is refused with `cluster.forward.wire`, so two versions of the Raft encoding never mix during an upgrade. The decoders of these payloads are fuzzed by the target `raft_payloads`.

Peers find each other's cluster ports in the member records (`cluster.members`, written when a controller joins). Each controller's cluster port must be reachable from every other controller: allow 8444/TCP between the controllers.

### 12.6 Revocations and nodes across controllers

A revocation made on any controller replicates; every controller reads its revocation list again when the table changes and closes the connections of the revoked node within a moment. A node enrolled through another controller is looked up with a read through the leader before it is refused (`cluster.node.unknown`). Each controller records which nodes are connected to it (`cluster.connections`), so `GET /api/v1/nodes` shows the same connected view on every controller: a node connected to another controller shows that controller in `connection.controller`, without its heartbeat figures, and a connection held by a controller that left the cluster no longer counts. `Hello` answers with the cluster ports of every controller (`endpoints`), so a node can reach another controller when its own is down. The hourly prune of expired revocations and old tokens runs on the leader only, as leader-only work with the leader epoch as a precondition (`cluster.prune`).

### 12.7 State digests

`tenko cluster verify` (`GET /api/v1/cluster/digests?revision=`) asks every member for a SHA-256 over every non-empty table at one revision and compares them; it exits with status 9 when they differ. Without a revision it asks again at the newest revision a member reported, so a quiet cluster agrees; under constant writes a member may answer at a later revision than the others, which the column `REVISION` of the command shows.

### 12.8 Leader-only work

Work that must happen once for the whole installation runs on the leader only, under the leader supervisor of `tenko serve`. When a controller becomes leader (after it has applied its first commit of the term), the supervisor takes office: it raises the counter `sys.leader_epoch` by one in a write that expects the counter's current value, and starts every leader service with the new epoch. Every write of a leader service carries that epoch as a precondition, so once another controller has taken office the writes of a deposed one fail instead of racing the new leader's. When leadership moves, the services stop on the old leader and start on the new one; a service that fails is restarted after a pause that doubles from one second to a minute. Each change is a log line and a `cluster` event (`cluster.leader`, `cluster.leader.service`).

| Service | What it does |
|---|---|
| `jobs.runner` | Drives every job of the installation. A new leader takes the running and waiting jobs over at once; a step that was running when the old leader went away is run again when it is idempotent and otherwise fails and is rolled back. Before each step that is not idempotent the runner confirms with the cluster that it still leads. Group limits and `[jobs] workers` hold for the whole cluster, because only one runner drives jobs |
| `ipam.reconcile` | The reconciler: its interval runs, the debounced run after an observation reached any controller (the leader watches `ipam.obs.facts`) and the purge of old observations on its own timer. Its settings are read from the store at every run (`PUT /api/v1/settings/reconciler`, [reconciliation.md](reconciliation.md)) |
| `connect.poll` | The poll schedule of every connector instance. The plugin processes, the health checks and the runs a person asks for stay on every controller ([connectors.md](connectors.md)) |
| `vault.kek_rotation` | The online rotation of the key-encryption key |
| `cluster.prune` | The hourly prune of expired revocations and old enrolment tokens |
| `api.idempotency_purge` | The hourly purge of expired idempotency records |
| `auth.used_challenges_purge` | The hourly purge of the records of used sign-in challenges |
| `import.purge` | The hourly purge of expired import uploads and of staged uploads without an import |
| `cluster.clock` | Every minute, writes the leader's clock so every controller can compare its own with it |

`GET /api/v1/system/status` shows the office under `leader`: whether this controller leads (`leads`), its epoch and since when, every service with its state (`idle` on a follower; `running`, `restarting` or `finished` on the leader), its restarts and its last error, and `clock_skew_ms` (below). A service that waits for its restart is the warning `cluster.leader.service_failing`.

Jobs whose steps are tied to one host run on that controller's own runner instead: the install of a release runs on the controller that downloaded or received it. Installing a release from the web UI stays refused on a cluster (`update.install_blocked` with the reason `cluster`); update the controllers one at a time as described in [upgrades.md](upgrades.md).

What any controller can finish, whichever started it:

- **Sign-in ceremonies.** The state of a pending second factor, passkey sign-in or registration and TOTP enrolment travels sealed in the challenge id itself (AES-256-GCM under a key derived from the installation's cluster key), so a ceremony started on one controller finishes on another without sticky sessions. Nothing is written when a ceremony starts; finishing it records the challenge as used in the same write that completes the sign-in, so a replayed challenge is refused on every controller.
- **Retries.** The fingerprints of idempotent requests are keyed from the cluster key too, so a retry that reaches another controller replays the first answer.
- **Imports.** Uploads are staged in the store, encrypted under a key of their own that the vault holds, so preview, apply and discard work on every controller.

The cluster key (`sys.cluster_key`) is 32 random bytes kept as a system secret in the vault, created by the first controller that starts with this release.

**Clocks.** Ceremonies and tokens expire by the clock of the controller that checks them. Every controller compares its clock with the leader's beat (`cluster.clock`); a difference of more than five seconds is the warning `cluster.clock_skew` in `GET /api/v1/system/status` (params `skew_ms`, this controller's clock minus the leader's, and `tolerance_ms`) and a log line. Keep the controllers' clocks synchronised with NTP.

### 12.9 Limits per controller

Two limits count on each controller separately and are not shared across the cluster:

- **The API rate limiter** (`[rate_limit]`): each controller counts the requests it serves. Behind a load balancer that spreads a client over three controllers, the client gets up to three times the configured rate.
- **The login throttle** (the pause after wrong passwords or codes, IAM-05): each controller counts the failed attempts it has seen. An attacker spread over three controllers gets up to three times the free attempts before the persisted account lock takes over; the lock is stored and replicated, so it holds on every controller at once, and unlocking the user lifts it on every controller.

A wrong second-factor code keeps its ceremony open on the controller that checked it, with the attempt counted; another controller counts the attempts of the same challenge afresh, so the attempts per challenge are bounded per controller in the same way.

### 12.10 The cluster lab

The cluster lab runs real controllers against each other: separate `tenko serve` processes that join with `tenko cluster join`, as an administrator would, and faults that a test can switch on and off. It has three parts.

**The harness and the scenarios.** `crates/tenko/tests/cluster_support/` starts one to five controllers on one machine, each with its own data directory under the operating system's temporary directory, its own loopback ports, the internal CA on `localhost`, `heartbeat_secs = 1`, `isolation_after_ms = 1000` and `catch_up_timeout_secs = 30`. The first controller runs first-run setup; every further one joins with a controller token from the API. Every directed link between two controllers runs through a TCP relay of the harness, which `[cluster] peer_address_map` puts in the path (section 12.2), so a test can cut, delay or drop one link, and partition the controllers into sets. Probes are enrolled as in section 1 and are not relayed. The harness also kills, stops, restarts and wipes controllers, runs a steady write load through the API with an `Idempotency-Key` on every write, reads the event stream as the web UI does (resuming from `Last-Event-ID` on another controller), and compares the state digests of every member through its own API (section 12.7). Every wait has a limit and fails with the last log lines of every process.

| File | What it checks | When it runs |
|---|---|---|
| `cluster_smoke_grow.rs` | One controller grows to three: two joins, both learners promoted together, a write on a follower read on every member, equal digests; the relay's own tests | Every push (CI job `cluster-smoke`) |
| `cluster_failover.rs` | The leader killed at 100 writes per second: writes resume within 15 seconds, the survivors agree at the last committed revision and hold every committed address, the event stream resumes elsewhere without a gap, the probe reconnects and its buffer drains; a follower killed under load (no write fails, the follower catches up); all three restarted with their data | Weekly (`cluster-lab`) |
| `cluster_partition.rs` | Two against one through the relays: the minority isolated after about a second, reads with `Tenko-Staleness`, writes refused with 503 `cluster.no_quorum`, IPAM changes queued; the majority commits; after the heal the queue drains (one change applied, one conflict), the digests agree and the `cluster.quorum` events arrive ([partitions.md](partitions.md)) | Weekly |
| `cluster_membership.rs` | A rejoin with an empty data directory (M6), a dead voter replaced with `tenko cluster promote --replace`, a controller removed with `tenko cluster remove` (it is cut off and does not come back with its old identity), a step-down under load | Weekly |
| `cluster_observability.rs` | The `metrics` topic of a follower shows a sample of every controller and their sum; a write through a follower is one trace whose request span on the follower is an ancestor of the `tenko.store.propose` span on the leader ([observability.md](observability.md)) | Weekly |
| `cluster_mixed_versions.rs` | A rolling upgrade from an older binary, named by `TENKO_OLD_BIN` (followers first, then the leader after a step-down), with writes between the steps; without the variable it says so and passes | Weekly, and by hand with an older release |
| `cluster_measure.rs` | The measurements below; they run only with `TENKO_LAB_RESULTS` set | By hand, `bench/phase1-cluster/run.ps1` or `run.sh` |

**The measurements.** `bench/phase1-cluster/` runs M3 (failover, 20 runs), M12 (forwarded write latency), M4 on one host (1,000 writes per second, then the catch-up of an empty fourth controller), M1 on one host (reads on a follower during the snapshot install of a joining learner) and M6 (the state file after a rejoin), and writes the results in the house format. On one machine the links are the loopback and every controller shares one disk, so M4 and M1 are stand-ins: the 6 M record set catch-up over 1 Gbit and the test index of Spike A need the DNS module and three machines.

**The compose lab.** `deploy/compose/lab-cluster/` runs three controllers, two probes and HAProxy in front on one Docker host, with the controllers in TLS mode `reverse_proxy` behind HAProxy and the cluster port on the lab network; a partition there is `docker network disconnect`. Its `smoke.sh` brings the lab up from the repository root, joins the controllers, kills the leader under 100 writes per second, partitions a follower and tears everything down; the weekly CI job runs it. Its README says how to keep the lab up for hand tests and how to run it with two images.

What the lab shows is the behaviour of the software: elections, forwarding, catch-up from the log and from a snapshot, the quorum gate, the queue, the event stream and the probes across real processes and a real proxy. What it cannot show waits for three VMs in WP3.8: a power cut (M2), a 1 Gbit link and separate disks (M4), and the UI over two hosts (M7).

## 13. What comes next

- **Slice 3.** Configuration flows from the controllers to `dns` and `dhcp` nodes as resumable deltas with a bandwidth cap (OPS-28). The update check joins the leader services of section 12.8, where the reconciler loop and the connector polling schedule run since the Slice 2 follow-ups.
- **The cluster on three machines.** The measurements of section 12.10 move to three VMs (WP3.8): M2 power cuts, M4 with 6 M record sets over 1 Gbit, M7 over two hosts, and the final runs of M1, M3 and M12.
- **The probe.** What comes next for the scanner of the probe is in [scanning.md](scanning.md#14-what-comes-next).
