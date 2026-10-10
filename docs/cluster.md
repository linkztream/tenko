# Cluster: nodes, enrolment and the node transport

This page describes how Tenko DDI connects its data-plane nodes to its controllers: how an administrator enrols a node with a single-use token, which certificates the internal CA issues and how they renew, how a node is revoked, the gRPC protocol the two sides speak and how its version is negotiated, how heartbeats show the health of a node, how the observations of a probe travel through a disk buffer that survives outages, and which ports and settings an installation needs. It is for an administrator who adds a probe to a site and for a developer who works on the transport. It describes the behaviour of the `tenko-cluster` crate, of `tenko node` and the node process of `tenko serve` in the `tenko` crate, and of the `/nodes` routes in `tenko-api`; where this page and the code differ, the code is right. The requirements are OPS-04, OPS-08 and OPS-28 in [REQUIREMENTS.md](REQUIREMENTS.md). The messages are defined in the `.proto` files in [`crates/tenko-cluster/proto/tenko/cluster/v1/`](../crates/tenko-cluster/proto/tenko/cluster/v1/), package `tenko.cluster.v1`; their comments are part of the contract.

Controllers run the API, the web UI and the store. Data-plane nodes run `probe` today and `dns` and `dhcp` later. Controllers and nodes talk gRPC over mutual TLS on the cluster port (OPS-04), with certificates from the internal CA of the installation. The mechanism is the same for native, Docker and LXC installations. mTLS is structural: no security profile turns it off, and the transport speaks TLS 1.3 only. Nodes negotiate the protocol version with the controller (OPS-08) and keep working across controller outages (OPS-28): a probe keeps its observations on disk and sends them when a controller is back. This slice (Slice 2, WP2.2) carries node to controller traffic only: the handshake, heartbeats, certificate renewal and probe observations. Section 12 lists what comes next.

Terms used below: a **controller** is an installation that runs the `controller` role. A **node** is an enrolled data-plane installation with the roles `probe`, `dns` or `dhcp`. The **cluster port** is the TCP port on which controllers accept nodes (8444 by default). The **internal CA** is the certificate authority of the installation; its key lives in the vault of the controllers. An **enrolment token** is a single-use, time-limited secret that lets one node obtain its first certificate.

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
12. [What comes next](#12-what-comes-next)

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
| `roles` | The roles the node may take: `probe`, `dns`, `dhcp`. A token for `controller` is refused with 422 `cluster.enrolment.roles`; controllers join in Slice 3 | `["probe"]` |
| `name` | The name the node gets. It must be unique among nodes and has 1 to 63 letters, digits, dots, hyphens and underscores, starting with a letter or digit | The node chooses one, its host name |
| `vrf` | The VRF, by id, of the node's observations when a batch names none (section 6) | The default VRF |
| `expires_in_secs` | Seconds until the token expires, 60 to 604,800 (seven days) | 3,600, or `[cluster] enrolment_ttl_secs` |

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

A controller keeps its certificate for the cluster port and its key in the vault. It checks them daily and issues new ones 30 days before expiry (audit action `cluster.node.controller_cert`); the cluster port uses the new certificate for the next connection.

A node renews its certificate over the mutual TLS channel (`Node.Renew`). It generates a new key and sends a certificate request; the controller issues a certificate with the same node id and roles. The renewal is due when less than a third of the lifetime or fewer than 30 days remain, which for a one-year certificate is about 122 days before expiry. The node checks this with every heartbeat and tries again hourly while a renewal fails; the controller also asks for one in the answer to a heartbeat once fewer than 30 days remain. `tenko node renew` renews at once, also beside a running node process, which loads the new pair for its next connection.

The old certificate stays valid until it expires. Both serials are in the node record, and both are revoked with the node (section 3). The node swaps its files with `.new` and `.old` copies of the certificate and the key, so a crash never leaves a broken pair: when the current pair does not load, the node falls back to the `.old` pair. The renewal is audited as `cluster.node.renew`.

## 3. Revocation

`DELETE /api/v1/nodes/{id}` (administrators) revokes a node. The controller removes the node record and its name, and puts every unexpired certificate serial of the node on the revocation list, the table `cluster.revocations`. The TLS verifier of the cluster port checks that list at every handshake; a revoked certificate fails it with the alert `certificate_revoked`. The heartbeat stream of the node gets a directive that says it was revoked, and its connections close about 0.3 s later. The node then reports the state `revoked` (`cluster.node.revoked`) and tries again every five minutes, which fails the same way.

A revoked node does not come back by itself. It needs a new token and gets a new id; its name becomes free again. An entry leaves the revocation list after the expiry of its certificate, when the hourly maintenance pass finds it. The revocation is audited as `cluster.node.revoke`.

Today a controller reads the revocation list from the store at start and every hour. With several controllers (Slice 3) the list replicates through the store.

## 4. The protocol and its versioning rule

The protocol is the package `tenko.cluster.v1`. Like the plugin protocol of [plugins.md](plugins.md) it is compiled at build time from the `.proto` files, without `protoc`. Every call needs a client certificate of an enrolled node that still holds that certificate (`cluster.node.unknown`, `cluster.node.certificate_unknown`). A refused call carries the metadata entry `tenko-error-code` with a stable code.

| Service | Method | Purpose |
|---|---|---|
| `Handshake` | `Hello` | Agrees on the protocol major. Frozen across majors |
| `Node` | `Heartbeat` | A bidirectional stream: a beat from the node, a directive from the controller for every beat, and directives the controller pushes (a revocation) |
| `Node` | `Renew` | Issues a new certificate for the key of a certificate request |
| `Observations` | `Ingest` | Hands one batch of the buffer of a probe to the reconciler. Needs the role `probe` (`cluster.node.role`) |

### 4.1 Version negotiation (OPS-08)

The node offers every major it implements in `Hello`, with its software version and its roles. The controller answers with the highest major both sides implement, together with its own majors, its version, the node id it knows the certificate by, the heartbeat interval and its clock. When the sides share no major, the controller refuses with gRPC `FAILED_PRECONDITION`, the metadata entry `tenko-error-code: cluster.protocol.unsupported` and the entry `tenko-majors` with its own majors, for example `1, 2`. `Hello` and its two messages are frozen: every later major serves them unchanged, so two nodes of different majors can always find out what they share. Enrolment applies the same rule before it issues a certificate (section 1.3).

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

A node counts as connected while its heartbeat stream is open. The controller holds this in memory, and writes `last_seen` to the store at connect, at disconnect and at most every five minutes in between, so a quiet cluster does not write on every beat. `GET /api/v1/nodes` and `GET /api/v1/nodes/{id}` show `connected` and the live `connection`: since when, the address the controller sees, the major, the version, the last beat, the buffer and the certificate expiry as the node reports them.

`GET /api/v1/system/status` has a `cluster` object: the addresses the cluster port listens on, the majors of the controller, the number of nodes and of connected nodes, the software versions of the connected nodes with their counts, and the number of nodes whose handshake was refused. The object is refreshed every five seconds. Nodes with a refused handshake also produce the warning `cluster.protocol.mismatch`.

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
| `method` | `arp`, `nd`, `mdns`, `lldp`, `icmp`, `tcp_syn`, `os_fingerprint` or `snmp` |
| `complete` | The batch is the whole picture of the probe for this method |
| `collected_at` | When the probe finished collecting |
| `vrf` | The VRF of the addresses; optional |
| `sightings` | Each has `observed_at`, an optional `ttl_secs` and one subject: `address` (IP address, optional MAC address), `services` (IP address, open TCP ports), `os` (IP address, OS guess, confidence), `link` (two ends and a kind) or `attachment` (MAC address, device, port, VLAN) |

The controller files the sightings under the source `probe:<node>:<method>`. A complete batch therefore expires only what that method of that node reported before; the sources and the rules of expiry are in [reconciliation.md](reconciliation.md). The VRF is the one of the batch, else the one of the enrolment token of the node, else the default VRF. Until first-run setup has created the default VRF, the controller answers 503 `cluster.probe.no_vrf` and the node keeps the batch. A sighting that is malformed is counted as skipped. The answer to `Ingest` carries the sequence of the batch and the counts of new, changed, refreshed, unchanged, gone and skipped facts.

A batch that fails as a whole (no known method, no collection time, a bad VRF, or more than 250,000 sightings) is refused with `cluster.probe.invalid_batch`. The node logs it and drops it, because sending it again cannot help. Any other failure leaves the batch in the buffer.

### 6.1 The buffer

The buffer in `<data_dir>/node/buffer/` keeps every batch on disk until the controller has confirmed it. It sends the oldest batch first and one at a time, survives restarts of the node and of the controller, and replays in order when a connection is back. Delivery is at least once. Each batch has a sequence within the epoch of the buffer, a UUID that changes only when its epoch file is lost. The controller remembers the epoch and the highest sequence it ingested for each node, and answers a batch sent again after a lost answer with `duplicate` set, without ingesting it a second time. That memory is not persistent; a batch resent after a restart of the controller is ingested again, which the reconciler tolerates because a fact that did not change is not rewritten.

| Bound | Value |
|---|---|
| Size of the buffer | `[cluster] buffer_mib`, default 64 MiB |
| Batches | 10,000 |
| One batch | 16 MiB, or the size of the buffer when that is smaller |
| One `Ingest` message on the cluster port | 32 MiB |

When the buffer is full, the oldest batches go first and are counted as dropped. The counter is in the heartbeats and in `status.json`. The newest batch always stays, so the controller gets the latest picture of the segment after an outage.

Each batch is one file with a header of the magic `TKB1`, the length and the SHA-256 of the payload, written atomically. A file that fails the check when it reaches the head of the queue is set aside as `<sequence>.corrupt` and counted.

Other processes on the host hand batches to the node by dropping files into `buffer/incoming/`: the payload is the protobuf form of an `IngestRequest` with an empty epoch and sequence, written to a `.tmp` file and renamed to `.batch`. The node process adopts them within a second, in the order of their names. The scanner of WP2.3 writes into the same buffer.

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
| 8444/TCP | Controller | The cluster port: gRPC over mutual TLS | Nodes to the controllers |
| none | Node | A node opens no port | |

Nodes connect out to the controller. Allow 8444/TCP from the node networks to the controllers, and from no other source; the cluster port is not meant for administrators or clients. A probe in a DMZ needs only that outbound path in normal operation, and 8443/TCP to the controller once, while it enrols. The mutual TLS must reach the controller: a layer 4 forwarder in between works, a proxy that terminates TLS does not.

### 7.2 When the cluster port is open

| `[cluster] listen` | Behaviour |
|---|---|
| Not set | `0.0.0.0:8444`. The port opens at start when a node is enrolled or a token is waiting, and else when the first token is created |
| A list of addresses | The port is always open on those addresses. The server does not start when one cannot be bound (`cluster.listen`) |
| `[]` | The port is never open |

`[cluster] advertise` is a list of `host:port` endpoints that the controller tells nodes at enrolment. Use it for NAT, for a port other than 8444, or for a name that nodes resolve and administrators do not. When it is empty, the node uses the host name it enrolled through together with the port of the first listening address of the controller (`ddi.example.net:8444` for the example above). The node keeps the endpoints in `identity.json`.

### 7.3 Docker and LXC

A container publishes 8444 as well as 8443. Bridge networking is fine for the cluster port; DHCP and DNS need host or macvlan networking, see `deploy/`. A probe in a container keeps `/var/lib/tenko` on a volume, enrols once with `tenko node enrol` in that volume and then runs `tenko serve --roles probe`. LXC needs no special capability for the transport; the raw sockets of the probe come with WP2.3.

## 8. Configuration

The `[cluster]` section of `tenko.toml`, with the example in `deploy/tenko.example.toml`. A key is also set by the environment variable `TENKO_CLUSTER__` plus the key in upper case; a list is given as a TOML array, for example `TENKO_CLUSTER__LISTEN='["0.0.0.0:8444"]'`, and `TENKO_CLUSTER__LISTEN='[]'` keeps the port closed.

| Key | Environment variable | Applies to | Default | Meaning |
|---|---|---|---|---|
| `listen` | `TENKO_CLUSTER__LISTEN` | Controller | Not set | Socket addresses of the cluster port (section 7.2) |
| `advertise` | `TENKO_CLUSTER__ADVERTISE` | Controller | Empty | Endpoints (`host:port`) that nodes are told at enrolment |
| `heartbeat_secs` | `TENKO_CLUSTER__HEARTBEAT_SECS` | Controller | 10 | Seconds between two heartbeats of a node, 1 to 300 |
| `enrolment_ttl_secs` | `TENKO_CLUSTER__ENROLMENT_TTL_SECS` | Controller | 3600 | Lifetime of a token whose request names none, 60 to 604,800 |
| `buffer_mib` | `TENKO_CLUSTER__BUFFER_MIB` | Node | 64 | Size of the observation buffer in MiB, 1 to 4,096 |

An invalid value stops the start with `config.invalid`. A node reads `buffer_mib` from its own configuration, like the data directory.

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

The edits (creating and deleting a token, enrolment, renewal, revocation) run as inline jobs of the kind `cluster.edit`, with the step `cluster.write`. The change, the job record and the audit record commit as one write. Changes of the tables of the `cluster` namespace are events of the `cluster` topic of the event stream. Like every event they carry references, not bodies, so a client fetches again what it shows.

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
| `cluster.node.conflict` | 409 | The node changed during its revocation; try again |
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

## 12. What comes next

- **Slice 3, WP3.1.** Controllers join by the same enrolment and mutual TLS, first as learner and then as voter, and Raft runs over this transport. Configuration flows from the controllers to `dns` and `dhcp` nodes as resumable deltas with a bandwidth cap (OPS-28). Revocations and the state of the nodes replicate between controllers. The scheduling of jobs becomes leader-only.
- **WP2.3.** The scanner plugs into the observation buffer of the probe.
- **WP2.9.** The nodes page of the UI: enrolment tokens, node health and revocation.
