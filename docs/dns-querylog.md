# The DNS query log

This page describes the query log of a node's `dns` role: what it writes, where, for how long, how it protects the clients it names, how it is read, and its limits. It is the work of WP5.4 of [phase-2-plan.md](plans/phase-2-plan.md) (section 2.9 and owner decision P2-Q7) and will be folded into `docs/dns-resolver.md` section 8. The role itself, its settings and its commands are in [dns.md](dns.md) section 8.

The decision behind it (P2-Q7): query logs stay on the node that answered and are read through a node command, so that no controller and no copy in the replicated store ever holds them. An installation that wants them elsewhere sends them there with dnstap.

## 1. What is logged

One entry per answered query (or one in N with sampling): when the query arrived, the client, the transport (UDP, TCP, DNS over TLS, DNS over HTTPS), the query name and type, the RCODE answered, the view that matched, the block list that blocked it, whether the answer came from the cache, and the microseconds from arrival to answer. A query that the forwarder answers is logged when its answer leaves.

## 2. From the query path to the disk

The query path never waits for the log:

1. **The ring.** The answering thread copies the entry into a ring of 8,192 fixed-size slots under a short lock: no allocation, no system call. When the ring is full the entry is dropped and counted.
2. **The writer** is a thread of its own. Every 100 ms it swaps the ring with an empty one (the lock is held for the swap only, so recording goes on while the writer formats and writes) and appends the entries to the current segment, then lets the operating system have them.
3. **A failed write** (a full disk, a directory that was removed or made read-only) drops the batch and counts every entry in it. The segment is cut back to its last whole entry, and the next batch opens a new segment, so a disk that comes back is used again without a restart. The error is logged at most once a minute, with the number of failures since the last line, never once per query.
4. **The counters**: `dropped` (a full ring or a failed write), `written` and `write_errors`, since the role started. They are in the node's status (`GET /api/v1/nodes/{id}/dns`, `query_log`), in the detail of the node command `dns.stats`, and in the metric `tenko_dns_log_dropped_total` ([observability.md](observability.md) section 4).

The answers never depend on the log: under a full disk, a slow disk or a burst that overflows the ring, the node answers as before and the drop counter rises (`crates/tenko-dns/src/querylog/tests.rs` turns the directory into a file under a running writer; `tests/querylog_drain.rs` records from eight threads at once and checks that every entry is written or counted).

## 3. Files, rotation and retention

The segments are files in `log.path` (default `<data_dir>/dns/querylog`), named `queries-<microseconds>.<format>` after the arrival of their first entry:

- **Rotation.** A segment holds at most a sixteenth of `log.size_mb` (between 1 and 8 MiB) and one UTC day; the first entry of a new day opens a new segment.
- **Retention.** At start, after each new segment and once a minute, segments not written for more than `log.days` days are removed, then the oldest while the directory holds more than `log.size_mb`; the segment being written stays.
- **Recovery.** At start, an unfinished tail of the newest segment (the process stopped in the middle of a write) is cut off: a JSON-lines segment ends after its last newline, a dnstap segment after its last whole frame and gets its STOP frame. A segment with nothing whole left is removed. Nothing about it stops the role.

## 4. Formats

### JSON lines (`format = "jsonl"`, the default)

One object per line:

```json
{"at":"2026-10-17T12:00:00.123456Z","client":"p:3f2a9c0d81b7e645","transport":"udp","qname":"www.example.test","type":"A","rcode":0,"cached":false,"duration_micros":38}
```

`client` is absent when the log keeps no client; `view` and `blocked` appear when they are set.

### dnstap (`format = "dnstap"`)

Frame Streams files (`.dnstap`) that dnstap tools read (`dnstap -r`, `kdig` with its dnstap module, `fstrm_dump`):

```text
START control frame   00000000 | length | 00000002 | 00000001 | 22 | "protobuf:dnstap.Dnstap"
data frame            length (4 octets, big endian, never 0) | one Dnstap protobuf message
...
STOP control frame    00000000 | 00000004 | 00000003        (when the segment is closed)
```

Each query is two data frames: a `Message` of type `CLIENT_QUERY` with the query time and the query message, and one of type `CLIENT_RESPONSE` with the query and response times and the response message. Both carry `socket_family` (INET or INET6), `socket_protocol` (UDP, TCP, DOT, DOH) and `query_address`. The `Dnstap` envelope has `type = MESSAGE`, `identity` (`node-<id>`), `version` (the Tenko version) and `extra`, which says how the client was written: `tenko;client=pseudonym`, `tenko;client=address` or `tenko;client=hidden`, with `;cached` for an answer from the cache.

The ring keeps fixed-size slots, not the messages, so the messages are rebuilt from the logged fields: the header (ID 0, QR and the RCODE, an OPT record for an extended RCODE) and the question. The answer sections are not in the log. The protobuf fields are encoded by hand, without a protobuf compiler; `crates/tenko-dns/tests/dnstap.rs` reads the files back with a Frame Streams reader of its own, a decoder that `prost` derives from the field layout of `dnstap.proto`, and `hickory-proto` for the DNS messages.

Rotation, retention, sampling and the client setting apply as for JSON lines, and the reader of section 6 reads both formats.

## 5. The clients: pseudonyms, addresses or nothing

What the log keeps of the client (TGL-15):

| Setting | Written | Who can read an address |
|---|---|---|
| `pseudonymise = true` (the default in every profile) | `p:` and the first 8 octets of HMAC-SHA-256 of the address, in hexadecimal; in dnstap an address of the same family made of the first 4 or 16 octets | Nobody through the API |
| `pseudonymise = false` | The address | A principal that may update the node; others see no client |
| `client = "hidden"` | No client field at all; no key is made | Nobody |

**The keys.** Each UTC day has its own random 256-bit key, made by the writer when the first entry of the day arrives. The keys are kept in the file `pseudonym-keys` of the log directory (owner-only on Unix), one line per day, and removed with the last segment of their day.

What this gives:

- A client has the same pseudonym for a whole day, also across a restart of the node, so the queries of one device can be followed within the day.
- The next day it has another, and two days' pseudonyms cannot be linked by anyone who reads only the log.
- The files can be read, copied or exported (dnstap) without exposing addresses: a pseudonym cannot be turned back into an address without the key of its day.
- The node itself can tell which pseudonym an address had on a day still in the log: that is how the reader's client filter finds an address in pseudonymised files.

What it does not protect against:

- Whoever holds `pseudonym-keys` can reverse a pseudonym by trying every address (IPv4 has 2^32): the key file is as sensitive as the addresses. It never leaves the node, the API never returns it, and it is removed with the data it protects. Protect the log directory as you would the addresses.
- Names reveal what a client asked: pseudonymisation hides who, not what. Sampling and short retention reduce how much is kept.
- Within a day, the pattern of a pseudonym's queries may identify a device to someone who knows its habits.

## 6. Reading the log

`GET /api/v1/nodes/{id}/dns/log` (scope `dns.read` and read on the node) issues the node command `dns.log.read`, which the role executes on the node that holds the files; in Phase 2 that is the controller's own process, in Phase 5 the same command reaches a remote node. Parameters:

| Parameter | Meaning |
|---|---|
| `cursor` | The `next_cursor` of the previous page; absent for the newest line. A cursor is `<segment>:<offset>` and reads the entries before that offset, then the older segments |
| `limit` | Lines per page, 1 to 1,000 (default 100) |
| `qname` | The name and the names under it, labels compared without case: `example.test` finds `www.example.test`, not `badexample.test` |
| `client` | A pseudonym, or an address. An address also finds the entries where it was written as a pseudonym, through the key of each entry's day; it needs the right to update the node (403 otherwise) |
| `rcode` | The RCODE answered, 0 to 4,095 |
| `from`, `until` | The arrival time window (RFC 3339, both ends included) |

Lines come newest first. One read looks at 64 MiB of segments at most; a narrow filter may therefore answer a page with fewer lines than `limit` and a cursor, and the next read goes on from there. A malformed cursor or filter answers 400 `sys.invalid_value` with the field; a node whose log is off answers 409 `dns.node.not_dns`.

**Audit.** Every page read is recorded as a row of `cluster.node_commands` and audited as `dns.log.read` in the same write, with the principal, the node, the cursor range (`from_cursor`, `to_cursor`), the number of lines and every filter (`filter.qname`, `filter.client`, `filter.rcode`, `filter.from`, `filter.until`). The audit trail therefore says who read whose queries and when.

**Addresses** leave the node only for a principal that may update the node (an administrator): for any other reader the lines of a log that keeps addresses come without a client, and a filter by address is refused. Pseudonyms are shown to every reader of the log.

The web UI shows the log of a node on the DNS page **Query log** (`/dns/log`): the last queries with time, client, transport, name, type, RCODE, latency and the cache and block flags, the filters of the route, paging by cursor, the log's settings and counters, and for administrators the kill switch.

## 7. Settings and profiles

The `[dns.log]` section of `tenko.toml` ([deploy/tenko.example.toml](../deploy/tenko.example.toml)); environment variables override it as for every section (`TENKO_DNS__LOG__ENABLED=true`).

| Key | Default | Meaning |
|---|---|---|
| `enabled` | the profile's | Log queries |
| `path` | `<data_dir>/dns/querylog` | The directory of the segments and the key file |
| `format` | `jsonl` | `jsonl` or `dnstap` |
| `days` | the profile's | Days a segment is kept, 1 to 365 |
| `size_mb` | 256 | MiB the directory may hold, 1 to 102,400 |
| `sample` | 1 | Log one query in N, 1 to 1,000,000 |
| `pseudonymise` | `true` | Write pseudonyms instead of addresses |
| `client` | `logged` | `hidden` writes no client at all |

`enabled` and `days` follow the security profile when they are not set (TGL-15). The profile is the stored one after first-run setup, else `[profile] name`:

| Profile | Log | Days | Clients |
|---|---|---|---|
| Home | Off (opt-in) | 7 | Pseudonymised |
| Standard | On | 30 | Pseudonymised |
| Hardened | On | 30 | Pseudonymised |
| Lab | On | 7 | Pseudonymised |

Home is off because TGL-15 makes logging opt-in for the home user. Pseudonymisation is on in every profile, Lab included, although TGL-15 lists Lab as not pseudonymised: a lab that wants addresses sets `pseudonymise = false`. The export of the log with the audit stream that TGL-15 names for Hardened is not built; dnstap files are the path to an external collector. The settings are read at start; a change needs a restart of the node.

## 8. The kill switch

Two ways to stop logging:

- **At run time**: `POST /api/v1/nodes/{id}/dns/log/stop` (scope `dns.write` and update on the node), the node command `dns.log.stop`, and `.../start` (`dns.log.start`) to log again; the Stop logging and Start logging buttons of the log page do the same. A stopped log takes nothing from the query path (nothing is dropped, nothing is counted). The state is kept as the marker file `stopped` in the log directory, so the log stays stopped across a restart until it is started again. Both commands are recorded and audited (`dns.log.stop`, `dns.log.start`).
- **In the settings**: `enabled = false` in `[dns.log]` and a restart. The writer does not start, `GET /api/v1/nodes/{id}/dns` has no `query_log`, and the log page says the log is off.

Stopping keeps the files already written until their retention removes them; to remove them at once, delete the segments in the log directory.

## 9. Limits

- Only the header and the question of each message are in the dnstap output (section 4); the answer records, the query ID and the client port are not kept.
- Forwarded queries are `CLIENT_*` messages; `RESOLVER_*` and `FORWARDER_*` messages towards the upstreams are not written.
- The dnstap identity is `node-<id>`, not the host name.
- A read scans segments from the newest; a filter that matches nothing looks at 64 MiB per page and needs many pages to cover a large directory.
- The pseudonym keys are in the log directory; a backup of that directory carries them (section 5).
- The settings need a restart; only the kill switch acts at run time.
- `tenko dns log` in the command-line client is not built; read the log through the API or the UI.
