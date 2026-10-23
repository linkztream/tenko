# DNSSEC

Tenko signs the zones it is primary for on its controllers, with keys kept in the vault, and serves zones that arrive already signed. This page is for operators who sign a zone, put its DS at the parent, roll its keys or serve an imported signed zone. The decisions behind it are in [ADR 0018](adr/0018-dnssec-key-handling-and-signing.md); the routes, tables and codes are in [dns-contracts.md](dns-contracts.md).

Contents:

1. [The model](#1-the-model)
2. [Signing a zone](#2-signing-a-zone)
3. [The DS at the parent](#3-the-ds-at-the-parent)
4. [Key rollovers](#4-key-rollovers)
5. [Imported signed zones](#5-imported-signed-zones)
6. [Answers](#6-answers)
7. [Health findings](#7-health-findings)
8. [Profile defaults](#8-profile-defaults)
9. [Backups](#9-backups)
10. [Limits](#10-limits)
11. [Measurements (M20)](#11-measurements-m20)

## 1. The model

A zone's `dnssec` policy says how it is signed:

| Field | Default | Meaning |
|---|---|---|
| `mode` | `off` | `off`: not signed. `online`: signed by Tenko (primary zones only). `imported`: the zone's own DNSSEC records are served as they are |
| `algorithm` | `ecdsa_p256_sha256` | The algorithm of new keys: ECDSA P-256 with SHA-256 (13) or `ed25519` (15) |
| `denial` | `{"kind": "nsec"}` | NSEC, or `{"kind": "nsec3", "iterations": 0, "salt": ""}` (RFC 9276; opt-out is never used) |
| `csk` | `false` | One combined signing key instead of a KSK and a ZSK |
| `signature_validity_days` | 14 | How long a new signature is valid |
| `resign_before_days` | 7 | Signatures with less than this left are renewed |
| `zsk_rollover_days` | none | Roll the ZSK every this many days (no scheduled rollover when absent) |

The signer is the leader-only service `dns.signer` of `tenko serve` on the controllers. For a zone signed online it generates the keys (a KSK and a ZSK, or a CSK) with their private keys in the vault, and writes the zone's DNSSEC records as rows of the zone with the origin `dnssec`: the DNSKEY set, CDS and CDNSKEY for the key-signing key, an NSEC or NSEC3 record per owner (NSEC3PARAM at the apex for NSEC3) and an RRSIG row per owner. The rows reach the `dns` role like any other row, so the node answers from its index; nodes never hold a private key and never sign. The records list hides the signer's rows unless asked for them (`GET /dns/zones/{id}/records?origin=dnssec`, the filter of the UI); the zone file export includes them. No one else may change them: a change of an RRset of the origin `dnssec`, or of one of the types DNSKEY, CDS, CDNSKEY, NSEC, NSEC3, NSEC3PARAM and RRSIG in a zone signed online, is refused with `dns.record.origin`, `take_over` or not.

What is signed: every RRset of an owner that holds data and is not below a zone cut or a DNAME; at a delegation only the DS (the NS set and the glue belong to the child). The KSK (or CSK) signs the DNSKEY, CDS and CDNSKEY sets; the ZSK (or CSK) signs everything else. A signature starts an hour before it is made, so validators with a slow clock accept it, and is valid for `signature_validity_days` less a random part of up to half of `resign_before_days`, so the signatures of a zone signed at once expire, and are renewed, spread over days.

When the signer signs:

- When a zone turns `online`: a full pass over the whole zone.
- After every change of the zone's records (the store's change stream, gathered for 50 ms): an incremental pass over the changed RRsets, the owners whose NSEC must point elsewhere, and for NSEC3 the empty non-terminals above a change and the hashed owners before it.
- After a change of the zone's settings, of its keys, and when a controller takes over as leader: a full pass that keeps every signature that can stay.
- On its timer (every minute it looks): when `next_resign` (the earliest expiry less `resign_before_days`) has come, a full pass that renews every signature with less than `resign_before_days` and one day left, so the next renewal of the zone is about a day later.

A pass that writes anything moves the zone's serial once and journals its rows, so secondaries get the signatures by IXFR. A pass that changes more than 10,000 records (the first signing of a large zone, a key change, a renewal pass of a large zone) resets the zone's journal, as a large import does; a secondary then asks for IXFR, gets AXFR once, and IXFR again afterwards. Each change of records therefore shows as two serial steps on a secondary: the change and the signer's pass right after it.

`mode = off` removes the signer's rows (with one serial step) and retires the keys; they stay in the signing state and the vault, so turning signing on again takes the same keys up and the DS at the parent stays valid. Keys that a rollover removed lose their private key.

## 2. Signing a zone

Through the client:

```bash
tenko dns dnssec enable example.test
```

`--algorithm ed25519`, `--nsec3`, `--csk`, `--validity-days`, `--resign-days` and `--zsk-rollover-days` set the policy; `--imported` serves an imported signed zone instead (section 5). The command patches the zone's `dnssec` policy (`PATCH /api/v1/dns/zones/{id}` with `{"dnssec": {...}}`), and the signer signs the zone right after. The state:

```bash
tenko dns dnssec status example.test
```

shows the mode, the serial last signed, the earliest expiry, the next renewal, the keys with their tags, states and dates, the DS records for the parent and the findings of section 7 (`GET /api/v1/dns/zones/{id}/dnssec`). In the web UI the zone page has a DNSSEC tab with the same state, the DS records with a copy button, the policy form and the rollover buttons.

`tenko dns dnssec disable example.test` turns signing off.

The policy is a zone setting, so changing it needs `dns.write`; the rollover needs `dns.keys` (administrators).

## 3. The DS at the parent

A zone signed online is trusted by validating resolvers only when its parent holds a DS record for its key-signing key. Copy the DS lines from `tenko dns dnssec status` or the DNSSEC tab (SHA-256, digest type 2) into the parent zone: at your registrar for a domain under a public TLD, or in the parent zone of your own DNS. The zone also publishes CDS and CDNSKEY records for the same key (RFC 7344), which parents that scan for them (some registries and registrars) pick up by themselves. Until the parent holds the DS the zone validates as insecure, which is the same as unsigned: nothing breaks while you set it up.

When Tenko serves the parent zone too, add the DS there as an RRset of the delegation (a `set` change of type DS at the child's name through `POST /api/v1/dns/zones/{id}/records/batch`, with `key_tag`, `algorithm`, `digest_type` and `digest` as the status shows them); Tenko answers a DS query at the child's apex from the parent.

## 4. Key rollovers

```bash
tenko dns dnssec rollover example.test --role zsk
```

starts the job `dns.dnssec.rollover` (`POST /api/v1/dns/zones/{id}/dnssec/rollover` with `{"role": "zsk"}`, answered 202 with the job; follow it under Jobs or with `GET /api/v1/jobs/{id}`). The rollover button of the DNSSEC tab does the same. One rollover runs per zone; a second answers `dns.dnssec.rollover_running`, a zone not signed online `dns.dnssec.not_online`.

| Step | ZSK (pre-publication, RFC 6781 4.1.1.1) | KSK or CSK |
|---|---|---|
| `dns.dnssec.publish` | A new ZSK is generated and published; it signs nothing yet | A new key is generated and published; it signs the DNSKEY set beside the old one, and CDS and CDNSKEY list both |
| `dns.dnssec.wait` | The DNSKEY TTL (the zone's SOA TTL) and the propagation delay | The same |
| `dns.dnssec.parent` | | A person puts the new DS at the parent and confirms the step under Jobs, once the parent serves it and the old DS has had its TTL |
| `dns.dnssec.activate` | The new ZSK signs the zone (a full pass) and the old one is retired | The new key takes over; CDS and CDNSKEY list it alone |
| `dns.dnssec.wait` | The largest TTL of the zone and the propagation delay | The same |
| `dns.dnssec.retire` | The old ZSK leaves the DNSKEY set and the vault | The old key leaves the DNSKEY set and the vault |

The propagation delay is the SOA refresh, at most an hour, when the zone has secondaries (a transfer access list or NOTIFY targets), else nothing. With the default SOA TTL of 3,600 s a ZSK rollover takes about two hours plus the largest TTL of the zone. Every step and key change is audited (`dns.dnssec.rollover`, `dns.dnssec.key_state`). Steps run again safely after a restart or a change of leader: each reads where the rollover stands and a wait sleeps only what is left. A job that fails before its new key signed removes that key again.

With `zsk_rollover_days` set, the signer starts a ZSK rollover by itself when the active ZSK has signed for that many days. KSK and CSK rollovers need the parent and are started by hand.

To change the algorithm of a signed zone, change the policy's `algorithm`, turn signing off and on again (the new keys use the new algorithm; the parent's DS must follow, and the zone validates as insecure in between). An algorithm rollover that keeps the zone secure throughout is not built.

## 5. Imported signed zones

For zones signed elsewhere (an offline signer, a hidden primary) set `mode = imported` (`tenko dns dnssec enable example.test --imported`) and import the signed zone file (`tenko dns import example.test signed.zone --replace`). Tenko serves the zone's own DNSKEY, RRSIG, NSEC and NSEC3 records as they are (origin `manual`) and does not sign them again; the signer reads their earliest expiry every hour and warns 7 days before it (section 7). Import the zone again, signed again, before then.

## 6. Answers

A query with the DO bit (RFC 3225) gets the RRSIGs of every RRset of the answer and, in the authority section, the signed NSEC or NSEC3 records that prove an NXDOMAIN, a NODATA (an empty non-terminal included), that a wildcard answer's name does not exist, or that a delegation has no DS. A query without DO gets exactly what it got before signing. The authoritative side never sets AD. These records count against the client's UDP size like any other; an answer that does not fit is truncated and the client retries over TCP.

## 7. Health findings

The signing state is checked whenever it is read: in `GET /api/v1/system/status` (warnings, each naming its zone) and in the zone's DNSSEC status.

| Code | When | What to do |
|---|---|---|
| `dns.dnssec.clock_skew` | The controller's clock is more than 5 minutes behind the zone's last signing: it went back | Fix the time synchronisation of the controller (OPS-09); signatures made with a clock that is wrong start or end at the wrong time |
| `dns.dnssec.expiring` | An imported zone's earliest signature expires within 7 days | Import the zone signed again |
| `dns.dnssec.resign_overdue` | A zone signed online has a signature with less than half of `resign_before_days` left | The signer does not keep up or does not run: check that a controller leads and the signer's log |
| `dns.dnssec.expired` | A signature has expired | Validating resolvers answer SERVFAIL for the zone; sign or import it again at once |

A controller cannot see its own clock run ahead; the cluster's `cluster.clock_skew` compares the controllers' clocks with each other.

## 8. Profile defaults

A zone created without a `dnssec` policy (TGL-13):

| Profile | Default |
|---|---|
| Home | Not signed |
| Standard | Not signed; signing is switched on per zone |
| Hardened | Signed online when the zone is a primary zone served outside: not under a private suffix (`home.arpa`, `local`, `localhost`, `test`, `example`, `invalid`, `internal`, `lan`, `corp`, `home`, `intranet`, `private`, `localdomain`) and not the reverse zone of a private range (RFC 1918, loopback, link-local, ULA) |
| Lab | Not signed |

## 9. Backups

The private keys are envelopes of the vault in the store snapshot, and the key generations that open them are part of every backup (ADR 0016), so a restored installation signs with the same keys and the DS at the parent stays valid. Nothing else exports a private key; the API and the UI show public keys and DS records only.

## 10. Limits

- Signing needs a controller that leads. Nodes keep serving the signed data they have while no controller leads; signatures run out after `signature_validity_days`, and the findings warn before.
- The RRSIG row of an owner has one TTL, the smallest of the RRsets it covers; answers carry each signature with the TTL of its RRset, and the zone file export writes the row's TTL, which validators ignore.
- NSEC3 owner names are ordinary names of the index: a query for a hashed owner name itself is answered as a name that exists without data, not as NXDOMAIN.
- A rollover's waits hold a worker of the job runner while they sleep.
- No algorithm rollover; no RSA; changing `csk` on a signed zone takes effect after signing is switched off and on.
- The signer keeps the NSEC3 chain of each zone in memory while it leads (20 octets per name) and rebuilds it from the store after a change of leader.
- Additional-section records (glue, the addresses of MX and SRV targets) carry no RRSIGs; validators look them up when they need them.

## 11. Measurements (M20)

M20 asks for the Spike A data set of a million records signed in under 5 minutes with each algorithm, NSEC and NSEC3, and a 100-record change signed again in under a second. `bench/phase2-dns/scripts/run-m20-sign.sh` measures it through `tenko serve`; the figures are in `bench/phase2-dns/results/`.

| Case | Windows 11, release | WSL2, static musl |
|---|---:|---:|
| ECDSA P-256, NSEC: full pass / change (median) | 45.9 s / 0.52 s | 224.2 s / 0.35 s |
| ECDSA P-256, NSEC3 | 69.6 s / 0.54 s | 316.5 s / 0.38 s |
| Ed25519, NSEC | 45.2 s / 0.52 s | 213.6 s / 0.43 s |
| Ed25519, NSEC3 | 70.4 s / 0.54 s | 294.7 s (319.4 s in a second run) / 0.43 s |

The Windows build passes every case. On the shipped Linux binary NSEC passes and NSEC3 sits at the 5-minute threshold; the gap is musl's allocator in the store's write path, which slows the zone import as much (M18). Of a change's time about 0.4 s is the import job and the client's wait for it; the signer's own pass and write take 20 to 130 ms. The write-up with the procedure is `bench/phase2-dns/results/2026-10-18-m20-signing.md`.

## 12. Validation

The resolver validates every answer it gives, recursed or forwarded, with Tenko's own validator over the signer's primitives (ADR 0021 point 5, REC-Q3, REC-Q4; `tenko_dns::validate`). It runs on the runtime between the authority's answer and the cache insert; the worker never verifies a signature, it only renders the state the entry carries. Validation is on in every profile; the Lab profile may switch it off with `[dns.recursion] validate = false` (TGL-12), and a forwarding rule may set `validate = false` for one upstream.

### The chain

For each RRset of an answer the validator finds the nearest trust anchor at or above its signer, then walks down one label at a time. At each name it asks the parent for DS (a sub-query through the engine, or through the rule's upstream for a forwarded answer): a DS set signed by the parent's keys names the child's keys, and the child's DNSKEY set must be signed by one of them; a DS set that names only unsupported algorithms or digests makes the child insecure (RFC 6840 section 5.2); a NODATA proven by the parent's NSEC or NSEC3 records makes the child insecure when the name is a delegation (NS, no DS, no SOA, or an opt-out span) and no cut at all otherwise, so the parent's keys go on applying. What the walk finds is kept per zone until the smaller of the TTL and the signature expiry, in the infrastructure cache's DS slot for zones that have a cut and in the validator's own table for the rest (a zone served by the same server as its parent gets no referral and so no cut); the table is bounded like the cuts (1,000 under Home, 10,000 elsewhere, the least recently used first), shown in the node status beside the infrastructure figures and in `tenko_dns_validation_key_sets`, and emptied with `POST /nodes/{id}/dns/infra/flush`. A second name in a zone costs no DS or DNSKEY query. A change of the trust anchors or of the negative trust anchors forgets every state the walk made (the table and the DS slots) and the answers cached under a negative trust anchor that came or went, so the next query walks again under the new anchors. The delegation's NS set that an answer carries in its authority section is never judged: the parent does not sign it (RFC 4035 section 2.2).

Signatures are verified over the canonical form of RFC 4034 section 6 as RFC 6840 section 5.1 corrects it (the names inside record data lowercased for the types listed, the NSEC next name kept, the RRSIG signer lowercased) with RSA (5, 7, 8, 10), ECDSA P-256 and P-384 (13, 14) and Ed25519 (15) through `aws-lc-rs`, and DS digests SHA-1, SHA-256 and SHA-384; RSAMD5 and DSA are refused as RFC 8624 says, ED448 and GOST are unsupported (insecure, never bogus), and RSA keys below 1,024 bits are refused. The signer keeps signing with 13 and 15 only.

A negative answer must carry the proof of the zone that signed its SOA: with NSEC, the covering record, the closest encloser and the wildcard's denial for a name error, the matching record without the type (and without CNAME) or an empty non-terminal for NODATA (RFC 4035 section 5.4); with NSEC3, the closest encloser proof of RFC 5155 section 8.3 and the rules of sections 8.4 to 8.9, opt-out included. A wildcard answer must carry the proof that no closer name exists. A proof under an opt-out span makes the answer insecure (RFC 5155 section 9.2). More than 100 NSEC3 iterations make the zone insecure, more than 500 make the answer SERVFAIL with extended error 27 (RFC 9276).

### The states and the wire

| State | What it means | On the wire |
|---|---|---|
| `secure` | A chain from an anchor proves the data, or its absence | The data; AD when the client asked with AD or DO |
| `insecure` | A proof shows the data needs no signature: an unsigned delegation, unsupported algorithms, an opt-out span, a negative trust anchor | The data, AD clear |
| `bogus` | The data should be signed and the proof fails | SERVFAIL with the extended error that names the fault, unless the client set CD, which gets the data with AD clear and the same extended error |
| `indeterminate` | No trust anchor covers the name | The data, AD clear, extended error 5 |
| `unvalidated` | Validation is off (Lab), or the answer was asked with CD and the walk would have had to ask | The data, AD clear |

The extended errors of a bogus answer (RFC 8914): 6 "DNSSEC Bogus" for a signature that does not verify and for a cost cap, 7 "Signature Expired", 8 "Signature Not Yet Valid", 9 "DNSKEY Missing" (no key matches the DS or the signature, or a sub-query failed), 10 "RRSIGs Missing" (an unsigned RRset in a secure zone), 12 "NSEC Missing" (a proof that is missing or fails), 27 for the NSEC3 iterations; 1 and 2 are reserved for an unsupported algorithm or digest where it makes a chain bogus rather than insecure. The answer's state is the worst of its parts: bogus before indeterminate before insecure before secure, so a CNAME chain that crosses into an unsigned zone is insecure. The query log carries the state as `validation` and the code as `ede`; `tenko_dns_validation_total{state,reason}` counts the outcomes with the reason of a bogus one (`signature`, `expired`, `not_yet_valid`, `missing_key`, `missing_rrsig`, `nsec`, `cap`, `algorithm`) and `tenko_dns_validation_verifications_total` the signature verifications.

A query with CD set still runs the validator, so that the cache entry other clients share has the right state, but it never waits for a DS or DNSKEY sub-query that the resolution itself did not need: when the walk would have to ask, the answer is relayed unvalidated and not cached.

### The cost caps

The KeyTrap class (CVE-2023-50387) is bounded by four caps: at most 8 signature verifications per RRset, 16 DNSKEY candidates per key tag, 4 NSEC3 hash computations per proof step (the closest encloser search, the wildcard check or a match) and 32 verifications per client query. Past a cap the answer is bogus with extended error 6 and counted under `reason="cap"`; a zone with sixty-four DNSKEY records whose tags collide with the signing key's is answered within the caps in the lab (`val.keytrap`, M38). A name more than four labels below its closest encloser in an NSEC3 zone is therefore not proven.

### Trust anchors and RFC 5011

The trust anchors are rows of `dns.trust_anchors`, one per zone, replicated like every DNS setting and in the `dns` subset of node sync. The root's row is made from the anchors shipped in the binary (the IANA file of RFC 7958, today the 2017 and 2024 keys with their validity windows, `tenko --version` prints them) the first time a controller leads, and replaced by a release's shipped set on upgrade while the stored set is still a shipped one; a row an operator or RFC 5011 changed is kept. An operator adds an anchor for a private zone with `tenko dns trust-anchor add <zone> --ds "..."` or `--dnskey "..."` (`POST /dns/trust-anchors`, scope `dns.keys`, an interactive session); the root's row is replaced only under the Lab profile (`--replace-root`), elsewhere `dns.trust_anchor.root_protected` refuses it. The validator reads the rows through the catalog; a change drops the key sets validated under the old anchors.

The leader service `dns.trust_anchors` runs RFC 5011 through the node's own resolver: at the active refresh interval (half the signature validity, at least an hour, at most 15 days) it asks the zone's DNSKEY set, validated with the current anchors. A new key with the SEP bit enters AddPend and is Valid after the add hold-down of 30 days when still there; a Valid key the set no longer holds is Missing (still trusted) and Valid again when it returns; a key with the REVOKE bit that signed the set is Revoked (no longer trusted), Removed after the remove hold-down, then forgotten. Every change is a row change audited as `dns.trust_anchor.state` and an event `dns.trust_anchor`; `POST /dns/trust-anchors/{zone}/refresh` (`tenko dns trust-anchor refresh`) asks now. `GET /nodes/{id}/dns/recursion` lists the keys with their states, `GET /system/status` warns `dns.trust_anchor.pending` while a key waits and `dns.trust_anchor.stale` when every key of a zone is revoked or pending: the node then fails validation for the zone rather than switching it off, and the operator adds the current anchor (or a release ships it). Under the Lab profile `[dns.recursion] rfc5011_hold_down_secs` makes the hold-downs seconds and the service's pace follows, so that the lab round `rfc5011` rolls the lab root's KSK in minutes. Tenko's own signer has no REVOKE step yet; the lab produces the roll with BIND's tools, and a Tenko-signed zone rolled by RFC 5011 is a follow-up.

RFC 8509's sentinel names (`root-key-sentinel-is-ta-<tag>` and `root-key-sentinel-not-ta-<tag>`) are answered on secure A and AAAA answers, fresh and from the cache: SERVFAIL where the tag is not (or is) a trusted root key. RFC 8145's signalling query `_ta-<tags>.` is sent to the root once a day when `trust_anchor_signalling` is on (the default; off under Hardened).

### Negative trust anchors

A negative trust anchor (`dns.ntas`, RFC 7646) names a zone whose failing validation is treated as insecure for a while: `tenko dns nta add <zone> --expires 2d --reason "..."` (`POST /dns/ntas`, scope `dns.keys`, an interactive session). It lives at most seven days; under Hardened an expiry is required. Creation and deletion are audited (`dns.nta.create`, `dns.nta.delete`) and so is the expiry, which the leader service writes (`dns.nta.expire`); while it lives it is a warning `dns.nta.active` of `GET /system/status` with its reason. Names at or below the zone are insecure instead of bogus; the root is never a negative trust anchor.

### The clock and the forwarders

A signature's validity window is checked against the node's clock (OPS-09). When the root's DNSKEY set fails as not yet valid or expired, the node status shows the problem `clock` and `GET /system/status` the warning `dns.validation.clock`: the clock is probably wrong (the other explanation is a bad anchor), and validation keeps failing loudly rather than switching itself off.

A forwarding rule's answers go through the same walk, with the DS and DNSKEY asked of the rule's upstream. An upstream that answers without the DNSSEC records of a secure zone makes its answers bogus with extended error 10; the rule is reported as `dns.forwarder.strips_dnssec` until it gives a secure answer again, and `validate = false` on the rule (`tenko dns forwarder update ... --validate false`, or the field in `PATCH /dns/forwarders/{id}`) is the escape. The lab's round `recursion` checks the forwarded answers through BIND as a recursive upstream and through a proxy that strips the records.
