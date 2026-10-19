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
