# Reconciliation: observations, proposals and adoption

This page describes how Tenko DDI keeps what its sources see apart from what IPAM intends, how the reconciler compares the two, and how a difference becomes a proposal that a person, or the adoption policy of a prefix, decides. It is for an operator who reviews proposals and for a developer who adds a source or a rule. It describes the behaviour of the `observe`, `reconcile` and `proposals` modules of the `tenko-ipam` crate and of the API routes on top of them; where this page and the code differ, the code is right. The decision behind the design is [ADR 0005](adr/0005-ipam-intent-hub.md), the requirements are IPAM-12 to IPAM-17, IPAM-19 and IPAM-21 in [REQUIREMENTS.md](REQUIREMENTS.md), and the summary is the section "IPAM as the intent hub" in [ARCHITECTURE.md](ARCHITECTURE.md).

Terms used below: **intent** is what IPAM records as wanted (hosts, interfaces, addresses, prefixes). A **source** is anything that reports observations: a connector instance, a probe, later the DNS and DHCP engines. A **fact** is one source's latest knowledge of one subject. A **proposal** is a suggested change of intent that the reconciler derives from facts and that waits for a decision.

Contents:

1. [Intent and observation](#1-intent-and-observation)
2. [The observation layer](#2-the-observation-layer)
3. [The reconciler](#3-the-reconciler)
4. [Proposals](#4-proposals)
5. [Decisions](#5-decisions)
6. [Adoption policies](#6-adoption-policies)
7. [Moves](#7-moves)
8. [What later sources add](#8-what-later-sources-add)
9. [Tables, endpoints and events](#9-tables-endpoints-and-events)
10. [The DNS actuator](#10-the-dns-actuator)
11. [The reconciliation view](#11-the-reconciliation-view)

## 1. Intent and observation

IPAM holds intent: host X has address Y in network Z, with an assignment mode, a DNS name and a VLAN (IPAM-12). Everything the sources report is stored in separate tables, the `ipam.obs.*` tables, and never overwrites intent. The reconciler reads both layers and keeps a list of proposals in step with the differences it finds (IPAM-13). The rules that follow from ADR 0005:

- **Observations never become intent by themselves** (IPAM-15). A person approves a proposal, or an adoption policy that a person set on a prefix applies it. Adopting every observation automatically was rejected in the ADR, because a rogue device would become intended state.
- **Intent wins for managed hosts** (IPAM-16). A disagreement with a `static` or `reserved` host is a warning for a person, never something a policy applies. A locked host gets no proposal that would change it, and an `unmanaged` host gets none at all (section 4.4).
- **Every change is a job and is audited** (IPAM-17). Approvals, rejections and adoptions run as inline one-step jobs, and every state change of a proposal writes an audit record (section 5.4).

The reconciler described here works from observation to intent: it proposes changes to intent. It does not call actuators. The direction from intent to DHCP and DNS belongs to the move job today (section 7) and to the Tenko DNS and DHCP engines later (section 8).

## 2. The observation layer

### 2.1 Sources and keys

An observation names its source. Tenko turns the source into a canonical text, the **source key**, which is the first part of every fact key.

| Source | Source key | Delivered by |
|---|---|---|
| Inventory connector | `inventory:<connector id>` | The connector host (Phase 1) |
| Network controller connector | `network_controller:<connector id>` | The connector host (Phase 1) |
| Probe | `probe:<node>:<method>`, method one of `arp`, `nd`, `icmp`, `tcp_connect`, `reverse_dns`, `mdns`, `llmnr`, `snmp`, and the declared raw-socket methods `arp_sweep`, `tcp_syn`, `os_fingerprint`, `lldp` | Probes (WP2.3, see [scanning.md](scanning.md)) |
| DNS zone | `dns:<zone>` (the parent zone for an RFC 2317 zone) | The reconciler, from the zones in the store (Phase 2, section 10) |
| DHCP node | `dhcp:<node>` | The `dhcp` role, in the batch of every lease change (Phase 3, [dhcp.md](dhcp.md) section 12.3) |

A probe method is part of the key, so the ARP and the ICMP sightings of one probe are different sources with separate facts.

### 2.2 Facts

A fact is stored once per source and subject, under the key (source key, subject key). The subject is the source's own identity of the thing it reports; two reports of one subject by one source are the same fact, refreshed. Facts of different sources about the same device are never merged. The picture across sources is computed when it is read (section 2.5).

| Subject type | Subject key | Reported by | What the fact names |
|---|---|---|---|
| `host` | `host:<external id>` | Inventory connectors | Name, MAC addresses, IP addresses, OS, platform, parent host, tags |
| `address` | `address:<vrf>/<ip>` | Probes, DHCP leases | The address, the MAC address behind it when known, and the VRF of the source; for a lease the client's MAC address, `last_seen` the client's last transaction and `expires_at` the end of the binding (for a conflict, the MAC address that answered the probe, if any, until the hold ends) |
| `attachment` | `attachment:<mac>` | Network controllers, SNMP probes | The client's switch or access point, port, SSID and VLAN |
| `services` | `services:<ip>` | Probes | Open TCP ports, and the ones that answered a TLS handshake (SCAN-08) |
| `os` | `os:<ip>` | Probes | An OS guess and its confidence (SCAN-08) |
| `name` | `name:<ip>` | Probes, network controllers, DHCP leases | A name found for an address (reverse DNS, mDNS, LLMNR, the `sysName` of a polled device, the name of a client on a network controller, or the FQDN of option 81, else the host name of option 12, of a lease). It is not a sighting of the address |
| `vendor` | `vendor:<mac>` | Probes, network controllers, inventory connectors | The vendor of a MAC address: the organization its OUI is registered to, the vendor a network controller reports for a client, or the manufacturer an inventory source reports for a device |
| `link` | `link:<device>\|<port>\|<device>\|<port>\|<kind>` | Network controllers, SNMP probes | A link between two devices (IPAM-20); the same fact whichever end the source names first |

A fact carries the source and the subject (as structure and as canonical text), `observed` (the latest report with every attribute the source gave), `observation` (the observation that first reported the fact or last changed its attributes), `first_seen` and `last_seen` (the source's own times), `received_at` (when Tenko last wrote the fact), `expires_at`, `sightings` with `counted_at` (the number of counted sightings and the source time of the last one), and the store `revision`. A fact is **current** while `expires_at` is empty or in the future. Expired facts stay readable until retention removes them (section 2.4); the reconciler's rules use current facts only.

**Lease facts.** The facts of `dhcp:<node>` do not come through ingest (section 2.3): the `dhcp` role writes them in the batch of the lease change itself, with ingest's rules (a fact is written when it is new, when an attribute changed, when it had expired or when its refresh is due; a renewal within the refresh interval writes nothing), and a release, a decline or an operator's release expires them in that batch. A binding that runs out needs no write: its facts expire with it. The role keeps the facts of its source in a derived index so that it never reads the store while it builds a batch; [dhcp.md](dhcp.md) section 12.3 has the details.

### 2.3 Ingest

Ingest turns one batch of observations of one source into changes to that source's facts. It is written as one batch by `system:reconciler` with the audit action `ipam.observation.ingest`. The rules keep a quiet network from rewriting its facts on every poll:

- A subject seen for the first time is a new fact with one sighting. A host observation with an empty external id is refused and counted as skipped.
- A known fact is written again only when its attributes changed, when it had expired, or when a refresh is due. A refresh is due when the source's time has passed the last sighting by the refresh interval (15 minutes), or when the stored lifetime has less than half of a fresh lifetime left, so that a fact never lapses between two polls. Otherwise the report counts the fact as unchanged and writes nothing, so a repeated poll of an unchanged inventory writes nothing at all.
- A sighting is counted at most once per refresh interval. Counted sightings are what the adoption constraint `min_sightings` measures.
- A **complete** batch is the source's whole picture. The facts of the batch's source that it no longer reports expire at once (their `expires_at` becomes the receive time), even when the batch is empty. Observations of other sources inside the batch are ingested but never expired by it. Facts are not deleted here.
- Two observations of one subject inside one batch: the later one by source time wins, and for equal times the later position.
- Every fact write expects the revision it read. A concurrent writer makes the ingest read again with linearizable consistency and retry, up to 8 attempts, then it fails with `ipam.contended`.

The report of an ingest counts `new`, `changed`, `refreshed`, `unchanged`, `gone` and `skipped` facts and carries the revision of the write, which is empty when nothing was written. The audit record names the source and the counts.

### 2.4 Retention

Facts whose last sighting is older than the retention (30 days by default, section 3.1.1) are deleted together with their index rows, at most 2,000 per batch, with the audit action `ipam.observation.purge`. The same pass deletes the last sightings of intent objects that no longer exist (section 2.6). A batch that loses a race with an ingest is skipped, and the next pass takes what is still old. The leader runs the purge every hour by default. Because expiry and deletion are separate, a device that vanished stays visible as an expired fact for 30 days after its last sighting.

### 2.5 The computed view

`GET /api/v1/observations/{subject}` computes the picture of one subject across all sources. The subject is a MAC address (`00:00:5e:00:53:01` or `00-00-5E-00-53-01`), an IP address or a name; a name is compared as a whole and without case, and inventory hosts and the `name` facts of probes have names. The answer has four parts:

- **`facts`**: every fact that names the subject, found through the index tables, current facts first and then by last sighting, newest first.
- **`summary`**: whether any fact is current, the sources with a current fact, the first and last sighting, and the sorted, de-duplicated MAC addresses, IP addresses, names, operating systems, platforms, parent hosts, open TCP ports, the open TCP ports that answered a TLS handshake (`tls_tcp`), vendors, attachments (one per source and MAC address) and tags. It draws on the current facts, or on all facts when none is current.
- **`intent`**: the live hosts, interfaces, addresses and VRFs that match. Interfaces match by MAC address, addresses by IP address in any VRF, hosts by name and through their interfaces.
- **`sightings`**: the last sightings of the matching addresses and interfaces (section 2.6).

A subject that no fact names answers 404 `ipam.not_found`; a subject that cannot be one (empty, over 253 characters or with control characters) answers 400 `ipam.validation`.

`GET /api/v1/observations` lists the facts themselves. The filters are `source` (a source key, or a connector id, which matches both the inventory and the network controller source of that connector), `type` (a subject type from section 2.2), `mac`, `ip`, `within` (a network, matching facts that name an address inside it), `q` (case-insensitive text over the subject key, name, OS, platform, parent, tags and attachment device) and `current` (`true` for current facts, `false` for expired ones). `sort` takes `last_seen`, `first_seen`, `source` and `subject` with a leading `-` for descending, and defaults to `-last_seen`. Paging uses `limit` (1 to 1,000, default 100), `cursor` and `at_least` like every list.

### 2.6 Last sightings of intent

The table `ipam.obs.last_seen` records when an address or an interface of intent was last matched by a current fact: the time of the sighting, the source key and the observation behind it. The reconciler writes it during a run, not at ingest, and at most once per object and refresh interval. An address is matched by a fact that names its IP address in its VRF, an interface by a fact that names its MAC address. The orphan rule (section 4.7) reads these records, and the computed view returns them.

### 2.7 What the connector host hands over

The connector host (`tenko-connect`) normalizes what a plugin reports before it reaches the observation layer, with these rules:

- An inventory batch becomes one `host` observation per host, with sorted and de-duplicated MAC and IP addresses and de-duplicated tags, and one `vendor` observation per MAC address the batch reports a vendor for (the last report of a MAC address wins). A network controller topology becomes one `attachment` observation per client, one `vendor` observation per client with a vendor, one `name` observation per client with a name and an address, and one `link` observation per link, always as a complete batch.
- The batch keeps the source's time, unless that lies more than five minutes ahead of the host's clock. Then the host's receive time is used and a warning is recorded.
- Every observation expires three poll intervals after it was received, but not sooner than 15 minutes.
- Every batch names its source, so a complete batch with no observations still tells which facts are gone.

The server hands the batches to the reconciler through a function sink (`sink_fn`), which calls `Reconciler::ingest`. Without a reconciler the host uses a sink that discards the observations and records only their counts. A sink that returns an error makes the connector run fail.

## 3. The reconciler

### 3.1 When it runs

The loop and the purge are the leader service `ipam.reconcile`: they run on the controller that leads and nowhere else (on a single controller, at once). A run starts:

- right after the controller takes office, and then on an interval (every 5 minutes by default);
- 2 seconds (the debounce) after an ingest that wrote something, on whichever controller it happened: an ingest on a follower reaches the leader as a write to `ipam.obs.facts`, and the leader watches that table (the lease facts of the `dhcp` role make a light run, below);
- 2 seconds after a change to the intent tables, to a reverse template or to an adoption policy, including a change a person just made by approving a proposal;
- 2 seconds after a change to the DNS zones or records (`dns.zones`, `dns.rrsets`), so that a hand-deleted `ipam` record comes back (section 10), except a change of DHCP's names alone (below);
- on demand with `POST /api/v1/proposals/reconcile` (section 5.3), on the controller that answers.

**DHCP's changes.** Which change sets schedule a run, and what the run does, follows from what changed (`tenko_ipam::reconcile::signal`):

| A change set of | Schedules | The rules (step 3) | The DNS steps read the zones again |
|---|---|---|---|
| RRsets of the origin `dhcp` only (the DDNS worker's A, AAAA, DHCID and PTR sets with the zone's SOA serial step; a deletion counts as DHCP's when the `dhcp` role, `system:dhcp`, wrote the change set) | nothing | | |
| facts of the sources `dhcp:<node>` only (the lease facts the `dhcp` role writes with a lease change) | a light run | no: the waiting moves are confirmed (section 7), the rest waits for the periodic run | no |
| other facts (an ingest of a probe, a connector, the zones' records) | a run | yes | no |
| the intent, a reverse template, an adoption policy | a run | yes | the plan only (not for a policy) |
| an RRset of any other origin (a hand-written or an `ipam` set, also beside DHCP's in the same change set), a zone | a run | yes | yes |

The zones' facts take `ipam` and `manual` records only (section 10), the lease facts come with the lease change itself ([dhcp.md](dhcp.md) section 12.3) and the DNS actuator writes `ipam` sets only, so DHCP's names give a run nothing to do: a DHCP record is no DNS fact, and the name of a lease shows in the reconciliation view as the lease's own `name` fact. A busy DHCP server writes lease facts with up to a thousand commits a second; each of them used to start a run of the rules over every fact within the debounce, so the proposals for its clients (a discovered host per unknown device) wait for the periodic run instead, while a move that waits for a lease is still confirmed within the debounce. A run of the rules records the change epoch it ran at whether its write succeeded or not, so a failed pass is tried again by the next change of another kind or the periodic run, not by every lease. A run whose DNS inputs did not move since the last run that read them takes over that run's facts of the zones and its DNS findings, and skips the actuator when its last run wrote everything it planned (the report then shows the actuator with nothing written). The SOA set and the signer's rows are read by no step. The periodic run, the first run after taking office and the run on demand always do everything, so what this leaves out (a DHCP name that took over a record of another origin under `replace`) is seen within the interval. M31's stand-in measured the difference (`bench/phase3-dhcp/results/2026-10-22-m31-ddns.md`).

The service also purges old facts on its own timer (every hour by default). Its writes carry the leader epoch as a precondition, so a controller that lost the leadership commits nothing more; it stops when the leadership moves, and the new leader runs at once. Ingest stays on every controller.

### 3.1.1 Settings

The settings are the same on every controller: they live in the store (`ipam.reconciler_settings`), replicate, and are changed through the API with audit. There is no `[reconciler]` section in `tenko.toml`. The `ipam` start step seeds the table from the defaults when it is empty, and the reconciler reads the settings at every run, so a change applies at the next run (a new interval from the next wait) without a restart.

| Setting | Default | Limits | Meaning |
|---|---|---|---|
| `interval_secs` | 300 (5 minutes) | 30 to 86,400 | Interval of periodic runs |
| `debounce_secs` | 2 | 0 to 300 | Delay of a run after an ingest or an intent change |
| `orphan_after_secs` | 604,800 (7 days) | 3,600 to 31,536,000 | How long an address that was seen may go unseen before it is proposed as orphaned |
| `retention_secs` | 2,592,000 (30 days) | 86,400 to 31,536,000 | How long a fact is kept after its last sighting (section 2.4) |
| `refresh_secs` | 900 (15 minutes) | 60 to 86,400, and shorter than the retention | Refresh interval of an unchanged fact, and the shortest interval between two counted sightings |
| `purge_interval_secs` | 3,600 (1 hour) | 300 to 86,400 | Interval of retention purges |
| `adopt` | on | | Whether adoption policies are applied; off means every proposal waits for a person |
| `dns_actuator` | on | | Whether the DNS actuator writes after every run while the DNS module runs (section 10); off, its findings are still proposed |
| `dns_orphans` | `remove` | `remove`, `propose` | What happens to an `ipam` RRset whose address lost its name or its intent: deleted, or kept and proposed |

`max_attempts` (8 repeats of a run or an ingest that loses races with other writers) is a constant of the code, not a setting.

`GET /api/v1/settings/reconciler` (`get_reconciler_settings`) returns the settings with an `ETag`; `PUT /api/v1/settings/reconciler` (`update_reconciler_settings`) replaces all of them, honours `If-Match` (409 when stale), refuses a value outside its limits with 422 `ipam.reconciler.settings.invalid` (parameter `field`), and is audited as `ipam.reconciler.settings.update` with one change per field. Both are for administrators only. The settings page in the web UI comes with a later release; until then the API is the way to change them.

### 3.2 What a run does

1. It reads one consistent view: the live intent, every fact, the open proposals, the remembered rejections, the adoption policies and the last sightings.
2. It brings the last sightings of addresses and interfaces up to date from the current facts.
3. It evaluates the rules (section 4) and writes the proposals accordingly: it opens new proposals, refreshes unchanged ones, supersedes changed ones and expires those that no longer hold. Steps 2 and 3 are written by `system:reconciler` in batches under the store's batch limit (`max_batch_bytes`, 16 MiB by default, read from the store): the sightings and then the proposals in subject-key order, each proposal's rows complete in one batch, so that any prefix of the batches leaves the tables consistent and the next run writes what is left. A run that fits writes one batch; a run that opens tens of thousands of discovered hosts (a DHCP server's unknown clients) writes several, each filled to three quarters of the limit. Every batch carries the leader's epoch, and the last one the run's audit record `ipam.reconcile.run` (the batches, the proposal rows and sightings written, the items not written). A batch the store refuses is tried once more as two halves; what fails again is counted on the report as `unwritten` with the error code, the run goes on with the next batch, and the next run writes those items. A run that finds nothing to change writes nothing.
4. It applies the open proposals that an adoption policy covers (section 6), each in its own inline job.
5. With the DNS module, the DNS actuator writes the records of the intent and keeps the reverse zones (section 10). Its findings joined the rules of step 3, from the same view; the DNS records were ingested as observations before step 1.
6. It completes the observation step of move jobs when a current fact shows the device at its new address (section 7).

The answer of a run, `ReconcileReport`, counts `opened`, `refreshed`, `unchanged`, `superseded`, `expired`, `suppressed` (subjects not opened again because a person rejected the same evidence), `adopted`, `adoption_failures`, `sightings` (last sightings written) and `moves_confirmed`, carries the `revision` of the proposal write (its last batch), `batches` (how many the write took; 0 when nothing changed), `unwritten` (proposal writes and sightings a batch failed twice on, for the next run) and `failure` (the error code of the last failed batch), and with the DNS actuator `dns`: `zones_created`, `zones_adopted`, `rrsets_changed`, `batches`, the `failures` (zone, code, detail) and the `revision` of its last write.

### 3.3 Where an observed address belongs

Every rule first places each address that a current fact names. A fact names an address through an `address`, `host`, `services` or `os` fact; an attachment names only a MAC address, and a link names nothing. Addresses that IPAM does not track are ignored: loopback, link-local, multicast and unspecified addresses, and the IPv4 broadcast address. A `host` fact with exactly one MAC address pairs it with each of its addresses. With several MAC addresses the pairing is unknown, so each MAC address and each address stands alone.

| Placement | Meaning |
|---|---|
| In a network | A prefix with the role `network` in the VRF contains the address; the most specific one counts |
| Outside | The VRF is known but no network prefix contains the address. A supernet does not count as a network |
| Unplaced | Several VRFs have a network for the address and the source names none, or no network contains it and there is no default VRF. No rule produces anything for it |

The VRF comes from the source when the source names one, as probe `address` facts do. Otherwise Tenko looks at the VRFs that have a network containing the address: if there is exactly one, the address belongs there; if there is none, it is outside in the default VRF (the VRF `default` of the tenant `default`, or the only VRF), and unplaced when there is no default VRF; if there are several, it is unplaced.

### 3.4 Concurrency

- Runs never overlap on one controller; a run waits for the one before it.
- Every row a run reads carries its revision as a precondition of the write: the proposals, the open-key rows, the remembered rejections and the sightings. When a concurrent writer invalidates a batch, the batches before it stay, and the run reads again with linearizable consistency and repeats for what is left, up to `max_attempts`, then fails with `ipam.contended`; a proposal an earlier pass of the run wrote is counted once. At most one proposal per subject key is open, because opening one expects the open-key row to be absent or unchanged.
- In a cluster only the leader runs the loop (section 3.1). A run on demand on another controller and the leader's run are kept apart by the same preconditions; the leader's writes also carry its epoch.

## 4. Proposals

### 4.1 Fields

| Field | Meaning |
|---|---|
| `id`, `revision` | Identifier; the store revision, which is the `ETag` and the `If-Match` value of decisions |
| `kind`, `rule`, `key` | The kind (`discovered_host`, `orphaned_intent`, `address_mismatch`, `conflict` or `outside_prefixes`), the stable code of the rule such as `ipam.reconcile.discovered_mac`, and the subject key (section 4.3) |
| `severity`, `state` | `info`, `warning` or `critical`; and the state of section 4.2 |
| `subject` | What it concerns: `mac`, `ip`, `cidr`, `vrf`, `prefix` (the most specific network of the address), `name` and the intent `objects` involved |
| `summary`, `params` | A one-line English summary and the named values it was built from; the UI translates the rule with `params` |
| `evidence` | The facts behind it, one entry per fact and pair: source, subject key, observation, MAC address, IP address, name, first and last sighting, counted sightings |
| `commands`, `fingerprint` | The IPAM commands an approval applies (empty for conflicts and some mismatches); SHA-256 over the kind, the key, the evidence identities and the shape of the suggestion |
| `created`, `updated`, `decided`, `reason` | Times, who decided and when, and the rejection or expiry reason |
| `adopted_by`, `results`, `superseded_by`, `adoption_error` | The prefix whose policy adopted it, the objects its commands created or changed, the proposal that replaced it, and the error code of a failed adoption |

### 4.2 States

| State | Reached by | `decided` |
|---|---|---|
| `open` | The reconciler opens it | Empty |
| `accepted` | A person approves it, or a policy adopts it. The commands were applied and `results` lists the objects | The person, or `system:reconciler` with `adopted_by` set |
| `rejected` | A person rejects it. The evidence is remembered | The person, with the reason |
| `expired` | The rules no longer produce its key: the device is gone, intent caught up, or the host was locked or deleted | `system:reconciler`, with the reason "the observation behind it no longer holds" |
| `superseded` | The rules produce the same key with other evidence or commands, so a newer proposal replaced it. `superseded_by` names the newer one | `system:reconciler` |

Only an open proposal can be decided. The other states are final and the proposals stay in the table; a list returns all states unless `state` limits it.

### 4.3 Subject keys, fingerprint and rejection memory

The subject key makes a proposal unique among the open ones. The rules produce these keys:

| Rule | Key |
|---|---|
| `discovered_mac` | `discovered_host/mac:<mac>` |
| `discovered_address` | `discovered_host/ip:<vrf>/<ip>` |
| `address_unrecorded`, `address_mismatch` | `address_mismatch/interface:<interface>/<vrf>/<v4 or v6>` |
| `orphaned_address` | `orphaned_intent/address:<address id>` |
| `conflict_shared_address` | `conflict/shared:<vrf>/<ip>` |
| `conflict_networks` | `conflict/networks:<mac>/<v4 or v6>` |
| `conflict_address_taken` | `conflict/taken:<address id>` |
| `outside_prefixes` | `outside_prefixes/<vrf>/<cidr>` |

The fingerprint covers what the proposal says, not when or with which generated identifiers: times, sighting counts and the identifiers of objects the commands would create do not count. Each run compares the candidate for a key with the open proposal of that key:

- **Same fingerprint:** the proposal is kept. Its evidence, summary, parameters and severity are rewritten only when the newest sighting is at least a refresh interval later or the sighting count grew; otherwise nothing is written.
- **Other fingerprint:** the open proposal becomes `superseded` and a new one is opened in the same batch.
- **No candidate:** the open proposal becomes `expired`.

**Rejection memory.** A rejection stores the fingerprint under the subject key. While the rules produce the same fingerprint for that key, the subject is not opened again and the run counts it as suppressed. When the evidence changes, the proposal opens again and the stored rejection is forgotten. A rejected conflict therefore stays quiet until the conflict looks different.

**Host names.** A discovered host takes the first usable name any source gives, lowercased, with characters outside `a-z`, `0-9`, `-`, `_` and `.` replaced by `-` ("Web 01" becomes `web-01`). Without a name it is `host-<mac without separators>` or `host-<address with dashes>`. When the name is taken in the default tenant, or promised by another open proposal, a suffix `-2`, `-3` and so on is added.

### 4.4 Precedence: intent, lock and unmanaged

- **Intent wins for managed hosts** (IPAM-16). An observation never changes a host by itself. When it disagrees with a `static` or `reserved` host, the proposal is a warning and only a person can apply it. When the host is `dynamic`, where IPAM only observes (IPAM-14), the disagreement is `info` and a policy with `adopt_all` may apply it.
- **Locked hosts get no proposal that would change them.** The address rules (section 4.6) and the orphan rule skip a host with `lock` set, and the open address proposals of a host that is locked later expire at the next run. Conflicts carry no commands and change nothing, so they are still raised for a locked host. As a second line of defence the planner treats `system:reconciler` as automation and refuses a locked host with 423 `ipam.host.locked`. The lock stops automation, not people: a person who approves a proposal is not refused.
- **`unmanaged` hosts get nothing.** No mismatch or orphan concerns them, no conflict is raised about a MAC address or an intended address that belongs to one, and a MAC address that any live interface carries is never proposed as a new host. An address seen only from the MAC address of an `unmanaged` host does not suggest a network either (section 4.9).

### 4.5 Discovered host

A discovered host is a device that no intent knows. There are two rules, both with severity `info`.

- **`ipam.reconcile.discovered_mac`:** a MAC address that a current fact names and that no live interface of intent carries, whatever the host's mode or lock. A MAC-only fact, such as an attachment from a network controller, qualifies and gives a proposal for a host without addresses. The addresses seen with the MAC that lie in a known network are added: an address that IPAM has no record of in that VRF is created, and an address that IPAM has but nobody holds (no interface, or an interface without a live host) is bound to the new interface. Addresses outside every network, unplaced, or held by another host are left out. When the MAC has addresses and none of them can be created or bound, there is no proposal, because the outside and conflict rules speak first.
- **`ipam.reconcile.discovered_address`:** an address in a known network that a current fact names without any MAC address, that no other fact pairs with a MAC address, and that intent has no record of in that VRF.

The suggested commands create a host with the suggested name, the assignment mode `dynamic` and the tag `discovered`, an interface `eth0` carrying the MAC address (when there is one), and the addresses. A person's approval applies them as they are; a policy may set another `host_mode` (section 6).

### 4.6 Address unrecorded and address mismatch

Both rules concern a device whose MAC address belongs to an interface of intent. They are evaluated per interface, VRF and address family, for observed addresses that lie in a known network of that VRF. Nothing is raised when the interface's intended address in that VRF and family is among the addresses seen, when the host is locked or `unmanaged`, or when every observed address already belongs to a host (that is a conflict, section 4.8). Both rules share the kind `address_mismatch`.

| Rule | When | Severity | Suggested commands |
|---|---|---|---|
| `ipam.reconcile.address_unrecorded` | The interface has no intended address in this VRF and family | `info` | Add the observed address to the interface: create it, or bind it when IPAM has it unassigned |
| `ipam.reconcile.address_mismatch` | The interface has exactly one intended address and it is not seen | `warning`, `info` for a `dynamic` host | Renumber the intended address to the observed one. None when the observed address exists in intent already without a host |
| `ipam.reconcile.address_mismatch` | The interface has several intended addresses and none is seen | `warning` | None |

When several addresses are seen, the proposal names the first in address order.

### 4.7 Orphaned intent

`ipam.reconcile.orphaned_address` proposes to deprecate an active address that a source saw before and that no source has seen for the orphan age (7 days). It needs a recorded sighting, so an address that was never seen is never proposed. The address must be `active`, and its host, if it has one, must be neither locked nor `unmanaged`; an address without a host qualifies. The severity is `info`. The proposal has no evidence, since the evidence is an absence; `params` hold the last sighting, its time and its source, and the suggested command sets the status of the address to `deprecated`.

The rule measures time since the last sighting by any source, and it tells "gone" from "not scanned" with the scopes the probes apply (`scan.scopes`, see [scanning.md](scanning.md)): an address is proposed only when a probe scope covers it, that is a probe that is not stopped, whose VRF is the address's VRF or that names none, with a prefix that contains the address and no exclusion that does. An address outside every applied scope is "not scanned" and gets no proposal, however long it went unseen. With no probe scope at all, every address counts as scanned, as before probes reported scopes. A connector that stops reporting still ages the addresses it alone saw into orphans when a probe covers them.

### 4.8 Conflicts

A conflict is a contradiction between observations, or between an observation and intent (IPAM-23). Conflicts carry no commands, because the cause is a device or a decision that IPAM cannot settle. A person resolves the cause and then rejects the proposal to close it; approving one answers 409 `ipam.proposal.nothing_to_apply`. A conflict whose cause disappears expires by itself.

| Rule | When | Severity |
|---|---|---|
| `ipam.reconcile.conflict_shared_address` | Current facts pair two or more MAC addresses with one address in one VRF. Not raised when all of them are interfaces of one known host | `critical` |
| `ipam.reconcile.conflict_networks` | One MAC address is seen with addresses of one family in two or more networks, and not all of those networks are the networks of the addresses intended for its interfaces | `warning` |
| `ipam.reconcile.conflict_address_taken` | An address that intent assigns to an interface with a MAC address is seen with a MAC address that belongs to none of that host's interfaces | `warning` |

A probe keeps one fact per address and method, so a second device on the same address shows up there only through another method or another source.

### 4.9 Outside known networks

`ipam.reconcile.outside_prefixes` proposes a network for addresses seen outside every known network of their VRF (section 3.3). The suggested network is the /24 (IPv4) or /64 (IPv6) around the address, made longer until it contains no prefix that exists in the VRF; prefixes that contain it, such as a supernet, do not block it. Addresses inside a network already suggested in the same run join its proposal. Sightings from the MAC address of an `unmanaged` host are left out. The severity is `warning`, and the suggested command creates the prefix with the role `network` and the tag `discovered`. Such an address produces no discovered-host proposal until its network exists; after the network is approved, the next run proposes the hosts.

## 5. Decisions

### 5.1 Approve

`POST /api/v1/proposals/{id}/approve` needs the right `approve` on proposals and, for each command of the proposal, the right that command needs on its own (for example `create` on hosts and addresses). It takes:

- `dry_run=true`: plans the commands and answers with the plan and the warnings, and writes nothing.
- `acknowledge=<code>,...`: acknowledges plan warnings, exactly like any other change. A warning that needs it and does not get it answers 409 `ipam.plan.unacknowledged`.
- `If-Match: "<revision>"`: the `ETag` of the proposal. A proposal that changed since answers 412 `ipam.proposal.revision_mismatch`.

The commands are planned as the approving person with the same planner and checks as any other change, so a taken name answers 409 `ipam.name_taken` and so on. The commands, the proposal's new state (`accepted`, `decided`, `results`), the removal of its open-key row and all audit records then commit in one batch inside one inline job (`job_id` in the answer): all of it or nothing. If the intent changed between planning and writing, Tenko plans again. A decided proposal answers 409 `ipam.proposal.not_open`. A proposal without commands answers 409 `ipam.proposal.nothing_to_apply`; reject it once it is resolved.

### 5.2 Reject

`POST /api/v1/proposals/{id}/reject` needs `approve` on proposals. The body is `{"reason": "..."}` and the reason is optional: it is trimmed, a blank reason counts as none, and it has at most 1,024 bytes and no control characters other than line breaks and tabs (400 `ipam.validation` otherwise). `If-Match` works as for approval. The proposal becomes `rejected`, and the rejection memory (section 4.3) is written in the same batch inside an inline job.

### 5.3 Run now

`POST /api/v1/proposals/reconcile` needs `approve` on proposals and runs the reconciler once, now, on the server that answers. It returns the report of section 3.2. A server without a reconciler answers 503 `ipam.reconciler.unavailable`.

### 5.4 Audit actions

| Action | Written when | By |
|---|---|---|
| `ipam.observation.ingest` | An ingest wrote something; records the source and the counts | `system:reconciler` |
| `ipam.observation.purge` | Retention deleted facts or stale sightings | `system:reconciler` |
| `ipam.reconcile.run` | A run wrote something; records `batches`, `proposals` (rows written), `sightings` and `unwritten` (section 3.2) | `system:reconciler` |
| `ipam.proposal.open` | A proposal was opened | `system:reconciler` |
| `ipam.proposal.supersede` | A proposal was replaced by a newer one | `system:reconciler` |
| `ipam.proposal.expire` | A proposal expired | `system:reconciler` |
| `ipam.proposal.approve` | A person approved; names the proposal and the objects changed | The person |
| `ipam.proposal.reject` | A person rejected; records the reason | The person |
| `ipam.proposal.adopt` | A policy applied a proposal; records `policy_prefix` | `system:reconciler` |
| `ipam.proposal.adopt_failed` | A policy's attempt failed; a failed record with the error | `system:reconciler` |
| `ipam.adoption.set` | A person set a policy; records the old and the new value | The person |
| `ipam.adoption.clear` | A person removed a policy; records the old value | The person |

## 6. Adoption policies

A prefix can carry an adoption policy that lets the reconciler apply some proposals without a person (IPAM-15, "auto-adopt in network Z"). Adoption is on by default; the `adopt` setting of the reconciler switches it off for a server, and then every proposal waits for a person. An example policy:

```json
{
  "mode": "adopt_hosts",
  "only_dhcp_pools": true,
  "vendors": ["00:00:5e"],
  "min_sightings": 2,
  "host_mode": "dynamic"
}
```

### 6.1 Fields and modes

| Field | Meaning | Default |
|---|---|---|
| `mode` | What is adopted: `manual`, `adopt_hosts` or `adopt_all` | `manual` |
| `only_dhcp_pools` | Every address the commands create, bind or renumber to must lie in a DHCP pool of its network | `false` |
| `vendors` | Only devices whose vendor matches one entry (section 6.2). At most 32 entries of 1 to 64 characters; empty means any vendor | empty |
| `min_sightings` | Only after one source counted this many sightings of the device, 1 to 1,000 | 1 |
| `host_mode` | The assignment mode of the hosts that adoption creates | `dynamic` |

Unknown fields are refused. An invalid value answers 400 `ipam.adoption.invalid` and names the field.

| Mode | Adopts |
|---|---|
| `manual` | Nothing; every proposal waits for a person |
| `adopt_hosts` | Discovered-host proposals that carry a MAC address |
| `adopt_all` | Discovered-host proposals with or without a MAC address, and the address proposals of hosts that are all `dynamic` and not locked |

The policy that decides is the one in force for the proposal's prefix, the most specific network of its address. A proposal without a prefix, such as a discovered host that has only a MAC address, is never adopted.

### 6.2 Constraints

All constraints must hold.

- **`only_dhcp_pools`:** the proposal must have address commands, and each of their addresses must lie in a range with the role DHCP pool in its network.
- **`vendors`:** an entry that is an OUI (`00:00:5e`, `00-00-5E` or `00005e`) matches the first three octets of the device's MAC address. Any other entry is text, compared without case with a vendor name that a source reports. The vendors come from the current `vendor` facts of the device's MAC address, from any source: the OUI table of a probe, the vendor a network controller reports for a client, and the manufacturer an inventory such as Home Assistant reports for a device. One matching entry and one matching vendor are enough.
- **`min_sightings`:** the most counted sightings among the evidence. A sighting counts at most once per refresh interval, so three sightings take at least 30 minutes.

### 6.3 Inheritance

The policy in force for a prefix is its own, else the one of the nearest prefix of the same VRF that contains it and has one, else the default `manual`. A nearer policy replaces a farther one as a whole; policies are not merged. A prefix can set `manual` to opt out of a policy above it.

`GET /api/v1/prefixes/{id}/adoption` returns `policy` (the prefix's own, `null` when it inherits), `updated`, `effective` (the policy in force) and `source` (the prefix it comes from, `null` for the default). `PUT` sets the own policy, with the policy as the body, and `DELETE` removes it so that the prefix inherits again; both answer with the same view. The `ETag` and the `If-Match` value are the revision of the prefix's own policy, and `"0"` means that the prefix has none. A stale value answers 412 `ipam.revision_mismatch`. A deleted prefix answers 409 `ipam.object_deleted`. Setting the policy a prefix already has changes nothing. A change runs as an inline job and a run follows within the debounce interval, which applies the new policy to the proposals that are open.

### 6.4 What is never adopted

Whatever the mode, a policy never adopts conflicts, orphaned intent or outside-prefix proposals, address changes of `static` and `reserved` hosts (intent wins), anything that touches a locked or `unmanaged` host, a proposal with no commands, a proposal without a prefix, or a proposal whose last adoption failed.

### 6.5 Failures

Each adoption is planned and applied like an approval, as an inline job, by the principal `system:reconciler`. The planner treats that principal as automation, so a lock refuses it with 423 `ipam.host.locked`. A successful adoption sets the state `accepted`, `decided` to `system:reconciler` and `adopted_by` to the prefix whose policy applied, and writes `ipam.proposal.adopt`.

When the planner refuses, the proposal stays open. Its `adoption_error` holds the error code (for example a reservation inside a DHCP pool, when the policy's `host_mode` is `reserved`), the audit action `ipam.proposal.adopt_failed` records the refusal, and the run counts an adoption failure. The policy does not try that proposal again: a person decides it, or a change of evidence supersedes it with a new proposal that the policy may try. The failure is recorded once, not on every run.

## 7. Moves

The device move job (IPAM-19) waits for the device to show up at its new address. Its observation step, `ipam.move.observe`, is a manual task, so a person can still confirm it. The reconciler confirms it as `system:reconciler`, with a note such as "198.51.100.10 seen at 2026-10-10T08:00:00Z by inventory:<connector id>", when an observation meets all of these conditions:

- The job is waiting at its observation step. A sighting that arrives while the job still waits for an earlier manual task, such as the layer 2 change, cannot confirm anything yet; the next run confirms it from the facts that are still current.
- It names the move's new address in the target VRF. The VRF is the source's own, or is placed as in section 3.3. A DHCP lease fact (`dhcp:<node>`) counts at any address of the target network, because a dynamic device gets an address of the pool rather than the planned one; it must come from the interface's MAC address.
- It comes from the MAC address of the moved interface, when the interface has one. A sighting of another device at that address does not count.
- It was reported at or after the start of the job. A sighting from before the move does not count.

The reconciler checks this at ingest, so a waiting move completes as soon as the batch arrives, and again in every run, which also covers facts that arrived earlier. The step completes and the job goes on to its cleanup step. When the observation timeout of the move passes first, the job rolls back and the moved object is tagged `move-failed`.

Independently of moves, `Reconciler::ingest` hands the addresses of the ingested observations to the job engine's observation wake-up (`JobEngine::on_observation`), for steps that wait for an observation. It does so only when at least one job is waiting. Each address of a `host`, `address`, `services` or `os` observation is handed over as an `address` observation in its placed VRF, with the MAC address when the observation names exactly one; attachments and links are not handed over. The engine wakes the steps whose conditions match: `AddressSeen` now, and `LeaseInPrefix` once Tenko DHCP reports leases.

## 8. What later sources add

| Source | Phase | What it adds |
|---|---|---|
| Probes (WP2.3) | 1 | Delivered, see [scanning.md](scanning.md). `address` facts from the neighbor tables, ICMP, mDNS, LLMNR and SNMP (SCAN-02 to SCAN-05), each with the VRF of the probe, so the placement of section 3.3 needs no guess. `services` facts from the TCP connect scan and mDNS, and `os` facts from mDNS and SNMP (SCAN-04, SCAN-08), which fill the open ports and OS of the computed view. `name` facts from reverse DNS, mDNS, LLMNR and SNMP, `vendor` facts from the OUI table of the probe, and `attachment` and `link` facts from SNMP polling (SCAN-05). A `name` or `vendor` fact is never a sighting of an address: it neither wakes a waiting job nor confirms a move, at ingest or in a run, does not refresh the last sighting of section 2.6, and does not by itself make a discovered host, a suggested network or a conflict. A discovered host takes the name a probe found for one of its addresses when no inventory source names it. The `vendors` constraint of adoption policies reads the `vendor` facts (section 6.2). On-demand scans (SCAN-09) ingest like scheduled ones. The scan scopes tell the orphan rule "gone" from "not scanned" (section 4.7). The raw-socket methods (`arp_sweep`, `tcp_syn`, `os_fingerprint`, `lldp`) are declared and do not run yet |
| DNS records | 2 | Delivered (section 10): `name` facts of the `ipam` and `manual` A, AAAA and PTR records of the zones, and the DNS findings of the actuator, among them the orphaned `ipam` record |
| DHCP leases | 3 | Delivered (WP8.1): `dhcp:<node>` `address` and `name` facts in the batch of every lease change, without polling (DHCP-16), which confirm waiting moves in the reconciler's next run (a lease fact starts it like any new fact); reservations are intent ([dhcp.md](dhcp.md) section 12). The `LeaseInPrefix` wake-up of the job engine is not used by moves, whose observation step is a manual task the reconciler completes |

Phase 3 also adds the reconciliation views across the four truths (IPAM-21): ghost, rogue, orphan and PTR-mismatch views with "who wins" rules, built on the same facts and proposals.

## 9. Tables, endpoints and events

### 9.1 Tables

| Table | Key | Value |
|---|---|---|
| `ipam.obs.facts` | (source key, subject key) | `ObservedFact` |
| `ipam.obs.by_mac` | (MAC address, source key, subject key) | Empty; lists the facts that name the MAC address |
| `ipam.obs.by_ip` | (IP address, source key, subject key) | Empty; lists the facts that name the address |
| `ipam.obs.by_name` | (lowercase name, source key, subject key) | Empty; lists the facts that name the host |
| `ipam.obs.last_seen` | Intent object (address or interface) | `IntentSighting`: time, source key and observation |
| `ipam.proposals` | Proposal id | `IntentProposal` |
| `ipam.proposal_keys` | Subject key | The id of the open proposal of that key |
| `ipam.proposal_rejections` | Subject key | `Rejection`: fingerprint, proposal, who and when, reason |
| `ipam.adoption` | Prefix id | `StoredPolicy`: policy, who set it and when |
| `ipam.reconciler_settings` | None (one row) | `ReconcilerSettings` (section 3.1.1) |

The index tables follow their fact in the same batch.

### 9.2 Endpoints

| Endpoint | Operation id | Authorization |
|---|---|---|
| `GET /api/v1/observations` | `list_observations` | `read` on observations |
| `GET /api/v1/observations/{subject}` | `get_observation` | `read` on observations |
| `GET /api/v1/proposals` | `list_proposals` | `read` on proposals |
| `GET /api/v1/proposals/{id}` | `get_proposal` | `read`; returns an `ETag` |
| `POST /api/v1/proposals/{id}/approve` | `approve_proposal` | `approve` on proposals, plus the right each command needs |
| `POST /api/v1/proposals/{id}/reject` | `reject_proposal` | `approve` on proposals |
| `POST /api/v1/proposals/reconcile` | `reconcile_proposals` | `approve` on proposals |
| `GET /api/v1/prefixes/{id}/adoption` | `get_adoption_policy` | `read` on the prefix |
| `PUT /api/v1/prefixes/{id}/adoption` | `set_adoption_policy` | `update` on the prefix |
| `DELETE /api/v1/prefixes/{id}/adoption` | `clear_adoption_policy` | `update` on the prefix |
| `GET /api/v1/settings/reconciler` | `get_reconciler_settings` | administrators; returns an `ETag` |
| `PUT /api/v1/settings/reconciler` | `update_reconciler_settings` | administrators; `If-Match` |

`GET /api/v1/proposals` takes the filters `kind`, `state` and `severity` (each repeatable or comma-separated), `prefix` (proposals about the prefix, its addresses and its networks), `subject` (a MAC address, an IP address, an object identifier, or text of the subject name or key) and `sort` (`created`, `updated`, `severity`, `kind`, `state`, `last_seen`; `-created` by default), with the usual paging. A list is empty for a principal who may not read the kind.

### 9.3 Live updates

Changes of `ipam.proposals` and `ipam.adoption` are events of the `ipam` topic. Changes of `ipam.obs.facts` and `ipam.obs.last_seen` are table-level events of the `discovery` topic: they name the changed table and no object, because a poll can change many facts at once. Like every event they carry references, not bodies, so a client refetches what it shows.

## 10. The DNS actuator

With the DNS module, the reconciler drives the DNS actuator of IPAM (IPAM-13, plan sections 2.5 and 2.6): the A or AAAA and PTR records of every address with a DNS name, and the reverse zones of the managed prefixes, written through the zone service with the origin `ipam`. What the actuator writes and how it chooses zones is in [dns.md](dns.md) section 7; this section is the reconciler's side.

- **The DNS source.** Before each run, the reconciler reads the `ipam` and `manual` A, AAAA and PTR records of every primary zone from the store (the engine is never asked) and ingests them as `name` facts of the source `dns:<zone>`, one complete batch per zone, so a deleted record's fact expires at the next run. An RFC 2317 zone reports under its parent's name. A name is not a sighting (section 8): the facts show in the computed view and name the hosts the reconciler proposes; retention purges them like any other.
- **The findings.** The planner runs on the same view as the rules and its findings become proposals of the rules `ipam.reconcile.dns_*` ([dns.md](dns.md) section 7): `dns_no_zone` (orphaned intent, info: names without a zone in Tenko), `dns_record_held` (conflict, warning: an RRset IPAM wants held by another origin, among them an `ipam` record a person took over), `dns_orphaned_record` (orphaned intent, info: an `ipam` record without intent, with `dns_orphans = propose`), `dns_delegation` (orphaned intent, info: the RFC 2317 lines for a parent zone elsewhere), `dns_reverse_orphaned` and `dns_reverse_no_servers` (orphaned intent, info). They carry no commands and are never adopted; they expire when their cause is gone.
- **The writes.** After the proposals and the adoptions, while `dns_actuator` is on, the actuator plans again from a fresh view and writes: reverse zones to create and to adopt first, then one batch per zone, audited as `dns.record.actuate` by `system:reconciler`. A hand-deleted `ipam` record comes back in the next run (a change to `dns.rrsets` schedules one). Its changes are the `dns` part of the run's report.
- **The dry run.** The same planner, without writing, gives the move preview its DNS change ([moves.md](moves.md) section 2): the records the move removes and writes.
- **Moves in flight.** While a move job runs, its old address stays active and its new one is `planned`. Once the job's automatic DNS step has started, the planner publishes the new address instead of the old one, so a run in between keeps what the step wrote; when the job rolls back, the step's compensation and the planner both return to the old address.

## 11. The reconciliation view

The reconciliation view (IPAM-21, IPAM-23) puts the four truths of an address side by side and lists where they disagree, with the rule that says which truth wins. It is computed when read from one read view (`tenko_ipam::reconcile::view`) and writes nothing: it reads intent, the facts, the DHCP lease rows and the open proposals; a person acts through the proposals, the zones and the intent.

### 11.1 The four truths

| Truth | What it is | Where it comes from |
|---|---|---|
| Intent | the live address of intent, its host, the host's mode, the interface's MAC address, the DNS name | the IPAM tables |
| Lease | the current facts of the sources `dhcp:<node>`: MAC addresses, sources, the latest sighting, the lease's end | the lease facts ([dhcp.md](dhcp.md) sections 12.3 and 15.3) |
| DNS | the owner names of A and AAAA records with the address, the targets of its PTR records, the zones | the `name` facts of the sources `dns:<zone>` (section 10); a source whose zone ends in `.arpa` gives PTR names |
| Scan | the current facts of the probes and the connectors: MAC addresses, sources, the latest sighting | the observation layer (section 2) |

An address's VRF comes from the fact when the source reports one (DHCP, probe addresses), else from the networks of intent that contain it; an address whose VRF cannot be told, and an address IPAM does not track (loopback, link-local, multicast), is left out.

### 11.2 The lists and who wins

| Kind | A row when | Who wins (`rule_id`) |
|---|---|---|
| `ghost` | an active address on an interface of a `reserved`, `static` or `dynamic` host that no current fact shows (neither the address nor the interface's MAC address anywhere), and that nothing has shown for longer than the default lease time of the enabled Tenko scope of its network (the server's when the scope sets none), or than the reconciler's orphan age (`orphan_after_secs`) where no Tenko scope serves it; only where DHCP or a probe could see it (a Tenko scope, or a probe scope that covers it, or no probe scope known) | `intent_managed` (intent, IPAM-16) for `reserved` and `static` hosts; `lease_dynamic` (the lease) for `dynamic` hosts |
| `rogue` | a current lease or sighting inside a network of intent, at an address without intent, of a device whose MAC address no interface carries | `newest_sighting`: the newer of the lease and the scan; the row links the open discovered-host proposal (IPAM-15, `discovered_host/mac:<mac>` or `discovered_host/ip:<vrf>/<ip>`) |
| `orphan` | a DNS record of an address that no host holds | `orphan_rule` (intent) for a record IPAM wrote, linking Phase 2's `dns_orphaned_record` proposal; `manual_record` (DNS) for a record written by hand, which stays as written |
| `ptr_mismatch` | a PTR name that is not the address's DNS name of intent or, without one, not a name of its forward records | `intent_managed` when a managed host holds the DNS name; `forward_record` (DNS) otherwise |
| `conflict` | two or more MAC addresses on one address across the leases and the sightings, unless they all belong to one host's interfaces, or an address the `dhcp` role abandoned on a conflict (WP8.5) | `never_automatic`: no winner, never resolved automatically (IPAM-23) |

A conflict is not also listed as a rogue. An `unmanaged` host is never a ghost, and its leases and sightings agree with intent as long as they carry its MAC address. A row carries `rule` (the rule in English) beside `rule_id`; the web UI shows its own text of the rule.

The same address can have a row of several kinds (an orphaned record and a PTR mismatch at once). Rows are ordered by address, then kind (conflict, ghost, rogue, orphan, PTR mismatch).

### 11.3 The OS field and the vendors

Every row and the host summary carry the OS guess that wins by precedence, with its source, truth and confidence: an inventory's own statement (`Observed::Host.os`, confidence 100), then a probe's guess (`Observed::Os` of a probe source, the active scan), then the DHCP fingerprint's guess (`Observed::Os` of `dhcp:<node>`, [dhcp.md](dhcp.md) section 15); within a rank the higher confidence, then the newer sighting, then the source. For a host, the guesses of its own addresses count and those of every address where a current fact sees one of its MAC addresses (a pool lease of a host whose intent names another address). The vendors are the current vendor facts of the MAC addresses: the probes' OUI names and the DHCP vendor class.

### 11.4 Reading it

| Endpoint | Operation | Notes |
|---|---|---|
| `GET /api/v1/ipam/reconcile` | `get_ipam_reconcile` | read of observations; filters `prefix` (rows of addresses inside it, in its VRF), `host` (the host's addresses, its MAC addresses and the rows it is named in; the answer then carries `host`, the host's truths with the OS field, every guess and the vendors) and `kind`; paging with `limit` (1 to 1,000, 100 by default) and `cursor`; a scoped reader gets the rows whose address lies in its scope |

`tenko ipam reconcile [--prefix ID_OR_CIDR] [--host ID_OR_NAME] [--kind ghost|rogue|orphan|ptr_mismatch|conflict] [--all] [--json]` prints the rows as a table (address, kind, intent, lease, DNS, scan, winner, rule and the proposal) and, with `--host`, the host's OS field and vendors first. The web UI has the page IPAM → Reconciliation (`/ipam/reconcile`) with one list per kind, the filters, the four truths per row with the winner marked, and the link to the discovered-host proposal; the host page shows the OS field and the vendors in its observations section.

The system status (`GET /api/v1/system/status`) carries the warning `ipam.lease_conflict` while the view has conflict rows, with their count and up to five addresses and their MAC addresses (`params.count`, `params.addresses`).

### 11.5 Tests

`crates/tenko-ipam/tests/reconcile_view.rs` seeds one case of every kind beside quiet hosts and checks that the view lists exactly those, with their rules, the proposal link, the filters, the paging and the refusals, and the OS precedence (the DHCP guess, then a probe's, then an inventory's). E28 (`crates/tenko/tests/acceptance_reconcile.rs`) does the same through the binary: intent through the API, leases through the `dhcp` role in relay mode on loopback with Windows's and Android's options 55 and 60, records written by hand, and the sample connector's inventory sighting for the scans (a probe's own sighting of a non-loopback address needs a network the test does not have); the unmanaged TV's OS field comes from its lease, the health view names the conflict, and `tenko ipam reconcile` prints the same rows.
