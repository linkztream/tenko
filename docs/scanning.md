# Scanning: the probe's discovery methods

This page describes the discovery methods of the Tenko DDI probe: what each method does, what it needs from the host and the network, what it reports to the reconciler and how often it runs, how its traffic is limited and held back (rate limits, blackout windows, the kill switch), how an operator starts a scan by hand or from the controller and reads the state of the scanner, what an IDS or EDR product is likely to make of the traffic and how to allow-list the probe, and every key of the `[scan]` section. It is for the administrator who adds a probe to a segment, for the security team that has to tolerate or tune it, and for a developer who adds a method. It describes the behavior of the `tenko-scan` crate (the scanner and the scan control of the controllers), of `tenko node scan` and of the scanner wiring in the node process of `tenko serve` in the `tenko` crate, and of the `/scans` and `/nodes/{id}/scan-config` routes of `tenko-api`; where this page and the code differ, the code is right. The requirements are SCAN-01 to SCAN-09 in [REQUIREMENTS.md](REQUIREMENTS.md) and the toggles TGL-18 and TGL-19 in [SECURITY-PROFILES.md](SECURITY-PROFILES.md).

This release ships the methods that need no special privileges: the neighbor tables of the probe host, ICMP echo, TCP connect scans, reverse DNS, mDNS, LLMNR and SNMPv3 polling. It also ships the methods that need raw sockets: the active `arp_sweep`, `tcp_syn` and `os_fingerprint`, and the passive `lldp` (with CDP) and `dhcp_snoop`. On Linux these need `CAP_NET_RAW`; on Windows they answer `unsupported`, because raw sockets need Npcap, which Tenko does not bundle (section 9). The controllers hold the scan configuration of each probe, start scans on demand and switch the kill switch (sections 7.5 to 7.7); how this travels to the probes is in [node-sync.md](node-sync.md). Section 14 lists what comes next.

Terms used below: a **probe** is a node with the role `probe`; ARP and neighbor discovery do not cross routers, so there is one probe per segment (SCAN-01) and the probe in a DMZ is its own trust zone. A **method** is one way of looking at the segment (`arp`, `icmp`, `snmp` and so on). A **run** is one execution of a method. A **batch** is what one run hands over: the sightings of the run, a flag that says whether the batch is complete, and the time it was collected. A **sighting** is one thing a probe saw. A **fact** is the reconciler's latest knowledge of one subject from one source (see [reconciliation.md](reconciliation.md)). The **scope** is the set of prefixes a probe may look at, minus the exclusions. The **known addresses** are the addresses this probe saw recently through any method.

Contents:

1. [Overview](#1-overview)
2. [Methods](#2-methods)
3. [What the facts mean](#3-what-the-facts-mean)
4. [Scope, schedules and limits](#4-scope-schedules-and-limits)
5. [Blackout windows](#5-blackout-windows)
6. [Active probing (TGL-18)](#6-active-probing-tgl-18)
7. [Kill switch, on-demand runs and status](#7-kill-switch-on-demand-runs-and-status)
8. [Files](#8-files)
9. [Raw-socket methods](#9-raw-socket-methods)
10. [IDS and EDR](#10-ids-and-edr)
11. [The OUI table](#11-the-oui-table)
12. [Configuration reference](#12-configuration-reference)
13. [Error codes](#13-error-codes)
14. [What comes next](#14-what-comes-next)

## 1. Overview

The scanner runs inside the probe node process, `tenko serve --roles probe` (SCAN-01). It starts with the process, runs every method on its own schedule, and stops with the process. Each run produces one batch. On a probe node the batch goes into the observation buffer of the node, which sends it to the controller over the mutual TLS node transport and keeps it through outages (see [cluster.md](cluster.md#6-observations-and-the-buffer)). On a controller node that also has the `probe` role, the scanner starts with the controller and its batches go through a local buffer to the ingest of the controller, under the node id of the controller (see [node-sync.md](node-sync.md#8-the-relay-buffer)). In both cases the controller files the sightings under the source `probe:<node>:<method>`, so each method of each probe is its own source with its own facts and its own expiry (see [reconciliation.md](reconciliation.md#21-sources-and-keys)).

Where a probe gets its configuration depends on whether the controllers hold one for it. Once they do, the probe runs on that configuration, which an administrator edits with `PUT /api/v1/nodes/{id}/scan-config` (section 7.5) and which the controllers stream to the probe and the probe applies atomically ([node-sync.md](node-sync.md#4-on-the-node)); the profile values of TGL-18 and TGL-19 (sections 4 and 6) are set there. Until the probe has synced, and for `tenko node scan run`, it reads the `[scan]` section of its own `tenko.toml`; at its first connection it offers that section to the controllers as its initial configuration, without passwords, and the controllers keep it only when they hold none. SNMP credentials in a configuration held by the controllers are named as operator secrets of the vault with the purpose `snmp`: the probe fetches them from the controllers over its mutual TLS connection each time it polls, keeps them in memory only and never writes them to disk (section 12.3, [node-sync.md](node-sync.md#6-secrets)). The probe's own file can still name passwords or password files for the devices; they serve only while the probe runs on its own file, and they never leave the probe. Keep such files readable by the service account only. Tenko does not check their permissions.

A probe needs no scan configuration to start, and an empty `[scan]` section is valid, but without `prefixes` the scanner scans nothing: scans never leave the configured prefixes (section 4). A minimal section for one segment:

```toml
[scan]
prefixes = ["192.0.2.0/24", "2001:db8:10::/64"]
exclude = ["192.0.2.1"]
rate = "slow"
blackout = ["mon-fri 08:00-17:00"]
timezone = "Europe/Stockholm"

[scan.tcp_connect]
ports = [22, 80, 443, 3389]

[[scan.snmp.devices]]
address = "192.0.2.2"
name = "switch-a.example.net"
user = "tenko"
auth = "sha256"
auth_password_file = "/etc/tenko/snmp-switch-a-auth"
privacy = "aes128"
privacy_password_file = "/etc/tenko/snmp-switch-a-priv"
```

With the node enrolled (see [cluster.md](cluster.md#1-enrolment)), these commands start the node and show what the scanner does:

```
tenko serve --roles probe --data-dir /var/lib/tenko
tenko node scan status --data-dir /var/lib/tenko
tenko node scan run arp --dry-run --data-dir /var/lib/tenko
```

`[scan] enabled = false` switches the scanner off; the node process then runs without it. A configuration that does not validate stops the node process at start with the exit status 3 (section 12.4). The example file `deploy/tenko.example.toml` documents every key.

## 2. Methods

| Method | What it does | What it needs | Active probing (TGL-18) | Held by blackout windows | Default interval | Reports |
|---|---|---|---|---|---|---|
| `arp` | Reads the IPv4 neighbor table of the probe host | Unprivileged. Linux: `/proc/net/arp`. Windows: PowerShell `Get-NetNeighbor` | No | No | 5 minutes | `address` with MAC address, `vendor` |
| `nd` | Reads the IPv6 neighbor table of the probe host | Unprivileged. Linux: the `ip` command. Windows: PowerShell `Get-NetNeighbor` | No | No | 5 minutes | `address` with MAC address, `vendor` |
| `icmp` | Sends one ICMP echo request to every address of the sweep | Unprivileged. Linux: ICMP datagram sockets when `net.ipv4.ping_group_range` admits the group of the process, else the `ping` command. Windows: `ping.exe` | Yes | Yes | 30 minutes | `address` (no MAC address) |
| `tcp_connect` | Tries a TCP connection to a list of ports, with a TLS hint per open port | Unprivileged; outbound TCP | Yes | Yes | 6 hours | `services` |
| `reverse_dns` | Looks up the PTR name of every known address | Unprivileged; UDP to the DNS servers | No | Yes | 1 hour | `name` |
| `mdns` | Browses DNS-SD services, queries known addresses, listens for announcements | Unprivileged; UDP from an ephemeral port. Optionally shares UDP 5353 | No | Yes | 15 minutes | `address`, `name`, `services`, `os` |
| `llmnr` | Sends a unicast reverse query to every known address | Unprivileged; UDP to port 5355 | No | Yes | 1 hour | `address`, `name` |
| `snmp` | Polls the configured switches over SNMPv3 | Unprivileged; UDP to the devices, SNMPv3 credentials | No | Yes | 15 minutes | `name`, `os`, `address`, `attachment`, `link`, `vendor` |
| `arp_sweep` | ARP request to every IPv4 address of the scope (section 2.8) | Raw sockets (`CAP_NET_RAW`) | Yes | Yes | 1 hour | `address` with MAC, `vendor` |
| `tcp_syn` | Half-open SYN scan of a port list, up to all 65,535 ports (section 2.9) | Raw sockets | Yes | Yes | 1 hour | `services` (open ports) |
| `os_fingerprint` | SYNs a short port list and classifies the SYN-ACKs (section 2.10) | Raw sockets | Yes | Yes | 1 hour | `os` with a confidence |
| `lldp` | Listens for LLDP and CDP frames (section 2.11) | Raw sockets | No | No | 1 hour | `link`, `attachment`, `address`, `name`, `os`, `vendor` |
| `dhcp_snoop` | Listens for DHCPv4 DISCOVER, REQUEST, ACK (section 2.12) | Raw sockets | No | No | 1 hour | `address`, `name`, `os`, `vendor` |

"Active probing" is the class that TGL-18 switches (section 6). "Held by blackout windows" means the method sends packets, so a blackout window stops it (section 5). Passive in the TGL-18 sense is not the same as silent: `reverse_dns`, `mdns`, `llmnr` and `snmp` send packets and are therefore held by blackout windows although `active = false` leaves them running.

The intervals are the defaults of the method sections in section 12. Each method has its own schedule; a slow run of one method does not delay another. Section 4 gives the first-run delays and the jitter.

### 2.1 `arp` and `nd`

Both methods read a table that the operating system keeps and send nothing (SCAN-02). The table holds the neighbors the host talked to recently, so it shows a device only while the host has an entry for it; an `icmp` echo to an on-link address creates that entry.

| Platform | `arp` (IPv4) | `nd` (IPv6) |
|---|---|---|
| Linux | `/proc/net/arp` | `ip -6 neigh show` |
| Windows | `Get-NetNeighbor -AddressFamily IPv4` through `powershell.exe` | `Get-NetNeighbor -AddressFamily IPv6` through `powershell.exe` |

Entries that are incomplete, failed or unreachable are left out: in `/proc/net/arp` an entry counts only with the flag `0x2`, in `ip neigh` the states `FAILED`, `INCOMPLETE` and `NONE` and entries without `lladdr` do not count, and in `Get-NetNeighbor` the states `Incomplete` and `Unreachable` do not count. Entries whose MAC address is all zero, the broadcast address or another group address are left out too, and so is everything outside the scope. Each remaining entry is an `address` sighting with its MAC address, and each distinct MAC address that the OUI table knows adds a `vendor` sighting (section 11). A run reads the whole table, so it always covers everything and its batch is complete: an address that left the table expires at the controller. A read that fails or takes longer than 30 seconds fails the run with `scan.io`; the deadline of the method is 60 seconds.

### 2.2 `icmp`

One echo request goes to each target, and an answer within `timeout_ms` (default 1000) makes an `address` sighting without a MAC address. The targets are every usable IPv4 address of each prefix that holds at most `max_hosts_per_prefix` addresses (the network and broadcast addresses of prefixes of /30 and shorter are left out), minus the exclusions, plus the known addresses that lie in prefixes too large to enumerate, which includes all IPv6 networks (SCAN-04, SCAN-06).

How the echo is sent depends on the host. On Linux the probe opens an unprivileged ICMP datagram socket when `net.ipv4.ping_group_range` admits the group of the process; the kernel sets the identifier and the checksum, and the 8 bytes after the ICMP header read `tenko-sc`. When the socket cannot be opened, the probe runs the `ping` command (`ping -c 1 -W <seconds> <address>`), and a reply is an exit status of 0. On Windows the probe runs `ping.exe -n 1 -w <milliseconds> <address>`, and a reply is recognized by the text `TTL=` in the output for IPv4, which Windows prints in every language only in replies, and by a reply line that names the target for IPv6. Windows uses the command because the safe wrappers around `IcmpSendEcho` are unmaintained, and a command per address within the rate limit is cheap enough for the prefixes a probe covers. The consequence for monitoring is one short-lived process per address (section 10).

Because an echo to an on-link address makes the operating system resolve it, the next `arp` run sees the address with its MAC address even when the device drops ICMP. A run is complete when every target was probed and every echo could be sent. If no ICMP path exists (a Linux host outside `ping_group_range` without a `ping` command, or a Windows host without `ping.exe`), the method is `unavailable` and says why.

### 2.3 `tcp_connect`

A TCP connect scan through the operating system (SCAN-04, SCAN-08). The ports are the list `ports` (default: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 515, 548, 554, 631, 636, 1883, 3306, 3389, 5432, 5900, 6053, 8006, 8080, 8123, 8443). The targets are the known addresses inside the scope (`targets = "known"`, the default), or, with `targets = "all"`, also every address that a sweep enumerates (section 2.2). The scan goes port by port with the hosts inside the loop, so consecutive attempts go to different hosts.

A port counts as open when the connection completes within `timeout_ms` (default 1500). A refused connection and silence report nothing; the method never reports a closed port. Each address with at least one open port becomes one `services` sighting with its open ports (`open_tcp`) and the subset of them that answered a TLS handshake (`tls_tcp`). With `tls_hint = true` (the default) the scanner does the following on every open port, and nothing else:

1. It sends one TLS `ClientHello` (record version 3.1, handshake version 3.3, no server name, offering TLS 1.3 and 1.2, a fixed key share). The `random` field of the hello spells `tenko-scan-tls-hint` followed by the bytes 0x00 to 0x0c, so it starts at offset 11 of the TCP payload and an IDS rule can match it (section 10).
2. It waits up to 1.5 seconds and reads the first bytes of the answer, at least 3 and at most 5. A TLS record header (a handshake or an alert record with a version from 3.0 to 3.4) marks the port as TLS.
3. It closes the connection. No banner is read and no handshake is completed.

A service that does not speak TLS receives the bytes of the hello and may log them as a malformed request. `tls_hint = false` skips the exchange; the scan then only connects and closes. The method is complete when every address and port pair was tried. A complete run without any open port still goes out as an empty complete batch, so ports that closed expire at the controller.

### 2.4 `reverse_dns`

Looks up the PTR record of every known address inside the scope. It never sweeps a prefix: only addresses another method saw are looked up, which is why the method waits for the others at start (section 3.4). The queries go to `servers` (an address, with the port 53 unless given) or, when `servers` is empty, to the resolvers of the probe host (`nameserver` lines of `/etc/resolv.conf` on Linux, `Get-DnsClientServerAddress` on Windows; the placeholder resolvers that Windows lists on interfaces without DNS settings, and link-local servers that carry a zone, are left out). Each query is one UDP datagram with the recursion-desired flag, tried at each server in turn until one answers, within `timeout_ms` (default 2000). At most 8 lookups run at the same time. The DNS messages are built and parsed with the `domain` crate (ADR 0009).

A PTR answer becomes a `name` sighting with the first name of the answer. An NXDOMAIN or an answer without a PTR record is an answer, and reports no name. A run is complete when every address got an answer from some server; a run in which some lookups got none is partial and says how many in its notes. A reverse DNS name is a claim of a DNS server, not a sighting of the address (section 3.3).

### 2.5 `mdns`

Multicast DNS (SCAN-02) and DNS-based service discovery. A run does this, in order:

1. It sends a browse query for `_services._dns-sd._udp.local` to the group (`group`, default `224.0.0.251:5353`) from an ephemeral port. A query from a port other than 5353 is a legacy unicast query in the sense of RFC 6762, so responders answer that port directly and the probe needs no listening socket. The query leaves through the interface that the operating system picks for multicast; the scanner does not choose one.
2. It collects the answers for half of the window, then asks once for each service type that was announced (at most 32). The window is `listen_secs` (default 4) seconds.
3. It sends a unicast reverse query (PTR for the address) to `unicast_port` (default 5353) of every known address inside the scope (at most 4,096).
4. It collects answers and announcements for a whole window after the last query.

With `passive = true` (the default) the probe also joins the group on UDP 5353 with address reuse, so announcements that other devices send while it collects are heard as well; other mDNS responders on the host keep their sockets. When another program holds the port exclusively, the run uses queries only and notes `the mDNS port is not shared on this host; queries only`. Listening lasts for the collection phases of each run only. Tenko is not an mDNS responder: it never announces or answers anything.

Every datagram is read as a claim of its sender, because mDNS has no authentication. Inside the scope, each responder is an `address` sighting without MAC address, and the answers add:

| Finding | Source in the answer |
|---|---|
| `name` | The owner name of A and AAAA records, and PTR records under `in-addr.arpa` and `ip6.arpa` |
| `services` (open TCP ports; `tls_tcp` stays empty) | SRV records of `_<service>._tcp` instances, with the port of the record. Port 0, `_udp` services and `_workstation._tcp` (which Avahi announces on port 9 as a marker) are skipped |
| `os` with a confidence | HINFO records: Linux, Windows, macOS or FreeBSD at 60, any other text as it is at 40. TXT records of `_device-info._tcp`: `model=` starting with `Mac` or `iMac` is macOS at 60, `iPhone` is iOS at 60, `iPad` is iPadOS at 60, `AppleTV` is tvOS at 50, and a numeric `osxvers=` is macOS at 70. TXT records of `_esphomelib._tcp` with a `platform=` key are ESPHome at 60 |

A guess with a higher confidence replaces a lower one for the same address. The multicast browse uses the IPv4 group only; IPv6 addresses are reached through the unicast queries. A run covers everything when every query could be sent, but its batch is never complete: mDNS answers on a best-effort basis, so a device that stayed silent may only have missed the window, and its facts expire by their lifetime instead (section 3.3).

### 2.6 `llmnr`

Link-local multicast name resolution (SCAN-03). The method sends a unicast reverse query (PTR) to `port` (default 5355) of every known address inside the scope and collects the answers for `timeout_ms` (default 1000) after the last query. An LLMNR responder answers for its own names, so an answer gives the name of the host: each responder inside the scope is an `address` sighting without MAC address, and its name is a `name` sighting. LLMNR reports no services and no OS hint. The probe sends queries only; it does not listen for LLMNR and never answers one. Like `mdns`, the method never sends a complete batch (section 3.3).

### 2.7 `snmp`

Polls the switches in `[[scan.snmp.devices]]` over SNMPv3 (SCAN-05). Polling a device that an administrator configured is not a scan: the device addresses may lie outside the scan prefixes, for example in a management network, and the method still polls them.

Security. Only SNMPv3 with the user-based security model is spoken. Authentication is `sha1` (HMAC-SHA-1-96, RFC 3414) or `sha224`, `sha256`, `sha384`, `sha512` (RFC 7860); privacy is `aes128` (AES-128-CFB, RFC 3826). MD5 and DES are not supported, and a configuration that asks for `md5` or `des` is refused as an unknown value. A device that only offers them cannot be polled. Without `auth` the poll runs at the level noAuthNoPriv, which is for labs only; with `auth` and without `privacy` it runs at authNoPriv; privacy needs authentication (RFC 3414). Passwords have at least 8 characters. Requests are GetRequest and GetBulkRequest (RFC 3416) over UDP in SNMPv3 messages (RFC 3412), 20 repetitions per bulk request. Every datagram, a retry included, takes a permit of the rate limiter (section 4). A table is read up to 20,000 rows and then cut.

Tables read from each device:

| Table | MIB | Used for |
|---|---|---|
| `system` | SNMPv2-MIB | Name (`sysName`), description (`sysDescr`), type of the device |
| `ifTable`, `ifXTable` | IF-MIB | Interface names and the MAC addresses of the device itself |
| `ipNetToPhysicalTable`, `ipNetToMediaTable` | IP-MIB, RFC1213-MIB | The ARP and neighbor entries of the device, IPv4 and IPv6 |
| `dot1dBasePortTable` | BRIDGE-MIB | Bridge port to interface |
| `dot1qTpFdbTable` (Q-BRIDGE, with the VLAN) or, when it is empty, `dot1dTpFdbTable` (BRIDGE) | Q-BRIDGE-MIB, BRIDGE-MIB | Which MAC address sits behind which port, and in which VLAN |
| `lldpRemTable`, `lldpLocPortTable` | LLDP-MIB | Remote neighbors and local port names |

What a poll reports per device:

| Sighting | Contents |
|---|---|
| `name` | The `sysName` of the device, for its management address |
| `os` | The first line of `sysDescr`, at most 120 characters, for the management address, at confidence 90 |
| `address` with MAC address | Each entry of the ARP tables of the device whose address is inside the scope and whose MAC address is usable |
| `attachment` | The port and VLAN behind which each client MAC address was learned. The device name is the configured `name`, else `sysName`, else its address. MAC addresses of the device's own interfaces are left out, and so are clients on ports where an LLDP neighbor is seen, because those ports lead to other network devices that report their own clients; `attach_on_lldp_ports = true` reports them as well |
| `link` | One LLDP link per remote neighbor, between a port of the device and the neighbor (its system name, else its chassis id) |
| `vendor` | The OUI vendor of every MAC address in the address and attachment sightings (section 11) |

Scope applies to the address sightings only; the name and OS of the polled device, the attachments and the links are not filtered by the prefixes. A run is complete only when every device answered and no table was cut or failed; a device that did not answer, a rejected user (`scan.snmp.auth`) or a cut table makes the batch partial and adds a note, for example `192.0.2.2:161: [scan.snmp.timeout] no answer from 192.0.2.2:161 to ...`. The method is `unavailable` while `[scan.snmp]` lists no device. Credentials, their files and the warning about passwords in the file are in section 12.3.

### 2.8 `arp_sweep`

An active ARP sweep (SCAN-04). It sends an ARP request (RFC 826) for every usable IPv4 address of the scope from the probe's interface, honouring the rate limit (one probe per request), and collects the replies for `timeout_ms` (default 2000) after the last request. Each reply makes the same facts the passive `arp` method makes: an `address` sighting with the MAC address, and a `vendor` sighting for each MAC the OUI table knows (section 11). The host view and the IPAM observation path therefore see no difference between a swept and a passively read address. An ARP request to an on-link address also fills the operating system's neighbor table, so the next `arp` run sees it too.

The interface is the one whose address lies in the scope, or the `interface` key when set. IPv6 is left to the passive `nd` method; a neighbor-solicitation sweep is a follow-up, and the run notes so when the scope has an IPv6 prefix. A run is complete when a request was sent for every target and nothing stopped it; absence of a reply is not a closed address, only an address that did not answer.

### 2.9 `tcp_syn`

A half-open TCP SYN scan over raw sockets (SCAN-04, SCAN-08). The ports are the list `ports`, which takes single ports and `"a-b"` ranges and may hold up to all 65,535 ports, which the connect scan cannot (section 6). The targets are the known addresses in scope (`targets = "known"`, the default) or, with `targets = "all"`, also the addresses a sweep enumerates. A half-open scan is a link-layer send, so the method first resolves each target's MAC with an ARP request; a target that does not answer ARP (off-link or absent) is skipped and counted in a note. For each (host, port) it sends a raw SYN, honouring the rate limit, the blackout windows and the kill switch, and classifies the reply: a SYN-ACK is an open port, an RST is a closed port, silence is a filtered port. It sends an RST to close every open port it found. Each host with at least one open port becomes one `services` sighting with its `open_tcp` ports; `tcp_syn` reports no TLS hint (`tls_tcp` is empty). IPv4 only; an IPv6 SYN scan is a follow-up.

### 2.10 `os_fingerprint`

Passive and active-assisted OS fingerprinting (SCAN-04). It SYNs a short port list (`ports`) across the scope with the same engine as `tcp_syn` and classifies the first SYN-ACK of each host, p0f-style, from the TTL, the window size, the TCP option layout and the don't-fragment flag. The signatures are a small table in a fixture file (`crates/tenko-scan/fixtures/os_fingerprints.tsv`) compiled into the binary; a signature gives a family and a confidence, and with no match the family the TTL alone suggests is reported at a low confidence. The families are Windows, Linux, FreeBSD, macOS, Apple mobile, network gear, printer and unknown; a product name is never guessed beyond the family. Each classified host becomes one `os` sighting with its guess and confidence, which the host view's OS field reads.

### 2.11 `lldp` (and CDP)

Passive link-layer discovery (SCAN-02, SCAN-05). It listens on the probe's interface for LLDP frames (ethertype `0x88cc`) and, with `cdp = true` (the default), CDP frames (SNAP, Cisco OUI, protocol `0x2000`) for the listen window (`listen_secs`, default 35, raised to at least 65 when CDP is on, since CDP announces every 60 seconds), and parses their TLVs: chassis id, port id, TTL, port description, system name, system description, capabilities, management address and, for LLDP, the 802.1 port VLAN id and VLAN name; for CDP the device id, addresses, port id, capabilities, software version, platform and native VLAN. For each neighbour it emits facts in the shape of the SNMP LLDP neighbours, so the port mapping of section 3 merges them: a `link` between the probe's interface and the switch port, an `attachment` of the probe's own MAC to that switch port and VLAN, and, for a management address in scope, an `address`, a `name` (the system name) and a low-confidence `os` (the system description). It sends nothing, so blackout windows do not hold it; its batch is never complete, because the protocols announce periodically and one window may miss a frame.

### 2.12 `dhcp_snoop`

Passive DHCPv4 snooping (SCAN-03). It listens for DHCPv4 DISCOVER, REQUEST and ACK on the segment (UDP 67 and 68, broadcast and relayed) for the listen window (`listen_secs`, default 120) and reports, for each client, the MAC, the host name (option 12), the vendor class (60), the client id (61), the address offered or acknowledged (`yiaddr`) and the server that answered (54). The address in scope becomes an `address` sighting with the client MAC, the host name a `name`, the vendor class a low-confidence `os` (for example `MSFT` maps to Windows, `android-dhcp` to Android, `dhcpcd` to Linux), and the client MAC a `vendor`. The client id and the server identifier go into the run's notes, since no sighting subject carries them; full lease facts come with Tenko DHCP. The parse is a small local one of the four fields, replaced by `tenko-dhcp`'s DHCPv4 codec once it merges. It sends nothing, so blackout windows do not hold it; its batch is never complete.

## 3. What the facts mean

### 3.1 Subjects and keys

The controller turns each sighting into a fact. Facts of different sources are never merged: the `address` fact of `icmp` and the one of `arp` for the same address are two facts, and the computed view of [reconciliation.md](reconciliation.md#25-the-computed-view) puts them together when it is read. The VRF of the addresses is the `vrf` key of `[scan]`, else the VRF of the enrolment token of the node, else the default VRF.

| Fact | Subject key | Reported by | What it says |
|---|---|---|---|
| `address` | `address:<vrf>/<ip>` | `arp`, `nd`, `icmp`, `mdns`, `llmnr`, `snmp`, `arp_sweep`, `lldp`, `dhcp_snoop` | The address is in use; with the MAC address behind it when the method shows one (`arp`, `nd`, `snmp`, `arp_sweep`, `dhcp_snoop`) |
| `services` | `services:<ip>` | `tcp_connect`, `mdns`, `tcp_syn` | Open TCP ports; `tls_tcp` lists those that answered a TLS handshake (`tcp_connect` only) |
| `os` | `os:<ip>` | `mdns`, `snmp`, `os_fingerprint`, `lldp`, `dhcp_snoop` | An OS guess with a confidence in percent |
| `name` | `name:<ip>` | `reverse_dns`, `mdns`, `llmnr`, `snmp`, `lldp`, `dhcp_snoop` | A name found for the address |
| `vendor` | `vendor:<mac>` | `arp`, `nd`, `snmp`, `arp_sweep`, `lldp`, `dhcp_snoop` | The organization the OUI of the MAC address is registered to |
| `attachment` | `attachment:<mac>` | `snmp`, `lldp` | The switch, port and VLAN of a client |
| `link` | `link:<device>\|<port>\|<device>\|<port>\|<kind>` | `snmp`, `lldp` | An LLDP or CDP link between two devices |

A batch carries each subject once; when a run sees a subject twice, the later sighting wins.

### 3.2 Expiry

Every sighting carries a lifetime, and the fact expires that long after the time the probe saw it. The lifetime is `ttl_secs` of the method. The default is three intervals of the method, but at least 15 minutes and at most seven days, so one missed run does not age a device out: 15 minutes for `arp` and `nd`, 90 minutes for `icmp`, 45 minutes for `mdns` and `snmp`, 3 hours for `llmnr` and `reverse_dns`, 18 hours for `tcp_connect`. An explicit `ttl_secs` can be 60 seconds to 30 days. The controller refreshes and keeps facts as described in [reconciliation.md](reconciliation.md#23-ingest).

### 3.3 Completeness

A batch is complete when it is the whole picture of its method for the whole scope. Then the controller expires the facts of that source that the batch no longer reports, which is how a device that left the network disappears. A batch is complete only when all of this holds:

- the method covered everything it was asked to cover: every target probed, every address looked up, every device polled and every table read;
- the run covered the whole configured scope, so a run with `--target` is never complete;
- nothing stopped the run: not the kill switch, not a blackout window, not its deadline, not the shutdown of the process;
- the batch did not exceed 250,000 sightings, the limit of a batch; a longer batch is cut and is not complete;
- the method is one whose batches can be complete. `mdns` and `llmnr` are not: those protocols answer on a best-effort basis, so absence from one run proves nothing. Their facts expire by their lifetime (three intervals by default) and not at the next run. The status still shows the outcome `complete` for a run of these methods that covered everything (section 7.4); only the `complete` flag of the batch stays false.

A run that did not cover everything still sends what it saw, as a batch that is not complete, so it adds and refreshes facts but expires none. The scheduler sends an empty batch only when it is complete: an empty complete batch expires every fact the method reported before, and an empty batch that is not complete is not sent.

A name or a vendor says what a thing is called or who made it. It does not say that an address is in use, so the reconciler never counts a `name` or `vendor` fact as a sighting: such a fact does not wake a job or confirm a move, neither when its batch arrives nor in a later reconcile run, does not refresh the last sighting of an intended address (so a stale PTR record cannot keep an address from the orphan rule), and does not by itself make a discovered host, a suggested network or a conflict. A name still names things: when the reconciler proposes a discovered host for an address that some sighting shows in use, it takes the name a probe found for that address, after the names inventory sources give (see [reconciliation.md](reconciliation.md#8-what-later-sources-add)).

### 3.4 Known addresses

The scanner keeps the set of known addresses: for each address, the methods that saw it and until when each sighting counts. A delivered batch adds the addresses of its `address` and `services` sightings (names, OS guesses, vendors, attachments and links add none), valid until the sighting expires. A complete run also removes the addresses that the same method reported before and no longer reports, and an address leaves the set when no method keeps it; the entries of `mdns` and `llmnr`, whose batches are never complete, leave by expiry only. `reverse_dns` reports names only and so adds none. The set holds at most 65,536 addresses and is kept in `known.json` (section 8), so a restarted probe does not start from nothing.

`tcp_connect` and `reverse_dns` work on the known addresses, and so do the unicast queries of `mdns` and `llmnr`, and the sweep of `icmp` for prefixes it cannot enumerate. A probe therefore looks deeper only at what answered before. For the same reason `tcp_connect` and `reverse_dns` wait at start until every other method that runs on this probe has reported once, or until ten minutes after the start of the scanner, whichever comes first; their state is `waiting` meanwhile (section 7.4).

## 4. Scope, schedules and limits

### 4.1 The scope

`prefixes` lists what the probe covers, as prefixes (`192.0.2.0/24`, `2001:db8:10::/64`) or single addresses, and `exclude` lists prefixes and addresses inside them that are never probed or reported (SCAN-06). Nothing outside the scope is probed or reported: the active methods only target addresses that the scope allows, and every method filters its findings through the scope. IPv4-mapped IPv6 addresses count as IPv4. The one exception is the polling of a configured SNMP device (section 2.7), whose own address may lie outside the prefixes.

Without `prefixes` every method except `snmp` is `unavailable` with the reason `no prefixes in [scan]; scans never leave the configured prefixes`, and the node process logs a warning at start. `snmp` still polls its devices, but its address sightings are filtered through the empty scope and so are empty.

A sweep enumerates the addresses of an IPv4 prefix when the prefix holds at most `max_hosts_per_prefix` addresses (default 4,096, so a /20 is enumerated and a /19 is not). Larger IPv4 prefixes and all IPv6 networks are never enumerated; the methods that sweep cover them through the known addresses (section 3.4). A target of an on-demand run (`--target`) must lie inside one of the prefixes, and the exclusions stay in force.

### 4.2 Schedules

Each method has a loop of its own. After the start of the scanner it waits for its first-run delay, runs, and then waits one interval, moved by a random amount of up to 10 percent either way so that probes that were started together drift apart. The interval counts from the end of a run. The first-run delays put the passive methods first:

| Method | First run after |
|---|---|
| `arp` | 2 seconds |
| `nd` | 3 seconds |
| `mdns` | 10 seconds |
| `snmp` | 15 seconds |
| `icmp` | 20 seconds |
| `llmnr` | 40 seconds |
| `tcp_connect` | 90 seconds (and not before the other methods have reported, section 3.4) |
| `reverse_dns` | 120 seconds (and not before the other methods have reported) |

A method that is disabled or unavailable has no loop. The interval of a method is `interval_secs`, 30 seconds to seven days (section 12).

### 4.3 Rate limits (TGL-19)

One limiter serves all methods of a probe process (SCAN-06, SCAN-07). Every probe takes a permit first. The rate profile of TGL-19 sets the probes per second of the whole probe:

| Profile | TGL-19 value | `rate` | Probes per second |
|---|---|---|---|
| Home | Normal | `normal` (the default) | 100 |
| Standard | Slow | `slow` | 50 |
| Hardened | Slowest | `slowest` | 10 |
| Lab | Unlimited | `unlimited` | No limit |

`packets_per_second` overrides `rate` when it is set; 0 means unlimited. The limiter lets through a burst of up to a tenth of a second of probes (at least one) and then holds to the rate. What counts as one probe depends on the method:

| Method | One probe is | The spacing below is kept per |
|---|---|---|
| `icmp` | One echo request | Target address |
| `tcp_connect` | One connection attempt to one address and port, with its TLS hint exchange | Target address |
| `reverse_dns` | One query to one DNS server; the retry at the next server counts again | DNS server address |
| `mdns` | One multicast query to the group, or one unicast query to a known address | Group address, or target address |
| `llmnr` | One unicast query to a known address | Target address |
| `snmp` | One datagram to a device, retries included | Device address |
| `arp`, `nd` | None; reading a table sends nothing | |

Two more limits apply to every probe. `per_host_interval_ms` (default 100) is the least time between two probes to the same address, so a device never sees a burst even when the whole probe runs at full rate. `concurrency` (default 32) is the most probes in flight at once; `reverse_dns` uses at most 8 of them. As an illustration, `tcp_connect` over a /24 with `targets = "all"` and the 28 default ports makes 7,112 attempts, which takes about 71 seconds at 100 probes per second and about 12 minutes at 10.

The limits are those of one process. `tenko node scan run` (section 7.2) starts a scanner of its own, with its own limiter, so a run on demand adds to what the node process sends.

### 4.4 Deadlines

A run that takes longer than the deadline of its method is stopped. The scanner gives a stopped run 5 seconds to hand back what it saw, and sends that as a batch that is not complete. The run is recorded as `cancelled` with the error `stopped at its deadline`.

| Method | Deadline |
|---|---|
| `arp`, `nd` | 60 seconds |
| `mdns`, `llmnr` | 30 minutes |
| `icmp`, `tcp_connect`, `reverse_dns`, `snmp` | 1 hour |

## 5. Blackout windows

Blackout windows (SCAN-06) are times of the week when no method that sends packets runs, such as office hours. A window is written `[<days>] <HH:MM>-<HH:MM>`, in any case and with extra spaces. `blackout` is a list of windows, and `timezone` names the time zone they are read in.

| Days | Meaning |
|---|---|
| (left out), `daily` | Every day |
| `weekdays`, `weekends` | Monday to Friday, Saturday and Sunday |
| `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun` | One day |
| `mon-fri` | A range of days; `fri-mon` wraps over the weekend |
| `mon,wed,fri-sun` | A comma list of days and ranges |

The times run from `00:00` to `23:59`; `24:00` is allowed as the end. An end before the start crosses midnight, and the day names the start: `sun 22:00-02:00` runs from Sunday 22:00 to Monday 02:00. A window of zero length, such as `08:00-08:00`, is refused. Overlapping and adjacent windows count as one.

```toml
[scan]
timezone = "Europe/Stockholm"
blackout = [
  "mon-fri 08:00-17:00",
  "sun 22:00-02:00",
  "sat,sun 00:00-24:00",
]
```

The times are wall-clock times in `timezone`, an IANA name; the default is the time zone of the system. The windows follow daylight saving time: a time that falls in the gap of a spring change moves forward, a time that occurs twice in an autumn change is the first one, so a window is shorter or longer on the days the clocks change. An unknown zone or a window that does not parse stops the start with `scan.config`.

What a window does:

- It holds every method that sends packets: all of them except `arp` and `nd` (and the raw method `lldp`, which only listens). A scheduled run that falls due inside a window does not start; the method shows the state `blackout` and tries again a second after the window ends.
- A run in progress when a window begins is stopped at that moment. It is recorded as `cancelled` with the error `stopped by a blackout window`, and what it saw goes out as a batch that is not complete.
- An on-demand run inside a window is refused with `scan.blackout`; `--ignore-blackout` runs it anyway, and then a window that begins during the run does not stop it either (section 7.2).
- `tenko node scan status` shows the windows, their time zone and, while one is in force, when it ends.

A window that covers the whole week, such as `daily 00:00-24:00`, is looked up about a week and a half ahead at a time; the scheduler looks again when that time has passed.

## 6. Active probing (TGL-18)

`active` (default `true`) is the switch of TGL-18. It governs the methods that probe every address of a prefix or many ports: `icmp`, `tcp_connect` and the raw methods `arp_sweep`, `tcp_syn` and `os_fingerprint`. With `active = false` these methods are `disabled` with the reason `active probing is off (scan.active = false)`, and an on-demand run of one is refused with `scan.disabled`. The probe then stays passive in the sense of the profile: it reads the neighbor tables, listens and asks the names of addresses it already knows (`arp`, `nd`, `mdns`, `llmnr`, `reverse_dns`) and polls its switches (`snmp`). Those methods still send packets, which is why the blackout windows hold them.

The profiles map to the settings of the probe's file like this:

| Profile | TGL-18 value | TGL-19 value | Settings in `[scan]` |
|---|---|---|---|
| Home | On | Normal | `active = true`, `rate = "normal"` (the defaults) |
| Standard | On, scheduled, outside blackout windows | Slow | `active = true`, `rate = "slow"`, and `blackout` windows for the hours that must stay quiet. Tenko sets no window by itself |
| Hardened | Off (passive only) unless enabled per segment | Slowest | `active = false`, `rate = "slowest"`; `active = true` for a segment where scanning is allowed |
| Lab | On | Unlimited | `active = true`, `rate = "unlimited"` |

`active` and `rate` are set in the configuration the controllers hold for the probe (section 7.5), or in the probe's own file while it holds none. The profile matrix also names OS fingerprinting for Home and the full port range for Lab. OS fingerprinting is the raw method `os_fingerprint` (sections 2.10 and 9). The connect scan `tcp_connect` takes a list of at most 1,024 ports, so the full range of 65,535 ports cannot be listed; the raw `tcp_syn` scan takes single ports and `"a-b"` ranges and may list the whole range, which is the Lab profile's full port range. With `active = false` the raw active methods `arp_sweep`, `tcp_syn` and `os_fingerprint` are `disabled` along with `icmp` and `tcp_connect`; the passive raw methods `lldp` and `dhcp_snoop` keep listening, like the other passive methods, as long as the host has `CAP_NET_RAW`.

## 7. Kill switch, on-demand runs and status

The commands of this section run on the probe node and read its configuration the way `tenko node status` does. They take `--config FILE` (or `TENKO_CONFIG`), `--data-dir PATH` and `--json`. SCAN-09 asks for on-demand scans from the UI, the API and the CLI. Sections 7.1 to 7.4 describe the CLI on the probe; sections 7.5 to 7.7 describe what the controllers add: the configuration of a probe, the kill switch from the API and scans on demand as jobs. A probe reads the `[scan]` section of its own `tenko.toml` for the CLI commands, also when the controllers hold a configuration for it (section 7.5).

### 7.1 The kill switch

`tenko node scan stop [--reason TEXT]` turns the kill switch on and `tenko node scan resume` turns it off. The switch is the file `<data_dir>/scan/stop` (section 8), which holds the time and the reason, so it works across processes and survives a restart.

- The node process looks at the file once a second. Within that time every running scan is stopped, with the 5 seconds of grace that a stop gets to hand back what it saw as a batch that is not complete, and no method starts, on schedule or on demand. The methods show the state `stopped`.
- When the switch goes off, a method whose run it stopped runs again at once; the other methods wait for their schedules.
- A node process that starts while the file exists starts with the switch on.
- An on-demand run is refused with `scan.stopped` while the switch is on, and a run in progress stops when the switch is turned on: `tenko node scan run` looks at the file once a second itself, so this holds in its own process too. The stopped run hands back what it saw, which is queued as a batch that is not complete, and it is recorded as `cancelled` with the error `stopped by the kill switch`.

`resume` answers `the kill switch was not on` when there was nothing to remove.

### 7.2 On-demand runs

```
tenko node scan run <method> [--target ADDRESS|PREFIX] [--ignore-blackout] [--dry-run] [--json]
```

`<method>` is one of `arp`, `nd`, `icmp`, `tcp_connect`, `reverse_dns`, `mdns`, `llmnr`, `snmp`; hyphens and underscores are the same. The command runs the method once, now, outside its schedule:

- It runs in the process of the command, with a scanner of its own that uses the same `[scan]` section, the known addresses from `known.json` and a limiter of its own. It does not write the status file or `known.json`.
- It checks the same rules as the schedule does: the method must be available on the host, switched on in `[scan]` and allowed by `active`, the kill switch must be off, and no blackout window may be in force unless `--ignore-blackout` is given.
- `--target` narrows the run to an address or a prefix inside the configured prefixes. The batch of such a run is never complete, so it adds and refreshes facts and expires none.
- Without `--dry-run` the node must be enrolled, because otherwise nothing would reach a controller (exit status 2). The batch is written to `<data_dir>/node/buffer/incoming/`, and the running node process adopts it within a second and sends it like a scheduled batch (see [cluster.md](cluster.md#61-the-buffer)). A run that saw nothing and is not complete queues nothing.
- With `--dry-run` nothing is queued; the command prints what the method saw instead.

Example of a dry run on a /28, with 192.0.2.1 excluded:

```
$ tenko node scan run icmp --target 192.0.2.0/28 --dry-run
icmp: partial, 3 sighting(s), 13 probe(s) in 1.4 s
  address  192.0.2.2
  address  192.0.2.5
  address  192.0.2.9
dry run: nothing was queued
```

A run that is queued prints `queued for the controller; the running node process sends it within a second`, and a run with nothing to report and nothing to expire prints `nothing to queue`. A run whose batch could not be queued (the buffer directory cannot be written, the disk is full) prints `tenko node scan run: error: the batch could not be queued: ...` on standard error and ends with the exit status 1; what the run saw is lost. A run that was refused prints the error with its code and ends with the exit status of section 13. With `--json` the command prints the object `{"method", "run", "queued", "batch"}`, where `run` is the record of section 7.3, `queued` says whether a batch went to the buffer, and `batch` is the batch of a dry run; the exit statuses are the same. A run with the outcome `failed` ends with the exit status 1; a run that ended `partial` or `cancelled` and whose batch was queued ends with 0. Scans with progress and a result diff, started from the API, are in section 7.7.

### 7.3 Status

`tenko node scan status [--json]` shows what the scanner does. While a scanner runs, it writes `<data_dir>/scan/status.json` at every change of state and at least once a minute, and the command shows that file. A file older than three minutes is not from a running scanner. Then the command builds the picture from the configuration and the host, which shows what the scanner would do (prefixes, limits, capabilities, and for each method whether it is enabled and available), together with the last runs that the stopped scanner had recorded. Example:

```
$ tenko node scan status --data-dir /var/lib/tenko
scanner:        running (pid 4242, status of 2026-10-10T08:15:27.730411Z)
kill switch:    off
prefixes:       192.0.2.0/24, 2001:db8:10::/64
excluded:       192.0.2.1/32
active probing: on; rate 50 probes/s
blackout:       mon-fri 08:00-17:00 (Europe/Stockholm)
raw sockets:    no (CAP_NET_RAW is missing; grant it with AmbientCapabilities=CAP_NET_RAW or setcap cap_net_raw+ep); ICMP: datagram socket
known addresses: 23

METHOD          STATE        EVERY  LAST RUN                        OUTCOME    SIGHTINGS  NEXT RUN
arp             idle         5m     2026-10-10T08:12:01.104512Z     complete   14         2026-10-10T08:17:03.261870Z
nd              idle         5m     2026-10-10T08:12:02.011930Z     complete   2          2026-10-10T08:17:04.518226Z
icmp            idle         30m    2026-10-10T08:03:41.870115Z     complete   17         2026-10-10T08:33:12.405901Z
mdns            idle         15m    2026-10-10T08:10:19.342078Z     complete   9          2026-10-10T08:24:48.977310Z
llmnr           idle         1h     2026-10-10T07:46:52.600214Z     complete   3          2026-10-10T08:46:30.115042Z
snmp            idle         15m    2026-10-10T08:08:20.733481Z     complete   31         2026-10-10T08:22:41.390256Z
tcp_connect     idle         6h     2026-10-10T02:21:44.190766Z     complete   11         2026-10-10T08:23:31.652983Z
reverse_dns     idle         1h     2026-10-10T07:48:10.058329Z     partial    12         2026-10-10T08:49:02.880417Z
arp_sweep       unavailable  1h     -                               -          -          -
                needs raw sockets: CAP_NET_RAW is missing; grant it with AmbientCapabilities=CAP_NET_RAW or setcap cap_net_raw+ep
```

The rows of `tcp_syn`, `os_fingerprint`, `lldp` and `dhcp_snoop` look like the one of `arp_sweep` and are left out; with `CAP_NET_RAW` granted they are `disabled` (switched off by default) until enabled, and then `idle` like any other method. Below a row, the command prints why a method is unavailable, a note `switched off in [scan]` for a method that is switched off, the error of the last run when it had one (`last run: stopped by a blackout window`), and `the batch could not be queued: ...` when its batch could not be handed on. Without a running scanner the first line reads `scanner:        not running on this node (no current status file)`, and with `[scan] enabled = false` it reads `switched off ([scan] enabled = false)`.

`status` always exits with 0 unless the configuration does not load (3). With `--json` it prints `{"running", "enabled", "status"}`. The `status` object has these fields:

| Field | Meaning |
|---|---|
| `updated_at`, `pid` | When the scanner wrote the status, and the process that wrote it |
| `kill_switch` | Whether the kill switch is on |
| `prefixes`, `exclude` | The scope. Single addresses show as `/32` and `/128` prefixes |
| `active`, `per_second` | TGL-18 and the probes per second of TGL-19; `null` means unlimited |
| `blackout`, `timezone`, `blackout_until` | The windows as written, their time zone (`system` when none is set), and the end of the window in force |
| `capabilities` | `raw_sockets` with `raw_detail` (section 9), and how ICMP is sent: `datagram_socket`, `ping_command` or `unavailable` |
| `known_addresses` | Number of known addresses that count now |
| `methods` | For each method: `method`, `enabled`, `availability` (`ready`, or `unavailable` with a `reason`), `state`, `interval_secs`, `ttl_secs`, `next_run` and `last_run` |
| `last_run` | `started_at`, `finished_at`, `outcome`, `sightings`, `probes`, `queued` (whether a batch was handed on), `on_demand`, `target`, `error` (what failed or stopped the run), `delivery_error` (why the batch could not be handed on) and `notes` (devices that did not answer and so on, without secrets) |

### 7.4 States and outcomes

| State (text, JSON) | Meaning |
|---|---|
| `idle`, `idle` | Waiting for its next run |
| `waiting`, `waiting_for_addresses` | `tcp_connect` or `reverse_dns`, waiting for the other methods to report once (section 3.4) |
| `running`, `running` | A run is in progress |
| `blackout`, `blackout` | Held by a blackout window (section 5) |
| `stopped`, `stopped` | Held by the kill switch (section 7.1) |
| `disabled`, `disabled` | Switched off with `enabled = false`, or an active method with `active = false` |
| `unavailable`, `unavailable` | It cannot run here or with this configuration: no prefixes, no ICMP path, no SNMP device, a raw-socket method. The reason is shown |

| Outcome | Meaning |
|---|---|
| `complete` | The run covered everything it was asked to cover. The batch is complete too, except for `mdns` and `llmnr` (section 3.3) |
| `partial` | The run covered part: a narrower `--target`, a lookup or a device that did not answer, a batch that was cut |
| `cancelled` | The kill switch, a blackout window, the deadline or the shutdown stopped the run. What it saw went out as a batch that is not complete |
| `failed` | The method could not run at all. No batch was made, and the error is shown |

### 7.5 Configuration from the controller

The controllers hold one scan configuration per probe. It has the keys of the `[scan]` section (section 12), written as JSON, with one difference: SNMP passwords are named as operator secrets of the vault (`auth_secret`, `privacy_secret`, section 12.3), never as passwords or password files. The routes need the Discovery module and a controller; all paths are below `/api/v1`.

| Route | Needs | Answer |
|---|---|---|
| `GET /nodes/{id}/scan-config` | Read on the node (viewers, operators, administrators) | 200 with the configuration and its state; the `ETag` is the revision of the stored configuration and is absent while none is stored |
| `PUT /nodes/{id}/scan-config` | Update on the node (administrators) | 200 with the stored configuration and its new `ETag`. `If-Match` with the revision read makes the write fail with 412 `node.config.revision_mismatch` when the configuration changed since |
| `GET /scans/probes` | Read on nodes | 200 `{"items": [...]}`: every probe, this controller's own probe role first (named `controller-<id>`), then the enrolled probes by id |

`{id}` is the node id of a probe, or the node id of the controller when it runs the probe role. The answer of `GET` and `PUT` holds:

| Field | Meaning |
|---|---|
| `config` | The stored configuration, or the defaults while the controllers hold none |
| `stored` | Whether the controllers hold a configuration for the probe. While `false`, the probe runs on its own file |
| `origin` | `api` (an administrator set it) or `offer` (the probe offered its own file at its first connection) |
| `revision`, `updated_at`, `updated_by` | The revision of the stored configuration, when it changed and by whom |
| `applied` | What the probe last reported it applies: `prefixes`, `exclude`, `methods`, `vrf`, `active`, `stopped`, `stop_reason`, `origin` (`synced` or `local`), `revision`, `error`, `applied_at` and `reported_at` |
| `in_sync` | Whether the probe reports a synced configuration at least as new as the stored one and no error. True while none is stored |
| `lacking_secrets` | The addresses of SNMP devices that still need a vault secret before they are polled |
| `kill_switch` | Section 7.6 |

The items of `GET /scans/probes` hold `node`, `name`, `in_process`, `stored`, `revision`, `applied`, `in_sync` and `kill_switch`.

A `PUT` is checked before anything is written. The body must validate as a stored configuration: every key as in section 12, and no `auth_password`, `auth_password_file`, `privacy_password` or `privacy_password_file`, which are refused with 422 `node.config.invalid`. Every secret it names must exist and be an operator secret of the vault (422 `node.config.secret`; 503 `node.config.vault_unavailable` when the controller has no vault). The node must exist (404 `cluster.node.not_found`) and have the role `probe` (409 `node.config.not_a_probe`). The write is an inline job `scan.edit` with the audit record `scan.config.update` (the prefixes and the number of secrets). The probe receives the new row within seconds, over the open stream, and replaces its scanner; the configuration it had before keeps running if the new one does not build, and the error shows in `applied.error` ([node-sync.md](node-sync.md#43-the-probes-configuration)).

A probe offers its file at its first connection with the passwords and password files removed. A device of that file that relied on a password therefore has no credentials in the stored configuration: it is listed in `lacking_secrets`, and the probe skips it with a note (`waits for a vault secret for its passwords`) until an administrator puts the vault secrets into the configuration with a `PUT`. References to vault secrets in the offered file are dropped as well, because a probe cannot name secrets it was never given. The probe's own file stays in use for `tenko node scan run` and `tenko node scan status`, which never read the configuration from the controllers.

### 7.6 The kill switch from the controllers

| Route | Needs | Effect |
|---|---|---|
| `POST /nodes/{id}/scan/stop` | Update on the node (administrators) | Turns the kill switch of one probe on |
| `POST /nodes/{id}/scan/resume` | Update on the node | Turns it off |
| `POST /scans/stop` | Update on nodes | Turns the kill switch of every probe on: this controller's own probe role and every enrolled node with the role `probe` at that moment |
| `POST /scans/resume` | Update on nodes | Turns it off for every probe |

The stop routes take an optional body `{"reason": "text"}`; the reason is trimmed and kept to 200 characters, and defaults to `stopped from the controllers`. The answer is 202 with `{"commands": [{"node", "command"}]}`, one command per probe. The request is audited as `scan.stop` or `scan.resume`, with the scope `node` or `installation` and, for a stop, the reason. A node that does not exist gives 404 `cluster.node.not_found`, and a node without the role `probe` gives 409 `node.config.not_a_probe`. With no probe the installation-wide routes record nothing and answer an empty list.

The switch is a command that the controllers deliver to the probe ([node-sync.md](node-sync.md#9-the-kill-switch)): a connected probe has it as soon as the write is applied on the controller it talks to, and stops its running scans at once with the grace of section 7.1. A probe that is offline receives the command when it connects, and it does not expire. The probe keeps the switch in the file of section 8, so a restart does not undo it, and it stays on until a `resume` arrives or `tenko node scan resume` runs on the probe. A probe enrolled after an installation-wide stop does not get it.

`kill_switch` in the answers of section 7.5 has these fields: `stopped` (what the controllers asked for last), `reason`, `at` (when) and `by` (the user), and `confirmed`, which is true once the probe has reported the command done and false while the probe has not (it is offline, or has not applied it yet). The probe's own report of the switch is `applied.stopped` and `applied.stop_reason`. An on-demand scan that is running on a probe is stopped by the switch like any other run.

### 7.7 Scans on demand from the controllers

`POST /api/v1/scans` starts a scan of a network and answers 202 with the run, which `GET /api/v1/scans/{id}` shows from then on. The body:

| Field | Meaning | Default |
|---|---|---|
| `target` | `{"kind", "value"}`. `kind` is `prefix` (the id of a prefix of IPAM), `host` (the id of a host, scanning its addresses), `address` (`192.0.2.10`) or `network` (`192.0.2.0/28`) | Required |
| `kinds` | What to run: `passive_refresh` (`arp`, `nd`, `mdns`, `llmnr`, `reverse_dns`), `port_scan` (`tcp_connect`), `snmp_poll` (`snmp`) and `os_fingerprint` (`os_fingerprint`, which is a raw-socket method that does not run yet, section 9) | `["passive_refresh"]` |
| `vrf` | The VRF of an `address` or `network` target. A `prefix` or `host` target brings its own | The default VRF |
| `deadline_secs` | How long the job waits for the probes, 30 to 3,600 (422 `scan.job.invalid` outside) | 600 |

It needs the right to execute on the target: on the prefix or the host for those targets, on addresses in general for an `address` and on prefixes in general for a `network`. Operators and administrators have it. A prefix or host that does not exist is 404 `scan.job.target`, and a host without addresses or a value that does not fit its kind is 422 `scan.job.target`. If the scope of no probe covers the target, the request is refused with 422 `scan.job.no_probe`. The scope of a probe is the prefixes of its stored configuration minus its exclusions, else what it last reported; a probe whose scanner is switched off in its stored configuration covers nothing, and a probe in another VRF is left out. Each probe that overlaps the target gets the part of it that lies inside its scope. The request is audited as `scan.run`, with the run id, the networks and the kinds.

The scan is the job `scan.run` with three steps (the job id is `job_id` of the run, and `GET /api/v1/jobs/{id}` shows it):

1. `scan.dispatch` reads the facts of the target that the probes' methods reported before (the baseline, at most 20,000 facts) and issues one `scan.run` command to every probe, with the methods of the kinds in order, the part of the target inside its scope and the time left to the deadline. Blackout windows and the kill switch of the probe apply as for any run (sections 5 and 7.1): the command asks for no exception.
2. `scan.await` waits until every command is over and its batches have arrived, or until the deadline. A command that is not finished at the deadline is marked `expired`.
3. `scan.diff` compares what the batches reported with the baseline and stores the result in the run.

The run has these fields: `id`, `job_id`, `target`, `networks` (what the target resolved to), `vrf`, `kinds`, `requested_by`, `created_at`, `deadline`, `finished_at`, `error`, and:

| Field | Meaning |
|---|---|
| `state` | `queued` (waiting for the job runner), `running`, `done` (every probe finished and every batch arrived), `partial` (the deadline passed, or a probe failed, or batches are missing; the diff covers what arrived), `failed` (no probe covered the target any more when the job started) or `cancelled` (cancelled with its job: the commands that were not over are withdrawn and the probes are asked to cancel) |
| `progress` | Percent, the mean over the probes; 100 once the run ended |
| `probes` | Per probe: `node`, `command`, `target` (the part it scans), `state` of the command (`pending`, `accepted`, `running`, `done`, `failed`, `rejected`, `expired`, `cancelled`), `progress`, `detail` (the method it runs, or its notes), `batches` and `ingested` |
| `diff` | Once the run ended |

The diff counts, per fact type (`address`, `services`, `os`, `name`, `vendor`, `attachment`, `link`), the facts that are `new` (not known before), `changed` (other attributes), `unchanged` and `gone`, and lists the new, changed and gone facts as `items` with `change`, `fact_type`, `subject`, `source` and the attributes `before` and `after`; the list holds at most 5,000 items and `truncated` says that it or the baseline was cut. A fact is `gone` only when it was current in the baseline, came from a method of this run on a probe whose command finished, and the scan did not see it. A probe whose command did not finish removes nothing. The facts of the scan are also ingested by the reconciler like those of a scheduled run, so the scan updates the picture of the network as well as describing the difference.

`GET /api/v1/scans` lists the runs, newest first, with the usual `limit` and `cursor` parameters, and only the counts of each diff; it needs the right to read jobs (viewers, operators and administrators). `GET /api/v1/scans/{id}` shows one run with every item of its diff and answers 404 `scan.job.not_found` for an unknown id. Runs are kept for 30 days, and the commands behind them and their results for 7 days after they finish.

## 8. Files

The scanner keeps its files in `<data_dir>/scan/`. None of them holds a secret.

| File | Contents |
|---|---|
| `status.json` | What the running scanner last wrote for `tenko node scan status` (section 7.3): scope, limits, capabilities, and for each method the state, the next run and the last run. Replaced atomically at every change of state and at least once a minute |
| `known.json` | The known addresses (section 3.4): per address, the methods that saw it and until when. Written after every batch that was delivered, read at start, at most 65,536 addresses |
| `stop` | The kill switch (section 7.1). The file exists while the switch is on and holds the time and the reason |
| `relay/` | Only on a controller with the `probe` role: the local buffer between its scanner and its own ingest ([node-sync.md](node-sync.md#8-the-relay-buffer)) |

Batches that `tenko node scan run` queues go to `<data_dir>/node/buffer/incoming/` (see [cluster.md](cluster.md#61-the-buffer)).

## 9. Raw-socket methods

`arp_sweep`, `tcp_syn`, `os_fingerprint`, `lldp` and `dhcp_snoop` send and listen at the link layer, so they need a raw socket. On Linux this is `CAP_NET_RAW` and an `AF_PACKET` socket, taken through a safe dependency (`pnet_datalink`); the workspace uses no `unsafe` of its own. Each method's batch is filed under `probe:<node>:<method>` like any other. With the capability the methods run; without it they answer `unsupported` with the reason, and `tenko node scan status` says so. The frame parsers (Ethernet, ARP, IPv4, TCP, LLDP, CDP, DHCPv4) are in `crates/tenko-scan/src/frame/` and have fuzz targets (`scan_lldp_cdp`, `scan_arp`, `scan_dhcp_snoop`).

| Platform | What the methods need | Setup |
|---|---|---|
| Linux, native | `CAP_NET_RAW` in the effective set of the process | With systemd, the drop-in `deploy/systemd/probe.conf`: `AmbientCapabilities=CAP_NET_RAW`, `CapabilityBoundingSet=CAP_NET_RAW` (plus any other capability the unit needs) and `AF_PACKET` in `RestrictAddressFamilies`. Without systemd, `setcap cap_net_raw+ep` on the `tenko` binary; a replaced binary loses the file capability, so repeat the command after an update |
| Linux, Docker | `NET_RAW` in the capabilities of the container | Docker's default set includes it. If the container drops all capabilities (`--cap-drop=ALL`, `cap_drop: [ALL]`), add `NET_RAW` back (`--cap-add=NET_RAW`) |
| Linux, unprivileged LXC | `net_raw` kept in the container | An unprivileged container drops `CAP_NET_RAW` by default. Keep it in the container configuration: either list it in `lxc.cap.keep`, or make sure `lxc.cap.drop` does not name `net_raw` (and does not drop everything). On Proxmox VE this is a line in `/etc/pve/lxc/<id>.conf` such as `lxc.cap.keep: net_raw`; the container must be restarted. Check the result with `tenko node scan status` inside the container: the raw methods are `unavailable` until it is kept. A privileged container already has it |
| Windows | Npcap (not bundled) | The raw methods answer `unsupported` with `raw sockets need Npcap, which Tenko does not bundle`, because Tenko ships no packet driver. A later release may add a build that uses a user-installed Npcap (section 14); until then the passive and unprivileged methods cover a Windows probe |

The detection that `tenko node scan status` shows: on Linux the scanner reads `CapEff` in `/proc/self/status` and looks at bit 13, `CAP_NET_RAW`; on Windows it looks for `System32\Npcap\wpcap.dll`. The status line says which of the two it found, for example `raw sockets: yes (CAP_NET_RAW is in the effective set)` or, without the capability, `raw sockets: no (CAP_NET_RAW is missing; grant it with AmbientCapabilities=CAP_NET_RAW or setcap cap_net_raw+ep)`; a method then reports `needs raw sockets: <that reason>`. Everything else in this release works without raw sockets.

## 10. IDS and EDR

Scanning looks like an attack to the products that watch for attacks, and Tenko cannot know which products a site runs. This section says what the probe does that such products are likely to flag and why, how to allow-list the probe, and how to make it gentler (SCAN-07). It describes behaviors and categories; the names of alerts, rules and settings differ between products and versions, so check the documentation of the product at hand.

### 10.1 What is likely to be flagged

| Traffic | What a monitor sees | Why it is likely to be flagged |
|---|---|---|
| ICMP sweep (`icmp`) | One echo request to every address of a prefix within seconds, from one source. With the datagram socket the payload is the text `tenko-sc`. With the `ping` command, which is always the case on Windows, there is one short-lived `ping` process per address | Ping sweeps are the first step of network mapping, and signatures for them exist in every IDS ruleset. EDR agents on the probe host see the process creations |
| TCP connect scan (`tcp_connect`) | Connection attempts from one source to the same ports on many hosts. Each attempt is a TCP handshake that is closed right away, unless the TLS hint keeps an open port for up to 1.5 seconds: it sends a `ClientHello` without a server name whose `random` field starts with `tenko-scan-tls-hint` | Port scans are what scan signature families detect, for example those named SCAN in the Emerging Threats rulesets used by Suricata and Snort, and the IDS/IPS features of firewalls and network controllers such as OPNsense, pfSense or UniFi threat management. A service that does not speak TLS may log the hello as a malformed request |
| Ports of domain controllers | The default port list includes 53, 135, 139, 389, 445, 636 and 3389, the ports of DNS, RPC, NetBIOS, LDAP, LDAPS, SMB and RDP. Connections to them from a host that is not a domain member | Microsoft Defender for Identity includes detections for reconnaissance against domain controllers (enumeration over SMB, LDAP and DNS, for instance), and Defender for Endpoint or another EDR agent on the scanned hosts may report inbound scanning. Whether a probe triggers one depends on the product version, its sensitivity settings and the volume |
| Reverse DNS (`reverse_dns`) | One PTR query per known address to a DNS server, in a short burst | Bulk reverse lookups are a known reconnaissance technique, and identity-protection products watch DNS servers for it. The DNS server's query log grows by one line per address |
| SNMP (`snmp`) | An SNMPv3 discovery request without a user, then authenticated GetBulk walks. A wrong user or password makes the device count failed authentications, and most devices log them | Switches log authentication failures, and SNMP requests to a device that does not expect them are often alerted on |
| mDNS and LLMNR | A multicast browse query to 224.0.0.251, and unicast reverse queries to port 5353 and 5355 of known hosts | Some products watch LLMNR and mDNS, because poisoning tools abuse them. The probe only asks; it never answers a query or announces a name |
| `arp`, `nd` and the resolver list | Nothing on the network. On Windows the process `powershell.exe -NoProfile -NonInteractive -Command` with `Get-NetNeighbor` or `Get-DnsClientServerAddress`; on Linux `ip -6 neigh show` | EDR products log PowerShell command lines and may flag a service account that runs them |

The list holds in both directions. An IPS that drops the traffic does not only alert: the probe then sees unanswered lookups and missing sightings, which show up as `partial` runs and missing facts.

### 10.2 Allow-listing the probe

Give the probe a fixed address (a static address or a DHCP reservation), tell the security team what runs when, and then register that address where the products look:

- **IDS and IPS.** Suppress or pass by source address. A per-rule suppression keeps every other rule active for the address; in Suricata it is an entry in the threshold configuration, for example `suppress gen_id 1, sig_id <sid>, track by_src, ip 192.0.2.5`, with the signature id taken from the alert. Snort has an equivalent suppress mechanism. Firewall front ends for Suricata and Snort, such as the packages of OPNsense and pfSense, and the threat management of UniFi, offer a list of trusted addresses or a suppression per alert; use the one the product has. A pass list silences every rule for the address, which is a larger exception than a suppression.
- **Identity protection and EDR.** Add the probe's address or host to the exclusions or the suppression rules of the console, for the detections that fire. Defender for Identity and EDR consoles offer exclusions by IP address or by device; the place differs by product.
- **Content rules.** The TLS hint can be recognized by content: the `random` field of its `ClientHello` begins with the ASCII text `tenko-scan-tls-hint`, 19 bytes at offset 11 of the TCP payload. The echo payload of the Linux datagram sockets is `tenko-sc`. A rule that matches these can pass or tag the probe's traffic without an address. The `ping` command and the DNS, mDNS, LLMNR and SNMP queries carry no such marker.

### 10.3 Scanning gently

The settings below make the probe quieter. They combine, and the Hardened profile uses several of them (section 6).

1. **Slow the rate.** `rate = "slow"` (50 probes per second) or `"slowest"` (10), or a lower `packets_per_second`.
2. **Space the probes per host.** A larger `per_host_interval_ms`, for example 1000, keeps any one device to at most one probe a second.
3. **Probe fewer ports.** Trim `tcp_connect.ports` to the services that matter, and leave `targets = "known"` (the default) so that only addresses that answered before are scanned.
4. **Scan less often.** Raise `icmp.interval_secs` and `tcp_connect.interval_secs`; the sighting lifetimes grow with them (section 3.2).
5. **Keep quiet at set times.** Add `blackout` windows for business hours (section 5).
6. **Leave devices alone.** List domain controllers and devices that react badly to scans in `exclude`.
7. **Drop the TLS hint.** `tls_hint = false` removes the `ClientHello`; `tcp_connect` then only connects and closes.
8. **Stay passive.** `active = false` switches off `icmp` and `tcp_connect` (section 6). The neighbor tables, mDNS, LLMNR, reverse DNS and SNMP still tell most of what is on the segment.

## 11. The OUI table

The vendor of a MAC address comes from its OUI, the first three octets, looked up in a table that is compiled into the binary: [`crates/tenko-scan/data/oui.tsv`](../crates/tenko-scan/data/oui.tsv). The source is the MA-L registry (24-bit blocks) of the IEEE Registration Authority, `https://standards-oui.ieee.org/oui/oui.csv`. The table holds the whole registry as generated on 2026-10-10 (40,316 blocks, about 1.2 MB in the source tree and about 400 KB compressed), including the block `00005E`, `ICANN, IANA Department`, which contains the documentation MAC addresses of RFC 7042 (`00:00:5e:00:53:xx`). The registry changes every week; regenerate the table before a release with the generator below.

Locally administered addresses (the second-lowest bit of the first octet is set) and group addresses (the lowest bit is set) have no vendor and get no `vendor` sighting. The smaller MA-M and MA-S blocks share an OUI between several organizations and are not looked up.

To regenerate the table, download the CSV and run the generator with Node.js 22, which needs no packages:

```
node crates/tenko-scan/data/generate-oui.mjs <path to oui.csv>
```

The script keeps the rows of the registry `MA-L`, collapses white space in the names, drops control characters, cuts a name at 96 characters, keeps the first row when an OUI occurs twice, sorts by OUI and writes the table with a header (source, date, number of entries) to `oui.tsv` next to itself; an optional second argument names another output file. It exits with 0 on success, 1 when the CSV is not in the expected format and 2 for a bad command line or a file that cannot be read or written. The table is compiled in, so a regenerated table reaches the probes with the next build.

## 12. Configuration reference

The `[scan]` section of `tenko.toml`, with the example in `deploy/tenko.example.toml`. A probe reads its own file until it holds a configuration from the controllers, and for `tenko node scan` (section 1). The configuration that the controllers hold for a probe (section 7.5) has the same keys in JSON, with the differences of section 12.3.

### 12.1 `[scan]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Runs the scanner when the node has the `probe` role |
| `prefixes` | `[]` | The prefixes or addresses the probe covers (section 4.1). Empty: the scanner scans nothing |
| `exclude` | `[]` | Prefixes and addresses inside `prefixes` that are never probed or reported |
| `vrf` | Not set | The VRF of the addresses, as a VRF id. Not set: the VRF of the enrolment token, else the default VRF |
| `active` | `true` | Active probing (TGL-18, section 6) |
| `rate` | `"normal"` | Rate profile (TGL-19): `normal` (100 probes per second), `slow` (50), `slowest` (10) or `unlimited` |
| `packets_per_second` | Not set | Probes per second; overrides `rate`; 0 is unlimited |
| `per_host_interval_ms` | 100 | Least milliseconds between two probes to the same address, 0 to 60,000 |
| `concurrency` | 32 | Most probes in flight at once, 1 to 1,024 |
| `max_hosts_per_prefix` | 4,096 | Most addresses of an IPv4 prefix that a sweep enumerates, 1 to 65,536 |
| `timezone` | Not set | The IANA time zone of `blackout`. Not set: the system time zone |
| `blackout` | `[]` | Blackout windows (section 5) |

### 12.2 The method sections

Every method has a section `[scan.<method>]` with `enabled`, `interval_secs` and `ttl_secs`. `ttl_secs` is not set by default; the lifetime is then three intervals, at least 15 minutes and at most seven days (section 3.2).

| Section | `enabled` | `interval_secs` | Further keys |
|---|---|---|---|
| `[scan.arp]`, `[scan.nd]` | `true` | 300 | None |
| `[scan.icmp]` | `true` (needs `active`) | 1,800 | `timeout_ms` (1,000): wait for an echo reply |
| `[scan.tcp_connect]` | `true` (needs `active`) | 21,600 | `ports`: the port list of section 2.3. `timeout_ms` (1,500): wait for a connection. `tls_hint` (`true`): the TLS exchange per open port. `targets` (`"known"`): `known` or `all` |
| `[scan.reverse_dns]` | `true` | 3,600 | `servers` (`[]`): DNS servers, an address with the port 53 unless given; empty uses the resolvers of the host. `timeout_ms` (2,000) |
| `[scan.mdns]` | `true` | 900 | `listen_secs` (4): collection window, 1 to 60. `passive` (`true`): also listen on port 5353. `group` (`"224.0.0.251:5353"`): where queries go. `unicast_port` (5353): the port of unicast queries to known addresses |
| `[scan.llmnr]` | `true` | 3,600 | `timeout_ms` (1,000): wait for answers after the last query. `port` (5355) |
| `[scan.snmp]` | `true` (needs a device) | 900 | `timeout_ms` (2,000): wait for an answer. `retries` (2): resends of an unanswered request, 0 to 10. `attach_on_lldp_ports` (`false`): section 2.7. `devices`: the switches (section 12.3) |
| `[scan.arp_sweep]` | `false` (needs `active`) | 3,600 | `timeout_ms` (2,000): wait for ARP replies. `interface`: override the interface |
| `[scan.tcp_syn]` | `false` (needs `active`) | 3,600 | `ports`: single ports and `"a-b"` ranges, up to 65,535 ports. `targets` (`"known"`): `known` or `all`. `timeout_ms` (2,000). `interface` |
| `[scan.os_fingerprint]` | `false` (needs `active`) | 3,600 | `ports`: a short list, single ports and `"a-b"` ranges. `timeout_ms` (2,000). `interface` |
| `[scan.lldp]` | `false` | 3,600 | `listen_secs` (35; at least 65 with `cdp`). `cdp` (`true`): also parse CDP. `interface` |
| `[scan.dhcp_snoop]` | `false` | 3,600 | `listen_secs` (120). `interface` |

### 12.3 SNMP devices

Each switch is one `[[scan.snmp.devices]]` entry.

| Key | Default | Meaning |
|---|---|---|
| `address` | Required | The management address of the device |
| `port` | 161 | The SNMP port |
| `name` | `sysName`, else the address | The device name in attachments and links |
| `user` | Required | The SNMPv3 user, 1 to 32 characters |
| `auth` | Not set | Authentication protocol: `sha1`, `sha224`, `sha256`, `sha384` or `sha512`. Not set: no authentication, for labs only |
| `auth_password_file` | Not set | A file whose first line is the authentication password; preferred over `auth_password` |
| `auth_password` | Not set | The authentication password in clear in `tenko.toml`. At least 8 characters |
| `privacy` | Not set | Privacy protocol: `aes128`. Needs `auth`. Not set: no encryption |
| `privacy_password_file`, `privacy_password` | Not set | The privacy password, like the authentication password |
| `auth_secret` | Not set | The id of the operator secret of the vault that holds the authentication password. The probe fetches it from the controllers each time it polls |
| `privacy_secret` | Not set | The id of the operator secret that holds the privacy password |
| `context` | Empty | The SNMPv3 context name |

The password of a device comes from one of three places: a file (`auth_password_file`), the key in `tenko.toml` (`auth_password`) or an operator secret of the vault (`auth_secret`). A vault secret cannot be combined with the other two. In the probe's own file `auth` needs one of the three, and `privacy` needs `privacy_password_file`, `privacy_password` or `privacy_secret`. The scanner reads a password file each time it polls the device. An inline password is shown as `(hidden)` in the output of `tenko config check` and in debug output; a password file is shown by its path only. A password in clear in `tenko.toml` makes the node process log a warning at start. Prefer password files that only the service account can read, or the vault.

**In a configuration held by the controllers** (section 7.5) a device names vault secrets only. `auth_password`, `auth_password_file`, `privacy_password` and `privacy_password_file` are refused with 422 `node.config.invalid`, and every secret must exist as an operator secret of the vault (422 `node.config.secret`); the controllers store the list of the secrets with the purpose `snmp`. An example of a device in the JSON body of `PUT /api/v1/nodes/{id}/scan-config`:

```json
{
  "snmp": {
    "devices": [
      {
        "address": "192.0.2.2",
        "name": "switch-a.example.test",
        "user": "tenko",
        "auth": "sha256",
        "auth_secret": "<id of an operator secret>",
        "privacy": "aes128",
        "privacy_secret": "<id of another operator secret>"
      }
    ]
  }
}
```

A device with `auth` or `privacy` and without the matching secret is kept but not polled; the probe notes that it waits for a vault secret, and the device is listed in `lacking_secrets`. This is the state after a probe's offer, which carries no passwords (section 7.5).

The probe fetches the values over its mutual TLS connection at the start of every `snmp` run, and the controller audits each hand-over as `cluster.node.secrets` ([node-sync.md](node-sync.md#6-secrets)). The values stay in memory and are not written to disk. While no controller answers, the probe uses the values of its last fetch since the process started; after a restart without a reachable controller it has none, the `snmp` run is partial with the note that the secrets could not be fetched, and the other methods run as usual. A value that is not text is not used. A secret is handed only to the probe whose own configuration names it.

### 12.4 Checks and environment variables

A key the scanner does not know stops the start with `config.parse` (`config.env` when it came from an environment variable). A value out of range stops it with `config.invalid`, and the message names the key, for example `scan.concurrency must be between 1 and 1024`. The ranges not listed above are:

| Key | Allowed |
|---|---|
| `interval_secs` of every method | 30 to 604,800 |
| `ttl_secs` of every method | 60 to 2,592,000 |
| `timeout_ms` of `icmp`, `tcp_connect`, `reverse_dns`, `llmnr`, `snmp`, `arp_sweep`, `tcp_syn` and `os_fingerprint` | 10 to 60,000 |
| `tcp_connect.ports` | 1 to 1,024 ports, each from 1 to 65,535 |
| `tcp_syn.ports`, `os_fingerprint.ports` | single ports and `"a-b"` ranges, each from 1 to 65,535 (up to all 65,535) |
| `listen_secs` of `lldp` and `dhcp_snoop` | 1 to 3,600 |

A key is also set by an environment variable: `TENKO_SCAN__` plus the key in upper case, and a nested key joins its section with a double underscore. A list is given as a TOML array.

```
TENKO_SCAN__RATE=slow
TENKO_SCAN__ICMP__INTERVAL_SECS=600
TENKO_SCAN__PREFIXES='["192.0.2.0/24"]'
```

The list of SNMP devices is easier to keep in the file.

## 13. Error codes

A code is stable. The scanner reports it in the log, in the status (`error` and `notes` of a run) and in the output of `tenko node scan`. The codes of the scan control of the controllers follow in a second table.

| Code | Meaning | Exit status of `tenko node scan` |
|---|---|---|
| `scan.config` | The `[scan]` section is unusable: a prefix, window, time zone, VRF or SNMP credential does not parse or is out of range, or an SNMP password file cannot be read | 3 |
| `scan.io` | A socket, file or command failed: a neighbor table or a ping cannot be read or started, or a UDP socket cannot be opened | 1 when the run fails |
| `scan.unavailable` | The method cannot run on this host or with this configuration: no ICMP path, no SNMP device, no prefixes, a raw-socket method. It is reported before `scan.disabled` | 2 |
| `scan.disabled` | The method is switched off in `[scan]`, or it is active probing and `active` is `false` | 2 |
| `scan.out_of_scope` | The `--target` of a run lies outside the configured prefixes | 2 |
| `scan.stopped` | The kill switch is on | 2 |
| `scan.blackout` | A blackout window is in force and `--ignore-blackout` was not given | 2 |
| `scan.cancelled` | A run was stopped by the kill switch, a blackout window or the shutdown of the process. It appears in the error of a cancelled run and in the notes of an `snmp` run | 0 |
| `scan.snmp.timeout` | A device did not answer the discovery or a request after the retries, or its port is unreachable | 0, as a note of the run |
| `scan.snmp.auth` | A device rejected the user: unknown user, wrong password or protocol (wrong digest), wrong privacy password (decryption error), an unsupported security level, or a time window the device did not accept after a resynchronization | 0, as a note of the run |
| `scan.snmp.protocol` | A device broke the protocol: it answered with an error status (such as `noSuchName` or `tooBig`), rejected its own engine id after a new discovery, or sent an unexpected report | 0, as a note of the run |

The codes of the scan control answer the API routes of sections 7.5 to 7.7 as problem details with the status shown. The configuration sync and the commands have codes of their own, listed in [node-sync.md](node-sync.md#113-error-codes).

| Code | Status | Meaning |
|---|---|---|
| `cluster.node.not_found` | 404 | The node is not enrolled in this installation |
| `node.config.not_a_probe` | 409 | The node does not have the role `probe` |
| `node.config.invalid` | 422 | The configuration does not validate as a stored one: a key out of range (the message names it), or a password or a password file in an SNMP device |
| `node.config.secret` | 422 | A vault secret that the configuration names does not exist or is not an operator secret |
| `node.config.revision_mismatch` | 412 | `If-Match` names a revision other than the stored one; read the configuration again |
| `node.config.vault_unavailable` | 503 | The controller has no vault to check the secrets against |
| `scan.job.target` | 404, 422 | The prefix or host of the target does not exist (404), or the target cannot be scanned: a host without addresses, a value that does not fit its kind (422) |
| `scan.job.no_probe` | 422 | The scope of no probe covers the target; set the prefixes of a probe first |
| `scan.job.invalid` | 422 | A value of the request is out of range, such as `deadline_secs` |
| `scan.job.not_found` | 404 | There is no scan run with that id |

The last column is the exit status of `tenko node scan run` when it ends with that error. A run that ended `partial` or `cancelled` exits with 0 once its batch is queued. A run whose batch could not be queued exits with 1 and prints `the batch could not be queued` with the cause on standard error; the status of the node process shows the same cause as `delivery_error` of the run and the line `the batch could not be queued: ...` below the method. `status`, `stop` and `resume` exit with 3 when the configuration does not load, and `stop` and `resume` with 1 when the switch file cannot be written or removed.

## 14. What comes next

- **Raw-socket methods on Windows.** `arp_sweep`, `tcp_syn`, `os_fingerprint`, `lldp` and `dhcp_snoop` run on Linux with `CAP_NET_RAW` (section 9); on Windows they answer `unsupported`. A later release may add a build that uses a user-installed Npcap.
- **An IPv6 neighbor-discovery sweep.** `arp_sweep` covers IPv4; IPv6 is left to the passive `nd` method. A neighbor-solicitation sweep and an IPv6 SYN scan are follow-ups.
- **The DHCPv4 codec for the snoop.** `dhcp_snoop` parses the four fields it needs locally; once `tenko-dhcp`'s DHCPv4 codec merges, the snoop calls it instead, and full lease facts come with Tenko DHCP.
- **A fresher OUI registry at every release**: the table is regenerated by hand today (section 11); a release step could do it.
- **The scan scope for the orphan rule.** The probes report their effective scope to the controllers (`applied` in section 7.5), but the reconciler does not yet use it to tell a device that is gone from one that was not scanned (see [reconciliation.md](reconciliation.md#8-what-later-sources-add)).
