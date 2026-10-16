# Fixtures of the Proxmox VE connector

Each file holds the answers of the API by path, in the layout the mock of `tests/support` serves: `{"routes": {"/api2/json/<path>": <answer>}}`, where an answer is a body served with status 200 or `{"status": N, "body": ...}`.

## `documented.json`

A hand-written two-node cluster in the shapes of the API documentation, with documentation addresses (RFC 5737, RFC 3849), MAC addresses (RFC 7042) and invented names, and the edge cases the tests need (its `description` lists them: a guest agent that is not running, cloud-init addresses, a template, a stopped guest on a second node, an agent the token may not read, an SDN vnet). `tests/plugin.rs` asserts its exact values.

## `recorded.json`

The answers of a real Proxmox VE 9.1 node (one node, 9 QEMU and 5 LXC guests, no pool, no SDN), recorded on 2026-10-16 with the recorder in `tests/live.rs` through the plugin's own client and anonymised by `tenko_connect::sdk::anonymise` before anything was written to disk. It holds every route the plugin reads: `/version`, `/access/permissions`, `/cluster/resources` (21 resources), `/cluster/status`, the SDN vnets and zones, the network of the node, the configuration of each guest, and the live interfaces of the running guests (7 guest agent answers, 4 container interface lists), 32 routes in all. The node name in the paths is the same placeholder as in the answers. The test `the_recorded_node_reads_like_the_live_one` in `tests/plugin.rs` reads it through the mock and asserts the counts the live smoke printed the same day: 15 hosts (the node, 9 QEMU, 5 LXC; 1 online, 11 running, 3 stopped), 17 MAC addresses on 14 hosts, 17 IPv4 and 8 IPv6 addresses on 13 hosts, an OS on all 15, a parent on the 14 guests, 1 VLAN tag, no pool and no vnet. `the_recording_holds_placeholders_only` checks every address and MAC address in it.

What the anonymiser did, so that the shapes, counts and relations between records survive while nothing of the recorded environment does:

- Every MAC address became one of the documentation addresses `00:00:5e:00:53:xx`, the same placeholder wherever the address appears (in a `netN` property string, in a guest agent answer, in a container's interfaces), in the notation it was found in. The all-zero address of loopback interfaces was kept.
- The two private networks wider than a /24 and the other private blocks did not fit the documentation networks and the benchmarking range `198.18.0.0/15` at their real widths, so each wide network was narrowed to the blocks seen in it and its prefix length written narrower (one became a /22, the other a /24); the remaining blocks became documentation networks (`192.0.2.0/24`, `198.51.100.0/24`) or further blocks of the benchmarking range. The host part of every address was kept, so addresses stay inside their networks and gateways inside theirs. A bare prefix length next to an address (`netmask` of the node's network configuration, `prefix` of a guest agent address) was written as the width of the anonymised network that address is in: the width its CIDR is written with when the address is in a wide network, else 24, so that the `netmask` of an interface agrees with its anonymised `cidr` and no real width remains. IPv6 widths and those of loopback addresses were kept. Public IPv4 addresses each got a number of their own in `203.0.113.0/24`. IPv6 prefixes became `2001:db8:n::/48` with the subnet id kept and the interface identifiers replaced; link-local addresses keep `fe80::`.
- The property strings of a guest configuration (`net0`, `ipconfig0`, `agent`) were split, and each value was anonymised on its own: `virtio=<mac>,bridge=<bridge>,tag=99,firewall=1` keeps its keys, numbers and `dhcp`, `auto` and `manual`, while the MAC address, the bridge and the addresses became placeholders. Bridge names became `text-n`, the same placeholder as the interface of the node's network configuration they name.
- The node, guest, interface and container host names became `name-n` or `text-n`; tags became placeholders with their count kept; descriptions, storage names and other free text became `text-n`; UUIDs, digests and ids counters in the same format. VM ids (`vmid`) were kept: they are small numbers that tie the paths to the resources. `ostype`, `arch`, `status`, `type`, `method` and the other enumerations the plugin reads were kept.
- Of `/access/permissions` only the roots (`/`, `/vms`, `/nodes`, `/storage`, `/pool`, `/sdn`, `/access`, `/mapping`) were kept: the other paths of that answer name pools, storages and guests. Members whose keys name credentials (`cipassword`, `sshkeys`) were dropped.

Before the file was looked at, a grep over it for IPv4 addresses outside the documentation and benchmarking ranges, for MAC addresses outside `00:00:5e:00:53`, `00:00:5e:ff:fe` and `02:00:5e` (besides the all-zero address), for 12- and 16-digit hexadecimal tokens outside those blocks, for IPv6 addresses outside `2001:db8::/32` and `fe80::/10`, and for the host name of `PROXMOX_URL` and the user, realm and token name of `PROXMOX_TOKEN_ID` of the `.env` (counted, never printed) found nothing.

To record again: put the token into `.env` (see `.env.example`) and run

```
TENKO_LIVE_PROXMOX=1 TENKO_RECORD=1 cargo nextest run -p tenko-connect-proxmox -E 'test(live_record_fixture)' --no-capture
```

It prints counts only, among them `ipv4 exhausted`, which must be 0. Repeat the grep above before reading the output, and update the counts in `tests/plugin.rs` and in this file.
