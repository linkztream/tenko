# IPAM utilization and counts

- Status: Phase 1 (the prefix tree with utilization and alarms); one definition for networks and supernets since the release after 0.0.7
- Requirements: IPAM-02, IPAM-07, IPAM-10, IPAM-12, IPAM-21; the API fields are in `docs/api/openapi.json` (`UtilizationView`, `TreeNode`)

This page says what the numbers on the Networks page, a prefix's page, its Addresses tab and the Hosts page count, and which of them an alarm follows. The counting lives in `tenko_ipam::tree` (`Utilization`), and the web UI's mock API counts the same way (`ui/src/api/mock/ipam/tree.ts`).

## 1 The meter: addresses in use of the usable addresses

The utilization meter means the same thing on every row, for a network and for a supernet:

**percent = in use / usable**

- **Usable** (`capacity`): the addresses of the prefix that can be assigned. A network loses its network and broadcast address (IPv4 up to /30) or its subnet-router anycast address (IPv6 up to /126); /31, /32, /127 and /128 keep every address. A supernet is its whole size less those addresses of every network in its tree. The rest of a supernet's space stays usable, since an address may lie directly in a supernet (with the warning `ipam.address.in_supernet`).
- **In use** (`in_use`) is `used + reserved`:
  - **Recorded** (`used`): the live address objects inside the prefix. Addresses are keyed by address within a VRF, so each one counts once, however deep in the tree it lies. Deleted addresses (in the trash) do not count.
  - **Held by ranges** (`reserved`): the addresses of the prefix's ranges (DHCP pools, delegation pools, reserved and infrastructure ranges) that are not address objects. An address object inside a range counts once, as recorded.
- **Free** (`free`): usable addresses not in use.

For a supernet, recorded and held by ranges are the sums over its tree: every network below it, at any depth, and the addresses directly in the supernet or in a supernet between. Networks never contain prefixes, so the networks of a tree do not overlap and no range is counted twice.

Example: a supernet /16 with 13 child networks of /24 that together hold 150 recorded addresses and no ranges is at 150 of 65,510 usable addresses, 0.2 %. Each /24 shows its own share of its 254 usable addresses.

## 2 A supernet's allocation

How much of a supernet's space is allocated to child prefixes is a second figure, never the meter: **covered of size**, "3.3K of 66K allocated to 13 prefixes".

- **Size** (`size`): every address of the prefix, usable or not.
- **Covered** (`covered`): the addresses of the direct child prefixes (their union), network and broadcast addresses included.
- The number of prefixes is the node's `children`, its direct child prefixes.

The allocation shows on the supernet's page under the meter, in the "Allocated to prefixes" column of the Networks overview and of the supernet's Prefixes tab, and as the second line of the meter's tooltip in the tree. It says how much is left to allocate (Next free prefix), not how full the networks are.

## 3 Utilization alarms (IPAM-10)

A prefix with thresholds (`alarm.warn_pct`, `alarm.crit_pct`) is `warning` from `warn_pct` and `critical` from `crit_pct` of the meter's percent, with the meter's definition. A supernet's alarm therefore fires when the addresses in use across its tree reach the threshold, and never on allocation alone: a supernet whose space is fully allocated to empty networks is at 0 % and `normal`.

The level is computed in tenths of a percent (`permille`) and written as an `ipam.alarms` row and an `ipam.prefix.alarm` audit record when it changes. The tree marks a prefix for a new level when an address, a range or a prefix inside it changes, so a range added to a network re-evaluates the supernets above it. The alarm row carries `used`, `reserved` and `capacity` with the definitions of section 1. The status bar and the start page read the levels from `GET /api/v1/prefixes/tree`.

## 4 The counts on the pages

| Where | What it counts | Why it can differ from another count |
|---|---|---|
| A prefix's page, "N of M usable addresses in use" | In use of usable, section 1 | Includes the addresses ranges hold without a record |
| A prefix's page, "Recorded N · held by ranges M" | The two parts of in use | Recorded is the Addresses tab's number |
| The Addresses tab of a prefix, footer "N addresses" | The address rows of the list: the recorded addresses inside the prefix, the free ranges not counted | The same as Recorded while the list is complete and not filtered; fewer while more pages are to load, a filter is typed, or the principal may read only some of the addresses |
| The Hosts page, footer "N hosts" | Hosts of the list (by default the active ones of every network) | A host can have several addresses, and an address without an interface (for example a reserved one) has no host |
| Start page, "Addresses in use" | In use of usable summed over the top-level prefixes of each VRF | The same definition as the meter |

The network and broadcast addresses of a network are neither recorded (IPAM refuses an address object on them, `ipam.address.network_or_broadcast`) nor usable. A DHCP reservation is an address object bound to a host's interface, so it is recorded and has a host; a lease inside a DHCP pool without an address object is held by the pool.

## 5 Findings: alarms and ghost ageing

The findings model ([reconciliation.md](reconciliation.md) section 12) lists the IPAM conditions that may need a person beside the proposals, and `GET /api/v1/findings/counts` counts them for the rail and the status bar:

- **Utilization alarms.** A prefix at `critical` is a finding to act on, one at `warning` a finding to review, both of the kind `utilization` with the action "Open the prefix"; a prefix back at `normal` has none. The finding carries the percent with one decimal, the threshold, `used` and `capacity` of section 1.
- **Ghost addresses.** An active address of a managed or dynamic host that nothing has shown for longer than the lease time of its network's DHCP scope (or the reconciler's orphan age) is a ghost of the reconciliation view. It is information while it is young, and becomes a finding to review with the action "Decommission" once it has been unseen for `[ipam.findings] ghost_review_after_secs` of the configuration file (30 days by default, 1 to 365 days). The age counts from its last sighting, or, never seen, from the creation of the address; no "first unseen" time is stored, it is derived from the observation history.
- **Edge addresses.** A sighting of a network's network or broadcast address (IPv4 up to /30) or its subnet-router anycast address (IPv6 up to /126), the addresses section 1 leaves out of the usable ones, is a scan artifact: information, never a conflict.

## 6 API

`GET /api/v1/prefixes/tree` answers every node with `utilization`:

| Field | Meaning |
|---|---|
| `capacity` | Usable addresses (decimal string) |
| `in_use` | `used + reserved` |
| `used` | Recorded addresses (address objects), each once |
| `reserved` | Addresses held by ranges without an address object |
| `free` | `capacity - in_use`, at least 0 |
| `covered` | Addresses allocated to the direct child prefixes |
| `size` | Every address of the prefix |
| `percent` | `in_use` of `capacity`, one decimal; the meter and the alarm level |
| `by_role` | Ranges per role with their size and the address objects inside (for a supernet: of every network in its tree) |

Counts are decimal strings because IPv6 sizes exceed the exact integers of JSON.

## 7 The networks view

The Networks page (`/ipam`, a prefix at `/ipam/prefixes/<network>/<length>`, so the selected prefix is in the URL) finds the level in the tree and scans the networks in the pane (U6 of [the UI plan](plans/ui-plan.md), section 5.2).

- **The tree.** The supernets and top-level networks of the VRF in view are always shown, each with the number of its direct child prefixes (`children`). Children are closed and the tree never opens a node by itself, not even to show the selected prefix: a closed node that holds the selection is marked and is the tree's active item. The person opens a node with its chevron, the Right key, or by resting a drag on it (the move gesture); the open nodes are kept per VRF for the session. A filter shows the matches with their ancestors.
- **One network.** The header names the prefix with its description, role, VLAN, site, tenant and VRF. The meter is the one of section 1 (`percent`, in use of the usable addresses, one decimal under 10 %), with the alarm line at `alarm.warn_pct` and its scale named; it turns amber or red only at the warning or critical level of section 3. Beside it sit the network's DHCP scope (pools and active leases), the findings inside it by severity (`GET /api/v1/findings?prefix=`, with the way to Discovery) and its last three changes. The wireless networks of a prefix are not shown yet, since no route carries them per prefix.
- **The address map.** Above the address grid: one cell per address for a prefix of up to 1,024 addresses (a /24 draws 256 cells, a /22 1,024), with the last octet (for IPv6 the last digits of the last hextet) in each cell. A cell is colored only where a finding sits, in the color of its worst severity (Act now, Review; Info is a ring); otherwise it is in use (an address object), held by a range without one (hatched), free (empty, so free runs show at a glance), or an edge address that section 1 leaves out of the usable ones (hatched and dim). A larger prefix draws one cell per block of 256 addresses (an IPv4 /24) with the block's addresses in use, recorded or held by ranges, each counted once; a /16 draws 256 block cells, and a prefix of more than 1,024 blocks has no map. Hover and focus say the address and its state, Enter opens the address (on a block, the Addresses page filtered to the block).
- **A supernet.** Its direct child prefixes in one table, fullest first until the person sorts otherwise (the sort is kept with the table's layout): prefix, description, role, VLAN and utilization by default, the allocation as a hidden column, and the status said once in its header when every row shares it. "No VLAN" and "No description" filter the rows.

Every table's layout (hidden columns, order, widths and sort) is saved per person on the server (`/api/v1/auth/preferences`, [access.md](access.md) section 15) and follows the person to another browser after sign-in; "Reset columns" in the column chooser returns a table to its default.
