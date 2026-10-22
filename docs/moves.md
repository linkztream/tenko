# Moving devices between networks

- Status: Slice 2 (WP2.8); the automatic DNS step from Phase 2 (WP4.4); the automatic DHCP step, the lease observations and the release of the old lease from Phase 3 (WP8.1)
- Requirements: IPAM-19, IPAM-16, IPAM-18, CON-10, CONN-06, CONN-08, CONN-09, CONN-18, TGL-20, DNS-22, DHCP-16; acceptance E8, E17 and E25

A move takes hosts or addresses into another network: the operator drags them onto a network in the IPAM tree (or presses M and picks the network), checks the preview and starts the move. Dragging moves nothing physically (CON-10). A device stays in its old VLAN and keeps getting the old scope's address until its switch port or wireless association changes, and it takes its new address only after a link flap or a lease renewal. A move is therefore a job per device: it changes the intended state, gets the device into the target VLAN through the network controller where it can, waits until the device is seen at its new address, and cleans up. It rolls back when the device does not show up in time.

This page describes the whole job. Section 3 covers the L2 step, which runs through the network controller since Slice 2. The rules live in `tenko_ipam::moves`, and the route is `POST /api/v1/moves`.

## 1 What moves

A request names hosts or addresses (at most 1,000) and a target network prefix.

- An **address** moves itself. It must be in the target's address family and not already inside the target.
- A **host** moves every live address on its live interfaces that is in the target's family and not inside the target. Each address becomes its own item with its own job. Addresses of the other family stay where they are. A host with nothing to move is refused with `ipam.move.nothing_to_move`.
- `unmanaged` hosts are refused (422 `ipam.move.unmanaged`). Locked hosts are refused too (423 `ipam.host.locked`, IPAM-16): a move drives other systems, and a lock forbids that.

The new address keeps the host part (the last octet, or the interface ID for IPv6) when that address is assignable, outside every range of the target and free. Otherwise it is the next free address by the target's allocation policy, and the preview says why the host part changed. Items of one move never get the same address.

## 2 The preview

`POST /api/v1/moves?dry_run=true` answers a `MovePreview` and changes nothing. The network controllers are read, never written. For every device the preview shows:

- the old and the new address, and whether the host part stays and why not;
- the DHCP step of a `reserved` host: `dhcp.reservation` (automatic) when the target network has an enabled Tenko scope and the interface a MAC address or client identifier, else `dhcp.manual` (a task for a person; section 4);
- the DNS change (the name keeps pointing to the device, now at the new address): when the name falls under a zone Tenko serves, `dns.zone` names the zone and `dns.remove` and `dns.add` list the records the DNS step removes and writes, from the dry run of the DNS actuator ([dns.md](dns.md) section 7); otherwise the step is a task for a person;
- the **L2 step** (`l2`). This is a port profile on which switch port, a per-client VLAN override on which access point, a manual step and why, or a refusal of a guardrail with its code. It comes with the diff from the controller's current state, notes about side effects, and the SSIDs that carry the target VLAN;
- the steps of the device's job, automatic and manual, in order;
- the warnings of the device.

For the whole move, the preview shows the observation timeout and how it was chosen, the parallelism, the network controllers that were read, the warnings that need an acknowledgement, and a `fingerprint`.

The web UI shows the L2 action in the "Network change" column, and the diff and notes under a device's steps. Below the table it groups every manual task of the batch by step, so a person can work through them in one pass.

**What was previewed is what runs.** A submit (`POST /api/v1/moves` without `dry_run`) computes the plan again from a fresh read of the store and of the controllers; it never takes the client's copy. The fingerprint covers what would run: per item the address, the new address, the step kinds and the L2 decision with its change and diff. The identifiers of the new addresses and the read times are left out. A submit that names `expect_fingerprint` starts nothing and answers 409 `ipam.move.plan_changed` when its plan differs from the confirmed preview. The UI then shows the new preview to confirm. A submit also refuses while a warning that needs an acknowledgement is not listed in `acknowledge` (409 `ipam.plan.unacknowledged`).

## 3 The L2 step

### 3.1 Finding the device

The preview reads every enabled network-controller connector once, through the connector host's topology call (the same read as its scheduled poll, never cached for a move). It then looks up each device by the MAC address of the moved interface in the clients the controllers report.

| Situation | L2 step |
|---|---|
| The target network has no VLAN | Manual: move the device to the network (`ipam.move.l2.no_vlan`) |
| No network-controller connector is configured or enabled | Manual (`ipam.move.l2.no_controller`) |
| The interface has no MAC address | Manual (`ipam.move.l2.no_mac`) |
| No controller sees the MAC address | Manual (`ipam.move.l2.not_seen`) |
| Several controllers see it | Manual (`ipam.move.l2.controller_ambiguous`) |
| A controller could not be read and none sees the device | Manual (`ipam.move.l2.controller_unavailable`) with a warning to acknowledge, `ipam.move.controller_unavailable` |
| The device is in the target VLAN already | No L2 step (`ipam.move.l2.already_there`) |
| Another address of the same interface moves the device | No L2 step of its own (`ipam.move.l2.same_interface`); the first address's step moves it |
| One controller sees it | The rules below |

The target VLAN's network on the controller is the network with the VLAN id of the target prefix's VLAN. A controller without such a network leaves the step to a person (`ipam.move.l2.no_network`): create the VLAN with its network first ([topology.md](topology.md#8-the-vlan-provision-job)).

### 3.2 Wired devices: the port profile

A device on a switch port moves when the port gets a port profile whose untagged network is the target VLAN's network (`SetPortProfile`, CONN-06). The profile is chosen among the controller's profiles with that untagged network: one without tagged networks first, then by name. Tenko does not create port profiles; when none carries the VLAN untagged, a person sets the port (`ipam.move.l2.no_profile`).

- A port that also serves other devices is left to a person (`ipam.move.l2.shared_port`), because a profile change would move every device on it. This is typically a small unmanaged switch or a phone with a PC port behind it.
- A port that has the target profile already needs no change.
- The preview notes that the device loses its link for a moment while the switch applies the profile. It also notes when the port has no profile on record: the controller then keeps no undo step, so a rollback asks a person to put the port back.

### 3.3 Wireless devices: the per-client VLAN

A wireless device moves through the per-client VLAN override of the controller while it stays on its SSID (`SetClientVlan`, CONN-06 and CONN-18). The override takes effect when the client reconnects. It only works where the device's access point carries the VLAN. Tenko considers the VLAN carried when the access point broadcasts an SSID on that VLAN, or when its uplink switch port has the VLAN untagged or a profile with the network.

- An access point whose uplink port profile lacks the network does not carry the VLAN. Joining an SSID that carries the VLAN is then a change on the device itself, so the step becomes a task for a person that names the SSID (`ipam.move.l2.join_ssid`). Without such an SSID, the task says that no wireless network carries the VLAN (`ipam.move.l2.no_ssid`).
- When Tenko cannot tell (no uplink link reported, or a port without a profile), it sets the override and notes the uncertainty.

The preview lists the SSIDs that carry the target VLAN for every device. Moving a device to another SSID is always the device's own change (CONN-18).

### 3.4 Writes off, and what a person does

With writes off for the connector (TGL-20, the instance's `writes_enabled`), the change is still planned and shown, and it becomes a task for a person: give port 5 of a switch the profile IoT, or set the VLAN override of a MAC address to a network. Every manual L2 step says exactly what to do:

| Task | When |
|---|---|
| `ipam.move.task.l2_port`, `ipam.move.task.l2_client` | Writes are off: the change the controller would have made |
| `ipam.move.task.l2_port_vlan` | No profile carries the VLAN untagged: set the port to the VLAN |
| `ipam.move.task.l2_shared_port` | The port serves other devices: move this one by hand |
| `ipam.move.task.l2_ssid` | The access point does not carry the VLAN: join the named SSID |
| `ipam.move.task.l2_network` | The controller has no network for the VLAN |
| `ipam.move.task.l2_refused` | A guardrail refuses (section 3.5) |
| `ipam.move.task.l2_vlan` | Any other case: set the switch port to the VLAN or join an SSID that carries it |
| `ipam.move.task.l2` | The target has no VLAN: move the device to the network |

### 3.5 Guardrails (CONN-09)

Tenko never touches the port or VLAN through which Tenko or the controller is reached, and never touches uplinks, nor the ports, clients, networks and VLANs an administrator protected in the guardrail settings (`GET` and `PUT /api/v1/settings/guardrails`, see [connectors-unifi.md](connectors-unifi.md) section 6). The preview checks the change against the same rules as the connector host, from the read it made, before anything is planned on the controller. The connector host checks them again at every plan, every write and every revert. A change of the protected paths applies to the next check without a restart.

| Refused when | Code |
|---|---|
| The device's switch port is an uplink | `connect.guardrail.uplink` |
| Tenko or the controller is reached through the port | `connect.guardrail.management_port` |
| The device is the controller or Tenko's host | `connect.guardrail.management_client` |
| The target is a management network | `connect.guardrail.protected_network` |
| A configured protected port or client | `connect.guardrail.protected_port`, `connect.guardrail.protected_client` |

A refusal does not stop the move of the other devices. The refused device's L2 step becomes a task for a person (`ipam.move.l2.refused`, with the rule in `problem`), and the warning `ipam.move.l2_refused` must be acknowledged before the submit. The undo steps of a receipt are checked against a fresh topology before a rollback writes them, so an undo never touches a path that became protected.

## 4 The job

A submit starts one job per item. All jobs of a move share one job group named `ipam.move.<id>` (section 7). The steps of a job, in order:

| Step kind | Preview kind | Automatic | When |
|---|---|---|---|
| `ipam.move.intent` | `ipam.intent` | Yes: the new address as `planned` on the interface; the old one stays | Always |
| `ipam.move.dhcp` | `dhcp.reservation` | Yes: the reservation in the target scope comes from the planned address; the step waits until the `dhcp` role's image holds it | `reserved` hosts, the target network has an enabled Tenko scope and the interface a MAC address or client identifier |
| `ipam.move.dhcp` | `dhcp.manual` | No: create the reservation in the target scope, keep the old one | Other `reserved` hosts |
| `ipam.move.dns` | `dns.records` | Yes: the DNS actuator removes the A or AAAA record and the PTR record of the old address and writes those of the new one, with the origin `ipam` | An address whose DNS name falls under a zone Tenko serves |
| `ipam.move.dns` | `dns.manual` | No: point the name to the new address, address and reverse records | An address whose DNS name has no zone in Tenko |
| `ipam.move.device` | `device.manual` | No: reconfigure the device | `static` hosts |
| `ipam.move.controller` | `l2.controller` | Yes: the L2 change through the network controller | Section 3 found a change the controller can make |
| `ipam.move.l2` | `l2.move` | No: the exact manual action of section 3.4 | The controller cannot make it |
| `ipam.move.observe` | `observe` | Completed by the reconciler on a sighting (section 5), or by a person | Always |
| `ipam.move.cleanup` | `cleanup` | Yes: remove the old address, make the new one active, clear `move-failed`, release the old lease | Always |

The manual tasks come before the L2 change: a device waits for its ticked tasks before it moves (IPAM-19).

**The DHCP step.** A Tenko reservation is the IPAM host of mode `reserved` ([dhcp.md](dhcp.md) section 12): the intent step's planned address on the interface already gives the reservation in the target scope, while the old address keeps the old one, so both scopes hold a reservation until the cleanup. The step waits until the configuration image the `dhcp` role serves is at the revision of the new address (the revision `GET /nodes/{id}/dhcp` reports), so the device finds its reservation when it moves. It waits at most 60 seconds; then it fails with 503 `ipam.move.dhcp_not_served` and the job rolls back. A server without the role in its process records that the reservation is intent and goes on. Its output (JSON of `MoveDhcpOutput`) keeps both revisions. When the target has no Tenko scope (or the scope is disabled, or the network is IPv6 before Slice 9), or the interface has neither a MAC address nor a client identifier (IPAM-18), the step is the task for a person of Phase 1.

**The cleanup and the old lease.** With the `dhcp` role in the process, the cleanup releases the old lease when the moved interface's MAC address still holds it bound, through the node command `dhcp.lease.release` with its version precondition (history kind `reclaimed`). The old reservation goes with the old address. A release that fails is logged and the lease expires on its own; the cleanup does not roll back a confirmed move. Its output records `released_old_lease`.

**The DNS step.** When its name falls under a zone Tenko serves (the submit found the zone, and the server runs the DNS module), the step plans the records of the name from the current state with the move treated as in flight and writes the changes that concern the name: its A or AAAA set and the PTR sets that point to it, in the forward zone and in the reverse zones of both addresses where Tenko serves them. The step's output (JSON of `MoveDnsOutput`) lists the records removed and added. The collision rule of IPAM-19 is unchanged: the preview warns with `ipam.move.dns_collision` (to acknowledge) when another object of the target VRF has the name or another origin holds a record the step needs, and the step stops with 409 `ipam.move.dns_collision` when another origin holds the name's RRset or a PTR it needs, so the job rolls back. Until the cleanup the reconciler keeps what the step wrote, although the new address is still `planned` ([reconciliation.md](reconciliation.md) section 10). A reverse zone that does not exist yet gets its PTR from the reconciler's next run.

**The controller step.** When it runs, which may be hours after the submit while people work through the tasks, the step goes through these stages in order:

1. It reads the controller again. It refuses with 409 `ipam.move.l2_changed` when the device or its port is no longer as the submit found it. That is the case when the port is gone or has a different profile, the device is on another port, other devices are on the port, the device is wired now, or the target network is gone. The step writes nothing then, and the job rolls back.
2. It plans the change on the controller: read back and diff (CONN-08).
3. It runs a dry run.
4. It writes. The connector host refuses the write when writes are off or the plan is older than ten minutes, checks the guardrails against a fresh topology, and after the write plans the same change again and expects an empty diff. A read-back that differs fails the step with `connect.verify_mismatch` and the note that the controller may hold part of the change.
5. It keeps the controller's diff and the receipt with its undo steps as its output, JSON of `MoveL2Output`. The jobs view shows the diff, when it was written and verified, how many undo steps the receipt carries, and later the rollback.

When the controller already has the change, nothing is written. A step that ran again after an interruption and finds the change made cannot know whether it wrote it; its rollback then asks a person. The step has a timeout of 600 seconds, and each controller call has its own.

## 5 The observation

The observation step waits until the device is seen at its new address from its own MAC address, after the job started ([reconciliation.md](reconciliation.md#7-moves)). The sighting can come from any source that reports an address with the MAC address:

- the probes (ARP and neighbor tables, ICMP, SNMP; [scanning.md](scanning.md));
- the network controller's client table, which the UniFi connector reports as `host` facts with the MAC address and the addresses of every connected client at each inventory poll ([connectors-unifi.md](connectors-unifi.md#44-the-facts-this-yields));
- DHCP leases, when Tenko DHCP serves the target network: the `dhcp` role writes the lease's fact (source `dhcp:<node>`) in the commit of the lease itself, and the fact starts a reconciler run like any new fact, so the step completes a moment after the device takes its lease, without polling. A lease counts at any address of the target network when it comes from the interface's MAC address: a reserved device takes its new address, a dynamic one an address of the pool ([reconciliation.md](reconciliation.md#7-moves)).

A person can confirm the step by hand at any time. The timeout comes from the request (300 to 604,800 seconds). Without one, it is half the longest DHCP lease of the target's pools (the renewal point), never below 300 seconds, and 3,600 seconds when the target has no lease time. With a Tenko scope on the target, a pool's lease is the default time its clients get: the pool's DHCP settings, else the range's `lease_secs`, else the scope's lease times, else the server's (one day unless set); a scope without a pool counts its own. It runs from the start of the observation step.

## 6 Rollback

The job rolls back when the observation timeout passes, when a step fails, or when the job is cancelled. Steps are undone in reverse:

- The **controller step** is undone with the undo steps of its receipt: the previous port profile, or the previous per-client override, or none. A person is asked instead, with a manual undo task on the step that the jobs view explains with the previous value, in three cases: the receipt has no undo steps (the port had no profile on record), the undo fails (writes off by now, a guardrail refuses, or the controller changed since the write and Tenko will not overwrite that), or an interrupted attempt may have written without keeping the receipt.
- The automatic **DNS step** plans again without the move and writes the old address's records back; when that fails the reconciler's next run does it.
- The automatic **DHCP step** releases a lease the device already took at the new address; the new reservation goes with the new address when the intent step is undone, and the old reservation was never touched, so a cancel restores both.
- The **manual steps** have no undo task: a rollback never waits for a person to take back the DHCP reservation of a network outside Tenko, the DNS records of a name outside Tenko or a manual L2 change. The job's error names the reason, and the jobs view lists what was done.
- The **intent step** removes the new address, restores the old one if needed, and tags the moved object `move-failed`. The tag goes away with the next successful move of the object.

The job ends `rolled_back` with the reason in its error, or `cancelled` when a cancel started the rollback. Every address has its own job, so a failure rolls back that address only and never touches the other devices of the move.

## 7 Bulk moves

The jobs of one move form one job group whose limit is the move's parallelism: 4 by default, 1 to 64 per request. A job holds its slot from its start until it ends, while it waits for people or for the observation included. A bulk move of 60 IoT devices with the default therefore has at most four devices between "moved" and "confirmed", and its other jobs start as slots free up (CONN-09). The connector host also lets at most four calls per controller instance run at the same time, and the guardrail setting `max_parallel` (default 10, 1 to 64) bounds the real layer-2 writes and reverts through one controller instance across every move and VLAN job; a write over the limit waits for a free slot. The preview's parallelism selector offers 1, 2, 4 and 8.

## 8 What stays manual in this phase

| Step of IPAM-19 | Today | Later |
|---|---|---|
| 1. Choose the new address | Automatic | |
| 2. Create the reservation | Automatic when Tenko DHCP serves the target network (the reservation is intent); a task for a person otherwise (`reserved` hosts) | |
| 3. Update DNS | Automatic when the name's zone is in Tenko (the DNS actuator, section 4); a task for a person otherwise | |
| 4. L2 move | Automatic through the network controller, else a task with the exact action | |
| 5. Wait for the observation | Automatic from probes, the controller's client table and Tenko DHCP leases, or a person | |
| 6. Clean up | The IPAM part is automatic, and so are the DNS records in Tenko zones (the DNS step removed the old ones) and, with Tenko DHCP, the old reservation (it goes with the old address) and the old lease (released). Removing the old reservation of a network outside Tenko, and the old DNS records of a name outside Tenko, is part of the tasks of steps 2 and 3 | |
| 7. Roll back | Automatic for IPAM, the DNS records in Tenko zones and the L2 change; the manual steps are not taken back | |

`static` hosts keep the manual reconfiguration of the device until a hypervisor actuator can do it (Phase 5).

## 9 Errors

| Code | Status | Meaning |
|---|---|---|
| `ipam.move.invalid_request` | 400 | Empty, too large, a duplicate object, a timeout or parallelism out of bounds |
| `ipam.move.unmanaged`, `ipam.move.nothing_to_move`, `ipam.move.already_in_target`, `ipam.move.family_mismatch`, `ipam.move.unsupported_object`, `ipam.move.target_not_network` | 422 | An object cannot move |
| `ipam.host.locked` | 423 | A host is locked |
| `ipam.plan.unacknowledged` | 409 | A warning needs an acknowledgement (`ipam.move.dns_collision`, `ipam.move.l2_refused`, `ipam.move.controller_unavailable`, ...) |
| `ipam.move.plan_changed` | 409 | The plan differs from the confirmed preview (`expect_fingerprint`) |
| `ipam.move.l2_changed` | 409 | The job's controller step found the device or its port changed since the submit (a step error, the job rolls back) |
| `ipam.move.dns_collision` | 409 | The automatic DNS step found the name's RRset or a PTR it needs held by another origin (a step error, the job rolls back) |
| `ipam.move.dns_failed` | 409 | The automatic DNS step could not write (`cause` names the zone service's code; the job rolls back) |
| `ipam.move.dhcp_not_served` | 503 | The `dhcp` role's image did not reach the new reservation within 60 seconds (a step error, the job rolls back) |
| `ipam.move.dhcp_release_failed` | 503 | The role could not release a lease (`cause` names its code); the DHCP step's compensation reports it, the cleanup logs it and goes on |
| `ipam.move.no_engine` | 503 | The server runs no job engine |

A submit needs `Update` on every named object, `Execute` on jobs and `Execute` on every connector an automatic L2 step writes through. A preview needs `Read` on every named object.

## 10 Limits

- The live move against the owner's controller (E8 with a real device) has not run. The L2 step is proven against the in-memory controller and through the connector host's contract, and the UniFi plugin's writes against its fake controller ([connectors-unifi.md](connectors-unifi.md#55-status-of-the-live-test)).
- Tenko picks an existing port profile and never creates one; the contract has no change for it yet.
- Whether an access point carries a VLAN is inferred from its SSIDs and its uplink port's profile. A controller that places VLANs some other way, for example per-client VLANs from RADIUS, is not modeled.
- Two addresses of one interface in one move share the first address's L2 step. A rollback of that job puts the device back for both.
- The parallelism default (4) is a constant of the IPAM service; there is no `tenko.toml` key yet. There is no association between sites and controllers: every enabled controller is read, and a device seen by several of them is left to a person.
