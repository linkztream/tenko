# Moving devices between networks

- Status: Slice 2 (WP2.8); the automatic DNS step from Phase 2 (WP4.4); the automatic DHCP step, the lease observations and the release of the old lease from Phase 3 (WP8.1); the short lease before the move, the two times and the clock of moves (ADR 0027, Proposed); the port bounce and the client kick after the network change (ADR 0028, Proposed)
- Requirements: IPAM-19, IPAM-16, IPAM-18, CON-10, CONN-06, CONN-08, CONN-09, CONN-18, TGL-20, DNS-22, DHCP-16, DHCP-07; acceptance E8, E17 and E25

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
- the **nudge** (`l2.nudge`, section 3.6): whether the job bounces the device's switch port or disconnects it from its access point when it does not come back by itself after the change, or why neither;
- the **two times** (`timing`, section 5): when the device's next DHCP message is expected (`next_activity`, from its lease in Tenko's lease table, else half the target pools' lease time, else unknown) and the migration deadline in seconds from the start of the observation (`deadline_secs`), each with how it was chosen; the device's old lease (`lease_start`, `lease_end`) when Tenko serves its old network; and what the job does before the network change (`prepare`: wait for the next renewal, which gets the short lease of `short_lease_secs`; move at once because that renewal is expected later than the preparation limit, or because the operator chose "move now"; nothing, because Tenko holds no lease of the device or the interface has no MAC address);
- the steps of the device's job, automatic and manual, in order;
- the warnings of the device.

For the whole move, the preview shows the longest migration deadline of its devices and how it was chosen (`timeout_secs`, `timeout_source`), whether the move changes the networks at once (`move_now`), whether it bounces or kicks (`nudge`) and whether a controller that sees one of its devices offers that at all (`nudge_offered`), the parallelism, the network controllers that were read, the warnings that need an acknowledgement, and a `fingerprint`.

**Move now.** By default a device whose lease Tenko holds keeps its network until its next renewal, which gets the short lease (section 5). The preview's "Move now" choice (`move_now: true` in the request) changes the network at once instead: for a device known to ask for a new lease when its link changes, and for the port bounce of a later release. It removes the wait from the job and changes the fingerprint.

The web UI shows the L2 action in the "Network change" column, and the diff and notes under a device's steps. Below the table it groups every manual task of the batch by step, so a person can work through them in one pass.

**Bounce or kick.** When a controller offers it, the preview shows a switch beside "Move now", on by default: "Bounce the port or disconnect the device". Switched off (`nudge: false` in the request), no device of the move is bounced or kicked, and the fingerprint changes.

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

A bounce and a kick after the change have guardrails of their own (section 3.6).

A refusal does not stop the move of the other devices. The refused device's L2 step becomes a task for a person (`ipam.move.l2.refused`, with the rule in `problem`), and the warning `ipam.move.l2_refused` must be acknowledged before the submit. The undo steps of a receipt are checked against a fresh topology before a rollback writes them, so an undo never touches a path that became protected.

### 3.6 Bounce and kick after the change (ADR 0028)

A device that does not notice its VLAN change waits for its short lease (section 5). Two optional writes of the controller make it start over at once:

- a **port bounce**: the connector host takes the device's switch port administratively down for `[dhcp.moves] bounce_down_secs` (5 s, 1 to 30) and brings it up again, after a port profile change. Never a PoE power cycle, which would reboot the device;
- a **client kick**: the controller disconnects the wireless device from its access point, which it then joins again with the new VLAN, after a per-client VLAN override. The device is not blocked.

The controller offers them through its connector's capabilities `port_bounce` and `client_kick` (UniFi does, [connectors-unifi.md](connectors-unifi.md) section 5.6). Both are writes like the L2 change itself: the connector's write switch, the plan age limit, the guardrails against a fresh topology, the write slots of `max_parallel`, and an audit record with the job (`connect.port.bounce`, `connect.port.enable`, `connect.client.kick`).

**Who brings the port up.** Not the job: before the connector host sends the down, it writes a pending record of the port (the controller, the device, the port, the port's state as read back and when it is due up), and its own task brings the port up after the down time, whatever happens to the job (a timeout, a cancel, a failure). The record goes only when the read-back shows the port up. When it does not come up, the health view shows the condition `connect.port_stuck` with the controller, the device and the port, and the host keeps trying (after 5 s, 15 s, 60 s, then every 5 minutes); at every start it brings up every port a record names. See [plugins.md](plugins.md) section 6 and ADR 0028.

**Guardrails (CONN-09).** On top of those of section 3.5:

| Refused when | Code |
|---|---|
| Bounce: the port is an uplink or links to another device (an access point, a switch, an LLDP neighbour) | `connect.guardrail.uplink` |
| Bounce: Tenko or the controller is reached through the port, or the controller or Tenko's host is attached to it | `connect.guardrail.management_port` |
| Bounce: more than one client is behind the port (two listed clients, or more than one MAC address learned on it: a dock, an unmanaged switch, a phone with a PC port) | `connect.guardrail.shared_port` |
| Bounce: the port is down already (no link, or switched off) | `connect.guardrail.port_down` |
| Bounce: the fresh topology has no such port | `connect.guardrail.port_unknown` |
| Bounce: a protected port, or the port of a protected client | `connect.guardrail.protected_port`, `connect.guardrail.protected_client` |
| Kick: the device is the controller or Tenko's host | `connect.guardrail.management_client` |
| Kick: the device is not wireless | `connect.guardrail.not_wireless` |
| Kick: the controller does not see the device | `connect.guardrail.client_unknown` |
| Kick: a protected client | `connect.guardrail.protected_client` |

**What the preview says** (`l2.nudge` of an item with an automatic L2 change): `action` is `bounce` or `kick` with the `change` and `reappear_secs`, or `none` with the `reason`:

| Reason | Meaning |
|---|---|
| `ipam.move.nudge.no_capability` | The controller offers neither for this device |
| `ipam.move.nudge.refused` | A guardrail refuses it; `problem` names the rule. The move runs without it; nothing needs an acknowledgement |
| `ipam.move.nudge.off` | The move switched it off; `change` says what it would have done |

**When a port stays down (runbook).** The health view (`GET /api/v1/system/status`, the warnings on the start page) shows `connect.port_stuck` with the controller, the device, the port, the failed attempts and their cause, and the move's job failed with the same code. Tenko keeps trying on its own. To bring the port up at once:

1. Check that the controller answers: the connector's page shows its health and the last error.
2. Switch the port on at the controller. On UniFi the port's override has `forward` set to `disabled`: set it back to what the port forwarded before (usually all), or remove the override if the port had none.
3. The next attempt of the connector host reads the port back as up and removes the record; the warning goes away with it. A record of a connector that was deleted goes with the connector (its audit record names the port).

The audit log names every bounce, every way back up and every kick with its job (`connect.port.bounce`, `connect.port.enable`, `connect.client.kick`).

## 4 The job

A submit starts one job per item. All jobs of a move share one job group named `ipam.move.<id>` (section 7). The steps of a job, in order:

| Step kind | Preview kind | Automatic | When |
|---|---|---|---|
| `ipam.move.prepare` | `dhcp.prepare` | Yes: marks the device as moving in Tenko DHCP (the moving client, below) | A `reserved` or `dynamic` host with a MAC address on IPv4, when Tenko holds its lease on the old network or the target has an enabled Tenko scope |
| `ipam.move.intent` | `ipam.intent` | Yes: the new address as `planned` on the interface; the old one stays | Always |
| `ipam.move.dhcp` | `dhcp.reservation` | Yes: the reservation in the target scope comes from the planned address; the step waits until the `dhcp` role's image holds it | `reserved` hosts, the target network has an enabled Tenko scope and the interface a MAC address or client identifier |
| `ipam.move.dhcp` | `dhcp.manual` | No: create the reservation in the target scope, keep the old one | Other `reserved` hosts |
| `ipam.move.dns` | `dns.records` | Yes: the DNS actuator removes the A or AAAA record and the PTR record of the old address and writes those of the new one, with the origin `ipam` | An address whose DNS name falls under a zone Tenko serves |
| `ipam.move.dns` | `dns.manual` | No: point the name to the new address, address and reverse records | An address whose DNS name has no zone in Tenko |
| `ipam.move.device` | `device.manual` | No: reconfigure the device | `static` hosts |
| `ipam.move.lease` | `dhcp.short_lease` | Completed by the move's clock when the device renewed with the short lease or the renewal did not come (section 5); a person completing it moves the device at once | The prepare step names the device's old lease (not "move now") |
| `ipam.move.controller` | `l2.controller` | Yes: the L2 change through the network controller | Section 3 found a change the controller can make |
| `ipam.move.l2` | `l2.move` | No: the exact manual action of section 3.4 | The controller cannot make it |
| `ipam.move.nudge` | `l2.nudge` | Yes: waits up to `reappear_secs` for the device to come back by itself, then bounces its port or kicks it, once (section 3.6) | The controller step runs and the preview chose a bounce or a kick |
| `ipam.move.observe` | `observe` | Completed by the reconciler on a sighting, by the move's clock on the device's new lease (section 5), or by a person | Always |
| `ipam.move.cleanup` | `cleanup` | Yes: remove the old address, make the new one active, clear `move-failed`, release the old lease, remove the moving client | Always |

The manual tasks come before the L2 change: a device waits for its ticked tasks before it moves (IPAM-19). The wait for the short lease comes right before the L2 change, so the device's last renewal on its old network is as close to the change as possible.

**The moving client** (ADR 0027). The prepare step writes the device's row of `dhcp.moving`, keyed by the job: its MAC address, its old lease (VRF and address, unless "move now"), the short lease's time, the target scope and the job's deadline. The `dhcp` role serves the row in its configuration image: while the job is active, the device's next REQUEST for its old address gets at most the short lease (`[dhcp.moves] short_lease_secs`, 120 seconds by default; T1 and T2 derived from it as for any grant), and every DHCP message of its MAC address is noted, so the job sees the device's exchange near the deadline and its reconnection on the target scope. The stored lease row does not change. The row is the job's: the cleanup removes it, the rollback removes it first (section 6), and the leader's lease expiry removes a row whose job ended or that ran past the job's deadline; the role ignores a row past its deadline in any case.

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

**The nudge step** (ADR 0028). Right after the controller step, `ipam.move.nudge` waits up to `[dhcp.moves] reappear_secs` (30 s) for the device to come back by itself: many switches drop the link when the profile changes, and a device that notices asks for an address at once. The job sees that when it follows the device's DHCP (it has a moving client): the `dhcp` role saw the device's exchange on the target scope, or the lease table holds its lease there. Without Tenko DHCP on the target the step simply waits. Only when the device is not back does the step bounce its port or kick it, once, through the controller (section 3.6). Its output (JSON of `MoveNudgeOutput`) says what happened: back by itself (when, and whether by its DHCP exchange or its lease), the controller's report (when the port went down and came up, or when the client was disconnected), or why nothing was done. A refusal or a controller error at that time is no failure of the move: the device still comes back with its short lease. A port that does not come up again fails the step with `connect.port_stuck` (the device and the port in its parameters), and the job rolls back. A step that runs again after an interruption does not nudge a second time.

## 5 The observation

The observation step waits until the device is seen at its new address from its own MAC address, after the job started ([reconciliation.md](reconciliation.md#7-moves)). The sighting can come from any source that reports an address with the MAC address:

- the probes (ARP and neighbor tables, ICMP, SNMP; [scanning.md](scanning.md));
- the network controller's client table, which the UniFi connector reports as `host` facts with the MAC address and the addresses of every connected client at each inventory poll ([connectors-unifi.md](connectors-unifi.md#44-the-facts-this-yields));
- DHCP leases, when Tenko DHCP serves the target network: the lease table is the source `dhcp:<node>` (the role writes no fact rows, [ADR 0031](adr/0031-the-lease-table-is-the-observation-source.md)): the lease view gives the lease's fact as soon as it has taken the lease in and wakes the reconciler, so the step completes a moment after the device takes its lease, without polling. A lease counts at any address of the target network when it comes from the interface's MAC address: a reserved device takes its new address, a dynamic one an address of the pool ([reconciliation.md](reconciliation.md#7-moves)).

A person can confirm the step by hand at any time. With Tenko DHCP on the target, the move's clock also confirms it when the device holds a lease of the target scope given after the job started: the prepared address for a `reserved` host, any address of the network for a `dynamic` one.

### 5.1 What a moved device does

A device whose network changed under it keeps its old address. RFC 2131 section 4.4.5 says what it does next. At T1 (half its lease) it unicasts a REQUEST to its server; that REQUEST never leaves it, because it cannot reach its old gateway, and a NAK the server could send would go out on the server's own link or to the old network (`crates/tenko-dhcp/tests/engine_moves.rs` documents it), so T1 is no deadline and a NAK at T1 is no way. Without an answer it sends again after half the time left to T2, at least 60 seconds. At T2 (seven eighths) it broadcasts the REQUEST; the relay of the new network adds its `giaddr`, which selects the target scope, the engine NAKs the address of another network (when the scope is authoritative), and the device DISCOVERs and gets its new address. Then it sends again after half the time left to the end of its lease, and at the end it starts over with a DISCOVER. A device that does not react to the link change therefore comes back at T2 or at the end of its lease.

What shortens the wait, within the RFCs, is a short lease before the move: the job's prepare step marks the device (section 4), its next renewal still reaches Tenko on the old network and gets the short lease, and only then does the job change the network. The device then rebinds within the short lease, two minutes by default.

### 5.2 The two times

Both come from the device's own lease when Tenko serves its old network (the row of `dhcp.leases`: its `cltt` is the start, its `ends` the end; the row keeps no T1 or T2, so they are the RFC defaults of 50 and 87.5 percent), and from the target pools' default lease time otherwise, as before. A pool's lease is the default time its clients get: the pool's DHCP settings, else the range's `lease_secs`, else the scope's lease times, else the server's (one day unless set); a scope without a pool counts its own.

- **Next expected DHCP activity**: before T1, T1; after T1 the next retransmission of the schedule of section 5.1 (half the time left to T2, then to the end, at least 60 seconds); at the end, the end. Without the device's lease, half the pools' lease from now.
- **Migration deadline**, when the job gives up and rolls back, from the start of the observation step: the request's `timeout_secs` (300 to 604,800) when it names one; else the end of the short lease plus `[dhcp.moves] margin_secs` (60) when the preparation succeeded; else the end of the device's lease plus the margin, at most `deadline_limit_secs` (172,800); else the pools' lease plus the margin, at most the limit; else 3,600 seconds. Never below 300 seconds.

The preview estimates both as if the observation started now (with a planned preparation, as if the short lease started now). The job computes the deadline again from the lease table when its observation starts; the step timeout from the submit holds until then.

### 5.3 The wait for the short lease

`ipam.move.lease` is done at once when the device's lease is already short, when the device holds no lease on its old network any more, or when its next renewal is expected later than `[dhcp.moves] prepare_limit_secs` (3,600 seconds; 0 never waits). Otherwise it waits: the move's clock completes it when the lease table shows the renewal with the short lease, or when the renewal did not come by its expected time plus the margin (at most the preparation limit), and the job then changes the network without the short lease. A person completing the task moves the device at once, as "move now" does from the start.

### 5.4 The clock

The leader service `ipam.moves` looks at the waiting move jobs every second. Besides the wait of section 5.3, it handles the observation step of a job that follows the device's DHCP (it has a moving client):

1. **Verified.** The device holds its new lease on the target scope (above): the step is done.
2. **The deadline.** When the step starts waiting, the clock sets the migration deadline of section 5.2 from the lease table as it is then; the preparation succeeded when the device's lease is the short lease.
3. **The verification window.** Once the role saw the device's DHCP message on the target scope (its rebinding through the new relay, or its DISCOVER), the deadline becomes that time plus `verify_secs` (90) when that is earlier: the device should hold its new lease within seconds.
4. **The extension.** When the role saw a DHCP message of the device in the last `extend_window_secs` (15) before the deadline, the deadline moves by `extend_secs` (60), once per job, so the job does not roll back in the middle of the device's exchange.

Every change of the deadline is a transition of the job with a note that says why (`JobEngine::set_manual_deadline`).

### 5.5 Settings

`[dhcp.moves]` of `tenko.toml` (`deploy/tenko.example.toml`); the submit copies them into the job, so a running job keeps the values it was previewed with.

| Key | Default | Range | Meaning |
|---|---|---|---|
| `short_lease_secs` | 120 | 30 to 3,600 | The lease a device gets at its renewal before the network change |
| `prepare_limit_secs` | 3,600 | 0 to 86,400 | The longest wait for that renewal |
| `margin_secs` | 60 | 0 to 3,600 | What the deadline adds to a lease's end |
| `deadline_limit_secs` | 172,800 | 300 to 604,800 | The longest deadline computed from a lease; a request's timeout is not bounded by it |
| `extend_window_secs`, `extend_secs` | 15, 60 | 1 to 300, 1 to 3,600 | The extension near the deadline |
| `verify_secs` | 90 | 10 to 3,600 | The window after the device's exchange on the target is seen |
| `reappear_secs` | 30 | 0 to 600 | After the network change, how long the job waits for the device to come back by itself before it bounces or kicks (section 3.6) |
| `bounce_down_secs` | 5 | 1 to 30 | How long a port bounce keeps the port down |

## 6 Rollback

The job rolls back when the migration deadline passes, when a step fails, or when the job is cancelled. Before anything is undone, the first compensation removes the moving client (section 4); the compensations of the observation and of the preparation wait until the role's image no longer holds it (at most 60 seconds), so a device that comes back to its old network renews with its normal lease. The restored reservation is served again, and a device already in DISCOVER on its old network gets its old address back by itself. Then the steps are undone in reverse:

- The **controller step** is undone with the undo steps of its receipt: the previous port profile, or the previous per-client override, or none. When the move bounces or kicks (section 3.6), the same bounce or kick follows right after the undo, without a wait, so that the device takes its old address at once; what becomes of it is logged and never stops the rollback. A person is asked instead, with a manual undo task on the step that the jobs view explains with the previous value, in three cases: the receipt has no undo steps (the port had no profile on record), the undo fails (writes off by now, a guardrail refuses, or the controller changed since the write and Tenko will not overwrite that), or an interrupted attempt may have written without keeping the receipt.
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
| `connect.port_stuck` | 503 | The device's switch port did not come up again after the bounce (a step error, the job rolls back; the health view shows the port until the connector host brought it up) |
| `ipam.move.dhcp_release_failed` | 503 | The role could not release a lease (`cause` names its code); the DHCP step's compensation reports it, the cleanup logs it and goes on |
| `ipam.move.no_engine` | 503 | The server runs no job engine |

A submit needs `Update` on every named object, `Execute` on jobs and `Execute` on every connector an automatic L2 step writes through. A preview needs `Read` on every named object.

## 10 Limits

- The live move against the owner's controller (E8 with a real device) has not run, and neither has a live bounce or kick: the UniFi writes are proven against the fake controller with the recorded answers of a real one ([connectors-unifi.md](connectors-unifi.md) section 5.6).
- The nudge step sees a device come back by itself only through Tenko DHCP on the target network (its exchange, its lease); without it the step waits `reappear_secs` and then bounces or kicks. The L2 step is proven against the in-memory controller and through the connector host's contract, and the UniFi plugin's writes against its fake controller ([connectors-unifi.md](connectors-unifi.md#55-status-of-the-live-test)).
- Tenko picks an existing port profile and never creates one; the contract has no change for it yet.
- Whether an access point carries a VLAN is inferred from its SSIDs and its uplink port's profile. A controller that places VLANs some other way, for example per-client VLANs from RADIUS, is not modeled.
- Two addresses of one interface in one move share the first address's L2 step. A rollback of that job puts the device back for both.
- The parallelism default (4) is a constant of the IPAM service; there is no `tenko.toml` key yet. There is no association between sites and controllers: every enabled controller is read, and a device seen by several of them is left to a person.
- The clock sees the device's DHCP messages (the extension, the verification window) only from a `dhcp` role in its own process; with the role elsewhere it still sets the deadline from the lease table and confirms on the new lease. The short lease needs Tenko to serve the old network; a device on a network served by another DHCP server moves without it, with the deadline from the target pools' lease.
