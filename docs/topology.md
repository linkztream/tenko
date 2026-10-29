# Topology

- Status: Slice 2 (WP2.7)
- Requirements: IPAM-20, CONN-05, CONN-08, CONN-18; IPAM-03 for the VLAN provision job described in the last section; the root, the SSID view and the map defaults of sections 6.1 to 6.3 are U7 of the UI plan ([ui-plan.md](plans/ui-plan.md), UI-Q10)

Tenko draws the network as a graph: routers, switches, access points, hypervisors, virtual machines, containers and hosts as nodes; wired ports, wireless associations, LLDP links, uplinks and the placement of virtual machines as edges. The graph is computed from what the sources observe and joined with the intended state, so the map shows both what is plugged in where and what IPAM knows about it. Nothing about the graph is stored: it is computed from the store when it is read.

## 1 Sources

| Source | What it adds |
|---|---|
| Network controller (connector with the `network_controller` capability, CONN-05) | Its devices with name, model, kind (gateway, switch, access point), MAC and management address, and the port table of each switch (port names, untagged VLAN, uplink flag, link state); its networks with their VLANs, and the wireless networks with the access points that broadcast them (CONN-18). Every scheduled poll also reports where each client is attached (switch port or SSID, with the VLAN), the links between devices (uplinks, wired and wireless links) and the networks, which arrive as `attachment`, `link` and `network` observations; the reconciler turns the networks into VLAN proposals ([reconciliation.md](reconciliation.md) section 4.10) |
| SNMP probe (`snmp` method, [scanning.md](scanning.md)) | `attachment` observations from the bridge tables (switch, port and VLAN of each client), `link` observations from the LLDP tables, the `name` of each polled switch for its management address, and address sightings |
| Other probe methods | Address sightings with MAC addresses (ARP, ND), names (reverse DNS, mDNS, LLMNR), vendors of MAC addresses, operating system guesses |
| Inventory connectors (Proxmox, Home Assistant) | Hosts with their MAC and IP addresses, operating system and platform; a virtual machine or container names its hypervisor node as its parent |
| Intent | Hosts with their interfaces (MAC addresses) and addresses, the most specific network of each address, the VLAN and site of the network |

Only observations that are current count: an observation that expired, or that a complete batch of its source no longer reports, leaves the map. Facts of the observation layer are described in [reconciliation.md](reconciliation.md).

The device tables of the controllers are read through the connector host with the same call that its scheduled poll uses, and kept for five minutes (30 seconds after a failed read); a read waits at most three seconds for a refresh and otherwise draws the map with the tables it has. The summary of every answer lists each controller with the time of its last read or the error of the read, so a controller that cannot be reached is visible. Without a network controller the map is built from probes, inventories and intent alone.

## 2 Nodes

Every source names things its own way: a controller by its device reference, a probe by the system name of a switch or by MAC and IP addresses, an inventory by its own identifier, intent by host. These names are **aliases**, and the observations join the aliases that belong to one device:

- an address sighting with exactly one MAC address joins the address and the MAC address (an address seen with several MAC addresses joins nothing, so a shared or moving address never merges two devices);
- an inventory host joins its identifier with its MAC and IP addresses;
- a controller device joins its reference, its name, its MAC address and its management address;
- the SNMP name of a polled switch joins that name with the switch's management address, which is how a switch named in LLDP links and bridge tables finds its other aliases;
- an interface of intent joins its MAC address with its host, and an address bound to an interface joins the address with the host.

Each group of joined aliases that a current observation names is one node; intent alone makes no node, so hosts that were never seen do not clutter the map. Addresses are joined regardless of their VRF; installations with overlapping networks in several VRFs may see devices merged across them (see section 7).

The node identifier comes from its most telling alias, in this order: `h-` and the host of intent, `c-` for a controller device, `i-` for an inventory host, `m-` and the MAC address, `n-` for a device named by a probe, `a-` for an address. It stays the same as long as the device is seen the same way; a client that becomes a host of intent changes from `m-` to `h-`.

| Node kind | Evidence, strongest first |
|---|---|
| `router` | a controller reports a gateway |
| `switch` | a controller reports a switch, or clients are attached to its ports |
| `access_point` | a controller reports an access point, or clients are associated with it over an SSID |
| `hypervisor` | inventory hosts name it as their parent |
| `vm`, `container` | the platform an inventory reports (`qemu`, `kvm`, `vmware` and similar; `lxc`, `docker`, `podman`) |
| `device` | a network device that is only known as the end of a link |
| `host` | everything else |

A node carries its label (the host of intent, else the controller's name, the inventory name, a probe's name, the vendor with the end of the MAC address, the MAC or IP address), its MAC and IP addresses, vendor, model and operating system, the host of intent, the networks of its addresses, its VLANs (client attachments, the VLANs of its networks, the untagged VLANs of its ports), its site (the host's, else the network's, else the VLAN's), the SSIDs it broadcasts or uses, the sources behind it and its last sighting.

## 3 Edges

| Edge kind | From | Orientation |
|---|---|---|
| `wired` | an attachment with a port and without an SSID | `a` is the switch, `a_port` its port, `b` the client; `vlan` the client's VLAN |
| `wireless` | an attachment with an SSID | `a` is the access point, `b` the client; `ssid` and `vlan` |
| `lldp` | a link learned over LLDP | both ends with their ports, the smaller node identifier first |
| `uplink` | an uplink a controller reports | as `lldp` |
| `vm_host` | an inventory host with a parent | `a` is the hypervisor, `b` the virtual machine or container |

A client reported by several sources (the controller and an SNMP probe) is one edge with every source listed, whatever each source calls the port. Links are one edge per pair of ports. An edge whose two ends turn out to be the same device is dropped.

A `wired` or `wireless` edge that no network controller reports is **inferred** (`inferred: true`, also on the neighbours of the node view): only a bridge table of a probe names it, and a MAC address learned on a port says that the device is somewhere behind that port, not that it hangs on it. LLDP links, uplinks and placements of virtual machines are never inferred.

## 4 The API

`GET /api/v1/topology` answers the nodes, the edges and a summary: counts per node and edge kind before and after filtering, the VLANs in view with the names of their VLAN objects, the sites, the controllers with their last read or error and whether they allow writes (`writes_enabled`, TGL-20), the networks the controllers report (`networks`: the connector, the controller's reference, name, VLAN id, subnet, `dhcp` as `disabled`, `relay` or `server` when the controller reports it, and the `management` flag), and the root the map is drawn from (`root`: the node, the source that names it and whether a person chose it, section 6.1). Filters, combined with AND:

| Parameter | Keeps |
|---|---|
| `site` | nodes of the site |
| `vlan` | nodes in the VLAN: a VLAN id (1 to 4094) or the identifier of a VLAN object |
| `prefix` or `within` | nodes with an address in the prefix (identifier) or inside the network (`192.0.2.0/24`) |
| `kind` | nodes of these kinds (repeat the parameter or separate with commas) |
| `q` | nodes whose label, MAC or IP address, vendor, model or SSID contains the text |
| `limit` | at most this many nodes (1 to 20,000, default 5,000); `summary.truncated` says when the limit cut the answer, and network devices are kept first |

Without `kind`, an answer adds the context of the kept nodes, so a filtered map still shows how things connect: the network devices and hypervisors next to a kept node, and every network device reachable from those over links between network devices (the backbone). With `kind` the answer holds exactly the nodes of those kinds and the edges between them.

`GET /api/v1/topology/nodes/{id}` answers one node with its ports, its neighbours and the host of intent with its live addresses (network and VLAN of each). The ports are the controller's port table (name, uplink flag, untagged VLAN, link state) and every port the node's edges name, each with what hangs on it. `port` keeps one port, matched by the name the sources use or by the controller's port name: this answers "what is connected to this port". Both endpoints need read access to observations; the identifier of an unknown node answers 404 `ipam.topology.not_found`.

## 5 Computation and caching

The graph is computed from one read view of the store: every fact of the observation layer, the live hosts, interfaces, addresses, prefixes and VLANs, and the cached device tables. The result is kept with the revision of that view. A read at the same revision with the same device tables answers the kept graph; a newer revision recomputes it, at most once every two seconds unless the caller asks with `at_least` for a revision the kept graph does not reach. Filters and the node view work on the kept graph. A graph of 3,009 nodes (3,000 clients) computes in about 30 ms in a debug build on the development machine, so recomputing on change is cheaper than keeping an incremental structure in step with every kind of write; the computation is linear in the number of facts and aliases apart from sorting.

## 6 The map in the web UI

The topology area (`/topology`, the `T` chord of the `G` shortcuts) draws the graph as SVG and loads its code only when it is opened, so the first page load does not grow. Network devices form a forest from the root outward (section 6.1); the clients of a switch or an access point sit in a grid under it, collapsed into a count per port or SSID until opened (section 6.3), and with every endpoint drawn more than twelve clients under one parent are one group that opens on demand. Edge kinds have their own line styles. Filters choose the site, the VLAN, the kinds and a search text; the map follows live changes of observations and intent.

Under the controller lines, a disclosure "N networks from the network controllers" lists every network the controllers report: name, VLAN chip (or "untagged"), subnet (or "no subnet"), the DHCP mode and a "Management" tag for the network Tenko or the controller is reached through, with the controller's name when there are several. The list is also there when the controller runs on a server of its own and no gateway of it is on the map.

Selecting a node opens its panel with its ports and what hangs on each, its neighbours, and links to the host page and to the observations of the device. The panel of a router that a network controller reports also lists that controller's networks, as above. The panel highlights the path to the nearest router or between two chosen nodes. The map is keyboard reachable: one node is in the tab order at a time, the arrow keys move to the nearest node in that direction, Enter opens the panel, and `+`, `-` and `0` zoom and fit. VLAN colors follow the rules of IPAM-20 (design decision 11): hues spread around the circle for the VLANs in view with at least 3:1 contrast against the map, a swatch shape and the VLAN id as text as the redundant cues; with 150 or more VLANs in view only the selected VLAN keeps its color.

### 6.1 The root of the map

The map is drawn from one root, named by two sources in this order (UI-Q10):

1. **The controller's gateway**, when a network controller manages the gateway: the node a controller reports as a gateway (only a controller makes a `router`).
2. **The node's default route**: the next hop of the default route of the host Tenko runs on, read as the service account `tenko` can, with no privilege and no capability: `/proc/net/route` and `/proc/net/ipv6_route` on Linux (both world-readable), `Get-NetRoute -DestinationPrefix 0.0.0.0/0,::/0` through PowerShell on Windows (readable by every account); on other platforms nothing is read and the controller's gateway alone names the root. IPv4 comes before IPv6, the lowest metric first, and a read is kept for a minute. The candidate is the node that holds the next hop, else the address alone; an access point is never a candidate.

When both sources name a root and they are different nodes, the sources **disagree**: the findings index lists one finding to review, kind `topology_root`, area topology, with the two candidates in its parameters (`controller_label`, `controller_node`, `controller_ip`, `default_route_label`, `default_route_node`, `default_route_ip`) and the action `use_root`. The map shows the note "Topology root: sources disagree" above the drawing with **Use this** per candidate. The choice is stored (`ipam.topology_root`, one row: the source, the keys of the candidates on offer, who and when), audited as `ipam.topology_root.choose`, and survives a restart; while the sources offer the same candidates the finding stays away. The map follows the chosen source whenever that source names a root; other candidates raise the finding again. Without a choice the ranked source decides.

| Endpoint | Operation | Authorization |
|---|---|---|
| `GET /api/v1/topology/root` | `get_topology_root` | `read` on observations; the candidates, the root, `disagree`, `open` (the finding is raised), the stored choice and its `ETag` |
| `PUT /api/v1/topology/root` | `choose_topology_root` | `update` on VLANs; body `{"source": "controller" \| "default_route"}`, optional `If-Match`; 409 `ipam.topology.no_candidate` when the source names no root now |
| `DELETE /api/v1/topology/root` | `clear_topology_root` | `update` on VLANs; audited as `ipam.topology_root.clear`; 404 `ipam.topology.not_stored` without a choice |

The layout starts its forest from the root, then from the routers, then from switches and other network devices, and only then from access points, so an access point is never on top while a router, switch or device reaches it. A server is never drawn as the uplink of a switch: a host, virtual machine, container or hypervisor becomes the parent of a network device only over an LLDP link or an uplink.

### 6.2 The SSID view

First look: which SSID carries which VLAN, and how many clients sit on each. The topology page has two tabs, **Map** and **SSIDs** (`/topology?view=ssids`, arrow keys move between them). The SSID view is a tree: SSID, then VLAN, then clients; the access point and the band (2.4, 5 or 6 GHz) are columns of the client row, never levels of the tree. Per SSID: the VLAN it carries, the networks of intent linked to that VLAN, the client count, the policy of the WLAN rules (Track or Ignore) and the count of findings. A client shows its host of intent (or the controller's name, else the MAC address), a hashed name with vendor and address as a second line, the MAC address, the address the controller reports, the access point and the band; a client with a finding shows it with **Move…** (the host page, where the move flow of [moves.md](moves.md) starts) and **Keep on this WLAN**.

The clients come from the network controllers only (CONN-05): their topology read, with the access point, the SSID, the VLAN and the band; nothing is written to a controller (CONN-08, CONN-09). The two WLAN rules that read the view, the exception and the policy are in [reconciliation.md](reconciliation.md) section 4.12. `GET /api/v1/topology/ssids` (`list_topology_ssids`, `read` on observations) answers the view; a principal whose grants cover only some hosts sees the clients of those.

### 6.3 Defaults of the map

- **Infrastructure first.** Routers, switches, access points and hypervisors are drawn; the endpoints of one port or one SSID collapse into a count on it ("4 · 2 devices", "iot.example.test · 3 devices"), which opens on Enter or a click. The **Endpoints** switch of the filter bar draws every endpoint and is remembered by the browser. A kind filter shows exactly the kinds it names, as before.
- **Inferred links** draw dashed with a question mark, and the panel says "inferred from the MAC table".
- **Hashed names** (`host-00005e005301`, Tenko's own fallback) get the vendor and the address as a second line.
- **Not placed.** Devices with no link at all (other than network devices and hypervisors) are not drawn in the forest but listed in a "Not placed" line under the map; a device with the same name or an address of another device is marked as a duplicate there.
- **Read-only under Hardened.** While the Hardened profile is active and no network controller allows writes (TGL-20), the map and the SSID view offer no write action: no Use this, no Keep on this WLAN, no policy switch and no move (`docs/SECURITY-PROFILES.md`, "Read-only topology in Hardened"). The server still decides every request.

### Choice of the drawing library

The map needs a layout for a mostly tree-shaped network of up to a few thousand nodes, keyboard access to every node, and a lazily loaded chunk that keeps the area cheap. The candidates were compared on their published sizes and on what they offer for these needs:

| Option | Size (published, minified and gzip) | Fit |
|---|---|---|
| graphology with sigma.js | about 60 KB together | WebGL draws tens of thousands of nodes; nodes on a canvas are not focusable, so keyboard access and axe checks need a separate accessible structure; layouts are force-directed, which hides the tree shape of a network |
| ELK (elkjs) | several hundred KB | layered layouts of high quality, but the bundle alone is several times the whole first load of the UI |
| Cytoscape.js | about 110 KB | a complete graph toolkit with its own canvas renderer, the same accessibility problem as sigma.js |
| d3-force | about 10 KB | small, but a force layout of a few thousand nodes needs many iterations and still does not show the hierarchy |
| In-house layered layout drawn as SVG | the code of the area only | the network is a forest from the routers outward with many leaf clients; a deterministic layered layout with client grids and groups is a few hundred lines, every node is an SVG element that can take focus and an accessible name, and groups keep the number of drawn elements low |

The in-house layout was chosen (`ui/src/topology/layout.ts`, with `path.ts` for paths and `viewport.ts` for pan, zoom and keyboard navigation). It lays out 3,000 clients under 20 network devices in about 10 ms (its test allows 200 ms). The whole area, layout, map, panel and filters included, is a chunk of 42.3 KB (13.0 KB gzip) with 5.6 KB of styles (1.4 KB gzip) and a message pack of 1.8 KB gzip per language, loaded only when the area opens; the first page load stays at 67.4 KB gzip. The scale risk is the number of SVG elements a browser can move smoothly: groups keep it to the network devices and the clients of opened groups, and the 5,000-node limit of the API caps a single answer. If installations need tens of thousands of visible nodes, a WebGL renderer such as sigma.js can draw the same layout later.

## 7 Limits

- The device tables of controllers are read live and kept for five minutes; a scheduled poll does not hand them to the topology yet, so the first map after a start or after five minutes waits for one read (at most three seconds).
- Addresses join aliases regardless of their VRF.
- LLDP neighbours that no source classifies are `device` nodes; LLDP system capabilities and CDP are not read yet ([scanning.md](scanning.md)).
- Paths are computed in the browser over the graph in view.

## 8 The VLAN provision job

VLANs are objects of IPAM with a VLAN id (1 to 4094, unique per site), an optional VNI, a name, a site, tags and a description, and prefixes link to them (IPAM-03). `POST /api/v1/vlans/provision` creates a VLAN, optionally a network prefix for it, and gets the network onto the switches and access points through the network controller, as one job (E7):

1. **Preview** (`dry_run=true`): the IPAM plan (the VLAN and the prefix, created as `planned`), the network the controller should have (VLAN id, name, DHCP off or relaying to Tenko's DHCP servers), the controller's read-back diff of that network, the steps of the job and the warnings to acknowledge. Nothing is written.
2. **Submit**: computes the preview again and starts the job, which runs `ipam.vlan.intent` (create the VLAN and prefix as planned), `ipam.vlan.controller` (plan again and refuse a diff other than the submitted one, a dry run of the write, the write, and the connector host's verification by reading back and planning again, which must show no difference, CONN-08), and `ipam.vlan.activate` (the VLAN and prefix become active).
3. **Rollback**: a failed step, a timeout or a cancel undoes the write with the undo steps of its receipt (a person is asked when that fails) and soft-deletes the VLAN and prefix the job created.

The controller is the connector the request names, or the only enabled network controller. The network step becomes a manual task for a person, with its text in the job, when no network controller is configured, when the connector does not allow writes (TGL-20, with the planned diff shown and a warning to acknowledge), when several controllers exist and none is named (a warning to acknowledge), or when the request asks for it (`manual`). The connector host refuses the management VLAN and never touches uplinks (CONN-09, 409 `connect.guardrail.protected_vlan`); a provision with `manual` then creates the VLAN in IPAM only. A provision may also name an existing VLAN to put it onto the controller without changing IPAM. `GET /api/v1/vlans/{id}/prefixes` lists the prefixes of a VLAN; a prefix is linked to a VLAN by changing the prefix.
