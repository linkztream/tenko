# Topology

- Status: Slice 2 (WP2.7)
- Requirements: IPAM-20, CONN-05, CONN-18; IPAM-03 for the VLAN provision job described in the last section

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

## 4 The API

`GET /api/v1/topology` answers the nodes, the edges and a summary: counts per node and edge kind before and after filtering, the VLANs in view with the names of their VLAN objects, the sites, the controllers with their last read or error, and the networks the controllers report (`networks`: the connector, the controller's reference, name, VLAN id, subnet, `dhcp` as `disabled`, `relay` or `server` when the controller reports it, and the `management` flag). Filters, combined with AND:

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

The topology area (`/topology`, the `T` chord of the `G` shortcuts) draws the graph as SVG and loads its code only when it is opened, so the first page load does not grow. Network devices form a forest from the routers outward; the clients of a switch or an access point sit in a grid under it, and more than twelve clients under one parent are drawn as one group that opens on demand. Edge kinds have their own line styles. Filters choose the site, the VLAN, the kinds and a search text; the map follows live changes of observations and intent.

Under the controller lines, a disclosure "N networks from the network controllers" lists every network the controllers report: name, VLAN chip (or "untagged"), subnet (or "no subnet"), the DHCP mode and a "Management" tag for the network Tenko or the controller is reached through, with the controller's name when there are several. The list is also there when the controller runs on a server of its own and no gateway of it is on the map.

Selecting a node opens its panel with its ports and what hangs on each, its neighbours, and links to the host page and to the observations of the device. The panel of a router that a network controller reports also lists that controller's networks, as above. The panel highlights the path to the nearest router or between two chosen nodes. The map is keyboard reachable: one node is in the tab order at a time, the arrow keys move to the nearest node in that direction, Enter opens the panel, and `+`, `-` and `0` zoom and fit. VLAN colors follow the rules of IPAM-20 (design decision 11): hues spread around the circle for the VLANs in view with at least 3:1 contrast against the map, a swatch shape and the VLAN id as text as the redundant cues; with 150 or more VLANs in view only the selected VLAN keeps its color.

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
