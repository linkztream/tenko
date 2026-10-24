# UniFi Network connector

This page describes the UniFi Network connector plugin of Tenko DDI: how it finds out what kind of controller it talks to and which API it uses, what it reads from the controller and how that becomes topology, inventory and facts, which changes it can write and how every write is planned, verified and undone, how the guardrails and the write switch of the host apply, how to set up the controller and the connector instance with least privilege, every setting, the health check, rate limits and retries, the error codes with what to do about them, and how the plugin is tested. It is for the administrator who connects a UniFi controller, for the reviewer of the writes the connector performs, and for a developer who works on the plugin or writes another network-controller plugin. It describes the behavior of the `tenko-connect-unifi` crate and of the network-controller discipline of the connector host in `tenko-connect` (the guardrails in `network.rs`, planning, applying and reverting in `host/service/calls.rs`); where this page and the code differ, the code is right. The requirements are CONN-05 to CONN-09, CONN-18 (the read part), IPAM-03 and IPAM-20 in [REQUIREMENTS.md](REQUIREMENTS.md) and the toggle TGL-20 in [SECURITY-PROFILES.md](SECURITY-PROFILES.md).

The plugin is a bundled reference plugin (CONN-20): the host starts it as `tenko plugin run unifi`, exactly as it starts a third-party plugin (see [plugins.md](plugins.md#10-installing-and-listing-plugins)). The same code is also built as the standalone executable `tenko-plugin-unifi`, which `tenko plugin test <path>` can start. It declares the capabilities `inventory` and `network_controller`. It never runs inside the controller; it is a client of the controller's web API, started and supervised by the Tenko host.

Terms used below: a **controller** is the UniFi Network application that Tenko talks to, either installed on its own (self-hosted) or running on a UniFi OS console. A **site** is the unit inside a controller that groups devices, networks and clients; it has a short name (`default` for the first one), which the address bar shows as `/manage/site/<name>/...`, and a description, which is not the name. The **classic API** is the long-standing API that the controller's own web interface uses (`/api/s/{site}/...`, answers wrapped in `meta` and `data`); it is reached with a session of a local account. The **Integration API** is the official, versioned API (`/integration/v1`, header `X-API-Key`); it is reached with an API key. A **local account** is an administrator account that exists in the controller itself and logs in with a user name and a password, as opposed to an account of Ubiquiti's cloud. An **instance** is one configured connector: the plugin, its settings and its secrets (see [plugins.md](plugins.md)); one instance talks to one site of one controller. The **host** is the Tenko process that starts the plugin and calls it. The **Site Manager** is Ubiquiti's cloud service at unifi.ui.com and api.ui.com.

Contents:

1. [Overview](#1-overview)
2. [Deployments and API families (CONN-07)](#2-deployments-and-api-families-conn-07)
3. [The spike (Slice 2, WP2.6)](#3-the-spike-slice-2-wp26)
4. [What the plugin reads (CONN-05, CONN-18)](#4-what-the-plugin-reads-conn-05-conn-18)
5. [What the plugin writes (CONN-06, CONN-08)](#5-what-the-plugin-writes-conn-06-conn-08)
6. [Guardrails (CONN-09)](#6-guardrails-conn-09)
7. [Setting up the controller with least privilege](#7-setting-up-the-controller-with-least-privilege)
8. [Settings reference](#8-settings-reference)
9. [Health check](#9-health-check)
10. [Rate limits and retries](#10-rate-limits-and-retries)
11. [Troubleshooting](#11-troubleshooting)
12. [Testing](#12-testing)
13. [What comes next](#13-what-comes-next)

## 1. Overview

The plugin keeps nothing between calls. Every call starts from the settings and the secrets in its call context (see [plugins.md](plugins.md#6-the-protocol)), builds an HTTPS client with the instance's TLS mode, detects the deployment when `deployment` is `auto` (section 2), logs in with the local account (or presents the API key), does its work and logs out. The password and the key live in memory for the length of the call and are wiped afterwards. The plugin has no cache, no session pool and no state on disk.

| Plugin call | Who calls it | What it does at the controller | Section |
|---|---|---|---|
| `Check` | The host, every 15 minutes and on demand | Detection, login, the site, the version | 9 |
| `Poll` | The host, every poll interval | Reads devices and clients and reports them as inventory hosts | 4.3 |
| `Topology` | The host, every poll interval; the topology map (at most every five minutes); and before every plan and every apply, to check the guardrails | Reads devices, clients, networks, port profiles and SSIDs and reports them as one topology | 4.1, 4.2 |
| `Plan` | The host | Reads what a change touches, diffs it against the change, fingerprints it; writes nothing | 5 |
| `Apply` | The host | Re-reads, refuses a stale plan, writes only in apply mode, reads back and verifies | 5 |
| `Revert` | The host | Undoes an applied change with the undo steps of its receipt | 5 |

The host runs the scheduled reads in a fixed order, `Poll` and then `Topology`, each as its own call with its own login. The default poll interval is 300 seconds (section 8). Policy stays in the host ([ADR 0012](adr/0012-connector-plugins.md)): the guardrails, the age of a plan, the write switch (TGL-20) and the verification by planning again are the host's, and the plugin has no write switch of its own.

## 2. Deployments and API families (CONN-07)

### 2.1 The two deployments

UniFi runs the Network application in two ways. They differ in the port, in a path prefix and in the login.

| | Self-hosted Network Application | UniFi OS console |
|---|---|---|
| Runs on | A server or container of its own | UDM, UCG, Cloud Key Gen2 and later |
| Port in the URL | 8443 | 443 (no port in the URL) |
| Path prefix of the Network application | None | `/proxy/network` |
| Login of a local account (classic API) | `POST /api/login` | `POST /api/auth/login` |
| Logout | `POST /api/logout` | `POST /api/auth/logout` |
| Classic API of a site | `/api/s/{site}/...` | `/proxy/network/api/s/{site}/...` |
| Integration API | `/integration/v1` | `/proxy/network/integration/v1` |
| Status page without authentication | `/status` | `/proxy/network/status` |
| `GET /` answers | 302 to `/manage` | 200 (the console page) |

### 2.2 Detection

With `deployment = auto` (the default) the plugin detects the deployment on every call. It reads nothing but public pages and needs no credentials. The steps, in order:

1. `GET /`. If the answer is a redirect whose `Location` contains `/manage`, the controller is self-hosted. The plugin then reads `GET /status` for the version.
2. If the answer is a success, the plugin reads `GET /proxy/network/status`. Any answer other than 404 means a UniFi OS console, and the version comes from that answer when it is JSON.
3. Otherwise the plugin reads `GET /status`. If it carries a version, the controller is self-hosted.
4. If none of this fits, the call fails with `connect.protocol` and the text "the address does not answer like a UniFi Network application; set `deployment` if it is one".

The version is `meta.server_version` of the status page. A controller that does not answer at step 1 fails the call with `connect.unreachable`, and a certificate problem fails it with `connect.invalid_settings` (section 11).

`deployment = self_hosted` or `unifi_os` fixes the paths and skips the detection; the plugin then only reads the status page for the version and ignores a failure of that read. Fix the deployment when you know it: it saves one to three requests per call.

### 2.3 Which API serves which call

| Credentials | API | Reads | Writes |
|---|---|---|---|
| A local account: setting `username` and secret `password` | Classic API | Everything in section 4 | Every change in section 5 |
| A local Integration API key: secret `api_key`, no `password` | Integration API | A reduced topology and the inventory (below) | None: every write answers `connect.unsupported` |
| A Site Manager key (created at unifi.ui.com) | None | Not used | Not used |

When both secrets are present the account wins and the key is not used.

**Why the classic API.** Only the classic API has the port tables with profiles and LLDP neighbours, the switch port or the access point and SSID and VLAN of a client, and the records that the writes change: `rest/networkconf` (networks), `rest/wlanconf` (SSIDs), `rest/portconf` (port profiles) and `rest/user` (clients). The plugin therefore reads and writes through it whenever it has a local account.

**What the Integration API gives.** With a local key and no account the plugin reads through the Integration API of the controller (`X-API-Key`). The API of the 9.x releases reports sites, devices with their upstream device, and clients with the device they hang on. The releases from Network 10.0 on also report the networks (`GET /sites/{id}/networks`, with `vlanId`, and per network `GET /sites/{id}/networks/{networkId}` with `ipv4Configuration`: `hostIpAddress`, `prefixLength` and `dhcpConfiguration.mode` `SERVER` or `RELAY`). No release reports port profiles, the port of a wired client, the SSID or the network of a client, or LLDP. The topology is therefore reduced:

- devices without port tables (a port that the plugin could not mark as an uplink must not appear as an ordinary port), with the kind taken from the features `accessPoint`, `gateway` and `switching`;
- links of the kind Uplink between a device and its upstream device, without ports;
- clients attached to a device without a port, an SSID or a vendor; from Network 10.0 on, a client is in the network whose subnet most specifically holds its address, with that network's VLAN (the API names no network of a client, so a client whose address is in no subnet has none);
- from Network 10.0 on, the networks with VLAN id, subnet and DHCP mode: VLAN 1, which the API gives the default network, is reported as untagged, a disabled network is left out, a management network is found as in the classic mode (section 4.2), and a network the gateway or a switch does not manage has no subnet; on 9.x the list answers 404 and there are no networks;
- no port profiles and no SSIDs.

**What only a local account gives.** The API key cannot deliver the VLAN of a client the controller itself assigns (a port profile, a per-client VLAN override, an SSID with a VLAN of its own), the port and SSID of a client, the port profiles and LLDP, and on releases before 10.0 any network or VLAN at all, because the Integration API does not publish them; for the VLANs of IPAM on a 9.x controller, and for the exact VLAN of every client on any release, configure a local account (a view-only one is enough, section 7).

The `site` setting is matched against the sites of the API by their `internalReference` or by their name. Lists are read 200 at a time, at most 50 pages. When the list of devices leaves out a device's upstream device, the plugin reads that device's detail, one more request per such device. The inventory from a key has one host per device, always with the tag `unifi:device`, and one host per client with the tag `unifi:wired` or `unifi:wireless`.

**The Site Manager key is not used.** It is a key of the cloud service, and the controller refuses it (section 3).

## 3. The spike (Slice 2, WP2.6)

The spike ran against a self-hosted Network Application before the plugin was written. It answered the three questions of the roadmap: which calls go through which API family, where the Integration API lives on a self-hosted installation, and whether an API key works on classic endpoints (see [ROADMAP.md](ROADMAP.md)).

| Question | Finding |
|---|---|
| Deployment and version | A self-hosted Network Application 9.2 on port 8443 without a path prefix; the Site Manager lists it as `network-server` |
| TLS | A self-signed RSA-2048 certificate with one DNS name; the system roots refuse it, so the fingerprint mode is needed |
| Detection | `GET /` answers 302 to `/manage`; `GET /status` answers 200 JSON with `meta.up`, `meta.server_version`, `meta.rc` without authentication; `/proxy/network/*` answers 404 |
| Integration API on the controller | Present at `/integration/v1` without the proxy prefix; 403 `FORBIDDEN` without a valid local key |
| A key created at unifi.ui.com, against the controller | Refused with the same 403 as no key or a random key: it is a Site Manager key |
| The same key at api.ui.com | Accepted: `/v1/hosts` and `/v1/sites` answer; `/v1/devices` lists nothing for a self-hosted application, and the cloud connector proxy to its Integration API times out (408). No device, client, port or VLAN data |
| Classic API with that key | 401 `api.err.LoginRequired` on `/api/self`, `/api/s/{site}/stat/*` and `/v2/api/...` |
| Classic API with a local account | Recorded on 2026-10-16 from a self-hosted Network Application 10.6 with a view-only local account: the anonymised answers are the fixtures under `tests/fixtures/recorded/` (section 12). Where they differ from the documented API: the port tables carry no `portconf_id` (ports are configured inline with `forward`, `native_networkconf_id` and `tagged_vlan_mgmt`, and `port_overrides` hold the same members), a `customize` port profile lists `excluded_networkconf_ids` and no `tagged_networkconf_ids`, VLAN ids of networks are text, VLAN-only networks have ten members and no subnet or DHCP members, `stat/sta` has no `name` (the alias lives in the client record), a UniFi switch names its port in LLDP as `local Port 7`, and `rest/user` records carry no `virtual_network_override_*` members while no override was ever set |

**Decision.** The classic API with a local account serves every read and every write, because only it has the port tables, the client attachments and the records that the writes change. A local Integration API key serves the health check and a reduced read-only topology when no local account is configured; detection needs no credentials at all. A key from the Site Manager is not used: the controller refuses it, and the cloud API has no device, client, port or VLAN data for a self-hosted application. The shapes of the classic answers are confirmed by the recordings of a real controller (section 12); the documented fixtures stay for the cases the recorded site does not have (a gateway, DHCP served by the controller, a relay, an SSID with a VLAN of its own, an unadopted device).

## 4. What the plugin reads (CONN-05, CONN-18)

### 4.1 The topology

A `Topology` call with a local account logs in, reads five endpoints of the site in this order, and logs out. Devices that the controller does not manage (not adopted) are left out.

| Classic endpoint | Becomes |
|---|---|
| `stat/device` | Devices with their ports, uplinks, LLDP neighbours and the SSIDs they broadcast |
| `stat/sta` | Clients (the currently connected ones) |
| `rest/networkconf` | Networks |
| `rest/wlanconf` | SSIDs |
| `rest/portconf` | Port profiles |

**Devices.** The reference of a device is its MAC address. The name is the name an operator gave it, else its model and MAC address, else the MAC address. The kind comes from the type code: `usw` is a switch, `uap` an access point, `ugw`, `udm` and `uxg` a gateway, anything else `other`. A device reports its management address and, for each port of its port table (index above zero):

| Port member | Rule |
|---|---|
| Index and name | `port_idx` and the `name` of the port |
| Profile | The configured profile: the override in the device's `port_overrides`, else the effective profile of the port. A Network Application that configures ports inline (10.x, section 3) reports no profile per port |
| Native VLAN | The untagged network the port reports itself, else the native network of its profile; the VLAN is the VLAN of that network, and it is empty for the untagged default network |
| Uplink | Section 4.2 |
| Link state | Up or down |
| Management | Section 4.2 |

**Links.** Three kinds, each between two devices and, where known, two ports:

- **Uplink.** The upstream connection of each wired device: the device's own port and the port of the parent device, both as text.
- **Wireless.** The upstream connection of a mesh access point. It has no ports.
- **Lldp.** Each LLDP neighbour that no uplink already covers, once per pair of ports whichever device names it first. A neighbour whose chassis id is a MAC address is named by it, otherwise by its chassis id text. For a managed neighbour the port text `Port 7` (or `local Port 7`, as a UniFi switch names its own port) becomes the index `7`; an unmanaged neighbour may name its port by its MAC address, which stays as text.

**Clients.** A wired client is attached to the switch (`sw_mac`) and the port (`sw_port`) the controller reports, a wireless client to the access point (`ap_mac`) and the SSID (`essid`). A client with neither a switch nor an access point is left out of the topology (the inventory still has it). The network is the client's `network_id` when it names a LAN network; the VLAN is the VLAN of that network, else the VLAN the controller reports for the client. The address is the IPv4 address, else the first IPv6 address. The name is the alias an operator gave, else the host name the client announced. The vendor is the `oui` text of the controller.

**Networks.** Only LAN networks: the purposes `corporate`, `guest` and `vlan-only`. WAN and VPN networks are left out. A network reports its id (`_id`, the reference that writes use, not the VLAN number), name, VLAN (only when `vlan_enabled`, from 1 to 4094), subnet (the gateway address and prefix `192.0.2.1/24` as the network `192.0.2.0/24`), DHCP mode and the management flag. The DHCP mode is `disabled` for a `vlan-only` network; otherwise `relay` when `dhcp_relay_enabled`, `server` when `dhcpd_enabled`, else `disabled`. The classic API does not report the relay targets per network, so a relaying network is reported as relay with an empty list of servers. A site without a UniFi gateway, whose DHCP is served elsewhere, therefore reports every network as `disabled`: its VLAN-only networks have no subnet and no DHCP members at all, and its default network has `dhcpd_enabled` off (the recorded site, section 12). The controller sends VLAN ids as text; they are read all the same.

**Port profiles.** A profile reports its id, name, native network and tagged networks. What the profile forwards decides the tagged networks:

| `forward` | Tagged networks |
|---|---|
| `native`, `disabled` | None |
| `customize` | The list `tagged_networkconf_ids` when the controller reports one; otherwise, on older controllers, every LAN network except the native one and the ones in `excluded_networkconf_ids` |
| `all` (and any other value) | The reported list when it is not empty; otherwise every LAN network except the native one |

**SSIDs (CONN-18).** An SSID reports its id, its name (the SSID), the network it carries (`networkconf_id`, when the network is known), the VLAN (the VLAN of that network, else the VLAN of the SSID itself on older controllers), whether it is enabled, and the access points that broadcast it: the managed devices whose `vap_table` lists the SSID by its record id or by its name.

### 4.2 Uplinks and the management path

The guardrails of the host (section 6) can only protect what the plugin reports as such, so the plugin follows two rules. They are written down in the module documentation of `model.rs`.

- **Uplinks.** A port is reported as an uplink when it carries a link to another network device: the device's own uplink port, the port of a parent device that a managed device hangs on, a port whose LLDP neighbour is a managed device, a port the controller marks as uplink, and every member of an aggregate one of those belongs to.
- **Management.** A network is a management network when it is the untagged default network, or its subnet holds the controller's address, the address Tenko reaches the controller from, or the address of a managed device. The client whose address is the controller's or Tenko's is a management client, and its switch port a management port.

"The controller's address" is the host of the instance's URL, resolved when it is a name, or `connect_address` when that is set. "The address Tenko reaches the controller from" is the local address that the operating system picks for the route to the controller; the plugin finds it by connecting a UDP socket, which sends nothing. A wireless management client is protected as a client, but it has no switch port to protect.

An example with documentation data. The controller is `192.0.2.10` and the Tenko node `192.0.2.11`; both are in the untagged default network `192.0.2.0/24`. The gateway `00:00:5e:00:53:01` has the switch `00:00:5e:00:53:10` on its port 2, and the switch reaches it over its own port 1. Ports 15 and 16 of the switch form an aggregate, and the LLDP neighbour on port 15 is a managed access point. The client `00:00:5e:00:53:30` with the address `192.0.2.10` sits on port 7. A second client on port 8 is in the network `IoT` (`198.51.100.0/24`, VLAN 30).

| Reported as | What |
|---|---|
| Uplink | Port 1 of the switch (its own uplink), port 2 of the gateway (the parent's port), port 15 of the switch (LLDP to a managed device) and port 16 (member of that aggregate) |
| Management port | Port 7 of the switch, where the controller's client sits |
| Management client | `00:00:5e:00:53:30` (the controller's address), and any client that has `192.0.2.11` |
| Management network | The default network `192.0.2.0/24` |
| Neither | Port 8 and its client, and the network `IoT` |

### 4.3 The inventory

A `Poll` call reads the same endpoints and reports hosts. It always returns the whole inventory as a complete batch (it has no cursor), so a device or client that is gone from the controller expires.

| Host | External id | Name | Addresses | Tags |
|---|---|---|---|---|
| Each adopted device | `device:<mac>` | The device name, else model and MAC address | The management address | `unifi:switch`, `unifi:access_point`, `unifi:gateway`, or `unifi:device` for any other kind |
| Each connected client | `client:<mac>` | The alias, else the announced host name | The IPv4 and IPv6 addresses | `unifi:wired` or `unifi:wireless`, and `unifi:guest` for a guest |

Each host has exactly one MAC address. A client whose MAC address is one of the controller's devices is reported as the device only. Offline clients are not reported: the controller lists connected clients.

### 4.4 The facts this yields

The connector host turns what the plugin reports into observations ([reconciliation.md](reconciliation.md#27-what-the-connector-host-hands-over)). The inventory is filed under the source `inventory:<connector id>` and the topology under `network_controller:<connector id>`.

| Fact | Subject key | From | Says |
|---|---|---|---|
| `host` | `host:device:<mac>`, `host:client:<mac>` | The inventory | Name, MAC address, addresses and tags of a device or client |
| `attachment` | `attachment:<mac>` | Each client of the topology | The switch or access point (the MAC address of the device), the port or SSID, and the VLAN |
| `link` | `link:<device>\|<port>\|<device>\|<port>\|<kind>` | Each link of the topology | An Uplink, Wireless or Lldp link |
| `vendor` | `vendor:<mac>` | Each client with a vendor | The vendor the controller reports for the MAC address |
| `name` | `name:<ip>` | Each client with a name and an address | The alias or host name of the client |
| `network` | `network:<network _id>` | Each network of the topology (a LAN of `rest/networkconf`, or of the Integration API from Network 10.0 on) | Name, subnet, VLAN id (none for the untagged default network), DHCP mode and the management flag |

What follows from them:

- **Address sightings and discovered hosts.** The `host` facts name addresses, so each address of a device or client is a sighting that the reconciler places and that can produce a discovered-host proposal with the name from the controller ([reconciliation.md](reconciliation.md#45-discovered-host)). The `attachment`, `link`, `vendor`, `name` and `network` facts are not sightings of an address.
- **VLANs and prefixes in IPAM.** The `network` facts are how the controller's VLANs arrive in IPAM. Each run of the reconciler compares them with the VLANs and prefixes of intent ([reconciliation.md](reconciliation.md#410-vlan-discovered-and-prefix-vlan-mismatch)): a tagged network whose VLAN id IPAM does not have opens a "VLAN discovered" proposal that creates the VLAN with the network's name, and a prefix whose range equals the network's subnet and is not linked to that VLAN opens a "Prefix VLAN differs" proposal that links it (and creates the VLAN when it is missing). Both wait on the Discovery page for a person; nothing becomes intent by itself. The untagged default network suggests nothing. With an API key on a release before Network 10.0 no network arrives, so the VLANs tab stays empty until a local account is configured (section 2.3).
- **No VRF.** Addresses from a controller carry no VRF. The reconciler places each in the VRF whose network contains it ([reconciliation.md](reconciliation.md#33-where-an-observed-address-belongs)). Where networks overlap in several VRFs, such an address stays unplaced and no rule produces anything for it.
- **Completeness and lifetime.** Both batches are complete, so a client, device or network the controller no longer lists expires at the next read. Every observation expires after three poll intervals, but not sooner than 15 minutes.
- **The device tables.** `GET /topology` ([topology.md](topology.md)) joins the controller's devices (name, model, kind, MAC and management address), the port tables (name, untagged VLAN, uplink flag, link state), the networks with VLAN and subnet, and the SSIDs with their access points. It reads them with the same `Topology` call and keeps them for five minutes. The management flag of ports and clients is not shown there yet.

## 5. What the plugin writes (CONN-06, CONN-08)

The plugin performs four changes that the VLAN provision and move jobs of the host ask for, and a fifth, `RemoveNetwork`, which is only the undo of a network that `EnsureNetwork` created. It writes through the classic API with a local account. With an API key, every `Plan`, `Apply` and `Revert` answers `connect.unsupported`.

| Change | Reads | Writes | Undo |
|---|---|---|---|
| `EnsureNetwork` | `rest/networkconf` | `POST rest/networkconf` (a `vlan-only` network) or `PUT rest/networkconf/<id>` (name, DHCP mode) | `RemoveNetwork`, or `EnsureNetwork` with the old name and DHCP mode |
| `SetPortProfile` | `stat/device`, `rest/portconf` | `PUT rest/device/<id>` with the whole `port_overrides` | `SetPortProfile` with the old profile |
| `SetClientVlan`, `ClearClientVlan` | `stat/user/<mac>`, `rest/networkconf` | `PUT rest/user/<id>` (`virtual_network_override_*`) | The opposite change |
| `RemoveNetwork` | `rest/networkconf` | `DELETE rest/networkconf/<id>` | `EnsureNetwork` with the old name and DHCP mode |

### 5.1 What each change does

**`EnsureNetwork`** makes the controller have the network of a VLAN. The plugin finds the network by the VLAN among the LAN networks.

- No network carries the VLAN: the plugin creates a `vlan-only` network with the name and the VLAN. A `vlan-only` network is a VLAN the controller does not route and on which it serves no DHCP; Tenko serves DHCP, and a router elsewhere routes the VLAN. A new network never gets a DHCP server or a DHCP relay from the plugin: a request for `server` or for relaying on a new network is refused with `connect.invalid_settings`.
- One network carries the VLAN: the plugin renames it when the name differs and switches its DHCP mode (`disabled`, `relay`, `server`) when that differs. A `vlan-only` network has no DHCP on the controller, so a change of its DHCP mode is refused with `connect.invalid_settings`.
- Several networks carry the VLAN, or another network already has the name (compared without regard to case): the plan is refused with `connect.invalid_settings`.
- **A relay list is not supported.** The classic API does not show the relay targets of a network, so a write could not be verified by reading back. A change that asks for relaying to a list of servers answers `connect.unsupported` at the plan. The empty relay list is accepted for an existing network, because that is what an undo carries to put a network that was relaying back into relay mode. A provision that asks the controller to relay to Tenko's DHCP servers therefore stops at the plan on this controller, while a provision with the DHCP of the controller off works.

**`SetPortProfile`** gives a switch port a port profile. The controller keeps the profiles of ports in the device's `port_overrides`, and a write replaces the whole list. The plugin therefore writes the device's whole `port_overrides` back with one entry changed: the entry of the port gets the new `portconf_id`, or a new entry is added, and every other override stays as the controller reported it. The current profile is the configured one (the override, else the effective profile). A device, port or profile that does not exist answers `connect.not_found`.

**`SetClientVlan` and `ClearClientVlan`** use the per-client VLAN override of the client record (`rest/user/<id>`): `virtual_network_override_enabled` and `virtual_network_override_id`, which is the `_id` of the network and not the VLAN number. The member `network_id` of the record alone is the fixed-IP network, not the VLAN override, and the plugin never writes it. Clearing the override sets `virtual_network_override_enabled` to false. A controller version whose client record lacks `virtual_network_override_enabled` does not know the override and answers `connect.unsupported`. A client the controller has no record of, or a target that is not a LAN network of the controller, answers `connect.not_found`.

**`RemoveNetwork`** deletes a network by its id, after checking that it is a LAN network, is not the default network and carries the VLAN named in the change. A network that is already gone is nothing to do: the diff is empty.

### 5.2 The discipline, in order

The host drives; the plugin performs the concrete calls ([plugins.md](plugins.md#network-controllers-and-actuators)).

1. The host reads `Topology` and checks its guardrails against it (section 6). A refusal ends the plan here.
2. The plugin plans (`Plan`). It reads the part of the controller that the change touches, computes the diff as lines of `path`, `before` and `after`, collects warnings, and fingerprints what it read. It writes nothing.
3. The host shows the plan as a preview. A plan carries the time it was read; the host applies it only while it is younger than ten minutes, and refuses an older one with `connect.verify_mismatch`.
4. The host applies (`Apply`) with the plan and a write mode. It refuses a real write with `connect.writes_disabled` when the `writes_enabled` of the instance is off (section 5.4), reads `Topology` again and checks the guardrails again. The plugin then re-reads the state. When the fingerprint differs from the one of the plan, it refuses with `connect.verify_mismatch` and the text "the controller changed since the plan; plan the change again".
5. A dry run, and any mode but an explicit apply, writes nothing; its receipt reports `verified` and carries no undo steps. A plan whose diff is empty also writes nothing.
6. A real write is performed, then the plugin reads the state back and diffs it against the change again. The write is `verified` when that diff is empty. The receipt carries the undo changes that restore the previous state, in order.
7. The host plans the same change again and expects an empty diff; otherwise it fails with `connect.verify_mismatch` ("after the write `<path>` is X instead of Y"). It fails the same way when the receipt says the read-back differed.
8. To undo, the host calls `Revert` with the receipt, again only with `writes_enabled`. The plugin first checks that the controller still shows what the write left (the original change must still read back with an empty diff). When it does not, the revert fails with `connect.verify_mismatch` and names the first path ("the controller changed since the write (`<path>` is X); undo it by hand"). Otherwise it applies each undo change in order, reading, writing and reading back each one, and fails with `connect.verify_mismatch` if a step does not read back. A receipt of a dry run, or one without undo steps, reverts nothing. Before it calls `Revert`, the host reads `Topology` and checks every undo step against the guardrails in force, so a path that became protected since the write is refused with its `connect.guardrail.*` code and never written.

**What the fingerprint covers.** The fingerprint is a SHA-256 digest of the relevant state, kept to 32 hexadecimal digits. For `EnsureNetwork` it covers the network of the VLAN (id, name, purpose, VLAN, DHCP mode) and whether another network has the name. For `SetPortProfile` it covers the id of the device, all its `port_overrides` and the current profile of the port. For the client changes it covers the id of the client record and its override network. For `RemoveNetwork` it covers the network. A change elsewhere on the controller does not make a plan stale; a change to what the plan touches does.

An example plan for creating the network of VLAN 30 (documentation data):

| Path | Before | After |
|---|---|---|
| `networks/vlan-30/name` | | `iot-net` |
| `networks/vlan-30/vlan` | | `30` |
| `networks/vlan-30/purpose` | | `vlan-only` |
| `networks/vlan-30/dhcp` | | `disabled` |

The paths of the other changes are `devices/<mac>/ports/<index>/profile` (with profile names, not ids) and `clients/<mac>/network` (with network names). The diff of `RemoveNetwork` lists `networks/vlan-<vlan>/name` and `networks/vlan-<vlan>/vlan` with a before value only.

### 5.3 Warnings in a plan

A plan carries English warnings that the preview shows and that the VLAN provision job asks a person to acknowledge.

| Warning | When |
|---|---|
| VLAN `<n>` is created as a VLAN-only network: the controller neither routes it nor serves DHCP on it | `EnsureNetwork` creates a network |
| The controller stops serving DHCP on VLAN `<n>`: clients there get no address until another DHCP server answers | `EnsureNetwork` switches a network from `server` to another mode |
| The device on port `<n>` loses its link for a moment while the switch applies the profile | `SetPortProfile` on a port that is up |
| The port has no profile on record, so the receipt carries no undo step | `SetPortProfile` on a port with no profile |
| The client moves when it reconnects | `SetClientVlan` or `ClearClientVlan` that changes the override |
| The client is wired: its VLAN follows its switch port's profile, and the override takes effect only where the port allows it | `SetClientVlan` for a wired client |

### 5.4 Writes are off unless the instance allows them (TGL-20)

The `writes_enabled` field of the instance is how TGL-20 takes effect. It is off for a new instance unless the create request turns it on, and it belongs to the instance, not to the settings of the plugin. With it off, the host answers a real `Apply` and every `Revert` with `connect.writes_disabled` (HTTP 403). `Plan` and the dry run of `Apply` work with writes off, which is how the provision job shows a preview and a read-back diff. The matrix of [SECURITY-PROFILES.md](SECURITY-PROFILES.md) proposes the default per profile: on in Home, Standard and Lab, and off in Hardened until it is explicitly enabled, with approval once IAM-02 exists. The plugin has no write switch of its own and writes whenever an `Apply` in apply mode arrives (ADR 0012).

### 5.5 Status of the live test

The live write test against a production controller (acceptance E7 of the Phase 1 plan) has not run. The writes are proven against the fake controller of the crate's tests (section 12), whose answers follow the documented classic API. Treat the first real write as a test: run the plan and the dry run, read the diff, and keep the role of the account as small as the change needs (section 7).

## 6. Guardrails (CONN-09)

The host refuses a change before the plugin plans or applies it. It reads a fresh topology for every plan and every apply and checks the change against it. A refusal is HTTP 409 with one of these codes.

| Change | Refused when | Code |
|---|---|---|
| `SetPortProfile` | The port is an uplink | `connect.guardrail.uplink` |
| `SetPortProfile` | The port is a management port (the client of the controller or of Tenko sits behind it) | `connect.guardrail.management_port` |
| `SetPortProfile` | The port is a configured protected port | `connect.guardrail.protected_port` |
| `SetClientVlan`, `ClearClientVlan` | The client is a management client | `connect.guardrail.management_client` |
| `SetClientVlan`, `ClearClientVlan` | The client is a configured protected client | `connect.guardrail.protected_client` |
| `SetClientVlan` | The target network is a management network or a configured protected network | `connect.guardrail.protected_network` |
| `EnsureNetwork` | The VLAN is the VLAN of a management network or a configured protected VLAN | `connect.guardrail.protected_vlan` |
| `RemoveNetwork` | The network is a management network or a configured protected network | `connect.guardrail.protected_network` |
| `RemoveNetwork` | The VLAN is the VLAN of a management network or a configured protected VLAN | `connect.guardrail.protected_vlan` |

Uplinks and the management path (ports, clients, networks and VLANs) are always protected. On top of them come the configured protected ports, networks, VLANs and clients: a setting of the installation in the store (`connect.guardrails`), the same on every controller, read with `GET /api/v1/settings/guardrails` (`get_guardrails`) and replaced with `PUT /api/v1/settings/guardrails` (`update_guardrails`, administrators only, `If-Match`, audited as `connect.guardrails.update`; 422 `connect.guardrails.invalid` for at most 256 paths, VLAN ids 1 to 4094, references of 1 to 128 characters and no duplicates). The same setting holds `max_parallel` (1 to 64, default 10): the most real writes, applies and reverts, that run through one controller instance at a time; further writes wait for a free slot. A change applies to the next plan, write or revert without a restart. The settings page in the web UI comes with a later release.

**What the plugin reports so that this works.** The rules of section 4.2 decide which ports are uplinks and management ports, which clients are management clients and which networks are management networks. They err on the side of marking: an aggregate marks all its member ports, an LLDP neighbour that is a managed device marks the port, and a network that holds the address of any managed device is a management network. The guardrails are only as good as what the plugin marks:

- The controller and Tenko are recognized by address, so a client that the controller lists without an address is not recognized.
- A management port exists only for a wired management client. A wireless Tenko node is protected as a client, but no port is.
- With an API key the topology has no ports and no networks, which does not matter because such an instance cannot write.

**Parallelism.** The host lets up to four calls of one instance run at the same time (`max_concurrent_calls`); a further call waits for a slot. Every call has its own session on the controller, and the plugin shares nothing between calls. VLAN provision jobs for one controller run at most four at a time, and the controller step of such a job has a timeout of ten minutes. The `max_parallel` field of the guardrails, meant for bulk jobs, is not read by any job yet.

## 7. Setting up the controller with least privilege

### 7.1 A local account

1. In the Network application, open Settings, Admins and Users, and create an administrator. Give it a name such as `tenko` and a long random password.
2. Tick "Restrict to local access only", so that the account has no cloud login and is a local account.
3. For reading, give it the role View Only. For writes, and only once writes are wanted, give it a role that may manage networks, devices and clients: Site Admin, or a custom role with those rights. The labels differ between releases. Start with View Only: the controller then refuses every write (`connect.forbidden`), which is a second lock behind `writes_enabled`.
4. The login sends the user name and the password and nothing else, so use an account that logs in with those alone (no second factor).
5. Store the password as an operator secret ([secrets.md](secrets.md#6-connectors-and-imports)) and give the instance a reference to it as its `password` secret. Put the user name into the `username` setting. A connector that holds a secret needs an administrator, who may reveal and update it. A login stored as `{"login": "tenko", "password": "..."}`, as an import produces it, works too: the plugin takes the user name from its `login` (or `username`) member, which then takes precedence over the setting.
6. Give the connector a secret of its own. Do not reference a secret that an import created ([secrets.md](secrets.md#8-open-items)).

### 7.2 A local Integration API key (optional)

Use it for a reduced, read-only topology without an account, or to try the connector without storing a password.

1. In the Network application, open Settings, Control Plane, Integrations, and create an API key.
2. Store it as an operator secret and refer to it as the `api_key` secret of the instance. Leave the `password` secret out.

A key created at unifi.ui.com does not work against the controller. It is a Site Manager key: the controller answers it with the same 403 as no key at all (section 3). Create the key in the controller.

### 7.3 TLS

A controller usually has a self-signed certificate that the roots of the operating system refuse. Pin it with the fingerprint mode:

1. Create the instance with `tls = fingerprint` and leave `tls_fingerprint` empty.
2. Run a health check. The instance is degraded, and the detail reads "set `tls_fingerprint` to the SHA-256 fingerprint the controller presents:" followed by the fingerprint, for example `AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89`. Nothing else is checked yet.
3. Compare it with the certificate in the settings of the controller or on its console, not with something read over the same network path. The check shows whatever certificate it was given, so an attacker between Tenko and the controller would show a different one.
4. Set `tls_fingerprint`. Calls now accept only that certificate; its names and dates are not checked, and the handshake signature still is. When the controller renews its certificate, calls fail until you repeat the steps with an empty fingerprint and set the new one.

For a controller with a certificate from an internal CA, use `tls = ca` and put the CA certificate in `tls_ca` (PEM). The host in the URL must be a name that the certificate carries. When the Tenko node cannot resolve that name, set `connect_address` to the IP address of the controller; the certificate is still checked against the name in the URL, and the URL must then hold a host name, not an IP address.

`tls = insecure` switches the check off. Tenko accepts it under the Lab security profile only: under any other profile an instance with it is refused with 422 `connect.tls.insecure_refused`, and one stored before the profile changed is degraded with that code and not called at all until its TLS settings change ([connectors.md](connectors.md) section 2.3). Under the Lab profile the instance is degraded, every call logs a warning, and the health detail repeats the fingerprint it saw so that you can pin it. A plain `http` URL is degraded the same way and sends the password in clear text.

## 8. Settings reference

The settings schema is part of the manifest, and the web UI builds the form from it. Unknown settings are refused.

| Setting | Type | Default | Meaning |
|---|---|---|---|
| `url` | String (a URI, up to 2,048 characters) | Required | The base URL of the Network application: `https://unifi.example.net:8443` for a self-hosted application, `https://unifi.example.net` for a UniFi OS console. No credentials, query or fragment; a trailing `/` is dropped. A plain `http` URL is accepted and degrades the health |
| `deployment` | `auto`, `self_hosted` or `unifi_os` | `auto` | The deployment (section 2). `auto` detects it on every call |
| `site` | String of letters, digits, `_` and `-`, up to 64 | `default` | The short name of the site as the address bar shows it (`/manage/site/<name>/...`), not its description |
| `username` | String, 1 to 128 characters | None | The user name of the local account for the classic API. Its password is the secret `password`. Empty: the connector reads through a local Integration API key only |
| `tls` | `system`, `ca`, `fingerprint` or `insecure` | `system` | How the certificate is checked. `system`: the authorities of the operating system (`SSL_CERT_FILE` and `SSL_CERT_DIR` are honored) and the host name of the URL. `ca`: only the authority in `tls_ca`, and the host name. `fingerprint`: only the certificate with the fingerprint in `tls_fingerprint`. `insecure`: no check, for a lab |
| `tls_fingerprint` | String | None | The SHA-256 fingerprint of the certificate of the controller, 64 hexadecimal digits with or without colons |
| `tls_ca` | String (PEM, up to 65,536 characters) | None | The certificate authority that signed the certificate of the controller |
| `connect_address` | String, up to 64 characters | None | An IP address to connect to instead of looking up the host of the URL. The certificate is still checked against the host of the URL, which must then be a name |

**Secrets.** The manifest declares two purposes. Neither is marked required, but a call needs one of them, or it fails with `connect.invalid_settings`.

| Purpose | Meaning |
|---|---|
| `password` | The password of the local account (`username`). A login stored as `{"login": ..., "password": ...}` is accepted too |
| `api_key` | A local Integration API key, used only when no `password` is given |

**Fields of the instance, not settings of the plugin.** The host owns these; the plugin does not see them.

| Field | Default | Meaning |
|---|---|---|
| `poll_interval_secs` | 300 | Seconds between scheduled reads (60 to 86,400) |
| `call_timeout_secs` | 60 | Timeout of one plugin call (1 to 600). A call holds a login, up to five reads and a logout; each request inside it has its own timeout of 20 seconds, and a connection takes at most 10 seconds to build |
| `writes_enabled` | Off | Whether writes through the instance are allowed (TGL-20, section 5.4) |

**Network targets.** The manifest declares the places the plugin contacts, so that the operator sees them before creating an instance: the host of the setting `url` and the address in `connect_address`, both on the ports 443 and 8443. The host does not block other connections today ([plugins.md](plugins.md#12-security-expectations)).

## 9. Health check

`Check` verifies, in this order:

1. The settings parse. With `tls = fingerprint` and no fingerprint yet, the check stops here and reports the fingerprint the controller presents (section 7.3). It reads that fingerprint over a separate connection that sends nothing after the handshake.
2. A local account or a local key is configured; otherwise `connect.invalid_settings`.
3. The deployment is detected (section 2.2).
4. With an account: the plugin logs in, lists the sites the account may see and reads the version (`stat/sysinfo`), and logs out. The configured site must be one of them. With a key: the plugin lists the sites of the Integration API, requires the configured site among them, and reads the version from `/info`.
5. The version is the one the controller reports, else the one from the status page.

The result is `HEALTHY` with the total time of the check, the version and a detail, for example:

```
self-hosted Network Application, classic API, site `default`
```

```
UniFi OS console, Integration API, site `default`; read-only: devices, uplinks and clients without ports, VLANs or SSIDs; writes need the local account
```

The report is `DEGRADED`, with the notes in the detail, when:

- the URL is `http` ("the connection is not encrypted (http); credentials travel in clear text"), unlike the Home Assistant and Proxmox plugins, which keep the health and show the note ([connectors.md](connectors.md) section 2.3);
- `tls = insecure` ("certificate checks are off (tls = insecure); use this in a lab only"), together with the fingerprint the controller presents and the advice to pin it;
- `tls = fingerprint` and no fingerprint has been set yet.

The detail also notes, without degrading the report, that the certificate is pinned by its fingerprint or checked against a pinned authority, and that a connect address is in use.

A failed check does not fail the call. The host turns an unreachable controller into `UNREACHABLE`, and rejected credentials (`connect.unauthorized`), missing permissions (`connect.forbidden`), a rate limit (`connect.rate_limited`) and settings the plugin cannot use (`connect.invalid_settings`) into `DEGRADED`, with the detail "message (code)". Other failures, such as `connect.protocol` for an address that is not a UniFi controller, stay errors of the call. The host checks every 15 minutes and on request (`POST /api/v1/connectors/{id}/check`).

## 10. Rate limits and retries

The plugin sends at most three attempts of a request. What it repeats depends on whether the request can change something on the controller.

| Answer or failure | Reads | Logins, logouts and writes |
|---|---|---|
| 429 (rate limited) | Retried | Retried |
| 502, 503, 504 | Retried | Not retried |
| Timeout, no connection | Retried | Not retried |
| Anything else | Not retried | Not retried |

A 429 means the controller did not act on the request, so repeating it is safe. After a gateway error or a timeout a write may or may not have happened, so the plugin does not repeat it; the read-back of the discipline in section 5.2 finds out what the state is.

The wait before the next attempt is the `Retry-After` of the controller when it sends a number of seconds, else 0.5 seconds and then 1 second, plus up to 100 milliseconds of jitter. A wait never exceeds 10 seconds. A 429 that persists through the third attempt becomes `connect.rate_limited`, with the `Retry-After` of the controller as the delay (the last wait when it sent none), which the host passes on.

More about the traffic:

- **One login per call.** A call logs in once, uses the session (cookie and CSRF token) for its reads and writes, and logs out at its end; a failed logout is ignored. Nothing is kept between calls. An instance therefore logs in twice per poll interval (`Poll` and `Topology`), once per health check, twice per plan (the topology read for the guardrails, then the plan) and three times per real apply (the topology read, the apply, and the plan that verifies it). An instance with an API key does not log in.
- **Limits.** A request times out after 20 seconds, the connection takes at most 10 seconds to build, and an answer is read up to 32 MiB.
- **Redirects and proxies.** The plugin follows no redirects and uses no proxy from the environment. Its user agent is `tenko-connect-unifi/<version>`.
- **Secrets.** Header values that carry the session cookie, the CSRF token or the API key are marked sensitive and never logged. A secret is never part of a URL.

## 11. Troubleshooting

| Symptom or code | Cause | What to do |
|---|---|---|
| `connect.unauthorized` at login | The controller refused the login: a wrong user name or password; an account that is not a local account (a cloud account does not log in to the API of the controller); or an account that needs more than a user name and a password. With a key: the controller refused the key, for example a key created at unifi.ui.com | Create a local account as in section 7.1 and test it in the web interface of the controller from the local network. For a key, create it in the controller (section 7.2) |
| `connect.forbidden` | The controller answered 403, or `api.err.NoPermission`: the role of the account lacks a right. A View Only account cannot write | Give the account the rights the change needs (section 7.1), or keep it read-only and leave writes off |
| `connect.invalid_settings` with "TLS:" | The certificate was refused. The text names the cause: an unknown issuer (a self-signed certificate or an internal CA), a certificate that does not name the host of the URL, an expired certificate, a pinned fingerprint that no longer matches after a renewal, or "the server does not speak TLS on this address; is the URL http instead of https?" | Pin the certificate (section 7.3), use the host name the certificate carries (with `connect_address` if needed), or point `tls_ca` at the right authority. After a renewal, clear `tls_fingerprint`, run a check and set the new fingerprint |
| `connect.invalid_settings`: "the controller has no login at `/api/login`; check `url` and `deployment`" | The login path answered 404: `deployment` names the other kind of controller, or the URL points at another service | Set `deployment` to `auto`, or to the kind the controller is, and check the port |
| `connect.invalid_settings`: "tls is `fingerprint` but tls_fingerprint is empty" | A scheduled read ran before the fingerprint was set | Run the steps of section 7.3 |
| `connect.invalid_settings`: "the controller has no site `x`" or "the account sees no site `x`" | The `site` setting is not the short name of a site that the account can see | Use the short name from the address bar (`/manage/site/<name>/...`), not the description, and check that the account has access to the site |
| `connect.invalid_settings`: "configure the local account ..." or "the local account needs a user name" | Neither a `password` secret with a `username`, nor an `api_key` secret, is configured | Set the `username` setting and the `password` secret, or the `api_key` secret |
| `connect.invalid_settings` in a plan: "several networks on the controller carry VLAN `n`", "the controller has another network named `x`", "a new network gets neither a DHCP server nor a DHCP relay from the plugin", "a VLAN-only network has no DHCP on the controller" | The change cannot be carried out as asked (section 5.1) | Fix the duplicate on the controller, choose another name, or ask for the DHCP of the controller to be off |
| `connect.invalid_settings`: "the controller refused the request: `api.err....`" | The controller itself refused a write, for example with `api.err.VlanUsed` | Read the code, fix the cause on the controller and plan again |
| `connect.rate_limited` | The controller limits logins or requests and kept answering 429 | Wait for the delay in the error. Lengthen the poll interval, and do not point several instances at one account (section 10) |
| `connect.unsupported` | A write was asked of an instance that has only an API key; a relay list (a non-empty list of servers) was asked of `EnsureNetwork`; the controller version has no per-client VLAN override (`virtual_network_override_enabled` is missing from the client record); or the Integration API does not know a path | Configure a local account for writes. Ask for the DHCP of the controller to be off instead of a relay list. Move the VLAN of a wired client through its port profile on a version without the override |
| `connect.verify_mismatch` | The controller changed between the plan and the apply; the plan is older than ten minutes; the read-back after a write differs from the plan (a device did not take the change); or a revert finds the controller changed since the write | Plan the change again and read the diff. For a read-back that differs, check that the device is connected and provisioned. After a failed revert, undo by hand, as the message says |
| `connect.writes_disabled` | `writes_enabled` is off for the instance | Turn writes on for the instance once writes are wanted (section 5.4) |
| `connect.guardrail.*` | The host refused the change (section 6) | Choose another port, client, network or VLAN. The guardrails cannot be switched off |
| `connect.protocol` | The address does not answer like a UniFi Network application ("set `deployment` if it is one"), the controller accepted the login but set no session cookie, a device has no valid MAC address, or an answer is not JSON or too large | Check the URL and the port (8443 for a self-hosted application, 443 for a console) and set `deployment` |
| `connect.unreachable` | No connection (refused, no route, a name that does not resolve), a timeout, or a 5xx answer after the retries | Check the address, the port and the firewall from the Tenko node, and the state of the controller |
| `connect.timeout` | The call timeout of the host (60 seconds by default) passed before the call finished, for example on a large site | Raise `call_timeout_secs` |
| An empty or thin topology with an API key | Expected: the Integration API has no ports, VLANs, networks or SSIDs (section 2.3) | Configure a local account for the full topology |
| A wired client has no port, or no attachment | The controller reports no switch or no port for it. Several clients on one port usually mean that an unmanaged switch hangs on that port | Nothing to fix in Tenko; the controller does not know the path behind a switch it does not manage |

**Where the plugin logs.** The plugin writes to standard error, and the host forwards it into its own log, labeled with the instance. A line starts with the level and the request id of the call: `WARN [<request id>] ...`. The plugin logs a warning for every call of an insecure instance, and one line for every applied or reverted change with the result of the read-back. It never logs a secret, a setting or a payload of the controller.

## 12. Testing

The tests of the crate need no real controller, except the live smoke at the end.

- **Unit tests** in the source files cover the lenient readers of the controller's JSON (members missing or of the wrong type), the mapping rules of section 4 (uplinks, management, tagged networks, the inventory), the envelopes and the error mapping of the classic API, the settings and the credentials (including that no secret is printed), and the manifest. `src/fuzzing.rs` is the entry point of a fuzz target (`connect_unifi_answers`) that feeds arbitrary bytes as controller answers through the readers and the mapping, since everything the controller sends passes them (CONTRIBUTING, rule 3).
- **Fixture tests** read answers of the classic API from `tests/fixtures/classic/` (`device`, `sta`, `networkconf`, `wlanconf`, `portconf` and `user`) and check the topology and the inventory they produce. The fixtures use documentation addresses and MAC addresses and follow the documented classic API, with the edge cases the tests need. Next to them, `tests/fixtures/recorded/` holds the anonymised answers of a real self-hosted Network Application 10.6 (the same endpoints, plus `stat/sysinfo`), recorded on 2026-10-16 by the recorder in `tests/live.rs` through the plugin's own session and anonymised by `tenko_connect::sdk::anonymise` before anything was written: MAC addresses became documentation addresses, IPv4 networks documentation or benchmarking networks with their members kept inside them, ids counters in the same format, names placeholders, credentials and locations dropped (the README there says exactly what). `tests/recorded.rs` reads them through the fake controller and asserts the counts the live smoke printed the same day; section 3 lists where the real shapes differ from the documented ones. Recording again takes `TENKO_LIVE_UNIFI=1 TENKO_RECORD=1` and the ignored test `live_record_fixtures`, and a grep of the output for anything outside the documentation ranges before it is looked at.
- **A fake controller** in the test code (`tests/support`) is an in-process stand-in that serves, on a loopback port, the parts of the classic API and of the Integration API that the plugin uses, in both flavors, self-hosted and UniFi OS, over plain HTTP or over TLS with a fresh self-signed certificate. It is loaded with the fixtures, and it behaves like a controller where the plugin depends on it: sessions with a cookie and a CSRF token, error codes, uniqueness of names and VLANs, and rate limits. A test changes its data between calls (drift, also right after a write, so that the read-back differs) and checks what the plugin wrote. The write discipline of section 5 is proven against it (`tests/write.rs`): the guardrails of the host refuse the uplinks and the management port and client that the topology marks, a dry run writes nothing, each change is written, read back, planned again with an empty diff and undone, a drifted read-back is reported as not verified, a stale plan and a revert after a change by someone else are refused without writing, and changes the controller cannot carry out are refused at the plan. The read tests (`tests/read.rs`) cover both flavors, TLS with a pinned and a wrong fingerprint, rate limits, wrong credentials, an unknown site and the Integration API.
- **The conformance suite** of the SDK runs against the `tenko-plugin-unifi` executable, started the way the host starts a plugin, twice: without settings, where every check that reaches the remote system must answer with a coded settings error, and against the fake controller over TLS with a pinned fingerprint, where the checks read the fixtures, every session ends with a logout and nothing is written. Every check must pass both times ([plugins.md](plugins.md#11-the-conformance-suite)). To run it by hand, use `tenko plugin test <path to tenko-plugin-unifi>`, with `--settings` and `--secret password=<VARIABLE>` to point it at a real or mock controller.

**The live read-only smoke** is ignored in a normal run and never part of CI. It runs only when `TENKO_LIVE_UNIFI=1` is set:

```
TENKO_LIVE_UNIFI=1 cargo nextest run -p tenko-connect-unifi --run-ignored all live
```

It reads only the `UNIFI_*` lines of the `.env` file of the repository, which git ignores: `UNIFI_URL`, either `UNIFI_USER` with `UNIFI_PASSWORD` (a local account) or `UNIFI_LOCAL_API_KEY` (a local Integration API key), and optionally `UNIFI_SITE` and `UNIFI_TLS_FINGERPRINT`. Unless `UNIFI_TLS_FINGERPRINT` is set, it pins the certificate the controller presents on first use. It calls only `Check`, `Poll` and `Topology`, never `Plan`, `Apply` or `Revert`, so it writes nothing. It checks that the topology passes the strict conversion of the host, and it prints counts and shapes only (devices by kind, ports, links, clients, networks, profiles, SSIDs), never a name, an address or an identifier.

## 13. What comes next

- **The live write test (E7).** The first real write against a production controller, with a dry run and a read-back diff, has not run yet. Until then the writes are proven against the fake controller only (section 5.5).
- **Inline port configuration.** A Network Application that configures ports inline (section 3) carries no `portconf_id` in its port tables or overrides. The reads cope (no profile per port, the native VLAN from `native_networkconf_id`), but the port-profile write puts `portconf_id` into `port_overrides`, which such a controller may ignore; the live write test must settle what a port change writes there, and whether `rest/user` takes a `virtual_network_override_*` member that the read never showed.
- **Relay targets and SSID writes.** The relay targets of a network become readable and writable once there is a way to read them back, which lets a provision relay to Tenko's DHCP servers. Writing SSID-to-VLAN mappings and creating SSIDs (the write half of CONN-18) follows the same verify-before-write and guardrail rules.
- **The management flag in the topology.** The port table of `GET /topology` and the map show the uplink flag but not yet the management flag of ports and clients ([topology.md](topology.md)).
- **Per-site association of controllers.** A request names the connector, else the only enabled network controller; IPAM has no association of a site with a controller yet.
- **The Integration API of newer releases.** The key-only mode reads the networks of Network 10.0 and later (section 2.3); where a release reports wireless networks, it can report them too. Writes stay with the classic API until the Integration API can be verified for them.
