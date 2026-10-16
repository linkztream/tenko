# Inventory connectors: Proxmox VE and Home Assistant

This page describes the two bundled inventory connectors of Tenko DDI, Proxmox VE and Home Assistant: how an inventory connector fits into Tenko, how the certificate check that both plugins share works, and for each plugin what it reads and how that becomes hosts, how to prepare the remote system with least privilege, every setting, the health check, what is deliberately not read, and what to do when something goes wrong. It then describes what the owner sees in IPAM after the first run and how a developer runs the live smoke tests. It is for the administrator who connects a Proxmox VE cluster or a Home Assistant instance, for the reviewer of what the plugins read from those systems, and for a developer who works on the plugins. It describes the behavior of the `tenko-connect-proxmox` and `tenko-connect-hass` crates and of the web helpers in `crates/tenko-connect/src/sdk/http.rs` that both use; where this page and the code differ, the code is right. The requirements are CONN-02 (the inventory source contract), CONN-03 (Proxmox VE inventory), CONN-04 (Home Assistant inventory) and CONN-20 (reference plugins bundled in the `tenko` binary) in [REQUIREMENTS.md](REQUIREMENTS.md). The UniFi Network connector has a page of its own: [connectors-unifi.md](connectors-unifi.md).

Terms used below: the **host** is the Tenko process that starts a plugin and calls it. An **instance** is one configured connector: a plugin, its settings and its secrets (see [plugins.md](plugins.md)). A **fact** is one source's latest knowledge of one subject, and a **proposal** is a suggested change of IPAM intent that a person decides (see [reconciliation.md](reconciliation.md)). In Proxmox VE a **node** is one server of the cluster and a **guest** is a virtual machine or a container. In Home Assistant a **device** is an entry of the device registry, an **entity** is one of its sensors, switches or trackers, and the **registries** are the lists of devices, entities and areas.

Contents:

1. [Inventory connectors in Tenko](#1-inventory-connectors-in-tenko)
2. [The certificate check](#2-the-certificate-check)
3. [Proxmox VE](#3-proxmox-ve)
4. [Home Assistant](#4-home-assistant)
5. [What the owner sees after the first run](#5-what-the-owner-sees-after-the-first-run)
6. [Live smoke tests for developers](#6-live-smoke-tests-for-developers)

## 1. Inventory connectors in Tenko

An inventory connector is a plugin with the `inventory` capability (CONN-02). The host calls it on a schedule. In a cluster every controller runs the plugin processes, the health checks and the runs a person asks for, but only the leader runs the schedule (the leader service `connect.poll`); a controller that takes over as leader starts the reads that fell due at once, so scheduled reads continue within one poll interval. The plugin reads one remote system and answers with the hosts it observes: for each an identifier of the source's own (`qemu/101`, `device/<id>`), a name, MAC addresses, IP addresses, an operating system, a platform, a parent host and tags, and optionally the vendor of a MAC address (see [plugins.md](plugins.md#inventory)). What the host does with the answer:

- Each host becomes a `host` fact under the source `inventory:<connector id>`, and each vendor becomes a `vendor` fact of its MAC address ([reconciliation.md](reconciliation.md#22-facts)).
- The facts are observations and never intent. They change nothing in IPAM by themselves. The reconciler compares them with IPAM and derives proposals, which a person, or the adoption policy of a prefix, decides (section 5).
- Both plugins report the whole inventory on every poll. The host puts all pages of a poll together and treats the result as a complete batch: the facts of this connector that the poll no longer names expire at once, for example a guest that was deleted or a device that was removed from Home Assistant. They stay readable as expired facts for 30 days.
- A poll that fails writes nothing, so a failed poll never makes a host disappear. The hosts that were reported before stay current until their lifetime ends, which is three poll intervals after they were received and at least 15 minutes ([reconciliation.md](reconciliation.md#27-what-the-connector-host-hands-over)).

Both plugins are bundled in the `tenko` binary (CONN-20). The host starts them like any third-party plugin, as `tenko plugin run proxmox` and `tenko plugin run hass`. That command speaks the handshake on its standard input and output and is not meant to be run by hand. Nothing is installed besides Tenko itself, and `tenko plugin list` shows both. The same code is also built as the executables `tenko-plugin-proxmox` and `tenko-plugin-hass`, which the tests and `tenko plugin test <path>` start. Both plugins declare the `inventory` capability and nothing else, and both are read-only: the Proxmox VE plugin sends GET requests only; the Home Assistant plugin sends GET requests and four registry commands over the WebSocket API. The write switch of an instance (`writes_enabled`) has nothing to switch for them. For bundled plugins in general see [plugins.md](plugins.md#10-installing-and-listing-plugins).

### 1.1 Creating an instance

1. Create the credential on the remote system, with the least privilege that the plugin needs: an API token for Proxmox VE (section 3.2), a long-lived access token of a dedicated user for Home Assistant (section 4.2).
2. Store the credential as an operator secret: on the Secrets page under Settings, or with `POST /api/v1/secrets`. Creating a secret needs an administrator ([secrets.md](secrets.md#2-policy)). Tag the secret with the purpose it is for (`token_secret` or `access_token`), so that the connector form offers it first.
3. Create the instance on the Connectors page, or with `POST /api/v1/connectors`. The form is built from the settings schema of the plugin. The instance does not hold the credential: it refers to the secret by purpose. A reference needs the right to reveal and to update the secret, so an administrator creates secret-bearing connectors ([secrets.md](secrets.md#6-connectors-and-imports)).

| Plugin | `plugin` | Secret purpose (required) | The secret is |
|---|---|---|---|
| Proxmox VE | `proxmox` | `token_secret` | The secret of the API token, a UUID that Proxmox VE shows once |
| Home Assistant | `hass` | `access_token` | A long-lived access token of a Home Assistant user |

The settings are checked against the schema of the plugin when an instance is created or changed. Unknown settings are refused, an absent setting takes the default of the schema, and a value that does not fit answers 422 `connect.settings.invalid` with the field. A change of the settings replaces the whole settings object.

**Fields of the instance, not settings of the plugin.** The host owns these; the plugin does not see them.

| Field | Default | Meaning |
|---|---|---|
| `poll_interval_secs` | 300 | Seconds between scheduled reads, 60 to 86,400 |
| `call_timeout_secs` | 60 | Timeout of one plugin call, 1 to 600. The default comes from the manifest of both plugins; the host's own default is 30. A paged poll gives each page its own timeout (sections 3.6 and 4.1) |
| `enabled` | `true` | Whether the instance runs. An enabled instance starts its plugin at once |
| `writes_enabled` | `false` | Whether writes are allowed. These plugins never write |

**Examples.** First the secret, with a placeholder for the value. Do not keep a real value in a script.

```json
POST /api/v1/secrets
{
  "name": "Proxmox VE inventory token",
  "kind": "token",
  "tags": ["token_secret"],
  "value": "<token secret>"
}
```

Then an instance of the Proxmox VE plugin. The answer to the first request carries the `id` of the secret, which goes into `secrets`:

```json
POST /api/v1/connectors
{
  "plugin": "proxmox",
  "name": "Lab cluster",
  "settings": {
    "url": "https://pve1.example.net:8006",
    "token_id": "tenko@pve!inventory",
    "tls": "fingerprint",
    "tls_fingerprint": "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
  },
  "secrets": { "token_secret": { "secret": "<id of the secret>" } },
  "poll_interval_secs": 300
}
```

And an instance of the Home Assistant plugin that leaves out the devices of the `unifi` integration, which the UniFi connector reports already (section 4.6):

```json
POST /api/v1/connectors
{
  "plugin": "hass",
  "name": "Home Assistant",
  "settings": {
    "url": "http://homeassistant.example.net:8123",
    "exclude_integrations": ["unifi"]
  },
  "secrets": { "access_token": { "secret": "<id of the secret>" } }
}
```

Once the instance exists, `POST /api/v1/connectors/{id}/check` runs the health check now and `POST /api/v1/connectors/{id}/run` starts a read now (202, with the job). The host also checks every 15 minutes by itself.

## 2. The certificate check

Both plugins reach their system with the same four TLS settings. They come from the shared web helpers of the SDK, and the UniFi connector uses them too. Neither plugin uses a proxy from the environment, and neither follows redirects: an answer with a redirect status is an error (`connect.protocol`), so put the final URL into `url`.

### 2.1 The four modes

| `tls` | A certificate is accepted when | Use it for |
|---|---|---|
| `system` (default) | It chains to an authority that the operating system of the Tenko node trusts (`SSL_CERT_FILE` and `SSL_CERT_DIR` are passed on to plugins), it names the host of the URL and it is in date | A certificate from a public authority, or from one your machines trust already, such as an ACME certificate on a reverse proxy |
| `ca` | It chains to an authority in `tls_ca` and to no other (the system authorities are not used), it names the host of the URL and it is in date | A certificate from an internal authority that the operating system does not know. Pin the authority once; renewed certificates keep working |
| `fingerprint` | Its SHA-256 fingerprint equals `tls_fingerprint`. Its names and dates are not checked; the signature of the TLS handshake still is | A self-signed certificate, or a server whose name you cannot use in the URL. A renewed certificate has a new fingerprint, so the setting must change with it |
| `insecure` | Any certificate | A lab (section 2.3) |

`tls_fingerprint` is read only in the mode `fingerprint`, and `tls_ca` only in the mode `ca`. In the other modes they are ignored.

- **`tls_fingerprint`.** The SHA-256 fingerprint of the server certificate: 64 hexadecimal digits, with or without colons, in either case. Tenko shows a fingerprint as upper-case digits separated by colons.
- **`tls_ca`.** The certificate authority as PEM text: one or more certificates between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines, up to 65,536 bytes. A PEM pasted without line breaks, or with spaces in place of them, works too, which is how it arrives from a single-line form field.
- **`connect_address`.** An IPv4 or IPv6 address. The plugin connects to that address, on the port of the URL, instead of looking up the host of the URL, and it still checks the certificate against the host name in the URL. Use it for a certificate, such as an ACME certificate, that names a host this machine cannot resolve. The URL must then hold the host name, not an IP address; the setting is refused otherwise. Example: `url` `https://pve1.example.net:8006` with `connect_address` `192.0.2.10`.

### 2.2 Pinning a certificate

A server with a self-signed certificate is pinned by its fingerprint. The health check shows the fingerprint, so you do not have to read it from anywhere else:

1. Create the instance with `tls` at its default, `system`.
2. Run a health check. It reports `unreachable` with a detail such as `TLS: the server certificate is not signed by a trusted certificate authority (unknown issuer); pin the certificate authority (tls = ca) or the certificate (tls = fingerprint). The server presents a certificate with the SHA-256 fingerprint AB:CD:EF:...`.
3. Compare that fingerprint with the one the server itself shows: for Proxmox VE the certificate list of the node (the node, System, Certificates). Do not compare it with something read over the same network path. The check shows whatever certificate it is given, so a party between Tenko and the server would show its own.
4. Change the instance to `tls` `fingerprint` and set `tls_fingerprint`.

When the server renews its certificate, calls fail with `TLS: the server certificate does not match the pinned fingerprint ...`, and the health detail carries the new fingerprint. Compare it again and replace `tls_fingerprint`. Do not start with `tls` set to `fingerprint` and an empty `tls_fingerprint`: the plugin refuses that as invalid settings and shows no fingerprint.

### 2.3 Insecure mode and plain HTTP

`insecure` switches the check off. Anyone on the path can then read the token and answer with invented data, so Tenko accepts it under the Lab security profile only. Under any other profile, creating an instance with `tls = insecure` or changing an instance to it is refused with 422 `connect.tls.insecure_refused` (field `settings.tls`). An instance stored with `insecure` before the profile changed away from Lab stays in the list but does not run: it shows as `degraded` with the code `connect.tls.insecure_refused`, no call reaches its plugin (scheduled and requested runs, the health check), and the host logs the refusal once, until the instance or the profile changes. Choose `system`, `ca` or `fingerprint` to bring it back.

Under the Lab profile it is loud on purpose: for an `https` URL the instance reports `degraded` with the note `certificate checks are off (tls = insecure); use this in a lab only`, and the plugin writes a `WARN` line to the log of the host on every call of the instance. It does not show a fingerprint; pin the certificate as in section 2.2 instead.

A plain `http://` URL is accepted, and it is the normal address of a default Home Assistant (port 8123). The token then travels in clear text on every call. The health detail says so: `the connection is not encrypted (http); credentials travel in clear text`. Whether the note also lowers the health is the plugin's call. The UniFi plugin reports `degraded` for an `http` URL, because a controller speaks `https` by default and `http` means a proxy in between or a mistake. The Home Assistant and Proxmox plugins keep the health of a working instance and show the note, because `http` on port 8123 is the normal address of a Home Assistant and the Proxmox API does not answer on `http` at all. Use `http` only on a network you trust, or put TLS in front of the system.

### 2.4 What the failure texts say

A failed certificate check shows in two places. The health check reports `unreachable` with the detail `TLS: <cause>`, and for a TLS failure it adds the fingerprint of the certificate that the server presents. A poll fails with `connect.invalid_settings` and the text `TLS: <cause>`, because an operator fixes it in the settings. The table gives the start of each cause and what to change. In the modes `system` and `ca` a cause ends with a hint (`; pin the certificate authority (tls = ca) or the certificate (tls = fingerprint)` in `system`, `; check tls_ca, or pin the certificate (tls = fingerprint)` in `ca`) that the table leaves out.

| Text after `TLS: ` | Cause | What to change |
|---|---|---|
| the server certificate is not signed by a trusted certificate authority (unknown issuer) | A self-signed certificate, or an issuer that the mode does not trust | Pin the certificate (`fingerprint`) or its authority (`ca`). In `ca`, check that `tls_ca` holds the authority that signed this certificate |
| the server certificate does not name the host of the URL | The URL holds an address or a name that the certificate does not carry | Use a host name that the certificate carries in the URL, with `connect_address` if the node cannot resolve it. Or pin the certificate |
| the server certificate has expired | The certificate is out of date | Renew it on the server |
| the server certificate is not valid yet (check the clocks) | The clock of the Tenko node or of the server is wrong | Correct the clocks |
| the server certificate is revoked | The authority revoked it | Replace the certificate |
| the server certificate has a bad signature | The certificate is damaged or forged | Replace it, and check the path to the server |
| the server certificate cannot be read | The certificate has an encoding the plugin cannot read | Replace it |
| the server certificate does not match the pinned fingerprint (tls_fingerprint); a renewed certificate has a new fingerprint | The mode is `fingerprint` and the server shows another certificate: renewed, replaced, or a wrong value | Compare the fingerprint in the health detail with the server's own, then replace `tls_fingerprint` |
| the server certificate is not meant for a TLS server | The certificate may not be used to authenticate a server | Replace it |
| the server certificate was refused | Any other reason for a refusal | As for an unknown issuer |
| the server ended the handshake with the alert ... | The server refused the connection, for example for an unknown server name or a required client certificate | Check the TLS settings of the server or the proxy, and that the host name in the URL is one it serves |
| the server presented no certificate | The service at this address is not a TLS server | Check the address and the port |
| the server does not speak TLS on this address; is the URL http instead of https? | A plain HTTP service on a port addressed with `https://`, or a service that is not HTTP at all | Use `http://`, or the right port |
| the server offers no TLS version or cipher this client accepts (TLS 1.2 or 1.3) | An old server | Enable TLS 1.2 or 1.3 on the server |
| the TLS handshake failed | Anything else that broke the handshake | Check the server and the path to it |

Other failures to reach the server are reported without the `TLS:` prefix. The health check shows `unreachable` and a poll fails with `connect.unreachable`, except for the last row.

| Text | Cause |
|---|---|
| the server did not answer in time | A request got no answer in time: 20 seconds per request (8 seconds for a Proxmox VE guest agent request, 30 seconds for a Home Assistant WebSocket answer), or the connection took longer than 10 seconds |
| no connection to the server (refused, no route, or the name does not resolve) | The address, the port, the name resolution or a firewall |
| the exchange with the server was interrupted | The connection broke off while it was in use |
| the request cannot be built from the settings | The settings produce no valid request. A poll fails with `connect.invalid_settings` |

**Settings that are refused.** These answer `connect.invalid_settings` before any request is sent:

| Text | What to change |
|---|---|
| url is not a valid URL; url must start with https:// or http://; url has no host | Write a base URL such as `https://pve1.example.net:8006` |
| url must not carry credentials; they belong in the instance's secrets | Remove the user name and password from the URL |
| url must not have a query or a fragment | Remove everything from the `?` or `#` on |
| tls is `fingerprint` but tls_fingerprint is empty | Set the fingerprint, or use another mode (section 2.2) |
| tls_fingerprint is not a SHA-256 fingerprint (64 hexadecimal digits, colons allowed) | Check the value |
| tls is `ca` but tls_ca is empty; tls_ca: no certificate (-----BEGIN CERTIFICATE-----) found | Paste the authority as PEM |
| connect_address is not an IPv4 or IPv6 address | Use an address, not a name |
| connect_address needs a host name in the URL, not an IP address | Put the host name into `url` |
| the secret `token_secret` is empty (`access_token` for Home Assistant) | The secret holds no value |

## 3. Proxmox VE

The plugin `proxmox` reads a Proxmox VE 8 or 9 cluster through its REST API with an API token (CONN-03). It finds the addresses that never appear in DHCP: the static addresses of cloud-init and of containers, and the addresses that a QEMU guest agent reports. It never writes anything to the cluster.

### 3.1 What the plugin reads and how it maps

All requests are GET requests below `/api2/json`, and all carry the header `Authorization: PVEAPIToken=<token id>=<token secret>`. The secret is never part of a URL.

| Request | When | Used for |
|---|---|---|
| `/version` | Health check; first page of a poll | The release, for the OS of the nodes and the health detail |
| `/access/permissions` | Health check only | The privileges of the token (section 3.4) |
| `/cluster/resources` | Every page | The nodes and the guests: id, node, name, status, template flag, pool, tags |
| `/cluster/status` | First page | The address of each node |
| `/nodes/<node>/network` | First page, for each online node | The addresses of the active interfaces of the node |
| `/cluster/sdn/vnets` and `/cluster/sdn/zones` | Every page that has guests | The VLAN or VXLAN of a vnet |
| `/nodes/<node>/qemu/<vmid>/config` and `/nodes/<node>/lxc/<vmid>/config` | Every guest on an online node | MAC addresses, bridges, VLAN tags, cloud-init addresses, `ostype`, the agent option |
| `/nodes/<node>/qemu/<vmid>/agent/network-get-interfaces` | Every running VM whose configuration enables the agent, when `guest_agent` is on | The addresses the guest reports |
| `/nodes/<node>/lxc/<vmid>/interfaces` | Every running container | The addresses the container shows |

The answers become these hosts:

| Host | `external_id` | Name | MAC addresses | IP addresses | OS | Platform | Parent |
|---|---|---|---|---|---|---|---|
| Node | `node/<name>` | The node name | None | From `/cluster/status`, and the `address`, `address6`, `cidr` and `cidr6` of the active interfaces of the node | `Proxmox VE <release>` | `proxmox-ve` | None |
| QEMU guest | `qemu/<vmid>` | The name of the guest | The MAC address of each `netN` | See below | From `ostype` | `qemu` | `node/<node>` |
| LXC container | `lxc/<vmid>` | The host name of the container | The `hwaddr` of each `netN` | See below | From `ostype` | `lxc` | `node/<node>` |

**Addresses of a guest.** The plugin first looks for live addresses. For a running VM these are the addresses that the guest agent reports on interfaces whose hardware address is one of the VM's configured MAC addresses. For a running container they are the addresses of the interfaces with one of its MAC addresses. Interfaces inside the guest with other MAC addresses, such as `docker0`, bridges and VPN adapters, are left out. Only when there is no live address does the plugin use the static addresses of the configuration: the `ip` and `ip6` of the cloud-init entry `ipconfigN` of a VM, and the `ip` and `ip6` of a container's `netN`. The values `dhcp`, `auto` and `manual` are not addresses. Loopback, unspecified, multicast and link-local addresses and the IPv4 broadcast address are never reported. A stopped guest (with `include_stopped` on) therefore has its MAC addresses and its static addresses only.

**Guests the plugin cannot look into.** A guest on a node that is not online comes with what `/cluster/resources` says about it (name, status, pool and tags) and no MAC or IP address, because its configuration cannot be read.

**Operating system.** A VM maps its `ostype`: `l26` is `Linux`, `l24` is `Linux 2.4`, `win11` is `Windows 11/2022/2025`, `win10` is `Windows 10/2016/2019`, `win8` is `Windows 8/2012/2012 R2`, `win7` is `Windows 7/2008 R2`, `w2k8` is `Windows Vista/2008`, `wvista` is `Windows Vista`, `w2k3` is `Windows 2003`, `w2k` is `Windows 2000`, `wxp` is `Windows XP`, `solaris` is `Solaris`; any other value (`other`) gives no OS. A container maps its distribution to `Linux (Debian)`, `Linux (Ubuntu)`, `Linux (Alpine)` and so on; an unmanaged container, or none given, is `Linux`, and a distribution the plugin does not know is `Linux (<ostype>)`.

**Tags.** A host carries these tags:

| Tag | On | Meaning |
|---|---|---|
| The Proxmox VE tags as they are | Guests | Proxmox VE tags cannot contain a colon, so they never collide with the tags below |
| `status:<status>` | Nodes and guests | `online`, `offline`, `running`, `stopped` and so on |
| `pool:<name>` | Guests | The resource pool of the guest |
| `template` | Guests | The guest is a template (with `include_templates`) |
| `bridge:<name>` | Guests | An interface is attached to a bridge that is not an SDN vnet |
| `vnet:<name>` | Guests | An interface is attached to an SDN vnet |
| `vlan:<id>` | Guests | The VLAN tag of an interface (`tag=`, 1 to 4094), or the tag of a vnet in a VLAN or QinQ zone |
| `vxlan:<vni>` | Guests | The tag of a vnet in a VXLAN or EVPN zone |

An example of a guest as the plugin reports it (documentation values):

| Field | Value |
|---|---|
| `external_id` | `qemu/101` |
| Name | `web01` |
| MAC addresses | `00:00:5e:00:53:01`, `00:00:5e:00:53:02` |
| IP addresses | `198.51.100.10` |
| OS, platform, parent | `Linux`, `qemu`, `node/pve-a` |
| Tags | `prod`, `web`, `status:running`, `pool:lab`, `vnet:vnet20`, `vlan:20`, `bridge:vmbr0`, `vlan:30` |

**On the map.** A guest names its node as its parent, so the topology map draws a VM-to-host edge (`vm_host`) from the node, which becomes a hypervisor, to the VM or container. The platforms `qemu` and `lxc` make the guests `vm` and `container` nodes ([topology.md](topology.md#3-edges)).

### 3.2 The API token with least privilege

The plugin needs read access only. Give it a token of its own and a role that cannot write.

1. **A user.** Create a user in the realm `pve` (Datacenter, Permissions, Users, Add), for example `tenko@pve`, or use an existing one. A user that exists only to own a token needs no password.
2. **A token with privilege separation.** In Datacenter, Permissions, API Tokens, Add, choose the user, give the token an ID such as `inventory`, and leave Privilege Separation ticked. Copy the secret at once: Proxmox VE shows it once. The ID the plugin needs is the full one, `tenko@pve!inventory`. Do not set an expiry date, or note the date: an expired token answers 401.
3. **The role, for the token.** In Datacenter, Permissions, Add, API Token Permission: path `/`, the token, the role `PVEAuditor`, Propagate ticked.
4. **The role, for the user.** Do the same with User Permission for the user. A token with privilege separation has the intersection of its own rights and its user's, never more than the user, so a token that holds the role while its user holds nothing sees nothing.

The same on the command line, on a node:

```console
pveum user add tenko@pve --comment "Tenko DDI inventory"
pveum user token add tenko@pve inventory --privsep 1
pveum acl modify / --users tenko@pve --roles PVEAuditor
pveum acl modify / --tokens 'tenko@pve!inventory' --roles PVEAuditor
```

The `token add` command prints the full token ID and the secret once. Put the secret into the vault (section 1.1) and the ID into the setting `token_id`. A token created with `--privsep 0` has exactly the rights of its user and needs only the user's entry, but it cannot be narrowed on its own.

**Privileges.** On Proxmox VE 9 the role `PVEAuditor` holds `Sys.Audit`, `VM.Audit`, `VM.GuestAgent.Audit`, `SDN.Audit`, `Pool.Audit`, `Datastore.Audit` and `Mapping.Audit`. That is everything the plugin needs and nothing that writes. The plugin uses these:

| Privilege | What it feeds | Without it |
|---|---|---|
| `VM.Audit` | The guests in `/cluster/resources` and their configuration: MAC addresses, bridges, tags, cloud-init addresses, OS, and the interfaces of containers | The token sees no guest. The health check is degraded, and the poll reports the nodes and no guests |
| `Sys.Audit` | The addresses of the nodes: `/cluster/status` and the network configuration of each node | Nodes without addresses; a note in the health detail |
| `VM.GuestAgent.Audit` (Proxmox VE 9) or `VM.Monitor` (Proxmox VE 8) | The addresses that the guest agent of a running VM reports | VMs without live addresses; their static cloud-init addresses are still used. A note in the health detail and a warning in the log |
| `SDN.Audit` | The vnets and zones: the `vnet:`, `vlan:` and `vxlan:` tags of a vnet | No vnet tags. The VLAN tag of an interface still gives `vlan:` |
| `Pool.Audit` | Held by `PVEAuditor`. The plugin does not read the pool endpoints: the pool of a guest arrives with `/cluster/resources`, and no check of the plugin looks for this privilege | Nothing the plugin shows |

`Datastore.Audit` and `Mapping.Audit` are in the role too and are not used.

**Proxmox VE 8.** `PVEAuditor` has no `VM.GuestAgent.Audit` there, and the guest agent commands need `VM.Monitor`, which the role does not hold. Create a role with the privileges of `PVEAuditor` plus `VM.Monitor` (Datacenter, Permissions, Roles, Create) and grant that role instead, for the token and for the user. A role with just what the plugin uses:

```console
pveum role add TenkoInventory --privs "Sys.Audit,VM.Audit,VM.Monitor,SDN.Audit"
```

`VM.Monitor` is broader than an audit privilege: it opens the monitor of a VM. The plugin sends no monitor command, but the token could. If that matters, leave `guest_agent` off on Proxmox VE 8: the plugin then reads no guest agent addresses and works with `PVEAuditor` alone, using the static addresses of the configuration.

A role granted on a narrower path shows the plugin only what the token may see. The health check merges the privileges of all paths, so it does not warn about a narrow grant.

### 3.3 Settings

The settings schema is part of the manifest, and the web UI builds the form from it. Unknown settings are refused.

| Setting | Type | Default | Meaning |
|---|---|---|---|
| `url` | String (a URI) | Required | The base URL of the API of one node, with the port: `https://pve1.example.net:8006`. Any node answers for the whole cluster, but the plugin asks the one in the URL, so use an address that stays up as long as the cluster does |
| `token_id` | String, `user@realm!name` | Required | The ID of the API token, for example `tenko@pve!inventory`. Its secret is the secret `token_secret` of the instance |
| `nodes` | Array of strings, up to 64 | Empty | Only these nodes and their guests. All nodes when empty |
| `pools` | Array of strings, up to 64 | Empty | Only guests in these pools. All guests when empty. Nodes are not filtered by pool |
| `include_stopped` | Boolean | `true` | Report guests that are not running, with the MAC addresses and the static addresses of their configuration |
| `include_templates` | Boolean | `false` | Report templates |
| `guest_agent` | Boolean | `true` | Ask the QEMU guest agent of running VMs for their addresses |
| `page_size` | Integer, 10 to 500 | 100 | Guests per page (section 3.6) |
| `tls` | `system`, `ca`, `fingerprint` or `insecure` | `system` | How the certificate is checked (section 2) |
| `tls_fingerprint` | String | None | The pinned SHA-256 fingerprint, for `fingerprint` |
| `tls_ca` | String (PEM, up to 65,536 characters) | None | The pinned certificate authority, for `ca` |
| `connect_address` | String, up to 64 characters | None | An IP address to connect to instead of looking up the host of the URL |

**Secret.** The manifest declares one purpose, `token_secret`, and requires it.

**Network targets.** The manifest declares the places the plugin contacts, so that the operator sees them before creating an instance: the host of `url` and the address in `connect_address`, both on port 8006. The host does not block other connections today ([plugins.md](plugins.md#12-security-expectations)).

### 3.4 Health check

`Check` reads `/version`, and then `/access/permissions` for the privileges of the token. It reports:

- **Healthy** when the server answers and the instance is not `insecure` over `https`, unless the token is known to lack `VM.Audit`. The remote version is `Proxmox VE <release>` and the latency is that of the `/version` request. The detail lists the notes below, if there are any.
- **Degraded** when the token holds `VM.Audit` on no path, or the instance is `insecure` over `https`. The host also reports degraded, with the detail `message (code)`, when the server rejected the token (`connect.unauthorized`), when it lacks permission (`connect.forbidden`), when it limits requests (`connect.rate_limited`) and when the settings cannot be used (`connect.invalid_settings`).
- **Unreachable** when no answer arrives (a TLS failure, a timeout, no connection) or the server answers with a server error (`connect.unreachable`). The detail names the cause (section 2.4).

Other failures, such as an answer that is not JSON (`connect.protocol`), stay errors of the call. The notes in the detail, joined with `; `:

| Note | When | Health |
|---|---|---|
| the connection is not encrypted (http); credentials travel in clear text | `http://` URL | Unchanged |
| certificate checks are off (tls = insecure); use this in a lab only | `insecure` over `https` | Degraded |
| the server certificate is pinned by its fingerprint; a renewed certificate needs the new fingerprint | `fingerprint` | Unchanged |
| the server certificate is checked against the pinned certificate authority | `ca` | Unchanged |
| connecting to `<address>` for the host of the URL | `connect_address` is set | Unchanged |
| the token cannot see any guest (VM.Audit is missing); give the token the role PVEAuditor on / | No `VM.Audit` on any path | Degraded |
| node addresses are not read (Sys.Audit is missing) | No `Sys.Audit` | Unchanged |
| guest agent addresses are not read (VM.GuestAgent.Audit is missing) | `guest_agent` is on and the privilege is missing. The text names `VM.Monitor` instead when the release is older than 9 | Unchanged |
| SDN vnets are not read (SDN.Audit is missing) | No `SDN.Audit` | Unchanged |
| the token's privileges could not be read | `/access/permissions` failed | Unchanged |

The host checks every 15 minutes and on request (`POST /api/v1/connectors/{id}/check`).

### 3.5 What the plugin does not read

- **Nothing is written.** There is no POST, PUT or DELETE request, and no task is started. The only request that touches a guest is the read of its network interfaces.
- **No guest agent command other than `network-get-interfaces`.** The plugin runs nothing inside a guest and reads no file of a guest.
- **Not read:** disks and storage, snapshots, backups, the firewall rules, high availability, Ceph, users, groups and other tokens, and the contents of the SDN beyond the vnets and zones.
- **Guest names only.** The name of a guest is the only free text the plugin keeps. Descriptions and notes are not reported. The API returns the whole configuration of a guest, as it does to every client, but the plugin uses only the `netN`, `ipconfigN`, `agent` and `ostype` entries and keeps nothing of the rest.

### 3.6 Paging, errors and load

**Paging.** A cluster is read in pages of up to `page_size` guests, in the order of the guest ids. Every page reads `/cluster/resources` again and continues after the last guest id of the page before, so the plugin keeps no state between calls. The first page also holds the nodes and reads their addresses. The host follows the pages (at most 1,000), gives each page its own timeout (`call_timeout_secs`), joins them, and hands over the complete inventory once. If any page fails, the poll fails and nothing is handed over.

**Load.** A page reads `/cluster/resources` and the two SDN lists once, and then one configuration request per guest and one more request per running guest (the guest agent for a VM, the interfaces for a container), four guests at a time. The first page also reads the version, the cluster status and the network configuration of each node. A cluster of 200 guests costs a few hundred requests per poll. The plugin does not retry within a call; the next poll is the retry. A guest agent that does not answer holds up its slot for 8 seconds.

**Answers.**

| Answer | Result |
|---|---|
| 401 | `connect.unauthorized` |
| 403 | `connect.forbidden` |
| 404 | `connect.not_found` |
| 429 | `connect.rate_limited`, 60 seconds |
| 5xx, and the Proxmox VE codes 590 and above (a node that does not answer) | `connect.unreachable` |
| Another status, a redirect, an answer that is not JSON of the expected shape | `connect.protocol` |

The answers about one guest are handled one by one:

| Answer about a guest | Result |
|---|---|
| Its configuration is gone (404) | The guest is left out: it disappeared between the two requests |
| Its configuration is refused (403) | The guest is reported without MAC and IP addresses, and a warning in the log counts such guests |
| Its configuration fails on the server (5xx) | The poll fails (`connect.unreachable`). A guest without addresses would look like a guest that lost them |
| The guest agent is refused (403) | The VM is reported without live addresses, and a warning in the log counts them |
| The guest agent does not answer, is not running or not installed, or an interface read of a container fails | No live addresses this time, and no error. The static addresses are used |
| 401 anywhere | `connect.unauthorized` |

The agent is asked only for a VM whose configuration enables it (the option `agent` is `1` or `enabled=1`).

### 3.7 Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Only the nodes appear, no guests. Health degraded: "the token cannot see any guest (VM.Audit is missing)". Proxmox VE lists only what the token may see and does not answer with an error, so the poll is a complete inventory without guests and the facts of the guests expire | The token has no rights of its own. With privilege separation both the token and its user need the role | Grant `PVEAuditor` on `/` with Propagate to the token and to the user (section 3.2) |
| `connect.unauthorized` | The token ID or the secret is wrong, the token was deleted or expired, or its user is disabled | Check `token_id` (`user@realm!name`) and the secret. The secret is shown once: create a new token and replace the value of the secret |
| `connect.forbidden` | Proxmox VE answered 403 to a request that the plugin cannot do without | Grant the role (section 3.2) |
| Running VMs have no IP addresses | The QEMU guest agent is not installed or not running in the VM. Or it is not enabled in the VM options (Options, QEMU Guest Agent), and the plugin does not ask a VM without the option; the change takes effect after a full stop and start of the VM. Or the privilege is missing (note in the health detail, warning in the log). Or `guest_agent` is off | Install and enable the agent, grant the privilege (section 3.2). Only addresses on the VM's own configured MAC addresses count |
| A container has no IP address | It is stopped and its `ip` is `dhcp`, `auto` or `manual`, which are not addresses | Start it, or give it a static address |
| A guest has a name and no MAC address | Its node is not online, or the token may not read its configuration (a warning in the log) | Check the node. Grant `VM.Audit` on the guest |
| A stopped guest is missing | `include_stopped` is off | Turn it on |
| A template is missing | `include_templates` is off | Turn it on |
| A guest or a node is missing | The filters `nodes` or `pools` exclude it, or the token cannot see it | Check the filters and the grant |
| A node has no addresses | `Sys.Audit` is missing (note in the health detail) | Grant it |
| `TLS: the server certificate does not name the host of the URL` | The URL holds an IP address or a name that the node certificate does not carry | Section 2.4 |
| `connect.unreachable` in a poll while the health check is healthy | A request about a guest got a server error, or a node of the cluster does not answer | Look for the failing node or guest in the Proxmox VE logs. The next poll tries again |
| `connect.timeout` | A page took longer than `call_timeout_secs`, for example with many VMs whose agents do not answer | Lower `page_size`, raise `call_timeout_secs`, or turn `guest_agent` off |
| The same machine appears from another source too | A UniFi client, a probe sighting or a Home Assistant device with the same MAC address. That is expected: every source keeps its own fact, the observation view of the MAC address shows them side by side, the reconciler joins them by MAC address, and the map shows one node | Nothing to fix (section 5) |

## 4. Home Assistant

The plugin `hass` reads the device registry of a Home Assistant instance through its REST and WebSocket APIs with a long-lived access token (CONN-04). The registry knows the MAC address, manufacturer and model of IoT devices that a port scan cannot identify; the plugin adds the IP addresses that the entities of a device show. It never calls a service and never writes anything.

### 4.1 What the plugin reads and how it maps

| Request | When | Used for |
|---|---|---|
| `GET /api/` | Health check | Reachability and the token |
| `GET /api/config` | Health check | The version |
| WebSocket `/api/websocket`, authenticated with the token | Health check, and every page of a poll | The four commands below |
| `config/device_registry/list` | Health check, and every page of a poll | The devices (required) |
| `config/entity_registry/list` | Every page | The entities of each device (required) |
| `config/area_registry/list` | Every page | The names of areas; without them the tag carries the area identifier |
| `config_entries/get` | Health check, and every page | The integration of each device. Home Assistant answers it for administrators; a refusal is not an error (section 4.2) |
| `GET /api/states` | Every page, when `entity_addresses` or `device_trackers` is on | The state and attributes of entities |

The token travels as a bearer token in the `Authorization` header and in the `auth` message of the WebSocket, never in a URL. A request times out after 20 seconds, the WebSocket handshake after 20, an answer on the WebSocket after 30. The registry of a large home is several MiB; an answer is accepted up to 64 MiB.

The answers become two kinds of hosts:

| Host | `external_id` | Name | MAC addresses | IP addresses | Platform | Tags |
|---|---|---|---|---|---|---|
| Device of the registry | `device/<registry id>` | The name the user gave the device, else its name | The `mac` connections of the device, and the `mac` and `mac_address` attributes of its entities | The IP addresses its entities show (below) | The model, else the model identifier, else the integration | `integration:<domain>`, `area:<area>`, `status:disabled` |
| Device tracker entity without a device | `entity/<entity id>` | `friendly_name`, else `host_name`, else `hostname` | The `mac` and `mac_address` attributes | The state and the `ip`, `ip_address` and `host` attributes | None | `integration:<platform>`, `domain:device_tracker` |

**Addresses of a device.** An address belongs to a device when one of its enabled entities shows it as its state (a sensor of the kind "IP address") or in the attribute `ip`, `ip_address` or `host`. Loopback, unspecified, multicast and link-local addresses and the IPv4 broadcast address are left out. A globally routable IPv4 address is left out too, because it is usually the internet address of a router; the setting `public_ipv4` brings it back. IPv6 addresses are reported as they are, except link-local ones. With `entity_addresses` off the plugin reads no entity state for devices: a device then has the MAC addresses of its connections and no IP address.

**Vendor facts.** The manufacturer of a device becomes a vendor fact of each of its MAC addresses. The host records them as `vendor` facts, so the vendor shows in the observations and on the map. Trackers without a device carry no vendor.

**Integration.** The integration of a device is the domain of its primary config entry, else of its first. Without the right to read config entries the integration comes from the platform of the device's entities (section 4.2). A device with no entity then has no integration, and the tag is missing.

An example of a device (documentation values):

| Field | Value |
|---|---|
| `external_id` | `device/<registry id>` |
| Name, platform | `Desk plug`, `Plug S` |
| MAC address | `00:00:5e:00:53:21` |
| IP address | `192.0.2.21` |
| Tags | `integration:shelly`, `area:Office` |
| Vendor fact | `00:00:5e:00:53:21` is `Example Devices` |

**What is left out, and why.**

- Devices and trackers without a MAC address and without an IP address. Radio devices (Zigbee, Z-Wave, Bluetooth) behind a bridge, services and helpers have no address of their own.
- Service entries of the registry (`entry_type` is `service`), and disabled devices, unless `include_disabled` is on; they then carry the tag `status:disabled`. Disabled entities contribute nothing.
- The Bluetooth and Zigbee identifiers that Home Assistant stores as connections of other types. They are not MAC addresses of a network interface, and only `mac` connections are read.
- The address of a tracker that is `not_home`. It is stale. The MAC address of that tracker is still reported.
- Public IPv4 addresses, unless `public_ipv4` is on.
- The relation `via_device` (a device behind a bridge or a hub). It does not mean that the device runs on the other one in Tenko's sense, so no host has a parent.
- A tracker that belongs to a device is not a host of its own: its address is read as part of the device.

**Paging.** A poll reports up to 500 hosts per page, in the order of the identifiers. Every page reads the registries and the states again, so a home with more than 500 hosts does its reads once per page. Each page has the call timeout of the instance, and the host joins the pages into one inventory. A poll that fails on any page hands over nothing.

### 4.2 The token with least privilege

Home Assistant has no read-only user in its interface, so use a user of its own that is not an administrator:

1. In Settings, People, Add person: give the person a name, turn on "Allow person to login", set a user name and a password, and leave "Administrator" off.
2. Log in as that user. Open its Profile, the Security tab, Long-lived access tokens, Create token. Give it a name such as `tenko-inventory` and copy the token at once; Home Assistant shows it once.
3. Store the token as an operator secret (section 1.1) and refer to it as the `access_token` of the instance.

A non-administrator can read the entity states and the device, entity and area registries, which is everything the plugin needs, but Home Assistant refuses it the config entries (`config_entries/get`). The health check says so in a note, and the plugin works without them: the integration of a device then comes from the platform of its entities. Should a release of Home Assistant refuse a non-administrator the device registry as well, the health check reports it as degraded (section 4.6) and the token of an administrator is needed.

An administrator's token works too, but it grants far more than the plugin needs. A non-administrator cannot change the configuration of Home Assistant, but it can still call services (switch a light, run a script), so the token of either user is sensitive: keep it in the vault and revoke it under Profile, Security when it is no longer needed. The plugin calls no service. A long-lived access token is valid for ten years unless it is revoked.

### 4.3 Settings

The settings schema is part of the manifest, and the web UI builds the form from it. Unknown settings are refused.

| Setting | Type | Default | Meaning |
|---|---|---|---|
| `url` | String (a URI) | Required | The base URL of Home Assistant, with the port: `http://homeassistant.example.net:8123`. Without `/api`. A path in the URL is kept, for an instance behind a path on a proxy |
| `entity_addresses` | Boolean | `true` | Read IP and MAC addresses that entities show as their state or in the attributes `ip`, `ip_address`, `host`, `mac` and `mac_address` |
| `public_ipv4` | Boolean | `false` | Also report globally routable IPv4 addresses that entities show; usually the internet address of a router |
| `include_disabled` | Boolean | `false` | Report disabled devices |
| `device_trackers` | Boolean | `true` | Report device tracker entities that belong to no device as hosts of their own |
| `integrations` | Array of strings, up to 64 | Empty | Only devices of these integrations (domains such as `esphome` or `shelly`: lower-case letters, digits and `_`, up to 64 characters). All when empty. A device whose integration is unknown is left out when this list is set |
| `exclude_integrations` | Array of strings, up to 64 | Empty | Never devices of these integrations, for example one that duplicates another connector |
| `tls` | `system`, `ca`, `fingerprint` or `insecure` | `system` | How the certificate is checked (section 2) |
| `tls_fingerprint` | String | None | The pinned SHA-256 fingerprint, for `fingerprint` |
| `tls_ca` | String (PEM, up to 65,536 characters) | None | The pinned certificate authority, for `ca` |
| `connect_address` | String, up to 64 characters | None | An IP address to connect to instead of looking up the host of the URL |

`/api/states` is read when `entity_addresses` or `device_trackers` is on. With both off, the plugin reads the registries only.

**Secret.** The manifest declares one purpose, `access_token`, and requires it.

**Network targets.** The host of `url` and the address in `connect_address`, both on port 8123.

### 4.4 Health check

`Check` reads `GET /api/` and `GET /api/config` (the version, reported as `Home Assistant <version>`), opens the WebSocket, and reads the device registry and the config entries once. It reports:

- **Healthy** when all of that works, or when only the config entries are not readable. The latency is that of the `GET /api/` request.
- **Degraded** when the WebSocket is not usable, when the device registry cannot be read, or when the instance is `insecure` over `https`. The host also reports degraded, with the detail `message (code)`, for `connect.unauthorized`, `connect.forbidden`, `connect.rate_limited` and `connect.invalid_settings`.
- **Unreachable** when no answer arrives or the server answers with a server error. A TLS failure names its cause and the fingerprint that the server presents (section 2.4).

The notes in the detail:

| Note | When | Health |
|---|---|---|
| the connection is not encrypted (http); credentials travel in clear text | `http://` URL | Unchanged |
| certificate checks are off (tls = insecure); use this in a lab only | `insecure` over `https` | Degraded |
| the server certificate is pinned by its fingerprint; a renewed certificate needs the new fingerprint | `fingerprint` | Unchanged |
| the server certificate is checked against the pinned certificate authority | `ca` | Unchanged |
| connecting to `<address>` for the host of the URL | `connect_address` is set | Unchanged |
| the device registry is not readable (`<code>`) | Home Assistant answered the command with an error | Degraded |
| the device registry could not be read (`<connect code>`) | The command got no answer | Degraded |
| the WebSocket API is not usable (`<connect code>`) | The WebSocket did not open or authenticate | Degraded |
| config entries are not readable (not an administrator); integrations come from the entities | A non-administrator token | Unchanged |

The host checks every 15 minutes and on request (`POST /api/v1/connectors/{id}/check`).

### 4.5 What the plugin does not read

- **Nothing is called or written.** The plugin calls no service, fires no event, and changes no entity, automation, script or scene. The WebSocket carries the four registry commands of section 4.1 and nothing else.
- **Not read:** the history and the logbook, automations, scripts, scenes, the list of services, dashboards, add-ons, backups, users and the energy dashboard.
- **Entity data.** The states of all entities are fetched, because the REST API offers no narrower read, but the plugin looks only at the entities of devices and at trackers, and in them only at the state and at the attributes `ip`, `ip_address`, `host`, `mac` and `mac_address`, plus `friendly_name`, `host_name` and `hostname` for the name of a tracker. Nothing else is kept.

### 4.6 Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| Health degraded: "the credentials were rejected (connect.unauthorized)"; or a poll fails with `connect.unauthorized` | Home Assistant answered 401 or `auth_invalid`: the token is wrong, was revoked, belongs to a deleted or deactivated user, or comes from another Home Assistant | Create a new token (section 4.2) and replace the value of the secret |
| `connect.invalid_settings`: "the URL does not lead to the Home Assistant API (404)" | The URL ends in `/api`, or points at another service or at a proxy path that does not lead to Home Assistant | Use the base URL only: `http://homeassistant.example.net:8123` |
| Health degraded: "the WebSocket API is not usable (connect.protocol)"; a poll fails with `connect.protocol`: "the WebSocket API did not open: WebSocket handshake failed: expected status 101, got ..." | A reverse proxy in front of Home Assistant does not pass WebSocket upgrades on `/api/websocket` | Let the proxy pass the `Upgrade` and `Connection` headers for `/api/websocket`, with a long timeout for the tunnel |
| `connect.protocol`: "the server answered with the status 400" | Home Assistant rejects requests from a reverse proxy that it does not trust | Add the proxy to the trusted proxies of the `http` integration of Home Assistant |
| `connect.protocol`: "the server answered with the status 301" (or 302, 307, 308) | The address redirects, for example `http` to `https`, or to another host name. The plugin follows no redirects | Put the final address into `url` |
| Health degraded: "the device registry is not readable (unauthorized)"; a poll fails with `connect.forbidden` | Home Assistant refused the registry command to this user | Use another user that may read the registries; an administrator as a last resort |
| Note: "config entries are not readable (not an administrator)" | A non-administrator token. This is expected (section 4.2) | Nothing. The integration comes from the entities |
| A device is missing | It has no MAC address and no IP address in the registry or on its entities, or it is a service entry, or it is disabled (`include_disabled`), or `integrations` or `exclude_integrations` leave it out, or `entity_addresses` is off and it has no `mac` connection, or its address is a public IPv4 address (`public_ipv4`) | Check the device in Home Assistant under its entities. A device behind a bridge without a MAC or IP address of its own cannot be reported |
| A device has a MAC address and no IP address | No entity of it shows an address, or its tracker is `not_home` | Nothing to fix; the address appears when an entity shows it |
| A router has no internet address | Its entity shows a globally routable IPv4 address, which is left out | Turn `public_ipv4` on if you want it |
| The same client appears from the UniFi connector and from Home Assistant | The `unifi` integration of Home Assistant makes device trackers of the UniFi clients. Tenko joins both by MAC address, so it is no duplicate in IPAM, but it is noise in the observations | Put `unifi` into `exclude_integrations`. Integrations that watch the network the same way (a router or `nmap_tracker`) can be excluded likewise |
| `connect.timeout` | A very large installation answers slowly | Raise `call_timeout_secs` |
| A device has the platform of its integration instead of its model | The registry has no model for it | Nothing to fix |

## 5. What the owner sees after the first run

The first poll of an enabled instance runs five seconds after its plugin starts, and the reconciler runs about two seconds after an ingest that wrote something ([reconciliation.md](reconciliation.md#31-when-it-runs)). What follows depends on what IPAM holds already.

**The facts.** The observations list one `host` fact per Proxmox VE node and guest and per Home Assistant device or tracker, under the source `inventory:<connector id>`. `GET /api/v1/observations?source=<connector id>` lists them, and the computed view of a MAC address or an IP address shows them next to the facts of other sources, which are never merged ([reconciliation.md](reconciliation.md#25-the-computed-view)). Home Assistant adds a `vendor` fact per MAC address for which a device names a manufacturer.

**A fresh installation, without networks.** Every address that the inventory names lies outside every known network. The first proposals are therefore "outside known networks" (`ipam.reconcile.outside_prefixes`, severity `warning`): one per /24 (IPv4) or /64 (IPv6) the addresses fall in, longer when that would overlap a prefix that exists ([reconciliation.md](reconciliation.md#49-outside-known-networks)). The inventory facts name no VRF, so the placement rules of [reconciliation.md](reconciliation.md#33-where-an-observed-address-belongs) decide where an address belongs. An address in a network that does not exist yet produces no proposal for a host. Approving a network proposal creates the prefix, and the next run proposes the hosts.

**Once the networks exist.** Each MAC address that no interface in IPAM carries gets a discovered-host proposal (`ipam.reconcile.discovered_mac`), per MAC address. It suggests a host in the mode `dynamic` with the tag `discovered`, an interface carrying the MAC address, and the addresses seen with that MAC address that lie in known networks. An address without a MAC address, such as that of a Proxmox VE node or of a Home Assistant device that shows only an IP address, gets a proposal of its own (`ipam.reconcile.discovered_address`). A guest that has MAC addresses and no address at all, such as a stopped VM without cloud-init addresses, gets a proposal for a host without addresses at once ([reconciliation.md](reconciliation.md#45-discovered-host)). A suggested host takes the first usable name any source gives, in lower case with unusual characters replaced by `-`: a guest called `web01` gives `web01`, and a Home Assistant device called `Desk plug` gives `desk-plug` ([reconciliation.md](reconciliation.md#43-subject-keys-fingerprint-and-rejection-memory)).

A host that reports several MAC addresses, such as a VM with two network interfaces, does not say which address belongs to which. The reconciler then treats each MAC address and each address on its own and proposes accordingly, until another fact, such as a probe's sighting, pairs them.

**Hosts IPAM knows already.** When an interface in IPAM carries the same MAC address, for example after an import, the proposals are not for a new host but for its addresses: add the observed address to the interface (`address_unrecorded`), or renumber the intended one (`address_mismatch`). Intent wins for `static` and `reserved` hosts: such a proposal is a warning that only a person can apply. A contradiction between sources is a conflict, which no policy adopts ([reconciliation.md](reconciliation.md#46-address-unrecorded-and-address-mismatch), [4.8](reconciliation.md#48-conflicts)).

**Adoption policies.** The proposals wait for a person unless a prefix carries an adoption policy. A policy with the mode `adopt_hosts` applies discovered-host proposals that carry a MAC address and an address in that prefix; the constraints `only_dhcp_pools` and `min_sightings` hold as for every source. A proposal without a prefix, such as a discovered host that has only a MAC address, is never adopted ([reconciliation.md](reconciliation.md#6-adoption-policies)).

**Vendors.** The manufacturers from Home Assistant feed the vendor shown in the observations and on the topology map. The constraint `vendors` of adoption policies does not read them yet: only its OUI entries (`00:00:5e`) match today, and a policy whose entries are vendor names adopts nothing. Proxmox VE reports no vendor.

**When a host goes away.** A guest or device that disappears from the source expires at the next complete poll. An address that was seen and then not seen for seven days may be proposed as orphaned. The reconciler does not yet know which networks a source covers, so a disabled or broken connector ages the addresses that only it saw into orphan proposals too ([reconciliation.md](reconciliation.md#47-orphaned-intent)).

**On the map.** Proxmox VE nodes become hypervisors, with their VMs and containers below them (section 3.1). Home Assistant devices appear as hosts with their vendor.

## 6. Live smoke tests for developers

Each crate has a smoke test against a real system. It is read-only, and CI never runs it. It lives in `tests/live.rs`, and it does nothing unless the variable `TENKO_LIVE_PROXMOX=1` (or `TENKO_LIVE_HASS=1`) is set:

```console
TENKO_LIVE_PROXMOX=1 cargo nextest run -p tenko-connect-proxmox -E 'binary(live)' --no-capture
TENKO_LIVE_HASS=1 cargo nextest run -p tenko-connect-hass -E 'binary(live)' --no-capture
```

In PowerShell, set the variable first: `$env:TENKO_LIVE_PROXMOX = '1'`. `--no-capture` is needed because the tests write to standard error. Without the variable the test is part of an ordinary run, prints `skipped: set TENKO_LIVE_PROXMOX=1 ...` and passes.

**The recording of a real node.** The Proxmox VE crate also has `tests/fixtures/recorded.json`: every route the plugin reads from a real Proxmox VE 9.1 node (the node, 9 QEMU and 5 LXC guests, 7 guest agent answers, 32 routes), recorded on 2026-10-16 by the recorder in `tests/live.rs` through the plugin's own client and anonymised by `tenko_connect::sdk::anonymise` before anything was written. MAC addresses became documentation addresses wherever they appear, the property strings of a guest configuration (`net0`, `ipconfig0`) were split so that their MAC address, bridge, VLAN tag and addresses stay readable as placeholders, the node name in the paths is the placeholder of the answers, private networks that did not fit the documentation and benchmarking ranges at their real width were narrowed to the blocks seen in them, names, tags, descriptions and storage names became placeholders, and only the roots of `/access/permissions` were kept; the README next to it says exactly what. The test `the_recorded_node_reads_like_the_live_one` reads it through the mock and asserts the counts the live smoke printed the same day (15 hosts, 17 MAC addresses, 17 IPv4 and 8 IPv6 addresses, 1 VLAN tag, no pool, no vnet). The real answers matched the documented shapes in every member the plugin reads, so the recording exposed no parse to fix; SDN, pools, cloud-init addresses and a second node stay covered by `documented.json`. Recording again takes `TENKO_LIVE_PROXMOX=1 TENKO_RECORD=1` and the test `live_record_fixture`.

**The recording of a real instance.** The Home Assistant crate also has `tests/fixtures/recorded.json`: the answers of a real instance (360 devices, 3346 entities, 2247 states), recorded on 2026-10-16 by the recorder in `tests/live.rs` through the plugin's own client and anonymised by `tenko_connect::sdk::anonymise` before anything was written. MAC addresses became documentation addresses, IPv4 addresses documentation addresses with their networks kept, registry ids counters in the same format, entity ids `<domain>.entity_n`, names, manufacturers, models and config entry titles placeholders, the attributes of a state reduced to the ones the plugin reads, credentials, pictures and coordinates dropped; the README next to it says exactly what. The test `the_recorded_instance_reads_like_the_live_one` reads it through the mock and asserts the counts the live smoke printed the same day. Recording again takes `TENKO_LIVE_HASS=1 TENKO_RECORD=1` and the test `live_record_fixture`, and a grep of the output for anything outside the documentation ranges before it is looked at. The shapes of the real answers matched the documented ones in every member the plugin reads; the recorded instance shows no IP address on any entity, so the address rules stay covered by `documented.json` and the unit tests.

The tests read their configuration from the process environment and from the `.env` file in the root of the repository, which git ignores. Only variables with the prefix `PROXMOX_` or `HASS_` are read, and the environment wins over the file.

| Variable | Plugin | Meaning |
|---|---|---|
| `PROXMOX_URL` | Proxmox VE | The base URL of the API. Required |
| `PROXMOX_TOKEN_ID` | Proxmox VE | The token ID, `user@realm!name`. Required |
| `PROXMOX_TOKEN_SECRET` | Proxmox VE | The token secret. Required |
| `HASS_URL` | Home Assistant | The base URL. Required |
| `HASS_TOKEN` | Home Assistant | A long-lived access token. Required. A value that is empty or contains `<` counts as a placeholder, and the test skips |
| `PROXMOX_TLS`, `HASS_TLS` | Both | The mode: `system`, `ca`, `fingerprint` or `insecure` |
| `PROXMOX_TLS_FINGERPRINT`, `HASS_TLS_FINGERPRINT` | Both | The pinned fingerprint |
| `PROXMOX_TLS_CA`, `HASS_TLS_CA` | Both | The path of a PEM file with the certificate authority (not the PEM text) |
| `PROXMOX_CONNECT_ADDRESS`, `HASS_CONNECT_ADDRESS` | Both | The address to connect to |

With `TENKO_LIVE_PROXMOX=1` set and a required variable missing, the Proxmox VE test fails. Do not commit the `.env` file. The secrets of the system under test stay in it and in the environment, never in the repository.

A test runs `Check`, and then `Poll` page by page, the way the host does. It prints shape and counts only, never a name, an address or a value from the system. For Proxmox VE: the health, whether the release is 9.x, the latency, which notes the detail holds, the number of hosts by platform and status, and how many have MAC addresses, IPv4 and IPv6 addresses, an OS, a parent, a pool, a VLAN tag and a vnet. For Home Assistant: the health, the number of hosts by kind (device or tracker), the vendor facts and the integrations, and how many hosts have MAC addresses, IP addresses, a platform and an area.

The other tests of the two crates need no real system: unit tests next to the code, tests against a mock API on a loopback port that serves fixtures of documentation data (`tests/fixtures/documented.json`; the Home Assistant mock also speaks the WebSocket protocol), for each also the anonymised recording of a real system (`tests/fixtures/recorded.json`, below), and the conformance suite of the SDK run against the executables `tenko-plugin-proxmox` and `tenko-plugin-hass` ([plugins.md](plugins.md#11-the-conformance-suite)). `tenko plugin test --bundled proxmox` and `tenko plugin test --bundled hass` run the suite by hand, with `--settings <file>` and `--secret <purpose>=<VARIABLE>` to point it at a real system. The inventory mapping of both plugins and the WebSocket frame decoder of the Home Assistant plugin have fuzz targets (`connect_proxmox_inventory`, `connect_hass_inventory`, `connect_hass_ws_frame`), since everything the remote system sends passes through them (CONTRIBUTING, rule 3).
