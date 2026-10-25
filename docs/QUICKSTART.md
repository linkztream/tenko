# Quick start

From nothing to a running node with a first network on one Linux box; every other page is
one link away (section 5). The node below is 192.0.2.10 in 192.0.2.0/24, the router 192.0.2.1.

## 1. Install

1. Download the installer of the latest release on the box, as root.

   ```bash
   curl -fsSLO https://github.com/linkztream/tenko/releases/latest/download/install.sh
   ```

2. Run it and answer its questions: the security profile (Home) and the data directory (on
   SSD or NVMe); everything else keeps its default. Outside the Hardened profile the
   installer does not ask for the roles: it prepares the box for all four (section 2) and
   the node starts with all four; under Hardened it asks and prepares only the chosen ones.

   ```bash
   bash install.sh
   ```

   Unattended, everything on one box in one line (setup then happens in the browser):

   ```bash
   bash install.sh --yes --host-name tenko.home.arpa
   ```

3. Open `https://<the node's address>:8443/`, accept the internal CA's certificate once,
   and paste the setup token the installer printed.
   To serve your own certificate instead of the internal CA's (for example one that an
   ACME client renews), or to see which certificate the node serves, read
   [certificates.md](certificates.md).
4. Finish the first-run wizard: the profile, the administrator, the host name, the data
   directory, the roles with their modules, and the DNS and DHCP steps (both can be skipped
   and done in section 3).
5. Done: sign in as the administrator.

Windows: install `tenko-<version>-windows-x86_64.msi` from the release and continue at step 3
([deploy/windows/README.md](../deploy/windows/README.md#msi-installer)). Proxmox VE: `deploy/proxmox/ct/tenko.sh`
creates a container and runs the installer in it ([deploy/proxmox/README.md](../deploy/proxmox/README.md)).

## 2. The roles

- `controller`: the API, the web UI and the replicated store; every node has one to talk to.
- `dns`: the authoritative and recursive name server on port 53.
- `dhcp`: the DHCP server on UDP 67, and DHCPv6 on UDP 547.
- `probe`: the discovery scans that fill IPAM, and the DHCP conflict probe before an offer.

One box runs all four. Switch a role off or on later on the Nodes page (the section "This
controller"); each role there says whether the box is prepared for it, and for one that is
not (under Hardened) it names what is missing and the installer command that prepares it,
such as `sudo bash install.sh --prepare --roles controller,dns,probe`. `sudo bash install.sh
--check` reports the same on the box. ARP does not cross routers, so each further segment
gets its own probe later, enrolled from the Cluster page with a token
([cluster.md](cluster.md)).

## 3. Your first network

The home network domain is `home.arpa` (RFC 8375), which Tenko's resolver answers locally;
a company uses its own name, such as `corp.example.com`. Never use `.local`: mDNS owns it,
and most clients resolve it without asking any DNS server. Each step names the UI path and,
where one exists, the `tenko` command; sign in once for the commands, as root on the node
(the client finds the node's own address and CA root in `/etc/tenko/tenko.toml`; from
another machine add `--url` and `--ca-file`):

```bash
tenko login -u admin
```

1. Create the network in IPAM, and note the `id` the command prints: IPAM, Add prefix,
   network `192.0.2.0/24`.

   ```bash
   tenko prefix create 192.0.2.0/24 --role network --description "Home LAN"
   ```

2. Create the forward zone: DNS, new zone, primary, name `home.arpa`, name server
   `tenko.home.arpa`.

   ```bash
   tenko dns zone create home.arpa --ns tenko.home.arpa --mname tenko.home.arpa --rname hostmaster@home.arpa
   ```

3. Let IPAM keep the reverse zone `2.0.192.in-addr.arpa` for the prefix: the prefix's form,
   reverse zones Managed.

   ```bash
   tenko prefix update 192.0.2.0/24 --dns-reverse managed
   ```

4. Add the pool as a range of the prefix (ranges have no command): the prefix page, Add
   range, role DHCP pool, `192.0.2.100` to `192.0.2.199`.
5. Create the scope for the prefix: DHCP, New scope, the prefix `192.0.2.0/24`.

   ```bash
   tenko dhcp scope create <prefix-id>
   ```

6. Point the clients at the node: the scope's options tab, router `192.0.2.1`, DNS server
   `192.0.2.10`, domain name `home.arpa` (codes 3, 6 and 15, as hex on the command line).

   ```bash
   tenko dhcp option set scope:<prefix-id> 3=c0000201 6=c000020a 15=686f6d652e61727061
   ```

7. Switch DDNS on so every lease gets its name (no command): the scope's DDNS tab,
   enabled, forward zone `home.arpa`.
8. If the wizard's DHCP step did not do it, add the section below to `/etc/tenko/tenko.toml`
   (direct mode on the LAN interface; relay mode without `interface` when the router relays
   to the node) and restart. Outside Hardened the installer has put the drop-in that direct
   mode needs in place already; under Hardened `install.sh --prepare` does it once the
   listener is set.

   ```toml
   [dhcp]
   listen = [{ address = "192.0.2.10", mode = "direct", interface = "eth0" }]
   ```

   ```bash
   systemctl restart tenko
   ```

9. Switch scanning on for the prefix (no command): Nodes, the node, Scan configuration,
   Scanner enabled, Prefixes `192.0.2.0/24`, Active probing on.

See it work: a renewed lease shows under DHCP, Leases; its name resolves through the node;
sightings show under IPAM, Hosts, and new devices wait as proposals under IPAM, Reconcile.

```bash
tenko dhcp lease list
dig laptop.home.arpa @192.0.2.10
tenko ipam reconcile --prefix 192.0.2.0/24
```

## 4. Firewall ports

| Port | Protocol | Direction | From | To | Why |
|---|---|---|---|---|---|
| 8443 | TCP | in | administrators, a node once at enrolment | controller | the web UI and the API |
| 53 | UDP and TCP | in | clients | dns role | DNS queries |
| 853, 443 | TCP | in | clients | dns role | only with DNS over TLS or DNS over HTTPS on |
| 67 | UDP | in | clients (broadcast), the router's relay (unicast) | dhcp role | DHCP requests |
| 547 | UDP | in | clients on the link, the router's relay | dhcp role | DHCPv6 requests |
| 68 | UDP | out | dhcp role | clients | DHCP replies to clients on the link |
| 8444 | TCP | in | probes and other controllers | controller | the cluster port (mutual TLS) |
| ICMP echo | ICMP | out and back | probe | the scanned prefixes | the `icmp` method, and the conflict probe of relayed scopes |
| ARP | link layer | on the segment | probe | the scanned prefixes | the `arp` and `arp_sweep` methods, and the conflict probe on the link |
| 53 | UDP and TCP | out | dns role | the internet | the recursive resolver's queries to authority servers |
| 443 | TCP | out | controller | github.com | `releases.json` for the update check, and the installer's download |

The ports are those of `deploy/tenko.example.toml`. On Linux the installer opens the inbound
ones of the roles the box is prepared for (8443, 8444, 53, 67 and 547; every role outside
Hardened) on firewalld or ufw when one is active, and names them in its closing lines when
neither is; the Windows MSI adds rules for 8443, 53, 67 and 547 the same way.

## 5. Where to go next

- Security profiles, Home to Hardened: [SECURITY-PROFILES.md](SECURITY-PROFILES.md).
- A second probe, more controllers, enrolment and the cluster port: [cluster.md](cluster.md).
- DNS: zones, transfers, views and updates in [dns.md](dns.md); the resolver, blocking and
  DoT/DoH in [dns-resolver.md](dns-resolver.md).
- DHCP: scopes, options, classes, reservations, DDNS and the cut-over: [dhcp.md](dhcp.md).
- Scanning: the methods, schedules, rate limits and IDS: [scanning.md](scanning.md).
- Reconciliation: how leases, records and sightings become proposals: [reconciliation.md](reconciliation.md).
- Migration from Windows DNS and DHCP, BIND and Kea: [MIGRATION.md](MIGRATION.md).
- Security: reporting a vulnerability in [SECURITY.md](../SECURITY.md); roles and access in [access.md](access.md).
