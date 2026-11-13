# Tenko DDI

Tenko (天狐) is the celestial fox of Japanese folklore, the oldest and wisest of the kitsune, said to watch over everything in its domain.

Tenko DDI is a DNS, DHCP and IPAM stack. Its goal is to replace Active
Directory-integrated Windows DNS and DHCP, and to scale from a single home-lab node to a
multi-site enterprise deployment. It ships as one Rust binary that runs any combination of
four roles: `controller` (API, UI, replicated store, job engine), `dns`, `dhcp`, and `probe`
(network discovery). The web UI is a SolidJS application embedded in the binary.

New here? [`docs/QUICKSTART.md`](docs/QUICKSTART.md) goes from nothing to a running node with a first network in a few minutes.

**Status:** pre-alpha. The latest release is on the [releases page](https://github.com/linkztream/tenko/releases);
[`docs/ROADMAP.md`](docs/ROADMAP.md) says where the work stands and what is free to take.

What a node does today, each part with its automated tests and, for DNS, DHCP and the
cluster, a lab in containers:

- **IPAM:** VRFs, prefixes, addresses, hosts, VLANs and sites; spreadsheet and CSV import,
  CSV export; the reconciliation of what IPAM intends with the leases, DNS records, scans
  and inventory it observes; device moves between networks, with the VLAN step through
  UniFi; the topology map.
- **DNS:** authoritative zones with views, dynamic updates with TSIG and, for Active
  Directory clients, secure updates with GSS-TSIG over Tenko's own Kerberos (tested against
  a Samba domain controller; the run against Windows is open); zone transfers in and out;
  DNSSEC signing; a forwarder and cache with response policy zones and block lists; DNS
  over TLS and over HTTPS; a recursive resolver with DNSSEC validation.
- **DHCP:** DHCPv4 and DHCPv6 with prefix delegation, reservations from IPAM, DDNS,
  classes and policies, PXE, conflict detection, and the export to Kea.
- **Discovery:** probes that scan their segment (neighbor tables, ICMP, TCP, mDNS, SNMPv3
  and more), and connector plugins for UniFi, Proxmox VE and Home Assistant.
- **Platform:** the API, the web UI in English and Swedish, and the `tenko` command-line
  client; security profiles, passkeys and TOTP, roles with scoped grants, a vault for
  secrets, an audit log with export; backup and restore; a cluster of controllers; updates
  of a single node from the web UI (a container updates by its image); metrics and traces.
  Installers for Linux (also as a Proxmox VE container) and Windows, and a container image.

What does not exist yet (each is planned in the roadmap):

- `dns` and `dhcp` nodes that keep serving without a controller, and DHCP failover pairs.
- Updates of a cluster from the web UI, one member at a time.
- Sign-in through OpenID Connect, LDAP or Kerberos: the API routes and commands exist and
  answer that they are not built yet.
- The takeover of Windows DHCP scopes and the flip of an Active Directory zone: the
  export script that mirrors a Windows DHCP server exists, the server side does not.
- Migration from BIND, Kea, dnsmasq and other sources; notifications; releases signed
  with a key that a node checks.

The live runs of the Phase 3 exit in the reference network are still open.

> **Pre-release.** Tenko DDI is under development; every release so far is a pre-release,
> and the data-directory format, the configuration and the API may still change between
> versions (an update migrates the data directory where it can, and says when it cannot). The binaries and installers that the release workflow
> produces are unsigned until a signing certificate exists
> ([`deploy/windows/README.md`](deploy/windows/README.md) says what that means when you
> install). Running it in production is at your own risk; please report what breaks.

## Documentation

- [`docs/README.md`](docs/README.md): the index of every document, the operator's pages
  per area included
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): system architecture
- [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md): requirements
- [`docs/ROADMAP.md`](docs/ROADMAP.md): phases and milestones
- [`docs/adr/`](docs/adr/README.md): architecture decision records
- [`CHANGELOG.md`](CHANGELOG.md): what each release changed, and what is merged for the next
- [`SECURITY.md`](SECURITY.md): how to report a vulnerability privately, and what to expect

## Repository layout

| Path       | Contents                                                       |
|------------|----------------------------------------------------------------|
| `crates/`  | Rust workspace crates, one per subsystem                       |
| `ui/`      | SolidJS + TypeScript web UI, built with Vite into `ui/dist`    |
| `fuzz/`    | `cargo-fuzz` targets, one per parser of network input          |
| `bench/`   | Spikes and benchmarks, excluded from the workspace             |
| `deploy/`  | Installers, Dockerfile, Compose labs, systemd and Windows service templates |
| `docs/`    | Architecture, requirements, roadmap, ADRs, the operator's pages |
| `scripts/` | The repository's checks and release tools                      |

## Development

Requirements: the stable Rust toolchain (pinned by `rust-toolchain.toml`) and Node.js 22.
The commands to build, test and lint, and to run the server from source with a subset of
roles, are in [`CONTRIBUTING.md`](CONTRIBUTING.md#commands).

The same `tenko` binary is the command-line client of a running controller's public API;
`tenko --help` lists its commands.

## License

Tenko DDI is source-available under the [Business Source License 1.1](LICENSE.md). The
source is public, you can read it, build it, change it and run it on your own networks
for free, and every version becomes free software under the Change License named in
`LICENSE.md` four years after its release. Until then, turning Tenko into a product or a
hosted service that you provide to others needs a commercial agreement; the next section
explains where the line runs. Contributions are welcome under the
[Contributor License Agreement](CLA.md); see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Commercial Use & Royalties

Tenko is free to use on your own networks, whoever you are and however big they are.
The license draws one line: you may use and change Tenko for yourself, but you may not
turn it into a product or a service that you sell or provide to others without an
agreement with the licensor. Here is what that means in practice.

### Free, no agreement needed

- **A home lab.** Run it on anything, change whatever you like, share your changes.
  Nothing to sign, nothing to pay.
- **A company's own network.** Any number of nodes, sites, users and devices, for the
  company and its subsidiaries. You may modify Tenko and you are not required to publish
  your modifications. Running it in production for your own network is exactly what the
  license is for.
- **Schools, universities, non-profits and public bodies.** The same as a company: your
  own network, your own members, free.
- **A consultant or integrator deploying Tenko for a customer.** Install it, configure it,
  migrate the customer's zones and scopes, train their staff, and charge for your time.
  The customer's use is internal use. Managing it for them afterwards, even remotely, is
  fine too, as long as Tenko runs on the customer's own infrastructure and serves the
  customer's own network.
- **Development, testing and evaluation.** Anyone may build, test and evaluate Tenko,
  including a vendor who is considering one of the arrangements in the next list.
- **Redistributing Tenko itself.** Packaging it for a distribution, publishing a
  container image, or sharing a modified version is allowed, under the same license and
  with the license file included; the people who receive it get the same rights and the
  same limits as you.

### Needs a royalty agreement

- **A hosting provider or managed service provider offering Tenko as a service.** If
  Tenko runs on your infrastructure and serves your customers' networks, whether as a
  multi-tenant platform, as a dedicated instance per customer, or under a different
  name, that is a hosted service to third parties.
- **A vendor bundling Tenko in an appliance or a product.** A firewall, router, network
  controller, NAC system or software suite that ships with Tenko inside, whether or not
  the price tag shows a separate line for it.
- **Reselling or sublicensing.** Selling Tenko, a rebranded fork, or access to it, for a
  fee or as a bonus to something else you sell.
- **An operator serving subscribers.** An ISP or a carrier that uses Tenko to provide
  DNS or DHCP to its paying subscribers is providing a service to third parties, even
  though the same ISP running Tenko for its own office network is not.

The test is not whether money changes hands for Tenko specifically. It is whether Tenko,
or its features, are part of what you provide to other people as a business.

### What a royalty agreement looks like

A royalty agreement is a short written agreement with the licensor, tailored to the
case. It grants the right to embed, host or resell Tenko and, where wanted, to use the
Tenko name, in exchange for a royalty: typically a share of the revenue of the product or
service that includes Tenko, or a fee per unit, per instance or per tenant. It can also
cover support, early access to releases and a say in the roadmap. Vendors who start with
a pilot and grow into a product are welcome; the agreement can start small.

Write to linkztream@gmail.com with a few lines about what you intend to build; a short
conversation is usually enough to settle the terms. If you are not sure which list your
case falls under, ask the same way, and you will get a plain answer.

### The four-year promise

Each released version of Tenko is placed under the Change License named in `LICENSE.md`
on the fourth anniversary of its release. That version then stays free software forever,
whatever happens to the project or the licensor, so nobody who builds on Tenko is left
without a way forward.
