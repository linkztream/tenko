# ADR 0004: Single binary with roles

- Status: Accepted
- Date: 2026-10-09

## Context

Tenko DDI must cover very different deployment shapes:

- **Home lab:** one box runs everything, with an idle target below 100 MB RSS (OPS-15).
- **Enterprise:** 3 to 5 controllers, N DNS nodes behind anycast, DHCP failover pairs per site, and one discovery probe per network segment.

Discovery has a hard topological constraint: ARP and ND do not cross routers, so a probe must sit in each segment, and the DMZ probe is its own trust zone (SCAN-01). Deployment targets are Windows services, Linux systemd units, Docker and LXC. DNS and DHCP must keep serving when the control plane is unavailable (OPS-02).

## Decision

1. Tenko ships as **one statically linked binary**, `tenko`.
2. The binary runs **any combination of four roles** on a node:

   | Role | Responsibility |
   |---|---|
   | `controller` | API, UI, Raft member, authentication, vault, IPAM logic, scheduler |
   | `dns` | Authoritative and forwarder/cache engines (recursion in Phase 5), local zone copy |
   | `dhcp` | DHCPv4 and DHCPv6 server, failover partner, local lease WAL |
   | `probe` | Passive and active discovery and SNMP polling within its segment |

3. **The data plane is independent of the control plane.** `dns` and `dhcp` serve from a durable local copy of zones, leases and configuration. No request path (DNS query, DHCP DORA) calls a controller or a database. Controllers are needed only to change configuration.
4. **Nodes communicate over gRPC with mutual TLS.** An internal CA issues node certificates; nodes join with enrollment tokens. The same mechanism applies to Docker, LXC and native installs (OPS-04). The node protocol carries version negotiation to allow rolling upgrades (OPS-08).

## Consequences

- One artifact to build, sign, distribute and upgrade; no version skew between components on a node.
- The home-lab profile is a single process with all four roles; enterprise deployments place roles on separate nodes.
- A controller outage stops configuration changes but not DNS or DHCP service. This is verified in Phase 1 by killing a controller in a 3-node cluster.
- In an all-in-one process, a crash affects every role on that node. Deployments that need fault isolation run roles on separate nodes.
- The binary contains code for all roles even where only one is enabled; disabled roles open no sockets and start no tasks.
- The probe role needs raw-socket privileges for active scanning (SCAN-04). A probe in the DMZ runs only the probe role, as a separate trust zone.
- mTLS between nodes is structural and not a security-profile toggle.

## Alternatives considered

- **Separate binaries per service.** Clearer process isolation, but more artifacts, more packaging and version-skew risk, and no benefit for the home-lab profile.
- **Containerized microservices.** Operational overhead that a home user will not accept, and Docker bridge networking breaks DHCP broadcast and DNS source addresses anyway (OPS-14).
- **Data plane reading from a central database.** Simpler consistency, but it puts the control plane in the DHCP and DNS request path, which conflicts with OPS-02.
