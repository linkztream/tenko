# The compose DHCP lab

Four client networks behind one gateway that relays every one of them to one Tenko DDI node,
on one Docker host: the topology of E23 ([phase-3-plan.md](../../../docs/plans/phase-3-plan.md)
section 2.5) with real clients, for the weekly check of the dhcp role (WP7.6) and for trying
things by hand. It is a lab, not a deployment example: every address is a documentation
value (`192.0.2.0/24`, RFC 5737), every MAC one of RFC 7042 (`00:00:5e:00:53:xx`), and
nothing in it reaches out.

It is a Linux Docker host lab. It runs on Docker Desktop too; the maintainer's host is WSL
Ubuntu 24.04 with Docker as root. It needs Docker 28 or later with the compose plugin (and
buildx to build the images), and with the binary as the node `curl` and `python3` on the
host, which reaches the node's API on the lab network.

The gateway is a container that routes between the bridges, so the node's reply to
`giaddr`, the gateway's address on a client network, comes in on the servers bridge. Docker
28 drops a packet for a container's address that arrives from another bridge (its raw-table
rules against reaching unpublished containers from outside); the lab's networks set
`com.docker.network.bridge.gateway_mode_ipv4: nat-unprotected`, which leaves those rules out.
The lab publishes nothing, so nothing is exposed by it.

## The topology

```text
            servers 192.0.2.0/26          lan 192.0.2.64/26
   node .10 ──┐  tester .20                 ┌── client-lan (00:00:5e:00:53:45)
client-servers┤                             │
              └──── .2 ┌─────────┐ .66 ─────┘
                       │  relay  │  dhcrelay -a, IP forwarding
              ┌──── .130└─────────┘ .194 ───┐
   client-iot ┘                             └── client-guest (00:00:5e:00:53:c5)
            iot 192.0.2.128/26           guest 192.0.2.192/26
```

| Service | What | Address |
|---|---|---|
| `relay` | The gateway: ISC's `dhcrelay` (Debian's `isc-dhcp-relay` 4.4) relays all four networks to the node, the node's own network included, so that the node runs in relay mode and never sees a broadcast (plan section 2.5, risk R56). It renames its interfaces after their networks and adds option 82 with that name as the circuit-id (`-a`); it routes between the networks, so that a renewal, a unicast from the client to the node, finds its way | `.2`, `.66`, `.130`, `.194` |
| `netns` | Owns the node's network namespace: the node's address, the route to the other networks through the gateway (replies to a relay go to `giaddr`), and `net.ipv4.ip_unprivileged_port_start=0`, so that the node binds port 67 without a capability | `192.0.2.10` |
| `tenko` (profile `tenko`) | The node: the image of `deploy/Dockerfile` (the static musl binary) with `--roles controller,dhcp`, the DHCP module on, the Lab profile, `[dhcp] listen = [{ address = "192.0.2.10", mode = "relay" }]`, the API in plain HTTP on 8443. Read-only root file system, no capability, the key-encryption key as a Docker secret | in `netns` |
| `node-example` (profile `example`) | Until the binary has the dhcp role: the engine's example server (`crates/tenko-dhcp/examples/dhcp_server.rs`, built by `example.Dockerfile` with the builder of `deploy/Dockerfile` for musl) with the in-memory reference store `MemLeaseStore`. It serves one scope, `198.18.0.0/15`, selected only by option 118 or the link selection sub-option, so the clients' rows cannot run against it | in `netns` |
| `client-servers`, `client-lan`, `client-iot`, `client-guest` | One client per network with a fixed MAC: ISC's `dhclient` with `scripts/dhclient.conf` and `scripts/client-script.sh` (which puts the address on the interface and writes one line per event to `/run/lab/events`), and BusyBox's `udhcpc` | `.5`, `.69`, `.133`, `.197` before their lease |
| `tester` | Kea's `perfdhcp` (Debian's `kea-admin` 2.2) and `scripts/relay-test.py`, a relay agent written against RFC 2131 that sends option 82 with a circuit-id and, when asked, the link selection sub-option or option 118, and checks the echo; for E27 it also sends options 60, 77 and 93 as a boot client, checks the boot file and option 60 of the replies, and sends the boot server discovery to the proxy DHCP port | `192.0.2.20` |
| `bootsrv` (profile `pxe`) | The boot server of E27's PXE rows (WP8.4): TFTP (Debian's `dnsmasq` with DNS and DHCP off) and HTTP (`python3 -m http.server`) with `undionly.kpxe` and `ipxe.efi` of Debian's `ipxe`, `boot/boot.ipxe` and `boot/menu.ipxe`; it logs to `/run/lab/tftp.log` and `/run/lab/http.log` | `192.0.2.21` |
| `pxe-bios`, `pxe-uefi` (profile `pxe`) | Two machines that boot over the network on lan (WP8.4): QEMU (Debian's `qemu-system-x86`) with the iPXE ROM of its virtio card in BIOS mode (SeaBIOS), and with OVMF in UEFI mode; the container bridges its `eth0` and the machine's tap device, so the machine's broadcasts reach the gateway. KVM where the host has `/dev/kvm` (`compose.kvm.yml`), else TCG | MACs `00:00:5e:00:53:a0` and `:a1` |

Everything except the node comes from the tools image (`tools.Dockerfile`, Debian 12 packages
only), so nothing on the other side of the wire shares code with Tenko.

## The smoke

From the repository root, without arguments:

```sh
bash deploy/compose/lab-dhcp/smoke.sh                    # builds tenko:lab, NODE=tenko
IMAGE=tenko:lab bash deploy/compose/lab-dhcp/smoke.sh    # reuses an image
NODE=example bash deploy/compose/lab-dhcp/smoke.sh       # the example server as the node
KEEP=1 bash deploy/compose/lab-dhcp/smoke.sh             # leaves the lab running
```

With the binary, the smoke sets the node up through the API under the Lab profile and
configures it: the four networks as IPAM prefixes, a `dhcp_pool` range in each (`.30` to
`.59` of each /26), a scope on each with a 60-second lease (T1 after 30 seconds), option 3
per scope (the gateway's address on the network) and options 6, 15 and 42 for the server.
Then the rows, one `PASS`, `FAIL` or `SKIP` line each:

| Row | Checks |
|---|---|
| `lease.<network>` | `dhclient` on each network gets an address of that network's pool through the relay, with option 3 the gateway, option 6 `192.0.2.53` and option 42 `192.0.2.123` (the options of E23) |
| `relay.<network>` | the lease row (`GET /dhcp/leases/{addr}`) holds `giaddr`, the gateway's address on the network, and the circuit-id `dhcrelay` added (the network's name): option 82 reaches the scope and the lease |
| `link-selection` | `relay-test.py` on servers sends option 82 with the link selection sub-option (RFC 3527) of iot: the offer and the ack come from the iot scope, option 82 back unchanged |
| `perfdhcp` | perfdhcp as a relay: 10 4-way exchanges, no drops |
| `udhcpc` | BusyBox's `udhcpc` on servers gets an address of the pool |
| `renew.<network>` | every `dhclient` renews its address at T1, a unicast through the gateway |
| `reservation` | an IPAM host of mode `reserved` with client-lan's MAC at `192.0.2.80`: after a release client-lan gets `192.0.2.80`, not its dynamic address |
| `filter.deny`, `filter.removed` | a deny filter for client-guest's MAC: no lease; the filter deleted: a lease again |
| `release` | `dhclient -r` on iot: the lease row is `released` |
| `restart.leases`, `restart.client` | `docker compose restart tenko`: the node lists the same active leases, and client-lan asking again (INIT-REBOOT) keeps `192.0.2.80` |
| `class.vendor` | E27 (WP8.4): a class by vendor class prefix `Printer` and a guest policy with the range `.230` to `.234` and option 15: `dhclient` with `scripts/dhclient-printer.conf` (option 60 `Printer-Lab-1`) on guest gets an address of the range and `printers.example.test` |
| `class.mac-wildcard` | a class by the MAC pattern `00:00:5e:00:*:85` and an iot policy with the range `.170` to `.175`, option 15 and a 120-second lease: client-iot gets all three |
| `class.user` | a class by the user class `lab-ops` and a servers policy with the range `.50` to `.54` and option 15: `dhclient` with `scripts/dhclient-ops.conf` on servers gets both |
| `pxe.bios`, `pxe.bios.lease` | the boot policies of lan (option 150 the boot server; option 67 `boot.ipxe` for the user class `iPXE`, `http://192.0.2.21/ipxe.efi` for `HTTPClient`, `ipxe.efi` for architecture 7 or 9, `undionly.kpxe` for 0): the BIOS machine's iPXE gets `boot.ipxe` by TFTP and the menu by HTTP, and fetches `/done?platform=pcbios`; its lease row holds architecture 0 and `PXEClient` |
| `pxe.uefi`, `pxe.uefi.lease` | the UEFI machine (OVMF) boots to the same menu (`/done?platform=efi`); its lease row holds architecture 7 or 9 |
| `pxe.http-boot` | `relay-test.py` as a UEFI HTTP boot client (option 60 `HTTPClient:Arch:00016`, option 93 16) gets `http://192.0.2.21/ipxe.efi` in the `file` field and option 60 `HTTPClient`, and the tester fetches the URL |
| `pxe.proxy` | after its lease, `relay-test.py` as a PXE client sends the boot server discovery to the node's proxy DHCP listener (`[dhcp] proxy`, port 4011): an ACK with no address and `ipxe.efi` |
| `export.kea` | E30 (WP9.3, `docs/dhcp.md` section 18): the node's configuration and leases from `GET /dhcp/export?format=kea`, with a policy added whose DDNS action Kea cannot express; `kea-dhcp4 -t` in the Kea image (`kea.Dockerfile`, Kea 2.6 from Debian 13) accepts the configuration |
| `export.kea.report` | the loss report names that policy (`export.kea.policy.ddns`) |
| `export.kea.reservation` | the node stops and Kea (the `kea` profile, on the node's address, from the exported configuration and lease file) gives client-lan its reservation `192.0.2.80` with options 3 and 6 |
| `export.kea.lease` | client-iot asks again (INIT-REBOOT) and Kea keeps the address of its exported lease |

The PXE rows build the pxe image (`pxe.Dockerfile`) and run QEMU; `PXE=0` leaves them out, `PXE_WAIT_SECS` (300) bounds a boot, and under TCG the UEFI boot takes the longest. The Kea rows run last, since they stop the node; they build the kea image (`KEA_IMAGE`, with `KEA_IMAGE_PREBUILT=1` an existing one), and `KEA=0` leaves them out.

With `NODE=example` the rows the example server can answer run: `relay-test.py` with option
118 (offer, ack, a renewal, a release in `198.18.0.0/15`, option 82 echoed), with the link
selection sub-option, and perfdhcp with option 118 (50 exchanges, no drops). The client rows
are `SKIP` lines that say why.

The smoke tears everything down at the end (containers, the data volume, the networks, the
work directory), also after a failure, after printing the logs of every service; `KEEP=1`
leaves the lab running and prints the commands.

## The round dhcp6

WP9.1 ([docs/dhcp.md](../../../docs/dhcp.md) section 19): the DHCPv6 server of one node behind
a gateway that relays two dual-stack client links to it, with real clients and a relay agent
written against RFC 8415. `ROUNDS` selects what the smoke runs: the default (`ROUNDS=default`)
keeps the rows above exactly as they are; `ROUNDS=dhcp6` runs only this round, which brings its
own compose project (`compose.dhcp6.yml`, `tenkodhcp6lab`) and its own networks, sets the node
up itself and tears down what it started; `ROUNDS="dhcp6 default"` runs both, this one first.
It needs the binary (`NODE=tenko`), and nothing else of the lab may run: the networks use the
same documentation addresses `192.0.2.0/24` as the lab above.

```text
          servers6 192.0.2.0/26, 2001:db8:100::/64
   node .10, ::10 ─┐   tester .20, ::20   router6 .30, ::30
                   └─── .2, ::2 ┌─────────┐ .66, ::1 ──── lan6 192.0.2.64/26, 2001:db8:101::/64
                                 │  relay  │                client-dhclient6 (…:53:61), client-networkd (…:53:62), client-pd6 (…:53:64)
                                 └─────────┘ .130, ::1 ─── iot6 192.0.2.128/26, 2001:db8:102::/64
                                                            client-iot6 (…:53:63)
```

| Service | What | Address |
|---|---|---|
| `relay` | The gateway: ISC's `dhcrelay -6` (Debian's `isc-dhcp-relay` 4.4) relays `lan6` and `iot6` up to the node's IPv6 address with the Interface-Id of each link (`-I`), and `dhcrelay -4` does the same for DHCPv4, so that one client can hold a lease of each family; it routes IPv4 between the networks. The interfaces keep Docker's names, so that their IPv6 addresses survive | `.2`, `.66`, `.130`; `::2`, `::1`, `::1` |
| `netns`, `tenko` | As above: the node's namespace (with `net.ipv4.ip_unprivileged_port_start=0`, which opens ports 67 and 547) and the node from `deploy/Dockerfile`, as `TENKO_PROBE_IMAGE` (`probe.Dockerfile`: the same binary with the file capability `cap_net_raw+ep`, `NET_RAW` in the bounding set, `no-new-privileges` off for this container; Docker gives a non-root user no effective capability, so this is the `setcap` way of `deploy/systemd/probe.conf`), with `--roles controller,dhcp,probe` (WP9.2: the probe role runs the router advertisement check), the modules `ipam`, `dns` and `dhcp` (DDNS needs the DNS module; the node serves no DNS) and `[dhcp] listen = [{ address = "192.0.2.10", mode = "relay" }, { address = "2001:db8:100::10", mode = "relay" }]` | `192.0.2.10`, `2001:db8:100::10` |
| `client-dhclient6` | ISC's `dhclient -6 -D LL` (a DUID-LL from the MAC, so that the reservation and the correlation rows can name it) with `scripts/dhclient6.conf` and `scripts/client6-script.sh`, which puts the address on the interface and writes one line per event to `/run/lab/events6`; also `dhclient -4` on the same interface (with the files of the DHCPv4 clients) for the correlation row. `dhclient6.conf` defines option 56, which dhclient does not know (the script decodes it) | `lan6`, MAC `00:00:5e:00:53:61` |
| `client-networkd` (profile `networkd`) | Debian 12's `systemd-networkd` (systemd 252) as a DHCPv6 client, started directly (`networkd.Dockerfile`, `scripts/networkd.sh`; there is no systemd as process 1) with `scripts/networkd-lab.network`: `DHCP=ipv6`, `WithoutRA=solicit`, Rapid Commit, a DUID-LL, DNS and NTP servers. Its debug log goes to the container log; what it learns is in `/run/systemd/netif/links`. It starts with its row | `lan6`, MAC `00:00:5e:00:53:62` |
| `client-iot6` | `dhclient -6` on the second link | `iot6`, MAC `00:00:5e:00:53:63` |
| `client-pd6` (WP9.2) | `dhclient -6 -P -D LL`, a requesting router asking for a delegated prefix only; `client6-script.sh` writes the prefix (`prefix=`) to `/run/lab/events6` and leaves the interface alone | `lan6`, MAC `00:00:5e:00:53:64` |
| `router6` (WP9.2) | Debian's `radvd` (`scripts/radvd.sh`) advertising `2001:db8:100::/64` on servers6 every three to four seconds with the router lifetime 0 (no default router) and A off (no SLAAC), so the other rows keep their routes and addresses; `radvd.sh flags <M> <O>` writes new flags and sends radvd SIGHUP. It starts with the RA rows | `192.0.2.30`, `2001:db8:100::30` |
| `kea6` (profile `kea`) | E30's DHCPv6 rows (WP9.3): Kea 2.6's `kea-dhcp6` from the kea image (`kea.Dockerfile`, `scripts/kea.sh 6`), in the node's namespace once the node has stopped, from the export the rows wrote into the work directory's `kea/` | `2001:db8:100::10` |
| `tester` | `scripts/relay-test6.py`: a relay agent written against RFC 8415 with the standard library only. It sends a RELAY-FORW around a SOLICIT and then around a REQUEST for the advertised address, from the tester's address on port 547 to the node's, optionally two deep (`--two-deep`: an inner lightweight relay of RFC 6221 with the link address `::`), with an Interface-Id (`--interface-id`), the Client Link-Layer Address of RFC 6939 (`--mac`), the Client FQDN of option 39 (`--fqdn`), Rapid Commit (`--rapid-commit`), a RELEASE at the end (`--release`) and a check of the address (`--expect`). It checks that the RELAY-REPL chain is as deep as the RELAY-FORW chain, that the Interface-Id is echoed in the layer that sent it, and an ADVERTISE and then a REPLY with an address. `relay-test.py` (DHCPv4) for the correlation row | `192.0.2.20`, `2001:db8:100::20` |

The node is set up as in the lab above (the Lab profile, through the API): the server's option
set holds the DHCPv4 options 6, 15 and 42 and the DHCPv6 options 23 (`2001:db8:100::53`), 24
(`lab6.example.test`) and 56 (`2001:db8:100::123`); each link has an IPv4 prefix (pool `.94`
to `.123` on lan6, `.158` to `.187` on iot6, option 3 the relay) and an IPv6 prefix with a
`dhcp_pool` range `::1000` to `::1fff`, and a scope on each. The IPv6 scope of lan6 has a
valid lifetime of 120 seconds and a preferred lifetime of 60 (T1 after 30); that of iot6
names the Interface-Id `lab-iot6`. Servers6 has no scope until the RA rows. WP9.2: the IA_PD
rows add the delegation network `2001:db8:180::/48` with a `dhcp_pd_pool` range
`2001:db8:180:100::` to `2001:db8:180:1ff:ffff:ffff:ffff:ffff` (`delegated_len` 60) and a
scope, and a shared network `lab-lan6` that holds lan6's IPv6 scope and that scope; the RA
rows add an IPv6 prefix `2001:db8:100::/64` with a scope and no pool.

| Row | Checks |
|---|---|
| `v6.lease.dhclient` | `dhclient -6` on lan6 gets an address of the lan6 pool through `dhcrelay`, with DNS server `2001:db8:100::53` (option 23), domain search `lab6.example.test` (24) and NTP server `2001:db8:100::123` (56) |
| `v6.lease.iot` | `dhclient -6` on iot6 gets an address of the iot6 pool: the relay's link address selects the scope (its own Interface-Id is not the one the scope names) |
| `v6.lease.networkd` | `systemd-networkd` on lan6 gets an address of the lan6 pool, and its state file holds the DNS server and the NTP server |
| `v6.rapid-commit` | networkd's SOLICIT carries Rapid Commit: the node's `tenko_dhcp_packets_total{family="v6",type="solicit",outcome="answered"}` rises while the REQUEST counter does not; `relay-test6.py --rapid-commit` gets a REPLY with the Rapid Commit option to its SOLICIT |
| `v6.renew` | `dhclient` renews at T1 (a RENEW6 event with the same address) |
| `v6.interface-id` | `relay-test6.py --two-deep --interface-id lab-iot6` with an outer link address on servers6 (no scope there) gets an address of the iot6 scope; the RELAY-REPL chain is two deep with the Interface-Id echoed in the inner layer |
| `v6.reservation` | an IPAM host of mode `reserved` with an interface whose DUID is dhclient's DUID-LL (`00030001` and the MAC) and the address `2001:db8:101::80`: after a release dhclient gets `2001:db8:101::80` |
| `v6.correlation.duid` | client-dhclient6 holds a DHCPv4 and a DHCPv6 lease: `GET /observations?mac=...&type=address` lists both addresses from a source `dhcp:<node>` (the server takes the MAC address from the DUID-LL) |
| `v6.correlation.rfc6939` | `relay-test6.py --mac 00:00:5e:00:53:6f` with a DUID-EN (no MAC in it; option 79 of the innermost RELAY-FORW carries it) and `relay-test.py` with the same MAC: both addresses are listed for the MAC |
| `v6.fqdn` | with a primary zone `example.test`, the reverse zone of `2001:db8:101::/64` and DDNS on for the lan6 scope: `relay-test6.py --fqdn host6` gets an address, and `host6.example.test` holds an AAAA record with it, a DHCID record (the API shows its type as `TYPE49`, identifier type 2 and digest type 1) and the PTR in `ip6.arpa`, all of origin `dhcp` |
| `v6.release` | `dhclient -6 -r` on lan6: the node counts a RELEASE answered; `relay-test6.py --release` for `host6` removes its AAAA record and the PTR |
| `v6.pd` | `dhclient -6 -P` on client-pd6 gets a /60 of the delegation pool through `dhcrelay` (the pool of a sibling scope in lan6's shared network), on its boundary inside the pool, and `GET /observations?type=network&current=true` lists it as a network fact of a source `dhcp:<node>` |
| `v6.pd.release` | `dhclient -6 -P -r`: the node counts a RELEASE answered and the network fact of the prefix is no longer current |
| `v6.ra.flags_off` | radvd on servers6 with M and O off, and a scope on `2001:db8:100::/64`: `GET /system/status` carries `dhcp.ra.flags_off` naming the scope (within 60 seconds) |
| `v6.ra.managed` | `radvd.sh flags on off`: the finding is gone and no `dhcp.ra.managed_without_scope` or `dhcp.ra.other_only` names the link |
| `v6.ra.without_scope` | the servers6 scope disabled while M stays on: `GET /system/status` carries `dhcp.ra.managed_without_scope` naming `2001:db8:100::/64` |
| `export.kea6` | E30 (WP9.3, [docs/dhcp.md](../../../docs/dhcp.md) section 18.5): a DUID-EN client takes a lease on iot6 through `relay-test6.py`, then the node's configuration and leases come from `GET /dhcp/export?format=kea`; with `interfaces-config` naming the node's interface and address, as the report asks, `kea-dhcp6 -t` accepts the `Dhcp6` document |
| `export.kea6.golden` | `kea-dhcp6 -t` accepts the golden file of the unit tests (`crates/tenko-dhcp/src/export/kea/fixtures/kea-dhcp6.json`) |
| `export.kea6.report` | the loss report names the relay listener's address (`export.kea.v6.interfaces.address`) and the server DUID Kea cannot hold, the node's default DUID-UUID (`export.kea.v6.server_id.type`) |
| `export.kea6.reservation` | the node stops and `kea6` starts from the export: `dhclient -6` on lan6 gets its reservation `2001:db8:101::80` through `dhcrelay`, with options 23, 24 and 56 |
| `export.kea6.lease` | the DUID-EN client asks again and Kea gives it the address of its exported lease, which was not the pool's first |

The Kea rows come last, since they stop the node; `KEA=0` leaves them out, and `KEA_IMAGE`
(with `KEA_IMAGE_PREBUILT=1`) names an existing kea image.

```sh
IMAGE=tenko:lab bash deploy/compose/lab-dhcp/smoke.sh   # the default rows
IMAGE=tenko:lab ROUNDS=dhcp6 bash deploy/compose/lab-dhcp/smoke.sh
```

`NETWORKD_IMAGE` (with `NETWORKD_IMAGE_PREBUILT=1`) names a built networkd image, as `TOOLS_IMAGE`
does the tools image; `TENKO_PROBE_IMAGE` names the node image the round builds from the Tenko
image with `probe.Dockerfile` (default `tenko-dhcp-lab-probe:latest`); `KEEP=1` leaves the round running and prints the commands. By hand, with
`KEEP=1`:

```sh
export LAB_DIR=/tmp/tmp.XXXXXX
alias lab6='docker compose -p tenkodhcp6lab -f deploy/compose/lab-dhcp/compose.dhcp6.yml --profile networkd'
lab6 exec client-iot6 dhclient -6 -D LL -v -1 -cf /lab/dhclient6.conf -sf /lab/client6-script.sh \
  -lf /run/lab/dhclient6.leases -pf /run/lab/dhclient6.pid eth0
lab6 exec client-iot6 cat /run/lab/events6
lab6 exec tester python3 /lab/relay-test6.py --server 2001:db8:100::10 --bind 2001:db8:100::20 \
  --two-deep --interface-id lab-iot6 --link 2001:db8:100::20 --expect 2001:db8:102::/64
lab6 exec relay tcpdump -ni any -c 20 udp port 547
lab6 down --volumes
```

## By hand

With `KEEP=1` the lab stays up; the work directory the smoke prints holds `tenko.toml` and
the key file. For example:

```sh
export LAB_DIR=/tmp/tmp.XXXXXX
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec client-iot \
  dhclient -v -1 -cf /lab/dhclient.conf -sf /lab/client-script.sh -lf /run/lab/dhclient.leases eth0
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec client-iot cat /run/lab/events
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko exec tester \
  python3 /lab/relay-test.py --server 192.0.2.10 --giaddr 192.0.2.20 --mac 00:00:5e:00:53:21 \
  --expect 192.0.2.192/26 --link 192.0.2.192 --release
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko logs relay
docker compose -f deploy/compose/lab-dhcp/compose.yml --profile tenko down --volumes
```

The API is at `http://192.0.2.10:8443` from the host (the Lab profile allows plain HTTP); the
first-run setup token comes from `docker compose ... exec tenko /usr/local/bin/tenko setup
token --data-dir /var/lib/tenko`.

## CI

The weekly job `dhcp-lab` in `.github/workflows/ci.yml` runs the smoke with the binary
(it builds `tenko:lab` from `deploy/Dockerfile`, the static musl binary) on the self-hosted
Linux runner, next to the cluster and DNS labs. The measurements (M26 to M28) are not part of
the lab: they run on a host or between the two lab VMs ([bench/phase3-dhcp](../../../bench/phase3-dhcp/README.md)),
since bridge networks and containers on one host say nothing about a real link.
