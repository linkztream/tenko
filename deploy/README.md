# Deployment

Tenko DDI is one binary, `tenko`. `tenko serve` runs the roles of a node; every other
command (`config`, `setup`, `login`, `prefix`, `import`, `export`, ...) is the
command-line client of the API. Phase 1 implements the `controller` role: the REST API
and web UI on one port (8443 by default), the replicated store and IPAM. The `dns`,
`dhcp` and `probe` roles are accepted in a role list next to `controller` and skipped
with a notice; a role list without `controller` exits with status 2.

| Path | Contents |
|---|---|
| `tenko.example.toml` | Every configuration key with its default and its environment name |
| `systemd/tenko.service` | Hardened unit for Linux (`Type=notify`) |
| `Dockerfile` | Multi-stage build of the container image (build from the repository root) |
| `compose/controller.example.yml` | The controller on a bridge network, key from a Docker secret |
| `compose/macvlan.example.yml` | The same on a macvlan network, for the later DHCP role |
| `windows/` | The Windows service, see [windows/README.md](windows/README.md) |

## Build

```
cd ui && npm ci && npm run build && cd ..
cargo build --release --locked -p tenko --target x86_64-unknown-linux-musl   # Linux
cargo build --release --locked -p tenko        # Windows: target\release\tenko.exe
```

On Linux, build the static musl binary that the releases ship, which lands in
`target/x86_64-unknown-linux-musl/release/tenko`. It needs the target
(`rustup target add x86_64-unknown-linux-musl`) and `musl-gcc` (the `musl-tools` package on
Debian and Ubuntu). A glibc build of the same source is not a supported binary: its
allocator keeps the start-up peak and its idle memory fails OPS-15
([bench/phase1-server/results/2026-10-16-m9-linux-memory.md](../bench/phase1-server/results/2026-10-16-m9-linux-memory.md)).

The build script of `tenko-api` embeds `ui/dist` into the binary. A release build refuses
the placeholder page; for Rust-only development set `TENKO_UI_STUB=1` and build without
Node.js. The container image builds the UI and the binary itself:

```
docker build -f deploy/Dockerfile -t tenko .
```

## Configure and check

Copy `tenko.example.toml` to `/etc/tenko/tenko.toml` (Linux) or
`C:\ProgramData\Tenko\tenko.toml` (Windows) and delete what you do not change. Then check
it:

```
tenko config check --config /etc/tenko/tenko.toml
```

The command validates the file and prints the effective configuration without secrets.
Exit status 3 means the configuration is invalid; the message names the key.

The order of precedence is the built-in defaults, the file, the `TENKO_*` environment
variables, then the flags `--data-dir` and `--roles`. A variable is `TENKO_` plus the key
in upper case, with a double underscore between a section and its key: `TENKO_DATA_DIR`,
`TENKO_TLS__MODE`, `TENKO_KEK__PATH`. Lists take a TOML array or, for most keys, a
comma-separated string (`kek.retired` and `auth.attestation_roots` need the TOML array).
`TENKO_CONFIG` names the file like `--config`. `TENKO_URL`, `TENKO_CA_FILE`,
`TENKO_TOKEN`, `TENKO_CREDENTIALS` and `TENKO_SETUP_TOKEN` belong to the client commands.

## Run

```
tenko serve --config /etc/tenko/tenko.toml [--data-dir PATH] [--roles controller]
```

`tenko serve` stays in the foreground, logs to standard error (`log.format` = `text` or
`json`; `log.file` adds a file, rotated by size with `log.max_file_mb` and
`log.keep_files`) and prints the console notes to standard output. It starts thirteen steps
in order, each logged with its duration: `kek`, `store`, `cluster` (the controller cluster;
nothing to do on a single controller), `vault`, `tls`, `auth`, `languages` (language packs of
the data directory), `ipam`, `jobs`, `connectors`, `nodes` (the node transport), `scans`
(the scan control and the probe role in process), `api`. After the last step the leader
supervisor starts the leader-only services on the controller that leads. A step that fails stops the start with exit status 4 and a
message that names the step and its code. `GET /api/v1/health/ready` answers 200 when the
node serves requests and 503 while it starts or shuts down; `GET /api/v1/health` is the
liveness probe. `SIGINT` and `SIGTERM` shut the server down gracefully: open requests
finish, the job runner stops and the store makes its state durable.

The data directory (`data_dir`, required: in the file, with `--data-dir` or with
`TENKO_DATA_DIR`) holds `kek/` (key generations, when no key file is configured), `store/`
(the redb files), `tls/ca-root.pem` (the public root of the internal CA) and `logs/`. It is
created with mode 0700. **Put it on SSD or NVMe.** The store fsyncs on every commit;
rotating and SMR disks are not supported (OPS-19). At start the server measures the fsync
median of the data directory, logs it, and warns when it is above 10 ms.

### TLS

`[tls] mode` has four values. `internal_ca` (the default) makes Tenko its own CA and issue
the server certificate for the host name; install `<data_dir>/tls/ca-root.pem` on admin
clients, or pass it to the command line with `--ca-file`. The root is also served at
`GET /api/v1/system/ca-root`; `tenko ca-root --url <url> --fingerprint <sha256> -o ca-root.pem`
downloads it before the client trusts the server, and accepts it only when its SHA-256
matches the fingerprint the server prints at start (console and log). `imported` serves your
certificate chain and key (`cert_path`, `key_path`, PEM) and reloads them when the files
change. `reverse_proxy` ends TLS in HAProxy, nginx or Caddy in front of Tenko: Tenko
accepts plain HTTP, or the PROXY protocol, only from `trusted_proxies`, takes the client
address, scheme and host from the proxy, and needs `public_host`, the name clients use,
which is also the passkey relying-party ID; every other peer gets 403, health probes
included. `plain` is plain HTTP from everyone and exists for the Lab profile only.

### First-run setup

A new installation has no administrator. While setup is open, every start of `tenko serve`
writes a new one-time setup token to `<data_dir>/setup-token` before the server is ready, and
keeps it out of the log: the log only says that first-run setup is open and names the command
that prints the token. The file holds the token and a newline and is readable by the service
account only (mode 0600 on Linux; on Windows it inherits the access control list of the data
directory, which `tenko service install` restricts to the service account, Administrators and
SYSTEM). The token changes at every start, and the file is removed when setup completes. Print
the token on the node, as the account that runs the server:

```
sudo -u tenko tenko setup token --data-dir /var/lib/tenko    # systemd; or --config /etc/tenko/tenko.toml
docker exec tenko tenko setup token                          # container; docker compose exec tenko tenko setup token
tenko setup token --data-dir C:\ProgramData\Tenko             # Windows, in an administrator shell
```

`tenko setup token` finds the data directory like `tenko serve` does (`--data-dir`, else
`TENKO_DATA_DIR`, else `data_dir` of the file named by `--config` or `TENKO_CONFIG`) and prints
the token alone. Exit status 1 and a message on standard error mean that no server has
written a token there yet or that setup is complete. Standard output of the server shows the
token itself only when it is a terminal (`tenko serve` at a prompt, `docker run -it`); anywhere
else the console block names the file, so the journal and the container log never carry it.

Open the URL the server prints in a browser and enter the token, or complete setup without
a browser. The command asks for the token and the password; `--setup-token` (or
`TENKO_SETUP_TOKEN`) and `--password-stdin` supply them without a prompt:

```
tenko setup --url https://ddi.example.org:8443 --ca-file ca-root.pem \
  --admin alice --host-name ddi.example.org [--profile home|standard|hardened|lab]
```

`--host-name` is the name clients use (the TLS subject and the passkey relying-party ID),
not an IP address. Then sign in; the command stores a personal API token, readable by your
account only, for the other client commands:

```
tenko login --url https://ddi.example.org:8443 --ca-file ca-root.pem --user alice
tenko prefix list
```

### Exit statuses

| Status | Meaning |
|---|---|
| 0 | Success; for `tenko serve`, a graceful shutdown |
| 1 | An unexpected failure: I/O, a server that stopped with an error, a bug |
| 2 | Usage: invalid arguments, a command that does not exist on this platform, or roles that Phase 1 does not implement |
| 3 | The configuration is invalid (`tenko serve`, `tenko config check`, `tenko upgrade check`), or `tenko serve` found a data directory of a newer format than it reads (`upgrade.format_newer`) |
| 4 | `tenko serve` refused to start: a start step failed |
| 5 | The server answered with an error (the problem code is printed) |
| 6 | Not signed in, or the stored credentials were refused: run `tenko login` |
| 7 | The server could not be reached (connection, TLS, timeout) |
| 8 | A job or an import ended without success |
| 9 | `tenko audit verify`: the audit chain does not verify |
| 10 | `tenko upgrade check`: the data directory needs a migration and the dry run passed |
| 11 | `tenko upgrade check`: this binary refuses the data directory (a newer format, a missing migration, records that disagree, or a migration that failed in the dry run) |
| 12 | `tenko serve`: stopped on purpose to be started again (an installed update, a switch back to the previous version, a changed module set); the service manager starts it |

## Linux: systemd

`systemd/tenko.service` runs `tenko serve --config /etc/tenko/tenko.toml` as the
unprivileged user `tenko`, `Type=notify` (the server sends `READY=1` once the API listens
and `STOPPING=1` at shutdown), with the state in `/var/lib/tenko` (`StateDirectory=`,
mode 0700), no capabilities, and system call and address-family filters. Configuration and
start refusals (exit 2, 3, 4) are not restarted. It needs systemd 250 or later. The header
of the unit lists the install steps; in short, as root:

```
useradd --system --home-dir /var/lib/tenko --no-create-home --shell /usr/sbin/nologin tenko
install -m 0755 target/x86_64-unknown-linux-musl/release/tenko /usr/local/bin/tenko   # from the repository root
install -d -m 0750 -o root -g tenko /etc/tenko
install -m 0640 -o root -g tenko deploy/tenko.example.toml /etc/tenko/tenko.toml   # then edit
tenko config check --config /etc/tenko/tenko.toml

umask 077                                  # the key-encryption key, once, see below
openssl rand -hex 32 | tee /dev/shm/tenko-kek.hex \
  | systemd-creds encrypt --name=tenko_kek - /etc/tenko/kek.cred
# keep /dev/shm/tenko-kek.hex in a password manager, then:  shred -u /dev/shm/tenko-kek.hex

install -m 0644 deploy/systemd/tenko.service /etc/systemd/system/tenko.service
systemctl daemon-reload && systemctl enable --now tenko
```

**The key-encryption key.** The vault encrypts secrets with a key-encryption key (KEK). On
Linux the default provider runs `systemd-creds encrypt` itself, which the unprivileged
`tenko` account cannot do without a TPM2 it may open; where sealing fails the KEK becomes a
plain file in `<data_dir>/kek` with a warning. The unit therefore hands the KEK over as an
encrypted credential (`LoadCredentialEncrypted=`): systemd decrypts `/etc/tenko/kek.cred`
with the host key or the TPM2 at each start and gives the service a read-only copy in
`/run/credentials/tenko.service/`, and the unit tells tenko to read it with the
`systemd_credential` provider (`TENKO_KEK__PROVIDER=systemd_credential`, credential name
`tenko_kek`). At rest the key is sealed to the host. The credential holds the key as 64
hexadecimal digits (what `openssl rand -hex 32` prints), 32 raw bytes or base64. The server
logs "loaded the key-encryption key from a systemd credential" at each start and does not
warn about a plain file. The credential is bound to the host: keep the offline copy of the
key, because a restored backup on a new host needs `systemd-creds encrypt` run again with
the same key, and a store restored without its key cannot open its secrets. A backup needs
both the data directory and the key; keep them in different places.

If the unit fails at once with status 243/CREDENTIALS, `/etc/tenko/kek.cred` is missing or
was encrypted with another `--name`. The unit comments describe the alternative for hosts
where the `tenko` account can use a TPM2. An installation that used the unit of an earlier
release (`TENKO_KEK__PROVIDER=file` with the credential as the key file) switches to the new
provider without re-wrapping anything: the key identifier is the same.

**Logs.** The log goes to the journal (`journalctl -u tenko`). `LogsDirectory=tenko` also
creates `/var/log/tenko`, owned by `tenko` (mode 0750) and writable by the service, for a
log file: set `file = "/var/log/tenko/tenko.log"` in the `[log]` section of `tenko.toml`.
The server rotates that file itself, by size, so no `logrotate` rule is needed.
`max_file_mb` (default 64) is the size at which `tenko.log` becomes `tenko.log.1`, and
`keep_files` (default 5) is how many rotated files are kept, `tenko.log.1` to
`tenko.log.5`; the oldest is deleted.

**Start time.** `TimeoutStartSec=` is 120 seconds. When the data directory is of an older
format, the start migrates it first. While the migration runs, tenko sends
`EXTEND_TIMEOUT_USEC` to systemd, so a long migration does not hit the start timeout; a
start that makes no progress still fails. See [../docs/upgrades.md](../docs/upgrades.md).

**Versions.** The unit does not run `/usr/local/bin/tenko` itself. `ExecStartPre=` runs
`tenko upgrade layout`, which on the first start copies the binary to
`/var/lib/tenko/updates/<version>/` and points the link `current` at it, and `ExecStart=`
runs `/var/lib/tenko/updates/current/tenko`. An update installed from the web UI is then a
switch of that link and a restart; `RestartForceExitStatus=12` makes systemd start the
server again when it stops itself with status 12. A newer binary placed at
`/usr/local/bin/tenko` is adopted at the next start. To keep the old layout, without
updates from the UI, put `/usr/local/bin/tenko serve --config /etc/tenko/tenko.toml` in
`ExecStart=` and delete the `ExecStartPre=` line. An installation made before the layout
existed gets it when the unit is installed again. The format of the data directory, the
procedure for upgrades and rollbacks, and the layout are described in
[../docs/upgrades.md](../docs/upgrades.md).

**The probe role.** The base unit has no capability. To run the probe role next to the
controller (`--roles controller,probe`, or `roles = "controller,probe"` in `tenko.toml`),
install the drop-in `systemd/probe.conf`:

```
install -d /etc/systemd/system/tenko.service.d
install -m 0644 deploy/systemd/probe.conf /etc/systemd/system/tenko.service.d/probe.conf
systemctl daemon-reload && systemctl restart tenko
```

It adds `CAP_NET_RAW` (the only capability, ambient so the unprivileged account has it),
and the address families `AF_NETLINK` (the `ip` command that reads the IPv6 neighbor table)
and `AF_PACKET` (layer-2 sockets for the raw scan methods, which do not run yet). Every
other hardening setting stays. The probe works without it; the capability only makes
`tenko node scan status` report raw sockets as available (see
[../docs/scanning.md](../docs/scanning.md), section 9). `systemd-analyze security` rates
the unit 1.2 without the drop-in and 1.6 with it.

**The smoke test.** `systemd/smoke.sh` checks the unit end to end on a host where systemd
is PID 1; the CI job `systemd-smoke` runs it on a Linux runner on the weekly schedule
and when the workflow is started by hand. It installs the binary,
the account, a smoke configuration, the unit and the credential, starts the service,
checks the key source and the log directory, stops and starts it, completes first-run
setup, installs the same binary as the next version from a release source on the loopback
interface (the service exits with status 12 and systemd starts it again), runs the probe
drop-in, and fails if the `systemd-analyze security` score is 2.5 or higher. Run it by
hand on a test VM with a debug build (only debug builds can install themselves as a newer
version):

```
cargo build -p tenko
sudo bash deploy/systemd/smoke.sh target/debug/tenko
```

Do not run it on a production host. It replaces `/usr/local/bin/tenko`,
`/etc/tenko/tenko.toml` and `/etc/tenko/kek.cred`, and deletes `/var/lib/tenko` and
`/var/log/tenko` at the start; it refuses to run when `/var/lib/tenko` exists and an earlier
run of the script did not make it (`SMOKE_FORCE=1` overrides that on a throwaway VM). It
talks to the loopback interface only. Each step prints a line that starts with `==>`. On
failure it prints the journal of the unit and the tenko log. At the end it stops and
disables the unit and removes the drop-ins it added; `KEEP=1` leaves everything in place
for inspection.

## Containers

The image runs `tenko serve` as the non-root user `nonroot` (65532) with no configuration
file: the defaults plus `TENKO_*` variables, and `TENKO_DATA_DIR=/var/lib/tenko`. It
exposes 8443/tcp (API and web UI) and 8444/tcp (the cluster port, below). A volume at
`/var/lib/tenko` keeps the state; use SSD or NVMe.

```
docker run -d --name tenko -p 8443:8443 -v tenko-data:/var/lib/tenko \
  --stop-timeout 30 tenko
docker exec tenko tenko setup token
```

There is no systemd-creds or TPM in a container, so without a key file the KEK is a plain
file on the data volume. Provide it as a Docker secret and keep it off the data volume:
`TENKO_KEK__PROVIDER=file` and `TENKO_KEK__PATH=/run/secrets/tenko_kek`, a file readable by
uid 65532 holding 32 raw bytes, 64 hexadecimal digits or base64 (`openssl rand -hex 32`).
The server warns about the file provider at every start, by design. A key stored on the
data volume protects nothing.

- `compose/controller.example.yml`: the controller on a bridge network with ports 8443 and
  8444 published, the key as a Docker secret, the settings as environment variables, a
  read-only root file system, and a commented variant behind a reverse proxy.
- `compose/macvlan.example.yml`: the controller and a separate probe service on a macvlan
  network, each with its own address on the segment. Nothing is published. The DHCP role
  will need layer-2 access to the client segment, so the bridge network does not work for
  it (OPS-14); the controller alone does not need macvlan, but a probe that scans a segment
  does. The parent interface, subnet and addresses are environment variables with the
  documentation values as defaults.
- `compose/host.example.yml`: the controller with the probe role in the same process on the
  host's network (`network_mode: host`).
- `compose/smoke-macvlan.sh`: starts the macvlan example on a dummy parent interface and
  checks it; the CI runs it (below).
- `compose/lab-cluster/`: the cluster lab, not an example to deploy: three controllers
  joined with `tenko cluster join`, two probes and HAProxy in front (`reverse_proxy` mode,
  health checks on `/api/v1/health/ready`, cookie stickiness), with `smoke.sh` for failover
  and a partition. Its README has the commands; `docs/cluster.md` section 12.10 says what
  the lab covers.

The image is distroless and static (no shell, no curl, no C library: the binary is the
static musl build). Its `HEALTHCHECK` runs `tenko health`, which
asks `/api/v1/health/ready` over `https://localhost:8443` with the internal CA root and exits
0 when the node is ready (5 when it answers that it is not, 7 when it cannot be reached). In
`reverse_proxy` mode add `127.0.0.1` to the trusted proxies or override the check; probes
from outside must come from a trusted proxy address there.
Run the other `tenko` commands in the same image, for example
`docker run --rm --entrypoint /usr/local/bin/tenko tenko config check`. Allow 30 seconds
for a stop (`--stop-timeout 30` or `stop_grace_period`); the default of 10 is too short.

**Updates.** A container is updated by pulling a new image and creating the container
again. The data volume keeps the state, and the server migrates the data directory at its
first start with the new image, after copying the store aside. The image sets
`TENKO_UPDATES__CONTAINER=true` (`/.dockerenv` and `/run/.containerenv` are recognized as
well), so the web UI announces new versions and shows the command that pulls them, for
example `docker pull ghcr.io/linkztream/tenko:0.2.0`; it installs nothing itself. Pin the
version in the tag instead of `latest`, and check the volume with the new image before you
switch:

```
docker run --rm -v tenko-data:/var/lib/tenko --entrypoint /usr/local/bin/tenko \
  ghcr.io/linkztream/tenko:0.2.0 upgrade check
```

### The cluster port (8444)

Controllers that join each other and nodes (probes) talk gRPC over mutual TLS on 8444/tcp.
Only a controller that has cluster members or enrolled nodes needs it reachable: the server
opens the port once a node is enrolled or an enrolment token is waiting, and a member of a
cluster opens it at once. The `[cluster] listen` setting defaults to `0.0.0.0:8444`, which
is every interface of the container, so a published port reaches it; the compose files set
`TENKO_CLUSTER__LISTEN='["0.0.0.0:8444"]'` anyway, so that a configuration file cannot
narrow it by accident. `TENKO_CLUSTER__LISTEN='[]'` keeps the port closed. Publish it
(`-p 8444:8444`) on a controller with nodes or members, and allow it in the firewall from
the node and controller networks only; do not publish it on a stand-alone controller. A
layer 4 forwarder in front of it works, a proxy that terminates TLS does not. When nodes
reach the controller under another name or port than the one they enrolled through (NAT, a
published port other than 8444), set `TENKO_CLUSTER__ADVERTISE='["ddi.example.org:8444"]'`.
See [../docs/cluster.md](../docs/cluster.md) section 7.

### A probe in a container

A probe is the same image with `--roles probe`. It keeps its identity in `/var/lib/tenko`,
which must be a volume that survives the container. Create a token on the controller
(`tenko node enrol-token --roles probe --name <name>`, or in the web UI), enrol once into
the volume, then run the node. `compose/macvlan.example.yml` has the commands in its header:

```
docker compose -f macvlan.example.yml --profile probe run --rm --no-deps \
  --entrypoint /usr/local/bin/tenko probe node enrol --controller https://192.0.2.10:8443 \
  --token <token> --ca-fingerprint <sha256> --address 192.0.2.11 --data-dir /var/lib/tenko
docker compose -f macvlan.example.yml --profile probe up -d probe
```

The image's `HEALTHCHECK` asks the API on 8443, which a probe does not serve; the example
replaces it with `tenko node status --check`, which also checks the connection to the
controller. In Phase 1 the probe role runs in two ways: inside the controller's process
(`--roles controller,probe`, no enrolment; `host.example.yml`), or as a node of its own
(`--roles probe`, enrolled; `macvlan.example.yml`). The image has no `ping` command and no
`ip` command: ICMP echo works through an unprivileged datagram socket, which needs
`net.ipv4.ping_group_range` to admit gid 65532 (Docker sets it in the network namespace of a
bridge or macvlan container; with host networking the host's value applies), and the IPv6
neighbor method of the scanner, which runs `ip`, is unavailable.

### Capabilities

The controller and every scan method of this release need no capability, and the examples
drop all of them. `NET_RAW` is needed only by the raw-socket methods (`arp_sweep`,
`tcp_syn`, `os_fingerprint`, `lldp`), which are declared but do not run yet
([../docs/scanning.md](../docs/scanning.md) section 9). The examples carry `cap_add:
[NET_RAW]` commented out. Without `cap_drop: [ALL]`, Docker's default set already has it.
`tenko node scan status` inside the container shows whether the process holds it.

### Host networking

`network_mode: host` puts the container into the host's network namespace
(`compose/host.example.yml`). Use it when the probe must see the segments the host itself is
on without a macvlan network (with macvlan the host cannot reach its own containers unless
a shim interface exists), or when you want no port publishing: the API and the cluster port
bind on the host's addresses. The price is no network isolation: the process can bind and
see every address and interface of the host, it competes with other services for ports,
Docker manages no firewall rules for it (the host firewall is the only protection of 8443
and 8444), and `ports:` and `networks:` do not apply. Narrow `TENKO_SERVER__LISTEN` and
`TENKO_CLUSTER__LISTEN` to the addresses that should serve. Only Linux has a real host
network; Docker Desktop does not give one.

### LXC

Tenko runs in a plain LXC container or a Proxmox VE container (an unprivileged one is the
default there), installed from the Linux binary with the unit in `deploy/systemd` (see
Linux: systemd above), not from the image. The cluster transport needs no special
capability. To check on a given host, from inside the container, in this order:

- **API, store, cluster port.** These are ordinary TCP listeners and file I/O; they work in
  an unprivileged container. Start the unit, run `tenko health --url https://localhost:8443
  --ca-file /var/lib/tenko/tls/ca-root.pem`, and from another controller or node check
  that 8444/tcp is reachable. The cluster port must be reachable between every pair of
  controllers and from the node networks to each controller. Give the container a bridged
  `veth` with its own address on the network the others reach (Proxmox: a bridged NIC, not
  NAT behind the Proxmox host unless you forward 8443 and 8444 and set `[cluster]
  advertise`).
- **Data directory on SSD (OPS-19).** `/var/lib/tenko` must be on SSD or NVMe storage: the
  store fsyncs on every commit. In Proxmox put the container's root disk or a mount point
  for `/var/lib/tenko` on SSD-backed storage (not on a rotating disk or an SMR disk, and
  not on a network file system that does not honour fsync). The server logs the median
  fsync at start and warns above 10 ms; read that line after the first start.
- **Raw sockets.** `CAP_NET_RAW` is a capability over the container's own network
  namespace, and an unprivileged container owns that namespace through its user namespace,
  so the container's root, and a service started with the capability inside it, can
  normally open raw and packet sockets on the container's own interfaces. LXC's default
  configuration drops capabilities such as `sys_module` and `sys_time` but not `net_raw`;
  a site configuration with `lxc.cap.drop` that lists it, or with `lxc.cap.keep`
  that omits it, removes it. This is a claim about the kernel and the container runtime,
  not something Tenko guarantees, so test it: `grep CapEff /proc/self/status` inside the
  container and `tenko node scan status` (it prints `raw sockets: yes` when bit 13 is in
  the effective set). The capability also has to reach the `tenko` account: use the
  `deploy/systemd/probe.conf` drop-in (`AmbientCapabilities=CAP_NET_RAW`). The raw methods
  do not run yet, so this only matters when they arrive. The capability never reaches
  other containers' or the host's interfaces: a probe in a container sees the segments its
  own interfaces are on.
- **systemd inside the container** works with the unit of `deploy/systemd`, but some of its
  hardening options need privileges that an unprivileged container does not have, and the
  unit then fails to start with status 226/NAMESPACE or 218/CAPABILITIES (`journalctl -u
  tenko`). The typical ones are `PrivateDevices=`, `ProtectKernelTunables=`,
  `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectClock=`,
  `ProtectProc=`, `ProtectHostname=`, `PrivateTmp=` and `ProtectSystem=` (mount namespaces
  need a container that allows them), `RestrictNamespaces=` and `SystemCallFilter=`. Do not
  edit the unit; relax only the failing options in a drop-in, one at a time, and keep the
  rest:

  ```
  # /etc/systemd/system/tenko.service.d/lxc.conf
  [Service]
  PrivateDevices=no
  ProtectKernelTunables=no
  ProtectKernelModules=no
  ProtectKernelLogs=no
  ProtectControlGroups=no
  ```

  then `systemctl daemon-reload && systemctl restart tenko`. The container is the isolation
  boundary then, so keep it unprivileged and do not give it extra devices or host
  mounts. Setting `features: nesting=1` on a Proxmox container lets systemd create the mount
  namespaces that `PrivateTmp=` and `ProtectSystem=` need on some hosts; try it before
  relaxing those. Leave the AppArmor profile of the container at its default; nothing in
  Tenko needs it unconfined. `systemd-creds` and TPM are usually unavailable in a container; use
  the `file` KEK provider with the key outside the data directory, as in the section on
  secrets above.

Upgrades in LXC are binary upgrades with `tenko upgrade` as on any Linux host
([../docs/upgrades.md](../docs/upgrades.md)); take a snapshot of the container first.

The Proxmox VE scripts in [proxmox/](proxmox/README.md) create the container of the
self-hosted CI runner in one command; that container is a build machine, not a Tenko
installation.

### Smoke test of the macvlan example

`compose/smoke-macvlan.sh` creates a dummy link `tenkosmoke0`, builds the image (or uses
`IMAGE=<tag>`), starts the controller on a macvlan network on it, waits for the
`HEALTHCHECK`, checks `/api/v1/health/ready` from a throwaway container on the same network,
runs first-run setup, enrols the probe with a token and checks that it runs, then removes
everything, the link included, even on failure. It needs root (sudo), Docker with the compose
and buildx plugins, and `ip`, and the Docker daemon must run in the network namespace of the
shell that creates the link (a Linux host, or docker.io inside a WSL distribution; the engine
of Docker Desktop runs elsewhere and does not see the link). The Docker host cannot reach
macvlan children, which is why every check runs in a container.

## Windows

`tenko service install` registers `tenko serve` as a Windows service; see
[windows/README.md](windows/README.md).

## Upgrades

A node has a binary, which has a version, and a data directory, which has a format. A new
binary migrates an older format when it starts, after copying the store aside; an older
binary refuses a newer format and changes nothing. `tenko upgrade check`, run with the new
binary on the stopped node, dry-runs the migration on a copy and reports with an exit
status: 0 nothing to do, 10 a migration is needed and passed, 11 refused (see the exit
statuses above). In short, on Linux with the shipped unit, as root:

```
systemctl stop tenko
cp -a /var/lib/tenko /srv/backup/tenko-20261009                  # and keep the key apart
sudo -u tenko /usr/local/bin/tenko-0.2.0 upgrade check \
  --config /etc/tenko/tenko.toml --data-dir /var/lib/tenko       # 0 or 10 means go on
sudo -u tenko /usr/local/bin/tenko-0.2.0 upgrade layout \
  --config /etc/tenko/tenko.toml --data-dir /var/lib/tenko       # switch `current`
systemctl start tenko
journalctl -u tenko --since '10 minutes ago' | grep -E 'data format|migrat'
tenko health --live --url https://ddi.example.org:8443 --ca-file /var/lib/tenko/tls/ca-root.pem
```

`/usr/local/bin/tenko-0.2.0` is the new binary, staged beside the installed one and
verified against `SHA256SUMS` of the release. To roll back, stop the unit and move the link
back with `sudo -u tenko ln -sfn 0.1.0 /var/lib/tenko/updates/current`. When the new
version migrated the data (`store/format` names a newer format than the old binary
writes), the old binary refuses the directory: restore the store from
`upgrade-backups/<name>/store` or from the backup first. Containers and the Windows
service follow the same steps with their own commands.

A start that has to migrate first checks that the file system has room for the copy of the
store (`upgrade.no_space`, exit status 4, nothing changed) and, under systemd, keeps
extending the start timeout while it copies and migrates.

A controller cluster is upgraded one member at a time, and its data keeps the old format
until every voter runs the new binary; the leader migrates then. Run
`tenko cluster upgrade-check` with the new binary first: it lists every member's version,
protocol majors, Raft wire version and data formats, says whether the new binary can replace
them (exit 0) or not (exit 11), and prints the order: learners, the following voters, and the
leader last after `tenko cluster step-down`. Wait until `tenko cluster members` shows each
member caught up on its new version before the next one. `GET /api/v1/system/status` shows
the stored format and, while a migration waits, the voters that block it
(`data_format.pending`).

[../docs/upgrades.md](../docs/upgrades.md) has the full procedure for Linux, Windows and
containers, the rolling upgrade of a controller cluster, the rollback in detail, updates installed from the web UI, how the release
manifest and the layout work, and the convention that developers follow when stored data
changes. [windows/README.md](windows/README.md) has the Windows commands.
