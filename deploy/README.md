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
cargo build --release --locked -p tenko        # target/release/tenko
```

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
`json`; `log.file` adds a file) and prints the console notes to standard output. It starts
eight steps in order, each logged with its duration: `kek`, `store`, `vault`, `tls`,
`auth`, `ipam`, `jobs`, `api`. A step that fails stops the start with exit status 4 and a
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

A new installation has no administrator. While setup is open, `tenko serve` prints a
one-time setup token on standard output (`Setup token: ...`) and writes it to the log as
`setup_token=...`; it changes at every start until setup is complete, so treat the console,
the journal and the container log as sensitive until then. Read it from the journal or the
container log:

```
journalctl -u tenko | grep -E 'Setup token|setup_token'
docker compose logs tenko | grep -E 'Setup token|setup_token'
```

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
install -m 0755 target/release/tenko /usr/local/bin/tenko        # from the repository root
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
`/run/credentials/tenko.service/`, and the unit tells tenko to read it with the `file`
provider. At rest the key is sealed to the host. tenko still warns that the key is a plain
file; with this unit that is expected. The credential is bound to the host: keep the offline
copy of the key, because a restored backup on a new host needs `systemd-creds encrypt` run
again with the same key, and a store restored without its key cannot open its secrets. A
backup needs both the data directory and the key; keep them in different places.

If the unit fails at once with status 243/CREDENTIALS, `/etc/tenko/kek.cred` is missing or
was encrypted with another `--name`. The unit comments describe the alternative for hosts
where the `tenko` account can use a TPM2.

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

## Containers

The image runs `tenko serve` as the non-root user `nonroot` (65532) with no configuration
file: the defaults plus `TENKO_*` variables, and `TENKO_DATA_DIR=/var/lib/tenko`. It
exposes 8443/tcp only. A volume at `/var/lib/tenko` keeps the state; use SSD or NVMe.

```
docker run -d --name tenko -p 8443:8443 -v tenko-data:/var/lib/tenko \
  --stop-timeout 30 tenko
docker logs tenko 2>&1 | grep -E 'Setup token|setup_token'
```

There is no systemd-creds or TPM in a container, so without a key file the KEK is a plain
file on the data volume. Provide it as a Docker secret and keep it off the data volume:
`TENKO_KEK__PROVIDER=file` and `TENKO_KEK__PATH=/run/secrets/tenko_kek`, a file readable by
uid 65532 holding 32 raw bytes, 64 hexadecimal digits or base64 (`openssl rand -hex 32`).
The server warns about the file provider at every start, by design. A key stored on the
data volume protects nothing.

- `compose/controller.example.yml`: the controller on a bridge network with port 8443
  published, the key as a Docker secret, the settings as environment variables, a
  read-only root file system, and a commented variant behind a reverse proxy.
- `compose/macvlan.example.yml`: the same on a macvlan network. The DHCP role will need
  layer-2 access to the client segment, so the bridge network does not work for it
  (OPS-14); the controller does not need macvlan.

The image is distroless (no shell, no curl). Its `HEALTHCHECK` runs `tenko health`, which
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

[../docs/upgrades.md](../docs/upgrades.md) has the full procedure for Linux, Windows and
containers, the rollback in detail, updates installed from the web UI, how the release
manifest and the layout work, and the convention that developers follow when stored data
changes. [windows/README.md](windows/README.md) has the Windows commands.
