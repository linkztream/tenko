# syntax=docker/dockerfile:1
#
# Container image for tenko (Tenko DDI): one binary, run as `tenko serve`.
#
# Build from the repository root, not from this directory:
#
#   docker build -f deploy/Dockerfile -t tenko .
#
# ---------------------------------------------------------------------------
# WHAT RUNS
#
# Phase 1 implements the controller role: the REST API, the web UI, the replicated
# store and IPAM, all on 8443/tcp (HTTPS by default; TENKO_TLS__MODE selects another
# TLS mode). The DNS and DHCP roles do not exist yet; a role list without
# `controller` makes the container exit with status 2.
#
# The image has no configuration file. It starts from the defaults plus TENKO_*
# environment variables (TENKO_DATA_DIR is set below). To use a file, mount it and
# name it with TENKO_CONFIG or with `--config` (see deploy/tenko.example.toml for
# every key and its environment name):
#
#   docker run --rm -p 8443:8443 -v tenko-data:/var/lib/tenko \
#     -v "$PWD/tenko.toml:/etc/tenko/tenko.toml:ro" tenko --config /etc/tenko/tenko.toml
#
# Other commands of the binary run in the same image, for example
#   docker run --rm --entrypoint /usr/local/bin/tenko tenko config check
#
# ---------------------------------------------------------------------------
# KEY-ENCRYPTION KEY (KEK)
#
# The vault encrypts secrets with a KEK. Without further settings the container has
# no systemd-creds and no TPM, so the KEK becomes a plain key file in
# /var/lib/tenko/kek and the server warns at every start. Give the container a key
# from a Docker secret instead:
#
#   TENKO_KEK__PROVIDER=file
#   TENKO_KEK__PATH=/run/secrets/tenko_kek
#
# The secret is 32 raw bytes, 64 hexadecimal digits or base64 of 32 bytes
# (`openssl rand -hex 32`). The file must be readable by uid 65532. Keep it OFF the
# data volume: a key stored next to the data it protects protects nothing, and it
# would travel with every backup of the volume. The file provider logs a warning at
# every start by design. See deploy/compose/controller.example.yml.
#
# ---------------------------------------------------------------------------
# NETWORKING AND PRIVILEGES
#
# The controller listens on 8443/tcp, above 1024: the image runs as the non-root user
# `nonroot` (65532) and needs no capability. The default bridge network with a
# published port is fine for it (deploy/compose/controller.example.yml); behind a
# reverse proxy use TENKO_TLS__MODE=reverse_proxy.
#
# Later roles are different. DHCP needs layer-2 access to the client segment (clients
# broadcast DISCOVER/SOLICIT), so a container running the `dhcp` role must use host
# networking or a macvlan/ipvlan network (deploy/compose/macvlan.example.yml); the
# bridge network does not work for it. Ports below 1024 (DNS on 53) and raw sockets
# (DHCP) then need `--cap-add NET_BIND_SERVICE` and `--cap-add NET_RAW`, or the sysctl
# net.ipv4.ip_unprivileged_port_start=0.
#
# ---------------------------------------------------------------------------
# STORAGE
#
# /var/lib/tenko holds the store, the internal CA root and the KEK generations (when
# no key file is given). Back it with SSD or NVMe: the store fsyncs on every commit,
# rotating and SMR disks are not supported (OPS-19), and the server warns at start
# when the median fsync takes more than 10 ms.
#
# ---------------------------------------------------------------------------
# HEALTH AND STOP
#
# The runtime image is distroless (no shell, no curl); the HEALTHCHECK below runs
# `tenko health`, which asks GET /api/v1/health/ready (503 while starting or shutting
# down) and exits 0 when the node is ready. It assumes the default internal-CA mode on
# port 8443. In reverse_proxy mode the probe comes from 127.0.0.1 inside the container:
# add 127.0.0.1 to TENKO_TLS__TRUSTED_PROXIES, or override the check
# (`healthcheck: test: [...]` in compose) or disable it. Orchestrators can also probe
# from outside: GET /api/v1/health (liveness) and GET /api/v1/health/ready.
#
# `docker stop` sends SIGTERM and the server shuts down gracefully; allow 30 seconds
# (`docker stop -t 30`, or stop_grace_period in compose) instead of the default 10.
# ---------------------------------------------------------------------------

# Stage 1: web UI bundle.
FROM node:22-bookworm-slim AS ui
WORKDIR /src/ui
# Copy the manifests first so the dependency layer is cached.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: the tenko binary.
FROM rust:1-slim-bookworm AS builder
WORKDIR /src
COPY . .
# The build script of tenko-api embeds ui/dist into the binary; a release build refuses
# the placeholder page that TENKO_UI_STUB=1 would give.
COPY --from=ui /src/ui/dist ui/dist
# The target directory is a cache mount and is not part of the image layer,
# so the binary is copied out to /out inside the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tenko \
    && mkdir -p -m 0700 /out/state \
    && cp target/release/tenko /out/tenko

# Stage 3: runtime image.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/tenko /usr/local/bin/tenko
# Create the state directory owned by the distroless "nonroot" user (65532) so
# that a new volume mounted here is writable (a named volume copies the owner and
# mode of this directory on first use).
COPY --from=builder --chown=65532:65532 /out/state /var/lib/tenko
USER nonroot:nonroot
ENV TENKO_DATA_DIR=/var/lib/tenko
VOLUME ["/var/lib/tenko"]
# 8443/tcp  HTTPS API and web UI (Phase 1: the controller role)
# Later roles will add: 53/udp and 53/tcp (DNS), 67/udp (DHCPv4), 547/udp (DHCPv6).
EXPOSE 8443/tcp
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/tenko", "health", "--url", "https://localhost:8443", \
         "--ca-file", "/var/lib/tenko/tls/ca-root.pem"]
ENTRYPOINT ["/usr/local/bin/tenko", "serve"]
