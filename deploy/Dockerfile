# Container image for tenko (Tenko DDI): one binary, run as `tenko serve`.
#
# The binary is the static musl build that the release workflow ships for Linux
# (x86_64-unknown-linux-musl, S3-Q10, OPS-01), so the runtime image carries no C library:
# distroless/static.
#
# Build from the repository root, not from this directory:
#
#   docker build -f deploy/Dockerfile -t tenko .
#
# ---------------------------------------------------------------------------
# HOW THE PUBLISHED IMAGE IS BUILT
#
# The image on ghcr.io is built by the release workflow (job `image-build` of
# .github/workflows/release.yml) from the release's own Linux binary: the file the build job
# produced, the smoke runs started, the security round tested and the provenance attestation
# names. Nothing is compiled for it, so no second build exists whose output could differ
# from the released binary, and its only base image is distroless/static, pinned by digest
# below. The workflow passes
#
#   --build-arg TENKO_BINARY_SOURCE=release \
#   --build-arg TENKO_BINARY=dist/tenko-<version>-linux-x86_64
#
# and pushes the result by digest after the security round and the attestations; the tags
# <version> and latest are added when the release is published.
#
# Without the arguments (the command above, the compose examples) the stages `ui` and
# `builder` build the web UI and the binary from the checkout, for local development. They
# never run for the published image; their base images are pinned by digest as well, and
# Dependabot moves every digest here (.github/dependabot.yml).
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
# The controller listens on 8443/tcp, and on 8444/tcp (the cluster port) when it has nodes
# or cluster members, both above 1024: the image runs as the non-root user
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

# The source of the binary: `source` (built below, local development) or `release` (the
# release workflow's binary, named by TENKO_BINARY).
ARG TENKO_BINARY_SOURCE=source

# Stage: web UI bundle (local development only).
FROM node:22-bookworm-slim@sha256:2f0e17f8955e766e776ae16d3ac47519ca3edf47c07e5c1423527926fdd5d568 AS ui
WORKDIR /src/ui
# Copy the manifests first so the dependency layer is cached. No install scripts: the UI's
# dependencies need none, and the release's UI job installs them the same way.
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --ignore-scripts
COPY ui/ ./
RUN npm run build

# Stage: the tenko binary (local development only), static for musl as in
# .github/workflows/release.yml.
FROM rust:1-slim-bookworm@sha256:ed2c95ca377d6571b124b05e75e01207973ded639dce7d5542eb7bcd797e32aa AS builder
# musl-tools provides musl-gcc, which the C code of aws-lc-sys, ring and jemalloc (the
# allocator of the musl binary) is built with for the musl target; jemalloc's build runs
# make. Nothing else is needed (no cmake, perl or clang).
RUN apt-get update \
    && apt-get install -y --no-install-recommends make musl-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# rust-toolchain.toml names the exact toolchain, which is not the one of the base image:
# install it with the musl target in its own layer, cached until the file changes.
COPY rust-toolchain.toml ./
RUN rustup toolchain install \
    && rustup target add x86_64-unknown-linux-musl
COPY . .
# The build script of tenko-api embeds ui/dist into the binary; a release build refuses
# the placeholder page that TENKO_UI_STUB=1 would give.
COPY --from=ui /src/ui/dist ui/dist
# The target directory is a cache mount and is not part of the image layer,
# so the binary is copied out to /out inside the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tenko --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/tenko /out-tenko

# The binary built here (TENKO_BINARY_SOURCE=source).
FROM scratch AS source
COPY --from=builder /out-tenko /tenko

# The binary the release workflow hands in (TENKO_BINARY_SOURCE=release): a file of the
# build context, with the execute bit set here because an artifact does not keep it.
FROM scratch AS release
ARG TENKO_BINARY=dist/tenko
COPY --chmod=0755 ${TENKO_BINARY} /tenko

# One of the two, by the build argument; the other stage is never built.
FROM ${TENKO_BINARY_SOURCE} AS binary

# An empty directory for the data volume, made here because the runtime image has no shell.
FROM scratch AS state
WORKDIR /state

# Runtime image: distroless/static (no shell, no package manager, no C library), by digest.
# The tag is nonroot; Dependabot moves the digest when the tag moves.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=binary /tenko /usr/local/bin/tenko
# The state directory is owned by the distroless "nonroot" user (65532) so that a new
# volume mounted here is writable (a named volume copies the owner and mode of this
# directory on first use).
COPY --from=state --chown=65532:65532 --chmod=0700 /state /var/lib/tenko
USER nonroot:nonroot
ENV TENKO_DATA_DIR=/var/lib/tenko
# Updates come as a new image: the web UI shows the pull command instead of installing.
ENV TENKO_UPDATES__CONTAINER=true
VOLUME ["/var/lib/tenko"]
# 8443/tcp  HTTPS API and web UI (Phase 1: the controller role)
# 8444/tcp  Cluster port: gRPC over mutual TLS. Other controllers joining this one and
#           data-plane nodes (probes) connect to it. It is only needed on a controller that
#           has cluster members or enrolled nodes; the server opens it once a node is
#           enrolled or an enrollment token is waiting (docs/cluster.md section 7). Publish
#           it with `-p 8444:8444` only then, and only to the node and controller networks.
# Later roles will add: 53/udp and 53/tcp (DNS), 67/udp (DHCPv4), 547/udp (DHCPv6).
EXPOSE 8443/tcp 8444/tcp
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD ["/usr/local/bin/tenko", "health", "--url", "https://localhost:8443", \
         "--ca-file", "/var/lib/tenko/tls/ca-root.pem"]
ENTRYPOINT ["/usr/local/bin/tenko", "serve"]
