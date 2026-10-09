# syntax=docker/dockerfile:1
#
# Container image for tenko (DNS, DHCP and IPAM roles in one binary).
#
# Build from the repository root, not from this directory:
#
#   docker build -f deploy/Dockerfile -t tenko .
#
# ---------------------------------------------------------------------------
# NETWORKING AND PRIVILEGES
#
# DHCP needs layer-2 access to the client segment (clients broadcast
# DISCOVER/SOLICIT). A container running the `dhcp` role must therefore use
# host networking or a macvlan/ipvlan network (see
# deploy/compose/macvlan.example.yml). The default bridge network does not
# work for DHCP.
#
# The image runs as a non-root user. Binding ports below 1024 requires
# `--cap-add NET_BIND_SERVICE` (and `NET_RAW` for the DHCP and probe roles),
# or the sysctl `net.ipv4.ip_unprivileged_port_start=0`.
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
# The UI bundle is embedded into the binary at compile time once the API
# serves it.
COPY --from=ui /src/ui/dist ui/dist
# The target directory is a cache mount and is not part of the image layer,
# so the binary is copied out to /out inside the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tenko \
    && mkdir -p /out/state \
    && cp target/release/tenko /out/tenko

# Stage 3: runtime image.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/tenko /usr/local/bin/tenko
# Create the state directory owned by the distroless "nonroot" user (65532) so
# that a new volume mounted here is writable.
COPY --from=builder --chown=65532:65532 /out/state /var/lib/tenko
USER nonroot:nonroot
VOLUME ["/var/lib/tenko"]
# 53/udp, 53/tcp  DNS
# 67/udp          DHCPv4 server
# 547/udp         DHCPv6 server
# 8443/tcp        HTTPS API and web UI (the API port is provisional)
EXPOSE 53/udp 53/tcp 67/udp 547/udp 8443/tcp
ENTRYPOINT ["/usr/local/bin/tenko", "serve"]
CMD ["--roles", "controller,dns,dhcp", "--data-dir", "/var/lib/tenko", "--config", "/etc/tenko/tenko.toml"]
