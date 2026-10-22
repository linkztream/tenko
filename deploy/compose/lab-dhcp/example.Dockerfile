# syntax=docker/dockerfile:1
#
# The DHCPv4 engine's example server (crates/tenko-dhcp/examples/dhcp_server.rs) as the
# lab's node while the binary has no dhcp role yet: the same builder as deploy/Dockerfile
# (the rust image, musl-tools, the toolchain of rust-toolchain.toml, the static musl
# target) and the same distroless runtime, with the example instead of tenko. It serves
# one scope, 198.18.0.0/15, selected by option 118, the link selection sub-option of
# option 82 or a giaddr inside it, with the in-memory reference store (MemLeaseStore).
#
# Build from the repository root (smoke.sh does, as tenko-dhcp-lab-example:latest):
#   docker build -f deploy/compose/lab-dhcp/example.Dockerfile -t tenko-dhcp-lab-example .
FROM rust:1-slim-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends make musl-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY rust-toolchain.toml ./
RUN rustup toolchain install \
    && rustup target add x86_64-unknown-linux-musl
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tenko-dhcp --example dhcp_server \
        --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/examples/dhcp_server /dhcp_server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /dhcp_server /usr/local/bin/dhcp_server
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/dhcp_server"]
