# syntax=docker/dockerfile:1
#
# The quirk responder of the DNS lab (WP10.1): the engine's example authoritative server
# (crates/tenko-dns/examples/authoritative.rs) in quirk mode, as a static musl binary in a
# minimal image. One container is authoritative for one zone and misbehaves in one way (no
# EDNS, broken 0x20, TC on everything, delayed answers, answers from the wrong source
# port, a referral with out-of-bailiwick glue); compose.yml gives each container its flags
# (the services `quirk-*`, profile `recursion`, image QUIRK_IMAGE).
#
# Build from the repository root, not from this directory:
#
#   docker build -f deploy/compose/lab-dns/quirk.Dockerfile -t tenko-quirk:lab .
#
# Run (the zone and the address are required; the port defaults to 53, so a container
# needs the sysctl net.ipv4.ip_unprivileged_port_start=0 or --listen above 1024):
#
#   docker run --rm tenko-quirk:lab --quirk-zone noedns.quirk.example.test \
#     --quirk-address 192.0.2.53 --no-edns
#
# The builder is the one of deploy/Dockerfile (same base image, toolchain file and musl
# target); the user interface is not part of this binary, so it needs no UI stage.

FROM rust:1-slim-bookworm AS builder
# musl-tools provides musl-gcc, which the C code of aws-lc-sys is built with for the musl
# target (the engine's TLS and cookies use aws-lc-rs).
RUN apt-get update \
    && apt-get install -y --no-install-recommends make musl-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# rust-toolchain.toml selects the toolchain, which is not the one of the base image.
COPY rust-toolchain.toml ./
RUN rustup toolchain install \
    && rustup target add x86_64-unknown-linux-musl
COPY . .
# The target directory is a cache mount and is not part of the image layer, so the binary
# is copied out to /out inside the same RUN.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --target x86_64-unknown-linux-musl \
        -p tenko-dns --example authoritative \
    && mkdir -p /out \
    && cp target/x86_64-unknown-linux-musl/release/examples/authoritative /out/quirk

# The binary is static and needs no libc; nothing else belongs in the image.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/quirk /usr/local/bin/quirk
USER 65532:65532
# 53/udp and 53/tcp: the quirk responder, on the lab network only.
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/quirk"]
