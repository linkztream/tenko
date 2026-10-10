//! Compiles the node transport protocol (`proto/tenko/cluster/v1/*.proto`) with the pure
//! Rust protobuf compiler `protox` into Rust messages, clients and servers, like the plugin
//! protocol of `tenko-connect`. No external `protoc` is needed.

use std::path::Path;

const PROTO_ROOT: &str = "proto";
const FILES: [&str; 8] = [
    "tenko/cluster/v1/handshake.proto",
    "tenko/cluster/v1/node.proto",
    "tenko/cluster/v1/observations.proto",
    "tenko/cluster/v1/raft.proto",
    "tenko/cluster/v1/membership.proto",
    "tenko/cluster/v1/config.proto",
    "tenko/cluster/v1/commands.proto",
    "tenko/cluster/v1/metrics.proto",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    for file in FILES {
        println!(
            "cargo:rerun-if-changed={}",
            Path::new(PROTO_ROOT).join(file).display()
        );
    }
    let descriptors = protox::compile(FILES, [PROTO_ROOT])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .btree_map(".")
        .compile_fds(descriptors)?;
    Ok(())
}
