//! Compiles the plugin protocol (`proto/tenko/connect/v1/*.proto`) with the pure Rust
//! protobuf compiler `protox` into Rust messages, clients and servers. No external
//! `protoc` is needed.

use std::path::Path;

const PROTO_ROOT: &str = "proto";
const FILES: [&str; 6] = [
    "tenko/connect/v1/common.proto",
    "tenko/connect/v1/plugin.proto",
    "tenko/connect/v1/inventory.proto",
    "tenko/connect/v1/network.proto",
    "tenko/connect/v1/actuator.proto",
    "tenko/connect/v1/migration.proto",
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
