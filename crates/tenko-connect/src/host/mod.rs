//! The host side of the plugin protocol: launching a plugin, the handshake, supervision,
//! typed calls with timeouts, and the connector service of the controller.

pub use service::{ConnectorHost, HostConfig, HostError};

pub mod backoff;
pub mod client;
pub mod guardrails;
pub mod launch;
pub mod normalize;
pub mod registry;
pub mod service;
pub mod supervisor;
