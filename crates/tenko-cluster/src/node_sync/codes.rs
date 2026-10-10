//! The error codes of the node sync, the commands and the ingest of the cluster port.

/// A controller that cannot write (isolated or electing, OPS-26) refuses a call that would
/// write (503); the node keeps what it sends and tries the next controller.
pub const NO_QUORUM: &str = "cluster.no_quorum";
/// A configuration payload in an encoding the receiver does not know (400).
pub const CONFIG_ENCODING: &str = "node.config.encoding";
/// A configuration payload that does not decode (400).
pub const CONFIG_PAYLOAD: &str = "node.config.payload";
/// A configuration that does not validate (422).
pub const CONFIG_INVALID: &str = "node.config.invalid";
/// The configuration kind is not one the node's roles use (403).
pub const CONFIG_KIND: &str = "node.config.kind";
/// The controller cannot reach the revision the node holds yet (503); the node tries
/// another controller.
pub const CONFIG_BEHIND: &str = "node.config.behind";
/// The node's configuration could not be written to its disk (500).
pub const CONFIG_FILES: &str = "node.config.files";
/// The node secrets cannot be served: no vault, or the audit record could not be written
/// (503).
pub const SECRETS_UNAVAILABLE: &str = "node.config.secrets_unavailable";
/// A purpose the node's roles do not use (403).
pub const SECRETS_PURPOSE: &str = "node.config.secrets_purpose";
/// No such command for this node (404).
pub const COMMAND_NOT_FOUND: &str = "node.command.not_found";
/// A command report that does not parse (400).
pub const COMMAND_INVALID: &str = "node.command.invalid";
/// A command that could not be recorded after several attempts (409).
pub const COMMAND_CONFLICT: &str = "node.command.conflict";
