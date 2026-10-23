//! The trust anchors and negative trust anchors (WP10.2, recursion plan section 2.4,
//! RFC 5011, RFC 7646, RFC 7958): the catalog's view of the rows `dns.trust_anchors` and
//! `dns.ntas` as the validator reads them ([`CatalogAnchors`]), the rows' writes through
//! the zone service ([`rows`]), the presentation forms of DS and DNSKEY records
//! ([`text`]), the IANA trust anchor file ([`xml`]), the leader service
//! `dns.trust_anchors` with the RFC 5011 state machine and the expiry of negative trust
//! anchors ([`service`]), and the resolver the service asks in process ([`resolver`]).

pub mod base64;
pub mod catalog;
pub mod resolver;
pub mod rows;
pub mod service;
pub mod text;
pub mod xml;

pub use catalog::CatalogAnchors;
pub use resolver::NodeResolver;
pub use service::{AnchorService, AnchorServiceConfig, AnchorWiring};
