//! The trust anchors and negative trust anchors (WP10.2, recursion plan section 2.4,
//! RFC 5011, RFC 7646, RFC 7958): the catalog's view of the rows `dns.trust_anchors` and
//! `dns.ntas` as the validator reads them ([`CatalogAnchors`]), the rows' writes through
//! the zone service ([`rows`]), the presentation forms of DS and DNSKEY records
//! ([`text`]), the IANA trust anchor file ([`xml`]), the leader service
//! `dns.trust_anchors` with the RFC 5011 state machine and the expiry of negative trust
//! anchors ([`service`]), and the resolver the service asks in process ([`resolver`]).

use base64::{
    alphabet,
    engine::{GeneralPurpose, general_purpose::PAD},
};

pub mod catalog;
pub mod resolver;
pub mod rows;
pub mod service;
pub mod text;
pub mod xml;

pub use catalog::CatalogAnchors;
pub use resolver::NodeResolver;
pub use service::{AnchorService, AnchorServiceConfig, AnchorWiring};

/// The base64 of DNSKEY keys (RFC 4034 section 2.2) and of the IANA trust anchor file (RFC
/// 7958): the standard alphabet with padding. Other programs write these texts, so non-zero
/// trailing bits are ignored, as RFC 4648 section 3.5 lets a decoder do.
const KEY_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    PAD.with_decode_allow_trailing_bits(true),
);
