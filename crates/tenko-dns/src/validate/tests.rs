//! The validator's tests: the published signature vectors (RFC 5702, RFC 6605, RFC 8080),
//! the proofs against the example zones of RFC 4035 appendix A and RFC 5155 appendix A,
//! and the chain walk over scripted authorities.

mod chain;
mod proofs;
mod vectors;
