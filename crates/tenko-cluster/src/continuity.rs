//! Key continuity of a controller's cluster certificates.
//!
//! A controller that renews its certificate signs the new public key with the key of the
//! certificate it renews: a [`Step`], written in the renewal's own batch to
//! [`CONTINUITY`] (keyed by the new serial). A store of another history that forked before
//! a renewal holds an older serial of that controller and never sees the step; a record
//! the controller signs later carries the chain of steps ([`chain_of`]), and a receiver
//! takes the signer as one its record holds when the chain starts at a certificate it
//! holds and every step verifies ([`Chain::reaches`]). A certificate minted with the CA's
//! key has no step signed by a key the receiver holds, so it reaches nothing.
//!
//! A chain is bounded ([`MAX_STEPS`], [`MAX_BYTES`]): the signer cuts it to its newest
//! steps. A receiver that holds none of the chain's certificates refuses the record and
//! shows it as unverified (`cluster.recover.unverified_history`); it never stops on a chain
//! it cannot check, or anyone holding the CA's key could stop it.
//!
//! The rotation of a first controller's key out of the vault is a renewal like any other:
//! the vault key signs the step. A new identity that no earlier key can sign (a restore on a
//! new host) starts a new chain; a history that forked before it cannot follow it.

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _,
    UnparsedPublicKey,
};
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use tenko_core::{NodeId, serde_util::HexBytes, table::TableDef};
use tenko_store::{ReadView, ReadViewExt as _};
use tenko_vault::SecretBytes;

use crate::{error::ClusterError, mtls::PeerIdentity};

/// The steps of every controller's renewals, keyed by the new certificate's serial.
pub const CONTINUITY: TableDef<String, Step> = TableDef::new("cluster.continuity");

/// What a step's signature covers before the node id and the new public key: a fixed
/// context, so that no other signature by the same key passes for a step.
pub const CONTEXT: &[u8] = b"tenko certificate continuity v1\0";

/// The most steps a chain carries.
pub const MAX_STEPS: usize = 4;

/// The largest chain, in bytes of DER and signatures: with the record it stays within
/// [`crate::generation::MAX_RECORD_BYTES`], so the newest record always fits an offer.
pub const MAX_BYTES: usize = 6 * 1024;

/// One renewal: the certificate renewed, the new one, and the renewed key's signature over
/// [`CONTEXT`], the node id (8 bytes, big-endian) and the new key's public point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The certificate renewed, DER.
    pub previous: HexBytes,
    /// The new certificate, DER.
    pub next: HexBytes,
    /// ECDSA P-256 SHA-256 (ASN.1 DER) by the renewed key.
    pub signature: HexBytes,
}

/// What the renewed key signs for a new key.
fn message(node: NodeId, point: &[u8]) -> Vec<u8> {
    [CONTEXT, &node.0.to_be_bytes(), point].concat()
}

/// The public point of a certificate.
fn point(der: &[u8]) -> Result<Vec<u8>, ClusterError> {
    use x509_parser::prelude::FromDer as _;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der)
        .map_err(|error| invalid(format!("a certificate of the chain: {error}")))?;
    Ok(cert.public_key().subject_public_key.data.to_vec())
}

fn invalid(detail: impl Into<String>) -> ClusterError {
    ClusterError::new("cluster.continuity.invalid", 403, detail)
}

/// The renewed key's signature for the new key `next_key` (PKCS#8) of `node`.
///
/// # Errors
///
/// `cluster.continuity.invalid` for a key that is not an ECDSA P-256 key.
pub fn attest(
    node: NodeId,
    previous_key: &SecretBytes,
    next_key: &SecretBytes,
) -> Result<Vec<u8>, ClusterError> {
    let pair = |key: &SecretBytes| {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key.expose())
            .map_err(|error| invalid(format!("not a controller key: {error}")))
    };
    let next = pair(next_key)?;
    let signature = pair(previous_key)?
        .sign(
            &aws_lc_rs::rand::SystemRandom::new(),
            &message(node, next.public_key().as_ref()),
        )
        .map_err(|error| invalid(format!("signing failed: {error}")))?;
    Ok(signature.as_ref().to_vec())
}

impl Step {
    /// The step from `previous` to `next` of `node` with `signature` ([`attest`]), checked.
    ///
    /// # Errors
    ///
    /// `cluster.continuity.invalid` when the signature does not verify with the renewed
    /// key over the new certificate's key.
    pub fn new(
        node: NodeId,
        previous: &CertificateDer<'_>,
        next: &CertificateDer<'_>,
        signature: Vec<u8>,
    ) -> Result<Self, ClusterError> {
        let step = Self {
            previous: HexBytes(previous.to_vec()),
            next: HexBytes(next.to_vec()),
            signature: HexBytes(signature),
        };
        step.verify(node)?;
        Ok(step)
    }

    fn verify(&self, node: NodeId) -> Result<(), ClusterError> {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point(&self.previous.0)?)
            .verify(&message(node, &point(&self.next.0)?), &self.signature.0)
            .map_err(|_| invalid("a step of the certificate chain does not verify"))
    }

    fn size(&self) -> usize {
        self.previous.0.len() + self.next.0.len() + self.signature.0.len()
    }
}

/// The chain of `serial`'s renewals in `view`, oldest first, cut to its newest
/// [`MAX_STEPS`] and [`MAX_BYTES`]; empty when `serial` was never renewed into.
///
/// # Errors
///
/// A store error.
pub fn chain_of(view: &dyn ReadView, serial: &str) -> Result<Vec<Step>, ClusterError> {
    chain(serial, |next| {
        Ok(view
            .get_typed(&CONTINUITY, &next.to_owned())?
            .map(|(step, _)| step))
    })
}

/// [`chain_of`] over any lookup of the step into a serial.
///
/// # Errors
///
/// The lookup's.
pub fn chain(
    serial: &str,
    lookup: impl Fn(&str) -> Result<Option<Step>, ClusterError>,
) -> Result<Vec<Step>, ClusterError> {
    let mut steps = Vec::new();
    let mut bytes = 0;
    let mut next = serial.to_owned();
    while steps.len() < MAX_STEPS {
        let Some(step) = lookup(&next)? else {
            break;
        };
        bytes += step.size();
        if bytes > MAX_BYTES {
            break;
        }
        let Ok(previous) = PeerIdentity::from_der(&step.previous.0) else {
            break;
        };
        next = previous.serial;
        steps.push(step);
    }
    steps.reverse();
    Ok(steps)
}

/// The certificates a receiver holds of one controller: serial and SHA-256 of the DER.
pub type Held = std::collections::BTreeMap<String, String>;

/// A chain of steps as a record carries it, oldest first.
pub struct Chain<'a>(pub &'a [Step]);

impl Chain<'_> {
    /// Whether the chain leads `node` from a certificate `held` holds (same serial and
    /// SHA-256) to `leaf`, every step verifying and no certificate on the way revoked or
    /// another node's. The chain's first certificate a receiver holds starts it: the
    /// steps before it are not needed.
    pub fn reaches(
        &self,
        node: NodeId,
        held: &Held,
        revoked: &dyn Fn(&str) -> bool,
        leaf: &[u8],
    ) -> bool {
        let steps = self.0;
        if steps.len() > MAX_STEPS || steps.iter().map(Step::size).sum::<usize>() > MAX_BYTES {
            return false;
        }
        let Some(start) = steps.iter().position(|step| {
            PeerIdentity::from_der(&step.previous.0).is_ok_and(|previous| {
                previous.node == node
                    && held.get(&previous.serial) == Some(&previous.sha256)
                    && !revoked(&previous.serial)
            })
        }) else {
            return false;
        };
        let mut at = steps[start].previous.0.as_slice();
        for step in &steps[start..] {
            let fits = step.previous.0 == at
                && PeerIdentity::from_der(&step.next.0)
                    .is_ok_and(|next| next.node == node && !revoked(&next.serial))
                && step.verify(node).is_ok();
            if !fits {
                return false;
            }
            at = step.next.0.as_slice();
        }
        at == leaf
    }
}

#[cfg(test)]
mod tests;
