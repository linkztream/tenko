//! Kerberos for Tenko DDI with no Kerberos library (ADR 0026 point 1, identity plan
//! section 4.2): the GSS-API acceptor that secure dynamic updates from Windows clients and
//! domain controllers (GSS-TSIG, RFC 3645; DNS-28, CON-03) and Kerberos sign-in to the web
//! UI (IAM-13) use, and the client half the controller uses to adopt, test and rotate the
//! service account.
//!
//! | Module | What |
//! |---|---|
//! | [`acceptor`] | The GSS-API acceptor: SPNEGO with both Kerberos OIDs and raw Kerberos tokens, the AP-REQ checks, the PAC, the replay cache and the AP-REP |
//! | [`cipher`] | RFC 3961 and RFC 3962 for the two AES encryption types: n-fold, the derived keys, string-to-key with the AD salts, AES-CTS, encryption and the checksum |
//! | [`client`] | The controller's Kerberos client: the AS exchange with pre-authentication, the TGS exchange and the change-password protocol of RFC 3244, over UDP with the TCP fallback |
//! | [`der`] | The DER codec of the Kerberos structures (RFC 4120 section 5), the GSS-API framing and SPNEGO |
//! | [`keys`] | The key set of the service account and the selection by a ticket's encryption type and key version |
//! | [`keytab`] | The import parser of the MIT keytab format, version 2 |
//! | [`mic`] | RFC 4121 MIC tokens over the context key |
//! | [`pac`] | The PAC reader of [MS-PAC]: the server signature and the SIDs |
//! | [`replay`] | The replay cache shared by an acceptor's negotiations |
//!
//! The only cryptography is `aws-lc-rs`. RC4, DES and 3DES are not implemented and NTLM is
//! never chosen (ADR 0026 point 3). The crate reads no clock and no file of its own: the
//! caller hands it the time, the keys and the keytab octets.

#![forbid(unsafe_code)]

pub mod acceptor;
pub mod cipher;
pub mod client;
pub mod der;
#[doc(hidden)]
pub mod fuzzing;
pub mod keys;
pub mod keytab;
pub mod mic;
pub mod pac;
pub mod replay;

#[cfg(test)]
pub(crate) mod fixtures;
