//! The protocol code of package `tenko.connect.v1` (messages, clients and servers),
//! compiled from `proto/tenko/connect/v1/*.proto` by the build script.
//!
//! Most code works with the domain types of this crate; [`crate::convert`] maps between
//! them and these messages.

/// Messages and services of protocol version 1.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    reason = "compiled from the protocol definitions by the build script"
)]
pub mod v1 {
    tonic::include_proto!("tenko.connect.v1");
}

use zeroize::Zeroize;

/// Secret values are wiped when the message is dropped, on the host after the request is
/// encoded and in the plugin after the call. Buffers inside the gRPC library are released
/// without wiping; the values never stay in a long-lived structure.
impl Drop for v1::Secret {
    fn drop(&mut self) {
        self.value.zeroize();
        self.purpose.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::v1;

    #[test]
    fn messages_round_trip_and_unknown_fields_are_ignored() {
        let request = v1::PollRequest {
            context: Some(v1::CallContext {
                instance_id: "0190d1c2-0000-7000-8000-000000000001".to_owned(),
                settings_json: "{}".to_owned(),
                secrets: vec![v1::Secret {
                    purpose: "api_key".to_owned(),
                    value: b"value".to_vec(),
                }],
                request_id: "r1".to_owned(),
            }),
            cursor: Some("c1".to_owned()),
        };
        let mut bytes = request.encode_to_vec();
        assert_eq!(
            v1::PollRequest::decode(bytes.as_slice()).expect("decode"),
            request
        );
        // A field number this version does not know (99, varint) is skipped: the additive
        // evolution rule of the protocol.
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert_eq!(
            v1::PollRequest::decode(bytes.as_slice()).expect("decode"),
            request
        );
    }
}
