//! The protocol code of package `tenko.cluster.v1` (messages, clients and servers),
//! compiled from `proto/tenko/cluster/v1/*.proto` by the build script.

/// Messages and services of protocol major 1.
#[allow(
    missing_docs,
    clippy::all,
    clippy::pedantic,
    reason = "compiled from the protocol definitions by the build script"
)]
pub mod v1 {
    tonic::include_proto!("tenko.cluster.v1");
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::v1;

    #[test]
    fn messages_round_trip_and_unknown_fields_are_ignored() {
        let request = v1::HelloRequest {
            majors: vec![1],
            version: "0.0.1".to_owned(),
            roles: vec!["probe".to_owned()],
        };
        let mut bytes = request.encode_to_vec();
        assert_eq!(
            v1::HelloRequest::decode(bytes.as_slice()).expect("decode"),
            request
        );
        // A field number this version does not know (99, varint) is skipped: the additive
        // evolution rule of the protocol.
        bytes.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert_eq!(
            v1::HelloRequest::decode(bytes.as_slice()).expect("decode"),
            request
        );
    }
}
