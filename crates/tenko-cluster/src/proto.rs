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
            capabilities: Vec::new(),
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

    #[test]
    fn the_fields_added_to_hello_round_trip_and_are_empty_from_an_old_peer() {
        let request = v1::HelloRequest {
            majors: vec![1],
            version: "0.0.1".to_owned(),
            roles: vec!["probe".to_owned()],
            capabilities: vec!["config-sync".to_owned()],
        };
        let response = v1::HelloResponse {
            major: 1,
            majors: vec![1],
            version: "0.0.1".to_owned(),
            node_id: 1001,
            heartbeat_secs: 10,
            server_time: None,
            capabilities: vec!["config-sync".to_owned()],
            endpoints: vec!["10.0.0.1:8444".to_owned(), "10.0.0.2:8444".to_owned()],
        };
        assert_eq!(
            v1::HelloRequest::decode(request.encode_to_vec().as_slice()).expect("decode"),
            request
        );
        assert_eq!(
            v1::HelloResponse::decode(response.encode_to_vec().as_slice()).expect("decode"),
            response
        );
        // A peer that predates the new fields sends only field 1 (major = 1): the rest
        // decodes as empty.
        let old = v1::HelloResponse::decode([0x08, 0x01].as_slice()).expect("decode");
        assert_eq!(old.major, 1);
        assert!(old.capabilities.is_empty() && old.endpoints.is_empty());
    }
}
