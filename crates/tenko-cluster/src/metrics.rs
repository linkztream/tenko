//! Metrics between controllers (OPS-20): the `Metrics.Snapshot` call that lets the start
//! page of any controller show the whole cluster.
//!
//! The callee answers its newest one-second sample, encoded by the API layer
//! ([`MetricsSource`], set on the node registry by the server binary with
//! [`NodeRegistry::set_metrics_source`](crate::registry::NodeRegistry::set_metrics_source));
//! this crate carries the bytes and does not read them. The caller is the publisher of the
//! `metrics` topic, once per second per peer, through [`fetch`]: a deadline of its own, the
//! peer transport's connection, and the answer `UNIMPLEMENTED` of an older build reported
//! as [`PeerReply::Unsupported`].
//!
//! A caller must hold a controller certificate. When the caller has a node record (every
//! controller that joined), the record must name the role and hold the certificate; the
//! first controller's own certificate has none and is accepted on the TLS verification
//! alone, as the `Raft` service accepts it.

use std::time::Duration;

use futures::future::BoxFuture;
use tenko_core::{NodeId, Timestamp};
use tonic::Request;

use crate::{
    peers::PeerNetwork,
    probe::{timestamp_from_proto, timestamp_to_proto},
    proto::v1,
};

/// The encoding of a sample in [`v1::MetricsSnapshot::payload`] (CBOR of the API's
/// `MetricsSample`).
pub const SAMPLE_ENCODING: &str = "cbor/1";
/// The largest answer the caller accepts.
const MAX_ANSWER_BYTES: usize = 1024 * 1024;

/// One controller's sample as it travels between controllers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSample {
    /// The controller that took it.
    pub node: NodeId,
    /// When it was taken, by that controller's clock.
    pub at: Timestamp,
    /// The encoding of `payload`, such as [`SAMPLE_ENCODING`].
    pub encoding: String,
    /// The sample.
    pub payload: Vec<u8>,
}

impl EncodedSample {
    /// The protobuf message.
    pub fn to_proto(&self) -> v1::MetricsSnapshot {
        v1::MetricsSnapshot {
            node_id: self.node.0,
            at: Some(timestamp_to_proto(self.at)),
            encoding: self.encoding.clone(),
            payload: self.payload.clone(),
        }
    }

    /// From the protobuf message; `None` without a valid time.
    pub fn from_proto(message: v1::MetricsSnapshot) -> Option<Self> {
        Some(Self {
            node: NodeId(message.node_id),
            at: message.at.as_ref().and_then(timestamp_from_proto)?,
            encoding: message.encoding,
            payload: message.payload,
        })
    }
}

/// Where `Metrics.Snapshot` reads this controller's newest sample.
pub trait MetricsSource: Send + Sync + 'static {
    /// The newest sample; `None` while there is none.
    fn current(&self) -> BoxFuture<'_, Option<EncodedSample>>;
}

/// What a peer answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerReply {
    /// Its newest sample.
    Sample(EncodedSample),
    /// It runs an older build: the call answered `UNIMPLEMENTED`.
    Unsupported,
    /// No answer within the deadline, or an error.
    Failed(String),
}

/// Asks controller `node` for its newest sample through `network`, within `deadline` (the
/// connection included).
pub async fn fetch(network: &PeerNetwork, node: NodeId, deadline: Duration) -> PeerReply {
    let call = async {
        let endpoint = network
            .endpoint(node, None)
            .await
            .map_err(|error| error.detail().to_owned())?;
        let channel = network
            .channel(&endpoint)
            .await
            .map_err(|error| error.detail().to_owned())?;
        let mut client = v1::metrics_client::MetricsClient::new(channel)
            .max_decoding_message_size(MAX_ANSWER_BYTES);
        let mut request = Request::new(v1::SnapshotRequest {});
        request.set_timeout(deadline);
        Ok::<_, String>(client.snapshot(request).await)
    };
    match tokio::time::timeout(deadline, call).await {
        Err(_) => PeerReply::Failed(format!("no answer within {} ms", deadline.as_millis())),
        Ok(Err(detail)) => PeerReply::Failed(detail),
        Ok(Ok(Err(status))) if status.code() == tonic::Code::Unimplemented => {
            PeerReply::Unsupported
        }
        Ok(Ok(Err(status))) => PeerReply::Failed(status.message().to_owned()),
        Ok(Ok(Ok(answer))) => match EncodedSample::from_proto(answer.into_inner()) {
            Some(sample) => PeerReply::Sample(sample),
            None => PeerReply::Failed("the answer has no valid time".to_owned()),
        },
    }
}
