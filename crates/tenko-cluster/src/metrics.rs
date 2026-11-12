//! Metrics between controllers (OPS-20): the `Metrics.Snapshot` call that lets the start
//! page of any controller show the whole cluster, and the `Metrics.History` call that brings
//! the history of a peer's dashboard tiles.
//!
//! The callee answers its newest one-second sample, encoded by the API layer
//! ([`MetricsSource`], set on the node registry by the server binary with
//! [`NodeRegistry::set_metrics_source`](crate::registry::NodeRegistry::set_metrics_source));
//! this crate carries the bytes and does not read them. The caller is the publisher of the
//! `metrics` topic, once per second per peer, through [`fetch`]: a deadline of its own, the
//! peer transport's connection, and the answer `UNIMPLEMENTED` of an older build reported
//! as [`PeerReply::Unsupported`].
//!
//! The history (dashboard history plan, section 2): the answer to `Metrics.Snapshot` also
//! carries the buckets of the callee's tiers that closed in its last two ticks
//! ([`EncodedSample::closed`], empty from an older build), and [`fetch_history`] reads all of
//! a peer's tiers once, when the peer first appears and when it answers again after missing
//! calls. A source without a history ([`MetricsSource::history`] answers `None`, the default)
//! makes the callee answer `UNIMPLEMENTED`, as a build before the history does, and the caller
//! reports both as [`HistoryReply::Unsupported`].
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
/// `MetricsSample`), and of the tiers in [`v1::MetricsSnapshot::closed`] and
/// [`v1::MetricsHistory::payload`] (CBOR of the API's `ControllerTiers`).
pub const SAMPLE_ENCODING: &str = "cbor/1";
/// The largest answer the caller accepts, for either call. A whole history of 25 figures is
/// about 230 KB.
const MAX_ANSWER_BYTES: usize = 1024 * 1024;

/// One controller's sample as it travels between controllers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSample {
    /// The controller that took it.
    pub node: NodeId,
    /// When it was taken, by that controller's clock.
    pub at: Timestamp,
    /// The encoding of `payload` and `closed`, such as [`SAMPLE_ENCODING`].
    pub encoding: String,
    /// The sample.
    pub payload: Vec<u8>,
    /// The buckets of the controller's history that closed in its last two ticks, with its
    /// start (always set by a controller with the history); empty from an older build.
    pub closed: Vec<u8>,
}

impl EncodedSample {
    /// The protobuf message.
    pub fn to_proto(&self) -> v1::MetricsSnapshot {
        v1::MetricsSnapshot {
            node_id: self.node.0,
            at: Some(timestamp_to_proto(self.at)),
            encoding: self.encoding.clone(),
            payload: self.payload.clone(),
            closed: self.closed.clone(),
        }
    }

    /// From the protobuf message; `None` without a valid time.
    pub fn from_proto(message: v1::MetricsSnapshot) -> Option<Self> {
        Some(Self {
            node: NodeId(message.node_id),
            at: message.at.as_ref().and_then(timestamp_from_proto)?,
            encoding: message.encoding,
            payload: message.payload,
            closed: message.closed,
        })
    }
}

/// One controller's history of the dashboard's figures as it travels between controllers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedHistory {
    /// The controller whose history it is.
    pub node: NodeId,
    /// The end of the newest sample folded into it, by that controller's clock.
    pub at: Timestamp,
    /// The encoding of `payload`, such as [`SAMPLE_ENCODING`].
    pub encoding: String,
    /// The history.
    pub payload: Vec<u8>,
}

impl EncodedHistory {
    /// The protobuf message.
    pub fn to_proto(&self) -> v1::MetricsHistory {
        v1::MetricsHistory {
            node_id: self.node.0,
            at: Some(timestamp_to_proto(self.at)),
            encoding: self.encoding.clone(),
            payload: self.payload.clone(),
        }
    }

    /// From the protobuf message; `None` without a valid time.
    pub fn from_proto(message: v1::MetricsHistory) -> Option<Self> {
        Some(Self {
            node: NodeId(message.node_id),
            at: message.at.as_ref().and_then(timestamp_from_proto)?,
            encoding: message.encoding,
            payload: message.payload,
        })
    }
}

/// Where `Metrics.Snapshot` and `Metrics.History` read this controller's figures.
pub trait MetricsSource: Send + Sync + 'static {
    /// The newest sample; `None` while there is none.
    fn current(&self) -> BoxFuture<'_, Option<EncodedSample>>;

    /// This controller's whole history of the dashboard's figures, encoded for the call: a
    /// peer asks only when it first sees this controller, after a missed call and after a
    /// restart, never per second or per subscription. `None` when it keeps none, which
    /// `Metrics.History` answers with `UNIMPLEMENTED`. The default keeps none.
    fn history(&self) -> BoxFuture<'_, Option<EncodedHistory>> {
        Box::pin(async { None })
    }
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

/// What a peer answered to `Metrics.History`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryReply {
    /// Its history.
    History(EncodedHistory),
    /// It keeps no history (an older build): the call answered `UNIMPLEMENTED`. The caller
    /// combines it as a missing controller.
    Unsupported,
    /// No answer within the deadline, or an error.
    Failed(String),
}

/// Asks controller `node` for its newest sample through `network`, within `deadline` (the
/// connection included).
pub async fn fetch(network: &PeerNetwork, node: NodeId, deadline: Duration) -> PeerReply {
    let call = async {
        let mut client = client(network, node).await?;
        let answer = crate::trace::rpc(Some(node), crate::trace::METRICS, "Snapshot", async {
            let mut request = Request::new(v1::SnapshotRequest {});
            request.set_timeout(deadline);
            crate::trace::inject(&mut request);
            client.snapshot(request).await
        })
        .await;
        Ok::<_, String>(answer)
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

/// Asks controller `node` for its history through `network`, within `deadline` (the
/// connection included).
pub async fn fetch_history(
    network: &PeerNetwork,
    node: NodeId,
    deadline: Duration,
) -> HistoryReply {
    let call = async {
        let mut client = client(network, node).await?;
        let answer = crate::trace::rpc(Some(node), crate::trace::METRICS, "History", async {
            let mut request = Request::new(v1::HistoryRequest {});
            request.set_timeout(deadline);
            crate::trace::inject(&mut request);
            client.history(request).await
        })
        .await;
        Ok::<_, String>(answer)
    };
    match tokio::time::timeout(deadline, call).await {
        Err(_) => HistoryReply::Failed(format!("no answer within {} ms", deadline.as_millis())),
        Ok(Err(detail)) => HistoryReply::Failed(detail),
        Ok(Ok(Err(status))) if status.code() == tonic::Code::Unimplemented => {
            HistoryReply::Unsupported
        }
        Ok(Ok(Err(status))) => HistoryReply::Failed(status.message().to_owned()),
        Ok(Ok(Ok(answer))) => match EncodedHistory::from_proto(answer.into_inner()) {
            Some(history) => HistoryReply::History(history),
            None => HistoryReply::Failed("the answer has no valid time".to_owned()),
        },
    }
}

/// A client of the `Metrics` service of `node`, with the answer limit.
async fn client(
    network: &PeerNetwork,
    node: NodeId,
) -> Result<v1::metrics_client::MetricsClient<tonic::transport::Channel>, String> {
    let endpoint = network
        .endpoint(node, None)
        .await
        .map_err(|error| error.detail().to_owned())?;
    let channel = network
        .channel(&endpoint)
        .await
        .map_err(|error| error.detail().to_owned())?;
    Ok(v1::metrics_client::MetricsClient::new(channel).max_decoding_message_size(MAX_ANSWER_BYTES))
}
