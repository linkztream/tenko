//! The `Commands` service: commands to nodes and their reports back (SCAN-09). The
//! records and the stream live in [`crate::node_sync::commands`]; this file authenticates
//! the caller and maps the answers.

use std::{pin::Pin, sync::Arc};

use futures::Stream;
use tokio::sync::mpsc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::{
    error::ClusterError,
    node_sync::{
        codes,
        commands::{self, Report},
    },
    proto::v1,
    server::{ClusterService, peer_of, status_of},
};

type CommandStream = Pin<Box<dyn Stream<Item = Result<v1::Command, Status>> + Send>>;

#[tonic::async_trait]
impl v1::commands_server::Commands for ClusterService {
    type SubscribeStream = CommandStream;

    async fn subscribe(
        &self,
        request: Request<v1::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let after = request.into_inner().after;
        let after = if after.is_empty() {
            None
        } else {
            Some(after.parse::<Uuid>().map_err(|_| {
                status_of(&ClusterError::new(
                    codes::COMMAND_INVALID,
                    400,
                    "`after` is not a command id",
                ))
            })?)
        };
        let (tx, mut rx) = mpsc::channel(16);
        tokio::spawn(commands::serve_subscribe(
            Arc::clone(self.registry.node_sync().store()),
            record.id,
            after,
            tx,
        ));
        let stream: CommandStream = Box::pin(futures::stream::poll_fn(move |cx| rx.poll_recv(cx)));
        Ok(Response::new(stream))
    }

    async fn report(
        &self,
        request: Request<v1::CommandEvent>,
    ) -> Result<Response<v1::ReportResponse>, Status> {
        let peer = peer_of(&request)?;
        let record = self.authenticate(&peer).await?;
        let report = Report::from_proto(request.get_ref()).map_err(|error| status_of(&error))?;
        let stored = commands::apply_report(
            self.registry.node_sync().store().as_ref(),
            record.id,
            &report,
        )
        .await
        .map_err(|error| status_of(&error))?;
        tracing::debug!(
            node = %record.id,
            command = %stored.id,
            state = %stored.state,
            progress = stored.progress,
            "command report"
        );
        Ok(Response::new(v1::ReportResponse {}))
    }
}
