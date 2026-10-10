//! The helper library for plugin authors in Rust.
//!
//! Implement [`Connector`] and the traits of the capabilities the manifest declares, then
//! hand them to a [`Plugin`] and call [`Plugin::run`] from `main`:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! use tenko_connect::{
//!     CallContext, Connector, ConnectorError, HealthReport, InventoryBatch, InventorySource,
//!     Cursor, Manifest, sdk::Plugin,
//! };
//!
//! struct Hosts;
//!
//! #[async_trait::async_trait]
//! impl Connector for Hosts {
//!     async fn check(&self, _ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
//!         Ok(HealthReport::healthy())
//!     }
//! }
//!
//! #[async_trait::async_trait]
//! impl InventorySource for Hosts {
//!     async fn poll(
//!         &self,
//!         _ctx: &CallContext,
//!         _cursor: Option<Cursor>,
//!     ) -> Result<InventoryBatch, ConnectorError> {
//!         Ok(InventoryBatch::complete(tenko_core::Timestamp::now(), Vec::new()))
//!     }
//! }
//!
//! fn main() -> std::process::ExitCode {
//!     let manifest = Manifest::parse(&std::fs::read("plugin.json").expect("read")).expect("manifest");
//!     let hosts = Arc::new(Hosts);
//!     Plugin::new(manifest, hosts.clone()).with_inventory(hosts).run()
//! }
//! ```
//!
//! [`Plugin::run`] performs the handshake on standard input and output, serves the declared
//! services on the endpoint the host named, refuses every call without the per-launch token,
//! converts between the protocol messages and the types of this crate, maps
//! [`ConnectorError`]s to gRPC statuses, and exits when the host asks (`Plugin.Shutdown`) or
//! when standard input closes. Log to standard error; the host forwards each line.

#[cfg(feature = "http-client")]
pub mod http;
mod services;

use std::{io, pin::Pin, process::ExitCode, sync::Arc, time::Duration};

use futures::FutureExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, BufReader},
    sync::Notify,
};
use tonic::{Request, Status, service::interceptor::InterceptedService};

use crate::{
    Actuator, Capability, Connector, InventorySource, MigrationSource, NetworkController,
    SUPPORTED_PROTOCOLS,
    handshake::{self, HANDSHAKE_FORMAT, HostHello, PluginHello, failure},
    manifest::{Manifest, ManifestError},
    proto::v1,
    status::{TOKEN_METADATA, token_refused},
    transport,
};

/// Largest message the plugin accepts or sends, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// How long in-flight calls may take to finish after a shutdown request.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// A plugin: its manifest and the implementations of its capabilities.
#[derive(Clone)]
pub struct Plugin {
    manifest: Manifest,
    connector: Arc<dyn Connector>,
    inventory: Option<Arc<dyn InventorySource>>,
    network: Option<Arc<dyn NetworkController>>,
    actuator: Option<Arc<dyn Actuator>>,
    migration: Option<Arc<dyn MigrationSource>>,
    options: ServeOptions,
}

impl std::fmt::Debug for Plugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Plugin")
            .field("name", &self.manifest.name)
            .field("version", &self.manifest.version)
            .field("inventory", &self.inventory.is_some())
            .field("network_controller", &self.network.is_some())
            .field("actuator", &self.actuator.is_some())
            .field("migration", &self.migration.is_some())
            .finish_non_exhaustive()
    }
}

/// How the plugin serves. Crate-private: the sample plugin turns safeguards off to act as
/// a misbehaving plugin for the conformance suite and the host tests.
#[derive(Debug, Clone)]
pub(crate) struct ServeOptions {
    /// Refuse calls without the per-launch token.
    pub(crate) check_token: bool,
    /// Exit when standard input closes.
    pub(crate) exit_on_stdin_close: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            check_token: true,
            exit_on_stdin_close: true,
        }
    }
}

/// Why a plugin stopped with an error.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// The plugin's own manifest is invalid.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The manifest declares a capability without an implementation.
    #[error("the manifest declares `{0}` but the plugin implements no such service")]
    MissingCapability(&'static str),
    /// The host's handshake line could not be read.
    #[error("the handshake from the host is not readable: {0}")]
    Handshake(String),
    /// The plugin refused the handshake (and told the host why).
    #[error("the handshake was refused ({code}): {message}")]
    Refused {
        /// The failure code sent to the host.
        code: &'static str,
        /// The detail sent to the host.
        message: String,
    },
    /// Writing to the host failed.
    #[error("writing to the host failed: {0}")]
    Io(#[from] io::Error),
    /// The gRPC server failed.
    #[error("the gRPC server failed: {0}")]
    Serve(#[from] tonic::transport::Error),
}

impl SdkError {
    /// The exit status for this error: 2 for a refused or unreadable handshake, 1 otherwise.
    pub fn exit_status(&self) -> u8 {
        match self {
            SdkError::Handshake(_) | SdkError::Refused { .. } => 2,
            _ => 1,
        }
    }
}

impl Plugin {
    /// A plugin with its manifest and its health check.
    pub fn new(manifest: Manifest, connector: Arc<dyn Connector>) -> Self {
        Self {
            manifest,
            connector,
            inventory: None,
            network: None,
            actuator: None,
            migration: None,
            options: ServeOptions::default(),
        }
    }

    /// Adds the inventory source (capability `inventory`, and `webhook`).
    #[must_use]
    pub fn with_inventory(mut self, inventory: Arc<dyn InventorySource>) -> Self {
        self.inventory = Some(inventory);
        self
    }

    /// Adds the network controller (capability `network_controller`).
    #[must_use]
    pub fn with_network_controller(mut self, network: Arc<dyn NetworkController>) -> Self {
        self.network = Some(network);
        self
    }

    /// Adds the actuator (capability `actuator`).
    #[must_use]
    pub fn with_actuator(mut self, actuator: Arc<dyn Actuator>) -> Self {
        self.actuator = Some(actuator);
        self
    }

    /// Adds the migration source (capability `migration`).
    #[must_use]
    pub fn with_migration(mut self, migration: Arc<dyn MigrationSource>) -> Self {
        self.migration = Some(migration);
        self
    }

    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    #[must_use]
    pub(crate) fn with_options(mut self, options: ServeOptions) -> Self {
        self.options = options;
        self
    }

    /// Runs the plugin on standard input and output until the host stops it, and returns
    /// the exit status for `main`. Errors are printed to standard error.
    pub fn run(self) -> ExitCode {
        ExitCode::from(self.run_status())
    }

    /// [`run`](Plugin::run) with the exit status as a number: 0 after a shutdown, 2 for a
    /// refused or unreadable handshake, 1 for other errors.
    pub fn run_status(self) -> u8 {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("ERROR the plugin cannot start its runtime: {error}");
                return 1;
            }
        };
        let outcome = runtime.block_on(self.serve_stdio());
        // Standard input is read by a blocking thread that may still wait for the host.
        runtime.shutdown_timeout(Duration::from_millis(100));
        match outcome {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("ERROR {error}");
                error.exit_status()
            }
        }
    }

    /// Serves on standard input and output; see [`serve`](Plugin::serve).
    ///
    /// # Errors
    ///
    /// [`SdkError`].
    pub async fn serve_stdio(self) -> Result<(), SdkError> {
        self.serve(tokio::io::stdin(), tokio::io::stdout()).await
    }

    /// Performs the handshake on `input` and `output`, serves gRPC on the endpoint the
    /// host named, and returns when the host asks the plugin to shut down or `input`
    /// closes.
    ///
    /// # Errors
    ///
    /// [`SdkError`] for an invalid manifest, a missing implementation, a refused or
    /// unreadable handshake, or a server failure.
    pub async fn serve<R, W>(self, input: R, mut output: W) -> Result<(), SdkError>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send,
    {
        self.manifest.validate()?;
        self.check_capabilities()?;
        let mut input = BufReader::new(input);
        let hello: HostHello = handshake::read_line(&mut input, |line| {
            eprintln!("WARN ignored before the handshake: {line}");
        })
        .await
        .map_err(|error| SdkError::Handshake(error.to_string()))?;

        let protocol = match self.accept(&hello) {
            Ok(protocol) => protocol,
            Err((code, message, supported)) => {
                handshake::write_line(&mut output, &PluginHello::failed(code, &message, supported))
                    .await?;
                return Err(SdkError::Refused { code, message });
            }
        };
        let incoming = match transport::listen(&hello.endpoint) {
            Ok(incoming) => incoming,
            Err(error) => {
                let message = format!("cannot serve on {}: {error}", hello.endpoint);
                handshake::write_line(
                    &mut output,
                    &PluginHello::failed(failure::ENDPOINT, &message, Vec::new()),
                )
                .await?;
                return Err(SdkError::Refused {
                    code: failure::ENDPOINT,
                    message,
                });
            }
        };

        let shutdown = Arc::new(Notify::new());
        let router = self.router(&hello.token, Arc::clone(&shutdown));
        handshake::write_line(
            &mut output,
            &PluginHello::ready(protocol, self.manifest.clone()),
        )
        .await?;
        drop(output);

        let stdin_closed = if self.options.exit_on_stdin_close {
            async move {
                let mut sink = [0u8; 256];
                loop {
                    match input.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            }
            .boxed()
        } else {
            std::future::pending().boxed()
        };
        let stop = {
            let shutdown = Arc::clone(&shutdown);
            async move {
                tokio::select! {
                    () = shutdown.notified() => {}
                    () = stdin_closed => {}
                }
            }
        };
        serve_until(router, incoming, stop).await
    }

    /// Checks the manifest's capabilities against the implementations.
    fn check_capabilities(&self) -> Result<(), SdkError> {
        for capability in &self.manifest.capabilities {
            let present = match capability {
                Capability::Inventory | Capability::Webhook => self.inventory.is_some(),
                Capability::NetworkController => self.network.is_some(),
                Capability::Actuator => self.actuator.is_some(),
                Capability::Migration => self.migration.is_some(),
            };
            if !present {
                return Err(SdkError::MissingCapability(capability.as_str()));
            }
        }
        Ok(())
    }

    /// Accepts the host's hello: the handshake format, the plugin name, the token shape and
    /// a common protocol version.
    fn accept(&self, hello: &HostHello) -> Result<u32, (&'static str, String, Vec<u32>)> {
        if hello.tenko_plugin != HANDSHAKE_FORMAT {
            return Err((
                failure::STARTUP,
                format!(
                    "handshake format {} is not supported; this plugin reads {HANDSHAKE_FORMAT}",
                    hello.tenko_plugin
                ),
                Vec::new(),
            ));
        }
        if !hello.plugin.is_empty() && hello.plugin != self.manifest.name {
            return Err((
                failure::WRONG_PLUGIN,
                format!(
                    "the host expected plugin `{}`, this is `{}`",
                    hello.plugin, self.manifest.name
                ),
                Vec::new(),
            ));
        }
        if !handshake::is_token(&hello.token) {
            return Err((
                failure::STARTUP,
                "the per-launch token is not 64 lowercase hexadecimal characters".to_owned(),
                Vec::new(),
            ));
        }
        let ours: Vec<u32> = self
            .manifest
            .protocol
            .iter()
            .copied()
            .filter(|version| SUPPORTED_PROTOCOLS.contains(version))
            .collect();
        // The refusal names what the manifest declares; this SDK serves only the versions
        // it implements.
        ours.iter()
            .copied()
            .filter(|version| hello.protocol.contains(version))
            .max()
            .ok_or_else(|| {
                (
                    failure::PROTOCOL_MISMATCH,
                    format!(
                        "no common protocol version: the host speaks {:?}, plugin `{}` speaks {:?}",
                        hello.protocol, self.manifest.name, self.manifest.protocol
                    ),
                    self.manifest.protocol.clone(),
                )
            })
    }

    /// The gRPC router with every implemented service behind the token check.
    fn router(&self, token: &str, shutdown: Arc<Notify>) -> tonic::transport::server::Router {
        let check = TokenCheck {
            token: Arc::from(token),
            enforce: self.options.check_token,
        };
        let plugin = services::PluginService {
            name: self.manifest.name.clone(),
            version: self.manifest.version.clone(),
            connector: Arc::clone(&self.connector),
            shutdown,
        };
        let declared = |capability| self.manifest.has(capability);
        let mut router = tonic::transport::Server::builder().add_service(InterceptedService::new(
            v1::plugin_server::PluginServer::new(plugin)
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
            check.clone(),
        ));
        if let Some(inventory) = self
            .inventory
            .clone()
            .filter(|_| declared(Capability::Inventory))
        {
            router = router.add_service(InterceptedService::new(
                v1::inventory_server::InventoryServer::new(services::InventoryService {
                    source: inventory,
                    webhooks: declared(Capability::Webhook),
                })
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
                check.clone(),
            ));
        }
        if let Some(network) = self
            .network
            .clone()
            .filter(|_| declared(Capability::NetworkController))
        {
            router = router.add_service(InterceptedService::new(
                v1::network_controller_server::NetworkControllerServer::new(
                    services::NetworkService(network),
                )
                .max_decoding_message_size(MAX_MESSAGE_BYTES)
                .max_encoding_message_size(MAX_MESSAGE_BYTES),
                check.clone(),
            ));
        }
        if let Some(actuator) = self
            .actuator
            .clone()
            .filter(|_| declared(Capability::Actuator))
        {
            router = router.add_service(InterceptedService::new(
                v1::actuator_server::ActuatorServer::new(services::ActuatorService(actuator))
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
                check.clone(),
            ));
        }
        if let Some(migration) = self
            .migration
            .clone()
            .filter(|_| declared(Capability::Migration))
        {
            router = router.add_service(InterceptedService::new(
                v1::migration_server::MigrationServer::new(services::MigrationService(migration))
                    .max_decoding_message_size(MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(MAX_MESSAGE_BYTES),
                check,
            ));
        }
        router
    }
}

/// Serves until `stop` completes, then lets in-flight calls finish for at most
/// [`SHUTDOWN_GRACE`].
async fn serve_until(
    router: tonic::transport::server::Router,
    incoming: transport::Incoming,
    stop: impl std::future::Future<Output = ()> + Send,
) -> Result<(), SdkError> {
    let (trigger, triggered) = tokio::sync::oneshot::channel::<()>();
    let server: Pin<
        Box<dyn std::future::Future<Output = Result<(), tonic::transport::Error>> + Send>,
    > = Box::pin(router.serve_with_incoming_shutdown(incoming, async move {
        let _ = triggered.await;
    }));
    let mut server = server;
    tokio::select! {
        result = &mut server => return result.map_err(SdkError::from),
        () = stop => {}
    }
    let _ = trigger.send(());
    match tokio::time::timeout(SHUTDOWN_GRACE, server).await {
        Ok(result) => result.map_err(SdkError::from),
        // Calls that do not finish in time are abandoned with the process.
        Err(_) => Ok(()),
    }
}

/// The per-launch token check in front of every service.
#[derive(Clone)]
struct TokenCheck {
    token: Arc<str>,
    enforce: bool,
}

impl tonic::service::Interceptor for TokenCheck {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        if !self.enforce {
            return Ok(request);
        }
        match request.metadata().get(TOKEN_METADATA) {
            Some(value) if handshake::token_matches(&self.token, value.as_bytes()) => Ok(request),
            _ => Err(token_refused()),
        }
    }
}
