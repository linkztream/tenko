# Writing a Tenko connector plugin

A Tenko connector plugin is a separate program that connects Tenko DDI to one kind of external system: a hypervisor, a network controller, a home automation hub, a DHCP or DNS server to migrate from. Tenko starts the plugin, supervises it and calls it over a versioned gRPC protocol. This guide is for someone who writes a plugin, in any language, and has not read Tenko's code. It describes everything around the protocol messages: the process structure, the handshake, the manifest, the error and secret conventions, the supervision rules and the conformance suite that tells you whether a plugin is ready. The messages themselves are defined in the `.proto` files in [`crates/tenko-connect/proto/tenko/connect/v1/`](../crates/tenko-connect/proto/tenko/connect/v1/), package `tenko.connect.v1`; their comments are part of the contract. The decision behind this design is [ADR 0012](adr/0012-connector-plugins.md); the connector interfaces come from [ADR 0006](adr/0006-connector-architecture.md).

Terms used below: the **host** is the Tenko process that starts and calls the plugin. An **instance** is one configured connector (a plugin, its settings and its secrets); each running instance has its own plugin process. The **operator** is the person who runs Tenko and creates instances.

Contents:

1. [What a plugin is](#1-what-a-plugin-is)
2. [Quick start in Rust](#2-quick-start-in-rust)
3. [Writing a plugin in another language](#3-writing-a-plugin-in-another-language)
4. [The handshake](#4-the-handshake)
5. [The manifest (`plugin.json`)](#5-the-manifest-pluginjson)
6. [The protocol](#6-the-protocol)
7. [Secrets](#7-secrets)
8. [Logging](#8-logging)
9. [Supervision](#9-supervision)
10. [Installing and listing plugins](#10-installing-and-listing-plugins)
11. [The conformance suite](#11-the-conformance-suite)
12. [Security expectations](#12-security-expectations)

## 1. What a plugin is

A plugin is one executable, or one script together with its interpreter, that the host runs once per connector instance. It speaks to the host in two stages. First, a handshake of two JSON lines over standard input and output exchanges the protocol version, the endpoint to serve on, a per-launch token and the plugin's manifest. Then the plugin serves gRPC over HTTP/2 without TLS on a local endpoint that the host named in the handshake: a Unix domain socket inside a private directory, or a Windows named pipe. The host is the only client. Nothing listens on a network address.

The protocol has four interfaces from ADR 0006 and one service that every plugin implements. A plugin declares in its manifest which interfaces it implements (its capabilities), and serves exactly those services.

| Interface | gRPC service | Capability | What it does |
|---|---|---|---|
| Connector (health, lifecycle) | `Plugin` | always | `Ping` (liveness), `Check` (reachability and credentials of the remote system), `Shutdown` |
| `InventorySource` | `Inventory` | `inventory`; `webhook` adds `HandleWebhook` | Reports observed hosts: names, MAC and IP addresses, operating system, platform, parent host, tags |
| `NetworkController` | `NetworkController` | `network_controller` | Reports topology (devices, ports, links, clients, networks, port profiles, wireless networks) and performs guarded Layer 2 writes: VLANs and networks, port profiles, per-client VLANs |
| `Actuator` | `Actuator` | `actuator` | Applies IPAM intent (DHCP reservations, DNS records, guest addresses) to a system Tenko does not own |
| `MigrationSource` | `Migration` | `migration` | Reads a system into the canonical intermediate representation (networks, VLANs, hosts, addresses) plus a loss report |

The protocol defines all four interfaces and the conformance suite checks all four. The host-side use of actuator plugins arrives in Phase 2 and of migration-source plugins in Phase 4.

**Policy stays in the host.** Verify-before-write, protected ports and uplinks, guardrails, rate limits, retries, bulk parallelism and the normalization of observations are enforced by Tenko. A plugin reports facts (inventory, topology, the result of a read-back) and performs the concrete calls it is asked to perform. It never decides whether a write is allowed, and it adds no policy of its own, such as silently skipping a port it considers important, because the host could not see that. A plugin may fail a call because the remote system refuses it or cannot do it; it reports that as a coded error (section 6).

**Treat the process as disposable.** The host restarts a plugin after a crash, after missed pings and when the operator disables and enables the instance again. Settings and secrets travel with every call, so changing them does not restart the plugin. Hold no state that you cannot rebuild; carry state between calls in the cursors of the protocol, not in the process.

The sequence from start to stop:

1. The host validates the plugin's manifest (the bundled registry, or `plugin.json` of an installed plugin) and allocates an endpoint: on Unix a private directory with mode `0700` and a random name, in which the plugin creates the socket `plugin.sock`; on Windows a pipe name with 128 random bits. It also draws a random 32-byte token.
2. The host starts the process with a cleared environment (section 9) and its standard input, output and error piped.
3. The host writes one JSON line to the plugin's standard input: the protocol versions it speaks, the endpoint, the token and the expected plugin name (section 4).
4. The plugin picks the highest protocol version both sides speak, starts serving gRPC on the endpoint, and writes one JSON line with the chosen version and its manifest to standard output. If it cannot serve, it writes a failure line instead and exits with a non-zero status.
5. The host checks the answer, connects to the endpoint and sends a `Ping` with the token. The plugin is now running.
6. While it runs, the host calls the plugin on the instance's schedule and on demand. In a cluster the plugin runs on every controller, which all answer on-demand calls and run health checks; only the leader (leader service `connect.poll`) calls it on the schedule. Every call carries the token in the `x-tenko-plugin-token` metadata entry and a deadline. The calls that may reach the remote system also carry a `CallContext` with the instance's settings and the secrets the manifest declares. The host pings every 10 seconds.
7. If the plugin exits or stops answering pings, the host restarts it with backoff (section 9).
8. To stop the plugin, the host calls `Plugin.Shutdown`, closes the plugin's standard input, waits up to 5 seconds for the process to exit, and then kills it. A plugin also exits by itself when its standard input closes, so it never outlives the host.

## 2. Quick start in Rust

The Rust helper library is the module `tenko_connect::sdk`. It performs the handshake, serves the declared services on the endpoint the host named, refuses every call without the per-launch token, converts between the protocol messages and Rust types, maps errors to gRPC statuses, and exits when the host asks or when standard input closes. You implement traits; you do not write gRPC code.

The crate `tenko-connect` is not published to a registry yet; the public SDK repository arrives with the plugin hub (CONN-21). Until then a Rust plugin is a crate in the Tenko workspace, or it depends on the crate by path:

```toml
[dependencies]
tenko-connect = { path = "../tenko/crates/tenko-connect" }
tenko-core = { path = "../tenko/crates/tenko-core" }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
```

You implement one trait per capability, plus `Connector` for the health check that every plugin has:

| Trait | Methods | Capability |
|---|---|---|
| `Connector` | `check(&self, ctx) -> Result<HealthReport, ConnectorError>` | always |
| `InventorySource` | `poll(&self, ctx, cursor: Option<Cursor>) -> Result<InventoryBatch, ConnectorError>`; `webhook(&self, ctx, request: WebhookRequest) -> Result<Option<InventoryBatch>, ConnectorError>` (defaults to `Unsupported`) | `inventory`, `webhook` |
| `NetworkController` | `topology(ctx)`, `plan(ctx, &L2Change)`, `apply(ctx, &L2Plan, WriteMode)`, `revert(ctx, &L2Receipt)` | `network_controller` |
| `Actuator` | `plan(ctx, &ActuatorIntent)`, `apply(ctx, &ActuatorPlan, WriteMode)`, `revert(ctx, &ActuatorReceipt)` | `actuator` |
| `MigrationSource` | `read(ctx, &MigrationScope) -> Result<(Ir, LossReport), ConnectorError>` | `migration` |

Every method receives a `CallContext`:

- `ctx.settings::<T>()` deserializes the instance's settings into your own type and fails with `ConnectorError::InvalidSettings` when they do not fit.
- `ctx.secret_str("api_key")` returns the secret of a declared purpose as UTF-8 text; `ctx.secret("api_key")` returns the bytes as an `Option`. An error names the purpose, never the value. The values are wiped when the context is dropped, and the `Debug` output of a context redacts them. Do not copy a secret into anything that outlives the call.
- `ctx.request_id` is a correlation identifier for your log lines; `ctx.instance` is the instance, absent when the conformance suite calls.

You return a `ConnectorError` for a failed call. The SDK turns it into a gRPC status with the `tenko-error-code` entry of section 6:

| Variant | Status | Code |
|---|---|---|
| `Unreachable` | `UNAVAILABLE` | `connect.unreachable` |
| `Unauthorized` | `UNAUTHENTICATED` | `connect.unauthorized` |
| `Forbidden` | `PERMISSION_DENIED` | `connect.forbidden` |
| `NotFound` | `NOT_FOUND` | `connect.not_found` |
| `VerifyMismatch { diff }` | `FAILED_PRECONDITION` | `connect.verify_mismatch` |
| `RateLimited { retry_after }` | `RESOURCE_EXHAUSTED`, with `tenko-retry-after-ms` | `connect.rate_limited` |
| `InvalidSettings(text)` | `INVALID_ARGUMENT` | `connect.invalid_settings` |
| `Unsupported` | `UNIMPLEMENTED` | `connect.unsupported` |
| `Protocol(text)` | `INTERNAL` | `connect.protocol` |
| `PluginFailed(text)` | `INTERNAL` | `connect.plugin.failed` |

The other variants (`Timeout`, `PluginUnavailable`, `GuardrailRefused`, `WritesDisabled`) are produced by the host and are not for plugins. A `Plugin` is built from the manifest and the implementations, and `Plugin::run` takes over `main`:

```rust
use std::sync::Arc;

use serde::Deserialize;
use tenko_connect::{
    CallContext, Connector, ConnectorError, Cursor, HealthReport, InventoryBatch,
    InventorySource, Manifest, sdk::Plugin,
};
use tenko_core::{MacAddr, Timestamp, observe::ObservedHost};

/// The settings of the manifest in section 5. The host has validated them already.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    url: String,
    #[serde(default = "default_verify_tls")]
    verify_tls: bool,
    #[serde(default = "default_page_size")]
    page_size: usize,
    #[serde(default)]
    queues: Vec<String>,
}

fn default_verify_tls() -> bool {
    true
}

fn default_page_size() -> usize {
    100
}

struct Printers;

#[async_trait::async_trait]
impl Connector for Printers {
    async fn check(&self, ctx: &CallContext) -> Result<HealthReport, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        let api_key = ctx.secret_str("api_key")?;
        // Call the print server with settings.url and api_key here. Map failures:
        // ConnectorError::Unreachable, Unauthorized, Forbidden, RateLimited { .. }.
        let _ = (&settings.url, api_key);
        Ok(HealthReport {
            latency_ms: Some(12),
            remote_version: Some("2.4.1".to_owned()),
            ..HealthReport::healthy()
        })
    }
}

#[async_trait::async_trait]
impl InventorySource for Printers {
    async fn poll(
        &self,
        ctx: &CallContext,
        cursor: Option<Cursor>,
    ) -> Result<InventoryBatch, ConnectorError> {
        let settings: Settings = ctx.settings()?;
        let _ = (&cursor, settings.page_size, settings.verify_tls, &settings.queues);
        let printer = ObservedHost {
            external_id: "printer-1".to_owned(),
            name: Some("printer-1.example.test".to_owned()),
            macs: vec![MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01])],
            ips: vec![std::net::IpAddr::from([192, 0, 2, 21])],
            platform: Some("printer".to_owned()),
            ..ObservedHost::default()
        };
        // One page that is the whole inventory. For several pages set `more` and
        // `cursor`; see section 6.
        Ok(InventoryBatch::complete(Timestamp::now(), vec![printer]))
    }
}

fn main() -> std::process::ExitCode {
    let manifest = Manifest::parse(include_bytes!("../plugin.json")).expect("a valid manifest");
    let printers = Arc::new(Printers);
    Plugin::new(manifest, printers.clone())
        .with_inventory(printers)
        .run()
}
```

Notes on the SDK:

- `Plugin::new(manifest, connector)` takes the manifest and the `Connector`; `with_inventory`, `with_network_controller`, `with_actuator` and `with_migration` add the capability implementations. A capability the manifest declares without an implementation is an error at start. A service is served only when the manifest declares its capability.
- Embed `plugin.json` in the executable (the example uses the `include_bytes` macro) so that the manifest in the handshake and the file that ships with the plugin cannot drift apart (section 4 lists what the host compares).
- `Plugin::run` builds a small multi-threaded Tokio runtime with two worker threads and runs your methods on it. Do not block in a method: a call that blocks both workers stops the `Ping` answers, and the host kills a plugin that misses three pings in a row. Use asynchronous clients, or `tokio::task::spawn_blocking` for blocking work.
- `run` returns the exit status for `main`: 0 after `Plugin.Shutdown` or when standard input closes, 2 when the handshake was refused or unreadable, 1 for other errors. It prints errors to standard error with the prefix `ERROR`.
- Log to standard error, one line per event, with a level word such as `INFO` or `WARN` at the start of the line (section 8). The SDK itself prints its errors this way.

The sample plugin is a complete working example: [`crates/tenko-connect/src/sample.rs`](../crates/tenko-connect/src/sample.rs). It is an inventory source that reports documentation data (`192.0.2.0/24`, `2001:db8::/32`, MAC addresses from the RFC 7042 documentation block, host names under `example.test`) and contacts nothing. It has settings with defaults, a paging inventory, an optional secret and a health check, and it is bundled in the `tenko` binary, so `tenko plugin run sample` starts it and `tenko plugin test --bundled sample` tests it. The crate also builds it as a standalone executable, `tenko-plugin-sample`, whose `--mode` argument makes it misbehave in one specific way (hang in the handshake, speak only protocol version 2, ignore the token, ignore a closed standard input, report malformed hosts, and so on). That is how the conformance suite itself is tested.

To test your own plugin:

```console
$ cargo build --release
$ tenko plugin test ./target/release/printer-inventory
```

Pass a plugin directory instead of the executable to have the suite also compare the handshake manifest with the directory's `plugin.json`; its `entry` then names the executable (section 11).

## 3. Writing a plugin in another language

Any language with a gRPC server that can listen on a Unix domain socket and, if you support Windows, on a named pipe can implement a plugin. The generated code comes from the published `.proto` files; the six files are `common.proto`, `plugin.proto`, `inventory.proto`, `network.proto`, `actuator.proto` and `migration.proto` in the directory `tenko/connect/v1/`. They import each other as `tenko/connect/v1/common.proto` and import `google/protobuf/timestamp.proto`, so give your compiler the directory that contains `tenko/` (`crates/tenko-connect/proto`) as the include path. The files declare no language options (no `go_package`, `java_package` or `csharp_namespace`); pass those on the command line or through your build tool.

### The steps

1. **Read one JSON line from standard input.** It is the host's hello (section 4): UTF-8, one JSON object terminated by a newline. Skip blank lines. Ignore members you do not know.
2. **Check the hello and choose a protocol version.** The handshake format `tenko_plugin` must be 1. If `plugin` is not empty, it must equal your manifest's `name`. The `token` must be 64 lowercase hexadecimal characters. Pick the highest version that appears in both the host's `protocol` list and your manifest's `protocol` list. If a check fails, write a failure line (section 4) and exit with a non-zero status.
3. **Serve gRPC on the endpoint, before you write the ready line.** If `endpoint.transport` is `unix`, bind a Unix domain socket at `endpoint.address`; the directory exists, belongs to the host's account and has mode `0700`, and the socket file does not exist yet. If it is `pipe`, create the named pipe `endpoint.address` as its **first instance** (so that nobody can create it before or beside you; creation must fail when the name is taken) and **reject remote clients**. Accept more than one connection: the host reconnects when a connection drops, and the conformance suite opens a second one. If you cannot create the endpoint, write a failure line with the code `endpoint`.
4. **Check the token on every call.** Read the metadata entry `x-tenko-plugin-token` and compare it with the token from the hello in constant time. If the entry is missing or differs, answer with the status `UNAUTHENTICATED` and the metadata entry `tenko-error-code: connect.plugin.token`, and do not run the call. Do this for every method of every service, `Ping` and `Shutdown` included, and for streaming methods as well as unary ones.
5. **Implement the services.** `tenko.connect.v1.Plugin` (`Ping`, `Check`, `Shutdown`) always, plus the service of each capability in your manifest and no other. A service that is not registered answers `UNIMPLEMENTED`, which is what the suite expects of undeclared capabilities; if you register `Inventory` without the `webhook` capability, `HandleWebhook` must answer `UNIMPLEMENTED` too, with `tenko-error-code: connect.unsupported`. `Ping` must return the `name` and `version` of your manifest.
6. **Write the ready line.** Once the server accepts connections, write one JSON line to standard output with the chosen version and your manifest, and flush (section 4). The host connects to the endpoint right after it reads the line, so a Unix socket or pipe that does not exist yet makes the start fail.
7. **Log to standard error.** Standard output after the ready line is also forwarded, but standard error is the place for logs (section 8). Never write anything but log lines to standard output after the ready line.
8. **Exit when asked.** On `Plugin.Shutdown`, answer first, let calls in flight finish for at most a few seconds, and exit with status 0. When standard input reaches end of file, exit as well. Both must end the process within 5 seconds; the conformance suite checks both.

### What the server must accept

- **HTTP/2 without TLS, with prior knowledge.** The host does not negotiate: it opens the connection and speaks HTTP/2 immediately. It sends the authority `plugin.invalid`; do not route or filter on it.
- **Messages of up to 16 MiB in both directions.** Many gRPC libraries default to a receive limit of 4 MiB. Raise it.
- **Concurrent calls.** The host pings every 10 seconds while a long `Poll` may be running, and the suite sends 16 pings in parallel. A server that handles one call at a time, or that blocks its event loop, fails the `concurrency` check, and the host kills such a plugin after three missed pings.
- **A deadline on every call.** The host sends it as the `grpc-timeout` header, which gRPC libraries expose as a context deadline. When the deadline passes, stop the work; the host has already given up and records the call as `connect.timeout`.

### Notes by language

- **Go (grpc-go).** Generate with `protoc-gen-go` and `protoc-gen-go-grpc`, with `M` options for the missing `go_package`. Use `net.Listen("unix", path)` for the Unix socket and a named-pipe listener library for Windows, for example go-winio's `ListenPipe`. Check that the library you pick creates the first pipe instance exclusively and rejects remote clients; the host relies on both. Register the token check as both a unary and a stream interceptor (`Migration.Read` streams), compare with `crypto/subtle.ConstantTimeCompare`, set `grpc.MaxRecvMsgSize` and `grpc.MaxSendMsgSize` to 16 MiB, and call `GracefulStop` from another goroutine once the `Shutdown` handler has returned.
- **.NET.** Use `Grpc.AspNetCore` with `Grpc.Tools` generating the server code. Kestrel can listen on a Unix socket (`ListenUnixSocket`) and, from .NET 8, on a named pipe (`ListenNamedPipe`, with the pipe name without the `\\.\pipe\` prefix). Set the endpoint's protocols to `HttpProtocols.Http2`: without TLS, Kestrel cannot negotiate HTTP/2 and falls back to HTTP/1.1 on a default endpoint. Do the token check in a gRPC interceptor and compare with `CryptographicOperations.FixedTimeEquals`. Set `MaxReceiveMessageSize` to 16 MiB. Test that a second process cannot create the same pipe name and that the pipe refuses remote clients.
- **Python (grpcio).** `grpcio` serves Unix sockets (`add_insecure_port("unix:" + path)`) and has no named-pipe support on Windows, so such a plugin lists only Unix platforms in its manifest (`linux-x86_64`, `linux-aarch64`, `macos-aarch64`) and not `any`. Generate with `python -m grpc_tools.protoc -I proto --python_out=gen --grpc_python_out=gen` and the six files. Give the thread pool more workers than the number of long calls that can run at once, so that `Ping` always finds a free thread. Raise `grpc.max_receive_message_length` to 16 MiB.

### A sketch in Python (Unix only)

This is an illustrative sketch of the steps above, not a tested or complete plugin. It implements the `Plugin` and `Inventory` services for an inventory manifest like the one in section 5, with the `entry` changed to `{"interpreter": "python3", "script": "plugin.py"}` and the platforms to Unix ones. It assumes protocol modules under `tenko.connect.v1` produced from the `.proto` files (`plugin_pb2`, `plugin_pb2_grpc`, `inventory_pb2`, `inventory_pb2_grpc`) and a `plugin.json` next to the script. It reads no settings and uses no secrets, and it serves no streaming method: the refusal in `TokenCheck` is a unary handler, so a plugin with `Migration.Read` needs a stream handler there too.

```python
import hmac, json, os, re, sys, threading
from concurrent import futures

import grpc
from tenko.connect.v1 import inventory_pb2, inventory_pb2_grpc, plugin_pb2, plugin_pb2_grpc

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = json.load(open(os.path.join(HERE, "plugin.json")))
MAX_MESSAGE = 16 * 1024 * 1024
stop = threading.Event()


def say(line):
    print(json.dumps(line, separators=(",", ":")), flush=True)


def refuse(code, message, supported=()):
    error = {"code": code, "message": message}
    if supported:
        error["supported"] = list(supported)
    say({"tenko_plugin": 1, "error": error})
    sys.exit(2)


class TokenCheck(grpc.ServerInterceptor):
    def __init__(self, token):
        self._token = token.encode()

        def deny(request, context):
            context.set_trailing_metadata((("tenko-error-code", "connect.plugin.token"),))
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "the call does not carry the token")

        self._deny = grpc.unary_unary_rpc_method_handler(deny)

    def intercept_service(self, continuation, details):
        presented = dict(details.invocation_metadata).get("x-tenko-plugin-token", "")
        if hmac.compare_digest(self._token, presented.encode()):
            return continuation(details)
        return self._deny


class PluginService(plugin_pb2_grpc.PluginServicer):
    def Ping(self, request, context):
        return plugin_pb2.PingResponse(name=MANIFEST["name"], version=MANIFEST["version"])

    def Check(self, request, context):
        try:
            settings = json.loads(request.context.settings_json or "{}")
            if not isinstance(settings, dict):
                raise ValueError("the settings are not a JSON object")
        except ValueError as error:
            context.set_trailing_metadata((("tenko-error-code", "connect.protocol"),))
            context.abort(grpc.StatusCode.INVALID_ARGUMENT, "malformed request: %s" % error)
        # Contact the remote system here and map failures to coded errors.
        return plugin_pb2.CheckResponse(health=plugin_pb2.HEALTH_HEALTHY)

    def Shutdown(self, request, context):
        stop.set()
        return plugin_pb2.ShutdownResponse()


class InventoryService(inventory_pb2_grpc.InventoryServicer):
    def Poll(self, request, context):
        host = inventory_pb2.ObservedHost(
            external_id="printer-1", name="printer-1.example.test",
            macs=["00:00:5e:00:53:01"], ips=["192.0.2.21"])
        return inventory_pb2.PollResponse(hosts=[host], complete=True)


def main():
    hello = json.loads(sys.stdin.readline())
    if hello.get("tenko_plugin") != 1:
        refuse("startup", "unsupported handshake format")
    if hello.get("plugin") and hello["plugin"] != MANIFEST["name"]:
        refuse("wrong_plugin", "the host expected plugin %s" % hello["plugin"])
    if not re.fullmatch(r"[0-9a-f]{64}", hello.get("token", "")):
        refuse("startup", "the token is not 64 lowercase hexadecimal characters")
    common = [v for v in MANIFEST["protocol"] if v in hello["protocol"]]
    if not common:
        refuse("protocol_mismatch", "no common protocol version", MANIFEST["protocol"])
    endpoint = hello["endpoint"]
    if endpoint["transport"] != "unix":
        refuse("endpoint", "this plugin serves Unix sockets only")

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=16),
        interceptors=[TokenCheck(hello["token"])],
        options=[("grpc.max_receive_message_length", MAX_MESSAGE),
                 ("grpc.max_send_message_length", MAX_MESSAGE)])
    plugin_pb2_grpc.add_PluginServicer_to_server(PluginService(), server)
    inventory_pb2_grpc.add_InventoryServicer_to_server(InventoryService(), server)
    try:
        bound = server.add_insecure_port("unix:" + endpoint["address"])
    except RuntimeError:
        bound = 0
    if not bound:
        refuse("endpoint", "cannot serve on " + endpoint["address"])
    server.start()
    say({"tenko_plugin": 1, "protocol": max(common), "manifest": MANIFEST})

    def watch_stdin():
        sys.stdin.read()  # returns at end of file: the host is gone or closed the pipe
        stop.set()

    threading.Thread(target=watch_stdin, daemon=True).start()
    stop.wait()
    server.stop(grace=2).wait()
    sys.exit(0)


if __name__ == "__main__":
    main()
```

### Mistakes the conformance suite finds

- The ready line is written before the server listens, so the host's first connection fails.
- A `Ping` waits behind a long call, so the host kills the plugin after about half a minute of silence.
- Only unary calls check the token, and a streaming call goes through.
- `Shutdown` is answered after the process has already exited, or the process ignores a closed standard input.
- A request the plugin cannot serve ends in an internal failure (`connect.plugin.failed`) instead of the code that names the cause (section 6).
- The manifest in the ready line differs from `plugin.json` (section 4).
- Output other than log lines is written to standard output after the ready line.

## 4. The handshake

The handshake is two JSON lines, one in each direction, before any gRPC call. Each line is one JSON object in UTF-8 on one line and ends with a newline. A line is at most 512 KiB. The host skips blank lines in your output, and it logs and skips any line before the answer that does not start with `{`; do not rely on that, and print nothing else to standard output before the ready line.

### The host line

The host writes this line to the plugin's standard input right after it starts the process. The example shows a Unix endpoint with a documentation token:

```json
{"tenko_plugin":1,"protocol":[1],"endpoint":{"transport":"unix","address":"/tmp/tenko-plugin-0123456789abcdef/plugin.sock"},"token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","plugin":"printer-inventory","host_version":"0.0.1"}
```

On Windows the endpoint is a named pipe (JSON escapes the backslashes):

```json
{"tenko_plugin":1,"protocol":[1],"endpoint":{"transport":"pipe","address":"\\\\.\\pipe\\tenko-plugin-0123456789abcdef0123456789abcdef"},"token":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","plugin":"printer-inventory","host_version":"0.0.1"}
```

| Member | Type | Meaning |
|---|---|---|
| `tenko_plugin` | integer | The handshake format. `1`. |
| `protocol` | array of integers | The protocol major versions the host speaks. Today `[1]`. |
| `endpoint.transport` | string | `unix` (a Unix domain socket) or `pipe` (a Windows named pipe). |
| `endpoint.address` | string | For `unix`, the path of the socket to create: `plugin.sock` inside a private directory of the host (mode `0700`, named `tenko-plugin-` and 16 random hexadecimal characters, under the host's runtime directory, which is the system temporary directory by default). The path is at most 100 bytes. For `pipe`, the name `\\.\pipe\tenko-plugin-` followed by 32 random hexadecimal characters. |
| `token` | string | The per-launch token: 64 lowercase hexadecimal characters (32 random bytes). The example is not a real token. |
| `plugin` | string | The plugin name the host expects (the manifest `name`). Empty when the conformance suite tests an executable without a manifest file. |
| `host_version` | string | The version of Tenko. |

The token travels only over standard input. It is never on the command line and never in the environment, where other local processes could read it. Keep it in memory and never log it.

### The ready line

The plugin answers with one line: the chosen protocol version and its manifest. The manifest is the document of section 5. This example carries the manifest of that section and is a single line on the wire:

```json
{"tenko_plugin":1,"protocol":1,"manifest":{"manifest_version":1,"name":"printer-inventory","version":"0.1.0","description":"Reports the printers of an example print server as observed hosts.","homepage":"https://example.org/tenko-printer-inventory","license":"Apache-2.0","protocol":[1],"capabilities":["inventory"],"settings":{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","title":"Print server","properties":{"url":{"type":"string","format":"uri","title":"Address","description":"Base URL of the print server API.","examples":["https://print.example.net:8443"]},"verify_tls":{"type":"boolean","title":"Verify the TLS certificate","default":true},"page_size":{"type":"integer","title":"Printers per page","minimum":1,"maximum":500,"default":100},"queues":{"type":"array","title":"Queues","description":"Only these queues are reported; all queues when empty.","items":{"type":"string","minLength":1,"maxLength":64},"maxItems":20,"uniqueItems":true}},"required":["url"],"additionalProperties":false},"secrets":[{"purpose":"api_key","description":"API key of the print server.","required":true}],"network":[{"setting":"/url","ports":[8443],"description":"The print server API."}],"platforms":["linux-x86_64","linux-aarch64"],"entry":{"executable":"bin/printer-inventory"},"defaults":{"poll_interval_secs":300,"call_timeout_secs":30}}}
```

| Member | Type | Meaning |
|---|---|---|
| `tenko_plugin` | integer | `1`. |
| `protocol` | integer | The chosen protocol version: the highest version in both the host's `protocol` list and the manifest's `protocol` list. |
| `manifest` | object | The plugin's manifest. |

Write the line only after the plugin serves on the endpoint (section 3, step 6).

### The failure line

A plugin that cannot serve writes a failure line instead of the ready line and then exits with a non-zero status:

```json
{"tenko_plugin":1,"error":{"code":"protocol_mismatch","message":"no common protocol version: the host speaks [2], plugin printer-inventory speaks [1]","supported":[1]}}
```

| Member | Type | Meaning |
|---|---|---|
| `error.code` | string | One of the codes below. |
| `error.message` | string | English detail for the operator. Never contains a secret. |
| `error.supported` | array of integers | The protocol versions the plugin speaks. Used with `protocol_mismatch`; omitted otherwise. |

| Code | When |
|---|---|
| `protocol_mismatch` | The plugin speaks none of the versions the host offered. |
| `wrong_plugin` | The hello names another plugin than this one. |
| `endpoint` | The plugin cannot create the endpoint (the pipe exists already, the socket cannot be bound, the transport is not available on this platform). |
| `startup` | Anything else that stops the plugin from starting: an unknown handshake format, a token of the wrong shape, an unusable configuration. |

### Version negotiation

The protocol version is a major version (`tenko.connect.v1` is version 1). The host offers every major version it speaks; the plugin lists the ones it speaks in its manifest; the plugin chooses the highest version that is in both lists. When there is none, the plugin writes `protocol_mismatch` with its own versions in `supported`, and the host reports both lists to the operator. The host also refuses a ready line whose `protocol` is not in its own offer or not in the manifest's `protocol` list.

### What the host does with the ready line

The host waits 10 seconds for the answer. It then checks, in this order:

1. The handshake format is 1, and the line is not a failure line.
2. The line carries a `protocol` and a `manifest`, and the manifest passes the validation of section 5.
3. The chosen protocol version is in the host's offer and in the manifest.
4. When the host launched the plugin with a known manifest (a bundled plugin, or an installed plugin with a `plugin.json`), the manifest in the line equals it in `name`, `version`, `capabilities` (as a set), the declared secret purposes (as a set) and the `settings` schema. Other members, such as `description`, may differ, but keep them identical.
5. The host connects to the endpoint (5 seconds) and pings with the token. The answer must carry the manifest's `name` and `version`.

A failure at any step stops the start. Steps 2 to 4 and a failure line are permanent failures; the host does not retry them until the operator acts (section 9).

## 5. The manifest (`plugin.json`)

The manifest describes what a plugin is, what it implements, which settings it takes, which secrets and network targets it needs and how to start it. Installed plugins ship it as `plugin.json` in the plugin directory; every plugin also sends it in the handshake. The host validates it before it starts the plugin and reports every problem found at once, each with the JSON pointer of the offending member, for example `/secrets/0/purpose`. Unknown members are refused everywhere in the manifest. A manifest file is at most 256 KiB.

### A complete example

```json
{
  "manifest_version": 1,
  "name": "printer-inventory",
  "version": "0.1.0",
  "description": "Reports the printers of an example print server as observed hosts.",
  "homepage": "https://example.org/tenko-printer-inventory",
  "license": "Apache-2.0",
  "protocol": [1],
  "capabilities": ["inventory"],
  "settings": {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "title": "Print server",
    "properties": {
      "url": {
        "type": "string",
        "format": "uri",
        "title": "Address",
        "description": "Base URL of the print server API.",
        "examples": ["https://print.example.net:8443"]
      },
      "verify_tls": {
        "type": "boolean",
        "title": "Verify the TLS certificate",
        "default": true
      },
      "page_size": {
        "type": "integer",
        "title": "Printers per page",
        "minimum": 1,
        "maximum": 500,
        "default": 100
      },
      "queues": {
        "type": "array",
        "title": "Queues",
        "description": "Only these queues are reported; all queues when empty.",
        "items": { "type": "string", "minLength": 1, "maxLength": 64 },
        "maxItems": 20,
        "uniqueItems": true
      }
    },
    "required": ["url"],
    "additionalProperties": false
  },
  "secrets": [
    { "purpose": "api_key", "description": "API key of the print server.", "required": true }
  ],
  "network": [
    { "setting": "/url", "ports": [8443], "description": "The print server API." }
  ],
  "platforms": ["linux-x86_64", "linux-aarch64"],
  "entry": { "executable": "bin/printer-inventory" },
  "defaults": { "poll_interval_secs": 300, "call_timeout_secs": 30 }
}
```

### Members and rules

| Member | Required | Rules |
|---|---|---|
| `manifest_version` | yes | The manifest format. Must be `1`. |
| `name` | yes | Lowercase ASCII letters, digits and single `-`, starting with a letter, at most 63 characters (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`). Unique among the plugins of an installation. The host expects this name in the handshake; an installed plugin lives in a directory of this name (section 10). |
| `version` | yes | Semantic versioning 2.0.0: `MAJOR.MINOR.PATCH` without leading zeros, with an optional `-prerelease` and `+build` suffix, at most 64 characters. |
| `description` | yes | One or two English sentences for the operator. Not empty, at most 500 characters, no control characters. |
| `homepage` | no | A URL starting with `https://` or `http://` and a host, no whitespace or control characters, at most 2,048 characters. |
| `license` | no | An SPDX licence expression. Not empty, at most 100 characters, only letters, digits, spaces and `.+()-`. |
| `protocol` | yes | The protocol major versions the plugin speaks. At least one, each at least 1, no duplicates. |
| `capabilities` | yes | At least one of `inventory`, `webhook`, `network_controller`, `actuator`, `migration`; no duplicates. `webhook` needs `inventory`. |
| `settings` | no | The JSON Schema of an instance's settings, in the subset below. Absent means no settings (an empty object schema that refuses any setting). |
| `secrets` | no | The secrets the plugin may receive, at most 16. See below. |
| `network` | no | The network targets the plugin contacts, at most 32. See below. |
| `platforms` | yes | At least one platform: `any` (a script; it must then be the only entry) or `<os>-<arch>` as Rust names them, such as `linux-x86_64`, `linux-aarch64`, `macos-aarch64` and `windows-x86_64` (`^[a-z0-9]+-[a-z0-9_]+$`). No duplicates. |
| `entry` | for installed plugins | How to start the plugin. Absent for a bundled plugin, which the host starts as `tenko plugin run <name>`. See below. |
| `defaults` | no | `poll_interval_secs`: seconds between inventory polls, 60 to 86,400 (the host default is 300). `call_timeout_secs`: timeout of one call, 1 to 600 (the host default is 30). The host applies them to new instances and enforces its own bounds. |

**Secret purposes.** Each entry of `secrets` has a `purpose`, a `description` and `required` (default `false`). The purpose is lowercase ASCII letters, digits and `_`, starting with a letter, at most 64 characters, unique in the manifest, for example `password` or `api_key`. The description is not empty and at most 500 characters. The host injects only the purposes declared here (section 7). `required` says that an instance needs the secret.

**Network targets.** Each entry of `network` names one place the plugin contacts, so that the operator sees it before an instance is created. It has exactly one of `setting`, a JSON pointer of the form `/name` to a settings property of type `string` that holds a URI, host name or IP address, and `host`, a fixed host name (RFC 1123) or IP address. It may carry `ports` (each from 1 to 65,535, when known) and has a required `description` of at most 500 characters. The targets are declarations for the operator. The host does not block other connections today (section 12).

**Platforms.** The host runs a plugin only on a platform the manifest lists. A script that runs everywhere says `any`. A plugin that ships a compiled executable lists the platforms it was built for. There is one `entry` per manifest; to support several platforms with different executables, publish one directory per platform with its own `plugin.json`, or start through an interpreter and a script.

**Entry.** An entry is exactly one of an `executable`, or an `interpreter` together with a `script`. Paths are relative to the plugin directory: `/` as the separator, no leading `/`, no drive letter, no `.` or `..` component, no empty component, at most 1,024 characters. The `interpreter` is a bare command name found on `PATH` (letters, digits and `._+-`, for example `python3` or `node`) or an absolute path. `args` (at most 64 entries of at most 4,096 characters each, no NUL) are appended after the executable or the script. For an installed plugin the host also checks that the files exist, resolve (through symbolic links) to a place inside the plugin directory, are regular files and, on Unix, that an executable has an execute bit. The host starts the plugin with the plugin directory as its working directory. A script entry looks like this:

```json
"entry": { "interpreter": "python3", "script": "plugin.py", "args": ["--quiet"] }
```

### The settings schema

The UI builds the configuration form of an instance from the settings schema, and the host validates every instance's settings against it before they reach the plugin. To make that possible the schema is a restricted subset of JSON Schema draft 2020-12: a flat object of simple properties.

- **Root.** `type` must be `"object"`. Allowed keywords: `$schema` (if present, `https://json-schema.org/draft/2020-12/schema`), `title` (at most 200 characters), `description` (at most 1,000), `type`, `properties` (at most 64), `required` (names of declared properties, no duplicates) and `additionalProperties`, which can only be `false`: unknown settings are always refused. No other keyword is accepted at the root.
- **Property names.** Lowercase ASCII letters, digits and `_`, starting with a letter, at most 64 characters.
- **Property types.** `string`, `integer`, `number`, `boolean` and `array`. Every property accepts `type`, `title` (at most 200 characters), `description` (at most 1,000), `default` and `examples` (an array). A `default` must itself satisfy the property's schema.

| Type | Further keywords |
|---|---|
| `string` | `enum` (unique strings), `minLength`, `maxLength` (counted in characters), `pattern`, `format` |
| `integer` | `enum` (unique integers), `minimum`, `maximum` |
| `number` | `minimum`, `maximum` |
| `boolean` | none |
| `array` | `items` (required: a schema of type `string` or `integer` with the keywords of that type, without `default` and `examples`), `minItems`, `maxItems`, `uniqueItems` |

- **Formats.** `uri` (a scheme, a colon and a rest, without whitespace), `hostname` (RFC 1123), `ipv4` and `ipv6`.
- **Patterns.** At most 1,000 characters, in the syntax of the Rust `regex` crate (no lookaround and no backreferences); stay within what common regular expression dialects share.
- **Secrets are refused.** A property whose name equals one of `password`, `passwd`, `secret`, `token`, `api_key`, `apikey` or `private_key`, or ends in an underscore followed by one of them (compared without regard to case), is rejected. Examples are `password`, `db_password`, `api_token` and `client_secret`. Declare such values in `secrets` instead. A name such as `token_url` is fine.
- **Defaults.** The validation of an instance's settings fills in the `default` of every absent property, refuses unknown settings and enforces `required`. Your plugin should still apply its own defaults for an absent optional member, as the sample does, and treat the settings as untrusted input.

A settings problem is reported with a stable code per kind: `connect.settings.type`, `.unknown`, `.required`, `.enum`, `.length`, `.pattern`, `.format`, `.range`, `.items` or `.unique`.

## 6. The protocol

The protocol is the package `tenko.connect.v1`. The `.proto` files carry the field-level documentation; this section covers the conventions around them.

### Services and methods

| Service | Capability | Method | Request, response | Purpose |
|---|---|---|---|---|
| `Plugin` | always | `Ping` | `PingRequest`, `PingResponse` | Liveness. Answers at once without contacting the remote system, with the manifest's `name` and `version`. Carries no `CallContext`. |
| `Plugin` | always | `Check` | `CheckRequest`, `CheckResponse` | Checks reachability and credentials of the remote system without changing anything. Returns a `Health` (`HEALTHY`, `DEGRADED`, `UNREACHABLE`), optionally the latency, the remote version and an English detail. |
| `Plugin` | always | `Shutdown` | `ShutdownRequest`, `ShutdownResponse` | Answers first, then the plugin exits within a few seconds. Carries no `CallContext`. |
| `Inventory` | `inventory` | `Poll` | `PollRequest`, `PollResponse` | Reports observed hosts; optional `cursor`; paged. |
| `Inventory` | `webhook` | `HandleWebhook` | `WebhookRequest`, `WebhookResponse` | Verifies and parses a webhook call that the host received for the instance (headers with lower-case names, raw body). |
| `NetworkController` | `network_controller` | `Topology` | `TopologyRequest`, `TopologyResponse` | Devices, ports, links, clients, networks, port profiles, wireless networks. |
| `NetworkController` | `network_controller` | `Plan` | `L2PlanRequest`, `L2PlanResponse` | Reads the state back, diffs it against a change, fingerprints the state. Writes nothing. |
| `NetworkController` | `network_controller` | `Apply` | `L2ApplyRequest`, `L2ApplyResponse` | Re-reads, refuses a stale plan, writes only in apply mode, reads back and verifies. |
| `NetworkController` | `network_controller` | `Revert` | `L2RevertRequest`, `L2RevertResponse` | Undoes an applied change with the undo steps of its receipt. |
| `Actuator` | `actuator` | `Plan`, `Apply`, `Revert` | `ActuatorPlanRequest`, `ActuatorApplyRequest`, `ActuatorRevertRequest` and their responses | The same discipline for IPAM intent: DHCP reservations, DNS records, guest addresses. |
| `Migration` | `migration` | `Read` | `MigrationReadRequest`, stream of `MigrationItem` | Streams the intermediate representation of a scope, followed by the loss entries. |

The change a network controller performs is one of five: `EnsureNetwork` (create or update the network of a VLAN, with the controller's DHCP off or relaying), `SetPortProfile`, `SetClientVlan`, `ClearClientVlan` and `RemoveNetwork` (the undo of a created network). A topology reports the controller's DHCP of each network as off, relaying, or `server` when the controller serves DHCP itself; Tenko never asks for `server`, but an undo step restores it. An actuator intent is one of `DhcpReservation`, `DhcpReservationRemove`, `DnsRecords`, `DnsRecordsRemove` and `GuestAddress`; identifiers of Tenko objects in it are UUIDs in text form.

### CallContext

Every method that may reach the remote system takes a `CallContext`:

| Field | Meaning |
|---|---|
| `instance_id` | The connector instance, a UUID in text form; empty when the conformance suite calls. |
| `settings_json` | The instance's settings as a JSON object in text form, already validated by the host against the settings schema of the manifest. |
| `secrets` | The secrets of the instance whose purposes the manifest declares: a `purpose` and a `value` (bytes). For this call only (section 7). |
| `request_id` | A correlation identifier. Put it in your log lines. |

A `settings_json` that is empty counts as `{}`. One that is not JSON, or not a JSON object, is a malformed request: answer `INVALID_ARGUMENT` with the code `connect.protocol` and keep running. Do not parse the settings of a request you have not authenticated; the token check comes first.

### Errors

A plugin answers a failed call with a gRPC status. It may add the metadata entry `tenko-error-code` with a stable code. The host prefers the code. When there is no code, or the code is unknown, the host derives one from the status, so a plugin that sets only the status is understood too.

| gRPC status | `tenko-error-code` | Meaning |
|---|---|---|
| `UNAVAILABLE` | `connect.unreachable` | The remote system did not answer. |
| `UNAUTHENTICATED` | `connect.unauthorized` | The remote system rejected the credentials. |
| `PERMISSION_DENIED` | `connect.forbidden` | The credentials lack a permission. |
| `NOT_FOUND` | `connect.not_found` | The object does not exist on the system. |
| `FAILED_PRECONDITION` | `connect.verify_mismatch` | A stale plan, or a read-back that differs from the plan. |
| `RESOURCE_EXHAUSTED` | `connect.rate_limited` | Slow down. `tenko-retry-after-ms` says for how long. |
| `INVALID_ARGUMENT` | `connect.invalid_settings` | The settings or the request are not usable. |
| `UNIMPLEMENTED` | `connect.unsupported` | The operation is not supported. |
| any other | `connect.plugin.failed` | The plugin failed. |

Three more codes appear in the protocol:

- `connect.plugin.token` goes with `UNAUTHENTICATED` and means that the call lacked the per-launch token. Do not confuse it with `connect.unauthorized`, which is about the credentials for the remote system.
- `connect.protocol` goes with `INVALID_ARGUMENT` for a request the plugin cannot read (a malformed message, settings that are not JSON), and with `INTERNAL` for a reply of the remote system that the plugin cannot make sense of. The host uses the same code for an answer from a plugin that it cannot convert.
- `connect.timeout` is produced by the host when a call exceeds its deadline. A plugin does not send it.

The host adds codes of its own for policy refusals (guardrails, writes switched off, a plugin that is not running). A plugin never returns those.

`tenko-retry-after-ms` carries a delay in milliseconds as decimal text; the host assumes 60 seconds when `RESOURCE_EXHAUSTED` has none. Keep status messages short, in English, free of secrets and free of personal data: the host keeps only the first 1,024 bytes. Report a failure of the remote system or of the request with the matching code of the first eight rows of the table, and keep `connect.plugin.failed` for failures of the plugin itself. The conformance suite has no real remote system to ask, so it accepts those eight codes as proper answers and fails on `connect.plugin.failed`, `connect.protocol`, a timeout or a crash.

### Timeouts and limits

- **Timeouts.** The host sets a deadline on every call, sent as `grpc-timeout`. The call timeout is a setting of the instance; the manifest suggests a default of 1 to 600 seconds and the host default is 30 seconds. The host also stops waiting by itself. A call that exceeds its deadline fails as `connect.timeout`. A paged poll gives each page its own timeout; for `Migration.Read` the timeout bounds the whole stream. The supervisor's `Ping` has a timeout of 3 seconds.
- **Message size.** At most 16 MiB per message, in both directions. Split large answers into pages.
- **Text.** Every identifier, name and tag the host accepts from a plugin is at most 1,024 bytes.
- **Inventory paging.** At most 1,000 pages per poll. A migration read accepts at most 1,000,000 items.

### Inventory

`Poll` without a `cursor` returns everything the source has; with the cursor of a previous answer it may return only changes. A large inventory goes out in pages:

- Set `more` on a page that is not the last, together with a `cursor`. The host then calls `Poll` again at once with that cursor. The sequence must end: the host fails the poll when `more` comes without a `cursor`, when a cursor repeats, and after 1,000 pages.
- `complete` says that this answer, together with the pages before it, is the whole inventory, so that hosts absent from it are gone. The host reads `complete` and `cursor` from the last page, so setting `complete` on every page is harmless. An incremental answer sets `complete` to false.
- `observed_at` is when the source produced the data; the host uses its own clock when it is absent.

An `ObservedHost` has a required `external_id` (the source's own identifier, such as a VM id or entity id, stable across polls and unique in the inventory), and optionally `name`, `macs`, `ips`, `os`, `platform` (such as `qemu`, `lxc` or `esphome`), `parent` (the `external_id` of the parent host) and `tags`. MAC addresses look like `00:00:5e:00:53:01`, in any case, with `-` accepted as the separator. IP addresses are IPv4 or IPv6 text without a prefix length.

**Vendor facts.** A page may also carry `vendors`: `VendorFact` entries of a MAC address and the vendor the source reports for it, such as the manufacturer in the device registry of a home automation hub (in Rust, `InventoryBatch::vendors`). The host records each as a `vendor` fact of the MAC address under the instance's inventory source, so the vendor shows in the computed view of the device and on the topology map. For a MAC address named twice, the last entry wins. A vendor fact is not a sighting of anything; report the MAC address on its host as well. The field was added within version 1 (field 6 of `PollResponse`); a host that predates it ignores it. Entries are converted leniently like hosts: an entry whose MAC address does not parse, or whose vendor is over 1,024 bytes, is skipped with a warning, and a blank vendor is ignored.

**Hosts are handled leniently.** One bad host does not discard a whole inventory. A host without an `external_id` (or with one over 1,024 bytes) is dropped with a warning. A MAC or IP value that does not parse, and an over-long text, is skipped with a warning. Blank optional values count as absent, and duplicate MAC addresses, IP addresses and tags are collapsed. The conformance suite fails a plugin whose inventory produces warnings, because a warning means that the plugin sent malformed data.

**Topology and plans are handled strictly.** For everything that the host bases a decision on (topology, plans, receipts, and the requests a plugin receives), one malformed member fails the whole message with `connect.protocol`, because a dropped port could hide an uplink from the guardrails. In particular: VLAN ids are from 1 to 4094, port indexes fit in 16 bits, MAC and IP values parse, identifiers of devices, networks, profiles and clients are not empty, texts are at most 1,024 bytes, and `observed_at` of a topology and `read_at` and `applied_at` of plans and receipts are present. Set `uplink` on every uplink port and `management` on the port and the client through which the controller is reached: the host never touches uplinks, the controller's own access port or the controller host (`connect.guardrail.uplink`, `connect.guardrail.management_port`, `connect.guardrail.management_client`), and it can only protect the ports and clients it knows to be such. A client may carry its `name` on the controller and the `vendor` the controller reports for its MAC address; the host records them as `name` and `vendor` facts.

### Network controllers and actuators

Writes follow one discipline, which the host drives:

1. The host reads `Topology`.
2. The host checks its guardrails against the topology: uplinks and the management path always, plus the protected ports, networks, VLANs and clients the operator configured.
3. The host calls `Plan` with the change. The plugin reads the current state back, computes the diff (`path`, `before`, `after` per line), fingerprints the state and returns the plan. It writes nothing. The fingerprint is an opaque string that changes when the relevant state changes.
4. The host shows the plan as a preview.
5. The host calls `Apply` with that plan and a write mode. The plugin re-reads the state. If the state no longer matches the plan's fingerprint it refuses with `FAILED_PRECONDITION` and `connect.verify_mismatch`. In `WRITE_MODE_DRY_RUN` it writes nothing and returns a receipt. In `WRITE_MODE_APPLY` it writes, reads the result back, and reports in `verified` whether the read-back matches the plan. The receipt carries, for a network controller, the `undo` changes that restore the previous state, in order.
6. After a write the host calls `Plan` for the same change again and expects an empty diff.
7. To undo, the host calls `Revert` with the receipt.

An unspecified write mode (`WRITE_MODE_UNSPECIFIED`, the default value) is a dry run: anything but an explicit apply writes nothing. The plugin performs the concrete calls; the host decides whether to call `Apply` at all.

### Migration sources

`Migration.Read` receives a scope (areas `IPAM`, `DNS`, `DHCP`; empty means everything the source has; DNS zones; empty means all) and streams `MigrationItem` messages, each one a network, a VLAN, a host, an address or a loss entry. A loss entry reports something the source has that the intermediate representation cannot carry: a location, a stable code such as `migrate.bind.unsupported_record`, and an English detail. By convention the loss entries come last. An item that does not convert (a CIDR that does not parse, a host name that is invalid, a VLAN outside 1 to 4094) is not dropped: the host turns it into a loss entry with the code `connect.migration.invalid_item`. The intermediate representation grows with new sources, as new members of the `MigrationItem` oneof.

### Versioning

Within major version 1 every change is additive. New fields take new numbers. No field, enum value or service method is removed, renamed or renumbered. A plugin and the host ignore fields they do not know. A breaking change is a new package, `tenko.connect.v2`, and a new protocol version in the handshake. A plugin declares the versions it speaks in its manifest, and the host refuses a mismatch with a clear error (section 4).

## 7. Secrets

A plugin never reads Tenko's vault. The rules:

- **Declared purposes only.** The manifest lists the purposes a plugin may receive (`secrets`, section 5). The host injects nothing else.
- **The host resolves and injects.** An instance's settings do not hold secrets; the operator stores them in the vault and the instance refers to them. The host resolves the references and puts the values into the `CallContext` of each call that needs them (`Check`, `Poll`, `HandleWebhook`, `Topology`, `Plan`, `Apply`, `Revert`, `Read`). `Ping` and `Shutdown` carry no context and no secrets. The host wipes the values after the call.
- **Every injection is audited.** The audit record names the principal (`system:connector`), the plugin and the purpose. It never contains the value.
- **The plugin keeps nothing.** A plugin must not store a secret (not in a file, not in a cache that outlives the call, not in a global), log it, return it in an answer or a status message, put it into an error, or pass it on to anything but the remote system it is declared for. Keep the secret out of URLs, which are logged by proxies and servers.
- **Settings never hold secrets.** The host refuses a settings property that looks like a secret (section 5). Do not work around that by putting a secret into a free-text setting.
- **A missing secret is an error, not a prompt.** If a call needs a secret that the context does not carry, answer with `INVALID_ARGUMENT` (`connect.invalid_settings`) and name the purpose, not a value.

The sample plugin shows the pattern for testing: when the host injects its optional `api_key`, every reported host carries the tag `credential:present`, so a test can see the injection without the value.

## 8. Logging

A plugin logs to standard error, one event per line. The host forwards standard error, and standard output after the handshake, line by line into its own log, labelled with the plugin's name or the instance.

- **Levels.** A line may start with one of the upper-case words `ERROR`, `WARN`, `INFO`, `DEBUG` or `TRACE`, followed by a space and the message. Without a level word the line is logged at `INFO`. The word must be followed by a space: `ERROR: failed` has no level.
- **Length.** A line is cut at 4,096 bytes. Blank lines are dropped.
- **Verbosity.** When the host's own environment has `TENKO_PLUGIN_LOG`, the host passes it on to the plugin unchanged. It carries the operator's wish for the plugin's log verbosity; the host does not interpret the value. A plugin may honour it by suppressing lines below a level.
- **Content.** Put the `request_id` of the `CallContext` in lines about a call. Never log settings documents, secrets, tokens or the payloads of the remote system. The last eight lines of standard error are also shown to the operator when the plugin dies during its start, so make the reason for a startup failure the last thing you print.

## 9. Supervision

The host supervises every running plugin. A plugin failure is a status of the connector instance; it never reaches the API or the data plane. Every change of that status, and of the remote health that `Check` reports, is announced as an event of the `connectors` topic that names the instance (`kind` `connect.health`, no revision), so the web UI follows it without a reload.

| Policy | Default |
|---|---|
| Liveness ping | every 10 seconds, with a timeout of 3 seconds |
| Missed pings | 3 in a row: the host kills the process and treats it as a failure |
| Restart backoff | 1 second after the first failure, doubling per consecutive failure up to 5 minutes; each delay is shortened by a random amount of up to 20 percent |
| Recovery | after 60 seconds of healthy running (answered pings) the failure count starts over |
| Circuit breaker | 5 failures within 10 minutes stop restarts for 15 minutes, then exactly one trial start; a failing trial opens the circuit again, a trial that runs healthy for 60 seconds closes it |
| Handshake | 10 seconds for the answer; 5 seconds to connect and ping |
| Shutdown | `Plugin.Shutdown`, then standard input is closed, then 5 seconds for the process to exit, then the process is killed |

A crash, a failed start and a plugin that stops answering are failures that go through the backoff and the circuit breaker. Some failures cannot be fixed by starting again, and the host does not retry them: it leaves the instance in the state `failed` until the operator acts: after installing a fixed plugin version, the operator enables the instance again (`POST /connectors/{id}/enable`, which starts a failed plugin anew) or disables and enables it. These are a protocol mismatch, an invalid manifest, a manifest that differs from the expected one, and a failure line of any code. If the problem might go away by itself, such as a remote system that is down at the moment, do not write a failure line: start, and report the state from `Check`.

The errors an operator sees for a plugin that did not start:

| Code | Cause | Restarts |
|---|---|---|
| `connect.plugin.endpoint` | The host could not allocate the endpoint (for example the socket path would be too long). | backoff |
| `connect.plugin.spawn_failed` | The process could not be started. | backoff |
| `connect.plugin.handshake_timeout` | No answer within 10 seconds. | backoff |
| `connect.plugin.handshake_invalid` | The answer is not a handshake line. | backoff |
| `connect.plugin.exited` | The process exited during its start; the message ends with the last lines of its standard error. | backoff |
| `connect.plugin.connect_failed` | The endpoint did not answer, or the first ping failed. | backoff |
| `connect.plugin.protocol_mismatch` | No common protocol version. | stop |
| `connect.plugin.refused` | The plugin wrote a failure line. | stop |
| `connect.plugin.manifest_invalid` | The manifest fails validation (section 5). | stop |
| `connect.plugin.manifest_mismatch` | The manifest differs from the expected one, or the ping names another name or version. | stop |

While a plugin is not running, calls to its instance fail with `connect.plugin.unavailable`.

**The environment.** The host clears the plugin's environment and passes only an allow-list of variables from its own: `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`, `TMPDIR`, `TEMP`, `TMP`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT`, `USERPROFILE`, `LOCALAPPDATA`, `APPDATA`, `PROGRAMDATA`, `PROGRAMFILES`, `NUMBER_OF_PROCESSORS` and `PROCESSOR_ARCHITECTURE`. Those that are not set in the host's environment are not set for the plugin. The host adds `TENKO_PLUGIN_NAME` (the plugin name) and, when it has it, `TENKO_PLUGIN_LOG`. Tenko's own configuration and credentials are never visible to the plugin, and neither are proxy variables such as `HTTPS_PROXY`: if a plugin needs a proxy, it takes the address as a setting. Secrets and the token never travel in the environment or on the command line. An installed plugin runs with its plugin directory as the working directory. On Windows the plugin has no console window.

## 10. Installing and listing plugins

There are two kinds of plugins.

**Bundled plugins** are part of the `tenko` binary. The host starts one by running its own executable as `tenko plugin run <name>`, exactly as it would start a third-party plugin, so the contract is exercised in every installation and the home user installs nothing extra. Standard input and output of that command carry the handshake; it is not meant to be run by hand. The sample plugin is bundled, and so are the reference plugins built on the same SDK: `proxmox` (Proxmox VE inventory) and `hass` (Home Assistant inventory), described for operators in [connectors.md](connectors.md). `tenko plugin list` shows the bundled set of a build. Their sources (`crates/tenko-connect-proxmox`, `crates/tenko-connect-hass`) are complete examples of inventory plugins that read a web API: settings with the TLS properties of `tenko_connect::sdk::http`, a secret per call, paging, vendor facts and fixture-based tests against a mock of the remote system.

**Installed plugins** live in a directory per plugin under the plugin directory, by default `<data_dir>/plugins/`:

```text
<data_dir>/plugins/printer-inventory/
  plugin.json
  bin/printer-inventory
```

The directory holds `plugin.json` and every file the entry names. The host validates the manifest and the entry before every start (section 5): the files exist, stay inside the directory and, on Unix, the executable has an execute bit. There is no installer yet: an operator copies the directory from a source they trust. Installing signed packages from a plugin hub (`tenko plugin install <name>`) is a Phase 5 item (CONN-21).

`tenko plugin list` shows the bundled plugins and the installed ones with a summary of each manifest. It takes `--config <file>` (or `TENKO_CONFIG`) and `--data-dir <path>` to find the installed plugins, `--plugins-dir <path>` to name the plugin directory directly, and `--json` to print JSON instead of a table. Operators create connector instances in the web UI or through the REST API: they pick a plugin, fill in the form that the UI generates from the settings schema, and refer to vault entries for the secrets.

## 11. The conformance suite

`tenko plugin test` runs the conformance suite: what any plugin, in any language, must do to be run by the Tenko host. It starts the plugin as the host does, with the same handshake, token, environment and endpoint, and checks the behavior from the outside.

```console
$ tenko plugin test <path>
$ tenko plugin test --bundled sample
```

`<path>` is one of:

- a plugin executable. The suite validates the manifest of the handshake but has nothing to compare it with.
- a plugin directory with a `plugin.json` and the files of its `entry`, started as the host would start an installed plugin.
- a `plugin.json` file; the suite starts the plugin its `entry` names and compares the handshake manifest with it.
- with `--bundled`, the name of a bundled plugin.

| Option | Meaning |
|---|---|
| `--settings <file>` | A JSON file with settings for the checks that reach the remote system. Without it, those checks use the schema defaults and only require a timely, well-formed answer. |
| `--secret <purpose>=<VARIABLE>` | Gives a secret for those checks, read from the environment variable `VARIABLE`. Secrets are never taken from the command line. May be repeated. |
| `--timeout <seconds>` | The timeout of one call. Default 30. |
| `--json` | Prints the results as JSON instead of a table: the plugin name and version, and for each check its `id`, its `outcome` (`pass`, `fail` or `skip`), a `detail` text and the elapsed milliseconds. |

The exit status is 0 when every check passes and 1 otherwise. Invalid arguments exit with 2, as for every `tenko` command. A check is skipped only when the plugin did not start, which is itself a failed `launch`.

The suite launches the plugin up to three times: for the main checks, once offering only an unknown protocol version, and once to close standard input. A plugin must therefore be able to start again, so it must not hold an exclusive resource that outlives its process. The checks, in the order they run:

| Check | Passes when |
|---|---|
| `launch` | The plugin starts, answers the handshake within the timeout and answers the first ping on its endpoint. |
| `manifest` | The manifest is valid, is equal to `plugin.json` when one is given (name, version, capabilities, secret purposes and settings schema), and lists this platform. Settings that do not satisfy the schema, and required secrets that were not given, are noted in the detail. |
| `ping` | `Ping` answers with the manifest's name and version. |
| `token` | A call without the token and a call with a wrong token are both refused with `UNAUTHENTICATED` and the code `connect.plugin.token`. |
| `concurrency` | 16 parallel pings all answer. |
| `check` | `Check` answers in time with a health value or a coded error, and the plugin still answers pings afterwards. |
| `capability.<name>` | One check per declared capability: a basic call answers in time and the answer is well-formed, with a coded error counting as an answer, and the plugin still lives. For `inventory`, the hosts have unique, non-empty identifiers and valid addresses (no lenient-conversion warnings), and paging ends. For `webhook`, a call with an empty JSON body is answered. For `network_controller`, the topology converts strictly. For `actuator`, a plan for a harmless intent is read. For `migration`, a read of the IPAM area is made. The suite never applies, reverts or writes. |
| `undeclared` | The services that the manifest does not declare (and `HandleWebhook` when `webhook` is not declared) answer `UNIMPLEMENTED`. |
| `malformed_request` | A `Check` whose settings are not JSON is answered with `INVALID_ARGUMENT`, and the plugin lives on. |
| `shutdown` | `Plugin.Shutdown` answers and the process exits with status 0 within 5 seconds. |
| `protocol_mismatch` | A launch that offers only an unknown protocol version is refused with a `protocol_mismatch` failure line that names the plugin's own versions. The plugin should exit with a non-zero status; the host stops waiting for it after half a second and kills it. |
| `stdin_close` | Closing the plugin's standard input ends the process within 5 seconds. |

The checks that reach the remote system are `check` and `capability.<name>`. Without a real system to talk to, an answer that reports on the remote system or the request passes: a health value, or one of the first eight error codes of the table in section 6, such as `connect.invalid_settings` (required settings missing) or `connect.unreachable`. A timeout, a crash, `connect.plugin.failed` and `connect.protocol` fail. Pass `--settings` and `--secret` to run them against a real or a mock system. Run the suite in your plugin's own continuous integration.

## 12. Security expectations

Plugins run with Tenko's identity on the host. A plugin can read the files that Tenko's account can read, and it reaches every network that the host reaches. This is recorded as risk R16 in the [Phase 1 execution plan](plans/phase-1-execution.md). The expectations are these.

**What a plugin author owes the operator:**

- Install and publish plugins from trusted sources only.
- Contact only the network targets the manifest declares. Add a target to the manifest before you add a connection to the code.
- Keep nothing on disk but temporary files, and remove them. Persistent state belongs to Tenko; carry it in cursors.
- Never weaken TLS verification silently. If you offer a setting to turn certificate verification off, make it explicit, default to verifying, and say in the `Check` detail when it is off. Honour the certificate locations the host passes (`SSL_CERT_FILE`, `SSL_CERT_DIR`).
- Never put secrets in settings, logs, status messages or answers (section 7).
- Treat everything the remote system returns as untrusted input: bound sizes, tolerate missing and unexpected members, and do not pass it to a shell, a file path or a query unescaped.
- Do not start background processes that outlive the plugin.

**What the host enforces today:**

- A cleared environment, so that Tenko's configuration and credentials are not inherited (section 9).
- Secrets only for declared purposes, injected per call, wiped after it and audited (section 7).
- A private endpoint (a directory with mode `0700` for the socket, or a pipe that the plugin creates exclusively and that refuses remote clients), and a per-launch token that travels only over standard input and is required on every call.
- Validation of the manifest before every start, a comparison with the manifest in the handshake, and validation of the settings of every instance against the schema.
- Timeouts on every call, limits on message size, paging, migration items, text and log lines (section 6), and supervision with restart backoff and a circuit breaker (section 9). A crashing or hanging plugin degrades its own connector only.

**What the host does not enforce today:**

- Network targets are declarations shown to the operator. The host does not block other connections.
- There is no sandbox. The plugin process has the operating system rights of the Tenko account.
- Plugins are not signed. Trust comes from where the operator got the directory.

**What arrives with the hub** (Phase 5, CONN-21): signed plugin packages and `tenko plugin install <name>`, a sandboxed WebAssembly component transport beside the process transport, and the protocol, SDK and conformance suite in a public repository. Until then the process transport and the expectations above are all the protection there is, as ADR 0012 records.
