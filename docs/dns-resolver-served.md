# DoT and DoH served to clients

This page describes how a node serves DNS over TLS and DNS over HTTPS to its clients (DNS-14, WP5.3 of the Phase 2 plan). It is meant to become section 7 of `docs/dns-resolver.md`. The engine side is `tenko_dns::tls` (`crates/tenko-dns/src/tls`). The role side is the `[dns.tls]` section of `tenko.toml`, read by the `dns` role start (`crates/tenko/src/serve/dns.rs`). The deployment steps, including the HAProxy snippets, are in [`deploy/README.md`](../deploy/README.md), section "DNS over TLS and DNS over HTTPS".

## 1. The transports

Both transports are off by default. `[dns.tls] dot = true` and `doh = true` turn them on. They run on the tokio runtime beside TCP and call the same responder as UDP and TCP, so a query gets the same answer on every transport: the same views (a view can match on `transport` `dot` or `doh`), the same cookie secret, the same forwarder, the same query log and the same metrics, only with another `proto` label.

| Transport | Default address | Framing | ALPN |
|---|---|---|---|
| DoT (RFC 7858) | each `[dns] listen` address on port 853 | the two-octet length prefix of RFC 7766 inside TLS | `dot` |
| DoH (RFC 8484) | each `[dns] listen` address on port 443 | HTTP/2, or HTTP/1.1 for clients that ask for it | `h2`, `http/1.1` |

**DoT** reads messages in arrival order. A client may pipeline queries; queries that were already received are answered before anything is written. The answers go out together, and are flushed, when no further query is buffered or 32 KiB of answers are waiting. A forwarded query is answered when the upstream's answer arrives, out of order with the rest, as RFC 7766 allows. A client that offers ALPN without `dot` fails the handshake. A client that offers no ALPN at all is served.

**DoH** serves one path, `/dns-query`:

| Request | Answer |
|---|---|
| `GET /dns-query?dns=<base64url>` (no padding; padding, also percent-encoded, is accepted) | `200`, `application/dns-message` |
| `POST /dns-query` with `Content-Type: application/dns-message` and the message as the body | `200`, `application/dns-message` |
| another path | `404` |
| another method | `405` with `Allow: GET, POST` |
| `POST` with another media type | `415` |
| a body over 65,535 octets | `413` |
| a missing or undecodable `dns` parameter, a message shorter than a header, a response, or a query the resolver drops | `400` |
| a forwarded query whose answer does not come within 15 s | `504` |

A DNS answer is always `200`, whatever its RCODE (RFC 8484 section 4.2.1). Its `Cache-Control` is `max-age=` the smallest TTL of the answer and authority sections. A negative answer therefore carries the TTL of its SOA, which the resolver has already capped at the SOA minimum (RFC 2308). An answer without records gets `max-age=0`. The answer keeps the query's ID; clients that send ID 0, as RFC 8484 recommends, get 0 back. Nothing else of HTTP is used: no cookies, no redirects, no content negotiation (the `Accept` header is not read), no server push.

## 2. The TLS material

There is no ACME (owner decision P2-Q8). DoT and DoH serve one of four sources:

| Setting | Certificate served | Renewal or reload |
|---|---|---|
| `[tls] mode = "internal_ca"` (the default), no `[dns.tls] certificate` | The API's server certificate from the internal CA, for the installation's host name, `[tls] alt_names` and `[tls] addresses` | Renewed by the API's renewal task; DoT and DoH follow it |
| `[tls] mode = "imported"`, no `[dns.tls] certificate` | The API's imported files (`[tls] cert_path`, `key_path`) | The API's watcher reloads changed files every `[tls] watch_interval_secs`; DoT and DoH follow it |
| `[dns.tls] certificate` and `key` | A PEM chain and key for DNS only, for example a certificate whose name is the resolver's name (`dns.example.test`) rather than the console's | Watched in the same way, every `[tls] watch_interval_secs`; a file that fails to load keeps the previous certificate and logs a warning |
| `[dns.tls] behind_proxy = true` | None. The reverse proxy ends TLS | In the proxy |

Hot reload works without a restart: the listeners keep one TLS configuration over a certificate resolver that swaps its certificate in place. The next handshake gets the new certificate, the listener is never dropped, and connections that are already open finish on the certificate they started with (`crates/tenko-dns/tests/tls.rs`). TLS 1.3 is preferred. TLS 1.2 is allowed unless `[tls] tls13_only` is set or the profile is Hardened. TLS 1.3 sessions resume with tickets, so a reconnecting client saves a round trip (RFC 7858 section 3.4). There is no early data and no client authentication.

**Clients of the internal CA.** A client must trust the CA root (`<data_dir>/tls/ca-root.pem`, or `GET /api/v1/system/ca-root`) and must ask for a name that is on the certificate. With `kdig`: `kdig @192.0.2.53 +tls-ca=ca-root.pem +tls-hostname=tenko.example.test www.example.test`. Operating systems that take a DoT or DoH resolver by name (Android's private DNS, browsers) only accept a certificate from a CA they trust. For them, use the imported mode or `[dns.tls] certificate` with a certificate from a public CA, or install the root on every client.

**Behind a reverse proxy.** The proxy ends TLS. DoT then reaches Tenko as plain length-prefixed DNS (HAProxy in TCP mode) and DoH as plain HTTP (HAProxy as HTTPS). Both are served on the `dot_listen` and `doh_listen` addresses, which must be listed and must not be wildcards (loopback or an internal address). Only peers in `[tls] trusted_proxies` may connect; any other connection is closed at once and counted as refused. The client address, which the views, the query log and the per-client limits use, is found in this order:

1. With `[dns.tls] proxy_protocol = true`, every connection must start with a PROXY protocol version 2 header (`send-proxy-v2`). The header's source address is the client. A `LOCAL` header (the proxy's own health check) leaves the proxy as the client. A connection without a valid header is closed. Version 1 (the text form) is not read.
2. Without it, DoH takes the last entry of the last `X-Forwarded-For` header (`option forwardfor`).
3. Otherwise the client is the proxy.

## 3. Limits

Each transport counts its own connections, separately from TCP's. A burst of encrypted connections therefore cannot take TCP 53 away from plain clients, and plain clients cannot take the encrypted transports away either.

| Limit | Default | What happens |
|---|---|---|
| `max_connections` | 1,000 per node and transport | A connection over the cap is closed at accept and counted as refused |
| `per_client` | 10 per client address and transport | The same. Behind a proxy only the node cap applies, because every connection comes from the proxy |
| `handshake_timeout_secs` | 5 | A TLS handshake or PROXY header that fails or takes longer closes the connection; counted as a handshake failure |
| `idle_secs` | 30 | A DoT connection with no query for this long is closed with a TLS `close_notify`. A DoH connection with no request in progress for this long is closed: HTTP/2 `GOAWAY`, or the end of the HTTP/1.1 keep-alive |
| `doh_streams` | 100 | Concurrent requests on one HTTP/2 connection (`SETTINGS_MAX_CONCURRENT_STREAMS`) |
| fixed | 65,535 octets | The largest message on either transport |

When the server stops, it stops accepting. DoT connections close after the query in hand, and DoH connections get `GOAWAY` and have 2 seconds to finish their requests. Response rate limiting (TGL-11, RRL) and the per-client query limits of the rate limiter apply to the query, not to the transport, and are the same as on TCP.

**Allocation.** Once a DoT connection is up, a query allocates nothing: it runs on the runtime thread's buffers, the same as TCP. Each connection allocates its read buffer, its write buffer and the TLS state. A DoH request allocates its HTTP request and answer (hyper), the decoded query and a copy of the answer. The query path behind them is the allocation-free one that `tests/alloc.rs` checks.

## 4. Settings

The `[dns.tls]` section of `tenko.toml` ([`deploy/tenko.example.toml`](../deploy/tenko.example.toml)). Environment variables follow the usual pattern, for example `TENKO_DNS__TLS__DOT=true` and `TENKO_DNS__TLS__DOH_LISTEN=192.0.2.53:443`. `tenko config check` validates the section against the rest of the file. The settings are read at start; a change needs a restart.

| Key | Default | Meaning |
|---|---|---|
| `dot`, `doh` | `false` | Serve DoT, DoH |
| `dot_listen` | each `[dns] listen` address on 853 | DoT addresses |
| `doh_listen` | each `[dns] listen` address on 443 | DoH addresses |
| `certificate`, `key` | not set: the API's certificate | A PEM chain (leaf first) and key for DoT and DoH only; both or neither |
| `behind_proxy` | `false` | Plain DNS and HTTP from `[tls] trusted_proxies`, on listed non-wildcard addresses |
| `proxy_protocol` | `false` | With `behind_proxy`, every connection starts with a PROXY v2 header |
| `max_connections` | 1000 | 1 to 100,000 per node and transport |
| `per_client` | 10 | 1 to 1,000 per client address and transport |
| `idle_secs` | 30 | 1 to 3,600 |
| `handshake_timeout_secs` | 5 | 1 to 60 |
| `doh_streams` | 100 | 1 to 1,000 |

The configuration check refuses the following:

- a DoT or DoH address that takes the port of the API (`[server] listen`) or the TCP port of `[dns] listen`, or DoT and DoH on the same port. DoH on the API's own port and path is not served; give DoH its own address or port, or put both behind the proxy;
- `behind_proxy` without `[tls] trusted_proxies`, without listed addresses, or with a wildcard address;
- `behind_proxy` together with `certificate`, and `proxy_protocol` without `behind_proxy`;
- terminating TLS when the API has no certificate (`[tls] mode = "reverse_proxy"` or `"plain"`) and `[dns.tls] certificate` is not set.

A certificate that does not load fails the start with `start.dns.tls`. An address that cannot be bound fails it with `start.dns.bind`. Ports 853 and 443 are below 1024 and need `CAP_NET_BIND_SERVICE` on Linux, as port 53 does.

## 5. Status and metrics

`tenko serve` ends the role's line with the encrypted listeners, for example `dns role answering on 192.0.2.53:53 (UDP and TCP), ...; DoT on 192.0.2.53:853, DoH on 192.0.2.53:443 with the API's certificate (internal_ca)`. The node's status (`GET /api/v1/nodes/{id}/dns`, `listeners`) lists each DoT and DoH address with the transport `dot` or `doh`. `Server::layout` reports, for each transport, its addresses, its open connections, the refused ones and the failed handshakes (`tls` in the worker layout); the API route shows the TCP counters only so far.

| Family | Type | Labels | Meaning |
|---|---|---|---|
| `tenko_dns_queries_total` | counter | `proto` = `dot`, `doh` (with `view`, `rcode`) | Queries answered, as on UDP and TCP |
| `tenko_dns_query_duration_seconds` | histogram | `proto` | Time from a query's arrival to its answer |
| `tenko_dns_connections` | gauge | `proto` | Open DoT and DoH connections |
| `tenko_dns_connections_refused_total` | counter | `proto` | Connections refused by a cap, or, behind a proxy, from an untrusted peer |
| `tenko_dns_tls_handshake_failures_total` | counter | `proto` | TLS handshakes and PROXY headers that failed or timed out |

The last three families are registered when DoT or DoH is on.

## 6. Conformance

| RFC | Behaviour | Status |
|---|---|---|
| RFC 7858 | DoT on port 853, length-prefixed messages, pipelining, idle close, connection reuse | Implemented |
| RFC 7858 section 3.4 | TLS session resumption | Implemented (TLS 1.3 tickets) |
| RFC 8310 | ALPN `dot` | Implemented |
| RFC 8484 | `GET` with `dns`, `POST` with `application/dns-message`, HTTP/2, HTTP freshness from the smallest TTL | Implemented |
| RFC 8484 section 5.1 | `max-age` for negative answers from the SOA | Implemented |
| RFC 7830, RFC 8467 | EDNS(0) padding of encrypted answers | Not done: the answers are not padded |
| RFC 9250 | DNS over QUIC | Not done |
| RFC 8484 section 5.2 | HTTP/2 server push | Not done (never used) |
| PROXY protocol | Version 2 header for the client address | Implemented; version 1 not read |

## 7. Known limits

- A change of the API's TLS mode while the process runs (the settings page switching to the reverse-proxy mode) removes the certificate that DoT and DoH share with the API, and their handshakes then fail until the node restarts with a matching `[dns.tls]`. A certificate of their own (`[dns.tls] certificate`) does not have this dependency.
- The API route of the node status shows the DoT and DoH listeners, but not yet their open and refused counters; `Server::layout` and the metrics have them.
- Answers are not padded (RFC 8467). A passive observer can guess an answer from its length.
- DoH is not served under `/dns-query` on the API's own listener (risk R49 of the Phase 2 plan). It needs an address or port of its own, or the reverse proxy in front of both.
