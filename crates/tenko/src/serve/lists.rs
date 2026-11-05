//! Block lists in the process (WP5.2, P2-Q6): the HTTP fetcher of the compile job and the
//! leader service `dns.lists` that schedules the fetches.
//!
//! The fetcher reads a list's URL with the process's HTTP client (rustls with the system's
//! roots, no redirects to other schemes than HTTPS and HTTP, `[dns.lists]
//! fetch_timeout_secs`), sends `If-None-Match` with the entity tag of the newest version
//! and reads at most `max_download` MiB. Every connection it opens passes the egress policy
//! of server-side fetches (`tenko_core::egress`, `[dns] egress_allow`): the URL's host
//! when it is an address, every address a host name resolves to (through the client's
//! resolver, at every lookup), and every redirect's target the same way, at most five
//! redirects. The detail of a failure names neither the URL nor what the server answered
//! beyond its status, since it is shown to every reader of the list. The leader service looks at the lists every
//! minute and submits the compile job `dns.list.compile` for every enabled URL list whose
//! newest version and last attempt are older than its interval (a list without a version
//! at once; a failed attempt again after 15 minutes, or its interval when that is shorter).
//! The service keeps no state the store does not hold beyond the attempts of its term: a
//! new leader fetches what is due from the versions' times.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::{
    RequestCtx, SystemComponent, Timestamp,
    cluster::LeaderService,
    dns::{BlockListId, ListSource},
    egress::{self, EgressPolicy},
};
use tenko_dns::{
    lists::{FetchFailure, Fetched, ListFetcher, ListStaging, fetch_status, job::Trigger},
    zone::ZoneService,
};
use tokio_util::sync::CancellationToken;

use crate::config::DnsListsSection;

/// How often the service looks at the lists.
pub(crate) const PERIOD: Duration = Duration::from_secs(60);

/// How soon a failed list is tried again at most.
const RETRY: Duration = Duration::from_secs(15 * 60);

/// How long a submitted job is waited for before the list may be submitted again.
const IN_FLIGHT: Duration = Duration::from_secs(15 * 60);

/// How many redirects a fetch follows at most.
const MAX_REDIRECTS: usize = 5;

/// The resolver of the fetcher's client: the system's lookup, with every address judged
/// by the egress policy. A name that resolves to a refused address does not resolve, so
/// no connection is attempted to any of its addresses (a mixed answer would otherwise
/// fall through to a refused one when the allowed one fails). Reqwest asks it for host
/// names only; a host written as an address is judged by [`check_url`] and the redirect
/// policy instead.
struct GuardedResolver {
    policy: Arc<EgressPolicy>,
}

impl reqwest::dns::Resolve for GuardedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let policy = Arc::clone(&self.policy);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // The port is a placeholder: the connector sets the URL's port.
            let addresses: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let ips: Vec<IpAddr> = addresses.iter().map(SocketAddr::ip).collect();
            policy
                .check_all(&ips)
                .map_err(|refusal| format!("the host resolves to {refusal}"))?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Checks a URL the client is about to request, before any lookup: an `http` or `https`
/// URL without credentials whose host, when written as an address, the policy allows.
fn check_url(policy: &EgressPolicy, url: &str) -> Result<(), FetchFailure> {
    egress::check_url(policy, url).map_err(|refusal| failure(refusal.reason()))
}

/// The fetcher over `reqwest`.
pub(crate) struct HttpFetcher {
    client: reqwest::Client,
    policy: Arc<EgressPolicy>,
    max_bytes: usize,
}

impl HttpFetcher {
    /// The fetcher of `[dns.lists]` under the egress `policy`.
    ///
    /// # Errors
    ///
    /// The client's error when it cannot be built.
    pub(crate) fn new(
        section: &DnsListsSection,
        policy: Arc<EgressPolicy>,
    ) -> Result<Self, String> {
        let redirects = Arc::clone(&policy);
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .dns_resolver(Arc::new(GuardedResolver {
                policy: Arc::clone(&policy),
            }))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= MAX_REDIRECTS {
                    return attempt.error("too many redirects");
                }
                match egress::check_url(&redirects, attempt.url().as_str()) {
                    Ok(()) => attempt.follow(),
                    Err(refusal) => attempt.error(format!("a redirect to {}", refusal.reason())),
                }
            }))
            .timeout(Duration::from_secs(section.fetch_timeout_secs))
            .user_agent(format!("tenko/{}", crate::version()))
            .build()
            .map_err(|error| format!("the HTTP client of the block lists: {error}"))?;
        Ok(Self {
            client,
            policy,
            max_bytes: usize::try_from(section.max_download)
                .unwrap_or(usize::MAX)
                .saturating_mul(1024 * 1024),
        })
    }
}

fn failure(detail: impl Into<String>) -> FetchFailure {
    FetchFailure {
        detail: detail.into(),
    }
}

/// The detail of a request error, without the URL that reqwest's own text carries: what
/// kind of failure it was, and for a redirect the policy's reason.
fn describe(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the source did not answer in time".to_owned()
    } else if error.is_redirect() {
        let reason = std::error::Error::source(error)
            .map(ToString::to_string)
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "a redirect the policy refuses".to_owned());
        format!("the source redirected: {reason}")
    } else if error.is_connect() {
        // The resolver's refusal and a refused connection both land here; the egress
        // reason is the source of the connect error when the resolver refused.
        let mut cause: Option<&(dyn std::error::Error + 'static)> =
            std::error::Error::source(error);
        while let Some(inner) = cause {
            let text = inner.to_string();
            if text.starts_with("the host resolves to") {
                return format!("the source could not be reached: {text}");
            }
            cause = inner.source();
        }
        "the source could not be reached".to_owned()
    } else if error.is_body() || error.is_decode() {
        "the source's answer could not be read".to_owned()
    } else {
        "the source could not be read".to_owned()
    }
}

#[async_trait::async_trait]
impl ListFetcher for HttpFetcher {
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<Fetched, FetchFailure> {
        check_url(&self.policy, url)?;
        let mut request = self.client.get(url);
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| failure(describe(&error)))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !status.is_success() {
            return Err(failure(format!("the source answered {status}")));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(failure(format!(
                "the source is larger than dns.lists.max_download ({} MiB)",
                self.max_bytes / (1024 * 1024)
            )));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| failure(describe(&error)))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(failure(format!(
                    "the source is larger than dns.lists.max_download ({} MiB)",
                    self.max_bytes / (1024 * 1024)
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Fetched::Changed { body, etag })
    }
}

/// The leader service `dns.lists`.
pub(crate) struct ListService {
    zones: Arc<ZoneService>,
    staging: Arc<ListStaging>,
    period: Duration,
}

impl ListService {
    /// The service over the zone service, looking at the lists every `period`.
    pub(crate) fn new(
        zones: Arc<ZoneService>,
        staging: Arc<ListStaging>,
        period: Duration,
    ) -> Self {
        Self {
            zones,
            staging,
            period,
        }
    }

    /// One look at the lists: submits the compile job of every list that is due.
    async fn tick(&self, submitted: &mut HashMap<BlockListId, Instant>) -> Result<(), String> {
        let view = self
            .zones
            .view(None)
            .await
            .map_err(|error| error.to_string())?;
        let rows = ZoneService::block_lists(view.as_ref()).map_err(|error| error.to_string())?;
        drop(view);
        let now = Timestamp::now();
        submitted.retain(|_, at| at.elapsed() < IN_FLIGHT);
        for row in rows {
            let list = &row.list;
            if !list.enabled || !matches!(list.source, ListSource::Url { .. }) {
                continue;
            }
            let interval = Duration::from_secs(u64::from(list.interval_hours) * 3600);
            let version_due = row
                .version
                .as_ref()
                .is_none_or(|version| now.saturating_since(version.fetched) >= interval);
            let attempt_due = fetch_status(list.id).is_none_or(|status| {
                let wait = if status.error.is_some() {
                    RETRY.min(interval)
                } else {
                    interval
                };
                now.saturating_since(status.checked) >= wait
            });
            if !version_due || !attempt_due || submitted.contains_key(&list.id) {
                continue;
            }
            let cx = RequestCtx::system(SystemComponent::Dns);
            match self
                .zones
                .start_list_compile(&cx, list.id, &self.staging, None, Trigger::Schedule)
                .await
            {
                Ok(job) => {
                    tracing::debug!(list = %list.name, %job, "block list fetch submitted");
                    submitted.insert(list.id, Instant::now());
                }
                Err(error) => {
                    tracing::warn!(list = %list.name, %error, "the fetch of a block list could not be submitted");
                }
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl LeaderService for ListService {
    fn name(&self) -> &'static str {
        "dns.lists"
    }

    async fn run(&self, _epoch: u64, stop: CancellationToken) -> Result<(), String> {
        let mut submitted = HashMap::new();
        loop {
            if let Err(error) = self.tick(&mut submitted).await {
                tracing::warn!(%error, "the block lists could not be read");
            }
            tokio::select! {
                () = stop.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.period) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetcher(policy: EgressPolicy) -> HttpFetcher {
        HttpFetcher::new(&DnsListsSection::default(), Arc::new(policy)).expect("client")
    }

    /// A fetch of a URL the policy refuses fails before any connection, and the detail
    /// names the class, not the URL.
    #[tokio::test]
    async fn a_refused_url_fails_before_any_connection() {
        let fetcher = fetcher(EgressPolicy::default());
        for (url, reason) in [
            ("http://127.0.0.1:1/hosts", "a loopback address"),
            ("http://[::1]:1/hosts", "a loopback address"),
            (
                "http://169.254.169.254/latest/meta-data",
                "a metadata service address",
            ),
            ("http://[fd00:ec2::254]/", "a metadata service address"),
            ("http://224.0.0.1/hosts", "a multicast address"),
            ("http://0.0.0.0/hosts", "the unspecified address"),
            (
                "http://user:secret@192.0.2.10/hosts",
                "a URL without credentials",
            ),
            ("ftp://192.0.2.10/hosts", "an http or https URL"),
        ] {
            let error = fetcher.fetch(url, None).await.expect_err(url);
            assert!(error.detail.contains(reason), "{url}: {}", error.detail);
            assert!(!error.detail.contains(url), "{url}: {}", error.detail);
        }
    }

    /// A refused host resolution is a connect failure whose detail names the class.
    #[tokio::test]
    async fn a_name_that_resolves_to_a_refused_address_is_not_connected_to() {
        let fetcher = fetcher(EgressPolicy::default());
        // `localhost` resolves to loopback on every host that runs the tests.
        let error = fetcher
            .fetch("http://localhost:1/hosts", None)
            .await
            .expect_err("loopback");
        assert!(
            error
                .detail
                .contains("the host resolves to a loopback address"),
            "{}",
            error.detail
        );
        assert!(!error.detail.contains("localhost"), "{}", error.detail);
    }

    /// An allowed prefix lets the policy's refusal through: the fetch then reaches the
    /// connection, which fails on a closed port with a detail without the URL.
    #[tokio::test]
    async fn an_allowed_prefix_reaches_the_connection() {
        let fetcher = fetcher(EgressPolicy::with_allowed(vec![
            "127.0.0.0/8".parse().expect("prefix"),
        ]));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = listener.local_addr().expect("address").port();
        drop(listener);
        let error = fetcher
            .fetch(&format!("http://127.0.0.1:{port}/hosts"), None)
            .await
            .expect_err("nothing listens");
        assert!(
            error.detail.starts_with("the source could not be reached")
                || error.detail.starts_with("the source could not be read"),
            "{}",
            error.detail
        );
        assert!(!error.detail.contains("127.0.0.1"), "{}", error.detail);
    }

    /// A redirect to a refused address is refused, with the class in the detail.
    #[tokio::test]
    async fn a_redirect_to_a_refused_address_is_refused() {
        let fetcher = fetcher(EgressPolicy::with_allowed(vec![
            "127.0.0.0/8".parse().expect("prefix"),
        ]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("address").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("a connection");
            let mut buffer = [0_u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await;
            let answer = "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            tokio::io::AsyncWriteExt::write_all(&mut socket, answer.as_bytes())
                .await
                .expect("the answer");
        });
        let error = fetcher
            .fetch(&format!("http://127.0.0.1:{port}/hosts"), None)
            .await
            .expect_err("the redirect is refused");
        server.await.expect("the server");
        assert!(
            error
                .detail
                .contains("a redirect to the host is a metadata service address"),
            "{}",
            error.detail
        );
        assert!(
            !error.detail.contains("169.254.169.254"),
            "{}",
            error.detail
        );
        assert!(!error.detail.contains("127.0.0.1"), "{}", error.detail);
    }

    /// An HTTP error carries the status alone, not the URL and not the body.
    #[tokio::test]
    async fn an_http_error_names_the_status_only() {
        let fetcher = fetcher(EgressPolicy::with_allowed(vec![
            "127.0.0.0/8".parse().expect("prefix"),
        ]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let port = listener.local_addr().expect("address").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("a connection");
            let mut buffer = [0_u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buffer).await;
            let answer = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsecret-body!";
            tokio::io::AsyncWriteExt::write_all(&mut socket, answer.as_bytes())
                .await
                .expect("the answer");
        });
        let error = fetcher
            .fetch(&format!("http://127.0.0.1:{port}/hosts"), None)
            .await
            .expect_err("503");
        server.await.expect("the server");
        assert_eq!(error.detail, "the source answered 503 Service Unavailable");
    }
}
