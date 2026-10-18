//! Block lists in the process (WP5.2, P2-Q6): the HTTP fetcher of the compile job and the
//! leader service `dns.lists` that schedules the fetches.
//!
//! The fetcher reads a list's URL with the process's HTTP client (rustls with the system's
//! roots, no redirects to other schemes than HTTPS and HTTP, `[dns.lists]
//! fetch_timeout_secs`), sends `If-None-Match` with the entity tag of the newest version
//! and reads at most `max_download` MiB. The leader service looks at the lists every
//! minute and submits the compile job `dns.list.compile` for every enabled URL list whose
//! newest version and last attempt are older than its interval (a list without a version
//! at once; a failed attempt again after 15 minutes, or its interval when that is shorter).
//! The service keeps no state the store does not hold beyond the attempts of its term: a
//! new leader fetches what is due from the versions' times.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use tenko_core::{
    RequestCtx, SystemComponent, Timestamp,
    cluster::LeaderService,
    dns::{BlockListId, ListSource},
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

/// The fetcher over `reqwest`.
pub(crate) struct HttpFetcher {
    client: reqwest::Client,
    max_bytes: usize,
}

impl HttpFetcher {
    /// The fetcher of `[dns.lists]`.
    ///
    /// # Errors
    ///
    /// The client's error when it cannot be built.
    pub(crate) fn new(section: &DnsListsSection) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .redirect(reqwest::redirect::Policy::limited(5))
            .timeout(Duration::from_secs(section.fetch_timeout_secs))
            .user_agent(format!("tenko/{}", crate::version()))
            .build()
            .map_err(|error| format!("the HTTP client of the block lists: {error}"))?;
        Ok(Self {
            client,
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

#[async_trait::async_trait]
impl ListFetcher for HttpFetcher {
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<Fetched, FetchFailure> {
        let mut request = self.client.get(url);
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let mut response = request
            .send()
            .await
            .map_err(|error| failure(format!("{url} could not be read: {error}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !status.is_success() {
            return Err(failure(format!("{url} answered {status}")));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(failure(format!(
                "{url} is larger than dns.lists.max_download ({} MiB)",
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
            .map_err(|error| failure(format!("{url} could not be read: {error}")))?
        {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(failure(format!(
                    "{url} is larger than dns.lists.max_download ({} MiB)",
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
