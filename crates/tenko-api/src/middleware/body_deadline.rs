//! The deadline for reading a request body, on both listeners (`outer` puts it on every
//! request that has a body).
//!
//! The server waits for a body at most [`GRACE`] plus one second per [`MIN_RATE`] bytes
//! received, so a route that admits `n` MiB has read its whole body within `GRACE` plus
//! `n` times 128 seconds, and a client that trickles its body or stops sending loses the
//! request. Only the time the server waits on the client counts, never the time a handler
//! spends before or between its reads. A body past its deadline ends with an error for its
//! reader, the unread rest is dropped, and `outer` answers 408 `sys.body_timeout` with
//! `Connection: close`. A request without a body is not wrapped, and answers (the event
//! stream, exports) are never touched.

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::{Body, Bytes, HttpBody},
    extract::Request,
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use hyper::body::{Frame, SizeHint};
use tokio::time::{Instant, Sleep};

use crate::problem::{ApiError, codes};

/// How long the server waits for a body before what arrived counts: the head's own limit
/// (`[server] header_read_timeout_secs` defaults to the same 30 seconds).
pub const GRACE: Duration = Duration::from_secs(30);
/// The slowest a body may arrive, in bytes per second: 64 kbit/s, the slowest link the
/// product measures for a branch site (OPS-28), so an upload over such a link still fits.
pub const MIN_RATE: u64 = 8 * 1024;

/// Puts the deadline on `request`'s body; answers the flag the body raises when it expires,
/// or `None` for a request without a body.
pub(crate) fn wrap(request: &mut Request) -> Option<Arc<AtomicBool>> {
    if request.body().is_end_stream() {
        return None;
    }
    let expired = Arc::new(AtomicBool::new(false));
    let inner = std::mem::take(request.body_mut());
    *request.body_mut() = Body::new(Deadline {
        inner,
        received: 0,
        waited: Duration::ZERO,
        pending_since: None,
        sleep: None,
        expired: Arc::clone(&expired),
    });
    Some(expired)
}

/// The answer to a request whose body missed its deadline.
pub(crate) fn refusal() -> Response {
    let mut response = ApiError::new(
        codes::BODY_TIMEOUT,
        408,
        format!(
            "the request body did not arrive in time: after {} seconds it must arrive at {} \
             KiB/s or faster",
            GRACE.as_secs(),
            MIN_RATE / 1024
        ),
    )
    .into_response();
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
    response
}

/// A request body with its deadline.
struct Deadline {
    inner: Body,
    /// The bytes received so far.
    received: u64,
    /// The time spent waiting on the client before the current wait.
    waited: Duration,
    /// When the current wait began.
    pending_since: Option<Instant>,
    sleep: Option<Pin<Box<Sleep>>>,
    expired: Arc<AtomicBool>,
}

fn timed_out() -> axum::Error {
    axum::Error::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "the request body did not arrive in time",
    ))
}

impl HttpBody for Deadline {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        let this = &mut *self;
        if this.expired.load(Ordering::Relaxed) {
            return Poll::Ready(Some(Err(timed_out())));
        }
        let now = Instant::now();
        if let Poll::Ready(frame) = Pin::new(&mut this.inner).poll_frame(cx) {
            if let Some(since) = this.pending_since.take() {
                this.waited += now.saturating_duration_since(since);
            }
            if let Some(data) = frame
                .as_ref()
                .and_then(|frame| frame.as_ref().ok()?.data_ref())
            {
                let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                this.received = this.received.saturating_add(length);
            }
            return Poll::Ready(frame);
        }
        let since = *this.pending_since.get_or_insert(now);
        let allowance =
            GRACE + Duration::from_millis(this.received.saturating_mul(1000) / MIN_RATE);
        let fired = match allowance.checked_sub(this.waited) {
            None => true,
            Some(left) => {
                let due = since + left;
                let sleep = this
                    .sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
                if sleep.deadline() != due {
                    sleep.as_mut().reset(due);
                }
                sleep.as_mut().poll(cx).is_ready()
            }
        };
        if !fired {
            return Poll::Pending;
        }
        this.expired.store(true, Ordering::Relaxed);
        // The unread rest goes now, not when the reader drops the body.
        this.inner = Body::empty();
        Poll::Ready(Some(Err(timed_out())))
    }

    fn is_end_stream(&self) -> bool {
        !self.expired.load(Ordering::Relaxed) && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use futures::StreamExt as _;

    use super::*;

    fn request(body: Body) -> (Request, Option<Arc<AtomicBool>>) {
        let mut request = Request::new(body);
        let expired = wrap(&mut request);
        (request, expired)
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_stops_arriving_ends_at_the_grace_and_raises_the_flag() {
        let started = Instant::now();
        let stalled = futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"{"))])
            .chain(futures::stream::pending());
        let (request, expired) = request(Body::from_stream(stalled));
        let expired = expired.expect("a body is wrapped");
        let error = to_bytes(request.into_body(), usize::MAX)
            .await
            .expect_err("the body is cut");
        assert!(
            error.to_string().contains("did not arrive in time"),
            "{error}"
        );
        assert!(expired.load(Ordering::Relaxed));
        // One byte buys no more than its share of a second.
        assert!(started.elapsed() >= GRACE);
        assert!(started.elapsed() < GRACE + Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_at_the_minimum_rate_arrives_whole_however_long_it_takes() {
        let chunk = usize::try_from(MIN_RATE).expect("chunk");
        // Four times the grace, one second per chunk.
        let chunks = 4 * GRACE.as_secs();
        let slow = futures::stream::iter(0..chunks).then(move |_| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok::<_, std::io::Error>(Bytes::from(vec![b' '; chunk]))
        });
        let (request, expired) = request(Body::from_stream(slow));
        let body = to_bytes(request.into_body(), usize::MAX)
            .await
            .expect("the whole body");
        assert_eq!(body.len() as u64, chunks * MIN_RATE);
        assert!(!expired.expect("a body is wrapped").load(Ordering::Relaxed));
    }

    #[tokio::test(start_paused = true)]
    async fn time_the_reader_spends_between_reads_is_not_the_clients() {
        let (request, expired) = request(Body::from("{}"));
        // The handler works for longer than the grace before it reads.
        tokio::time::sleep(GRACE * 2).await;
        assert_eq!(
            to_bytes(request.into_body(), usize::MAX)
                .await
                .expect("body"),
            "{}"
        );
        assert!(!expired.expect("a body is wrapped").load(Ordering::Relaxed));
    }

    #[test]
    fn a_request_without_a_body_is_not_wrapped() {
        assert!(request(Body::empty()).1.is_none());
    }
}
