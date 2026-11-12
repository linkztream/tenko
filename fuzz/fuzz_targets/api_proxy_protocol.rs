#![no_main]
//! The PROXY protocol reader of the API and UI listener (`tenko_api::server::proxy_protocol`),
//! a separate implementation from the one of DoT and DoH: the first octets of a connection
//! from a trusted reverse proxy, version 1 (text) and version 2 (binary, with TLVs).
//!
//! The input is one control octet and the octets of a connection. The control octet sets the
//! size of the reads the connection delivers (1 to 1,021 octets), so a header arrives split
//! at every place. It checks that a header that parses is self-delimiting (the same header
//! parses from its own octets and not from fewer) and within the limits of its version (107
//! octets for version 1, 4,096 for version 2); that the reader over the split connection
//! decides as the parser decides on the whole input, and hands on exactly the octets after
//! the header that it has read; and that the detector and the parser agree.

use std::{
    io,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
    time::Duration,
};

use libfuzzer_sys::fuzz_target;
use tenko_api::server::proxy_protocol::{self, Detection, ProxyError};
use tokio::io::{AsyncRead, ReadBuf};

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
});

/// A connection that delivers `data` in reads of at most `chunk` octets, then ends.
struct Split<'a> {
    data: &'a [u8],
    chunk: usize,
}

impl AsyncRead for Split<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let take = self.chunk.min(self.data.len()).min(buf.remaining());
        let (head, rest) = self.data.split_at(take);
        buf.put_slice(head);
        self.data = rest;
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, stream)) = data.split_first() else {
        return;
    };
    let detection = proxy_protocol::detect(stream);
    let parsed = proxy_protocol::parse(stream);
    match &parsed {
        Ok(Some((header, consumed))) => {
            assert!(matches!(detection, Detection::V1 | Detection::V2));
            let consumed = *consumed;
            assert!(consumed <= stream.len());
            match header.version {
                1 => assert!(consumed <= 107 && !header.tls),
                2 => assert!(consumed <= 4096),
                other => panic!("version {other}"),
            }
            // Self-delimiting: the header alone parses to the same, one octet less does not.
            let alone =
                proxy_protocol::parse(&stream[..consumed]).expect("the header alone parses");
            assert_eq!(alone, Some((header.clone(), consumed)));
            assert!(matches!(
                proxy_protocol::parse(&stream[..consumed - 1]),
                Ok(None)
            ));
        }
        Ok(None) => assert!(!matches!(detection, Detection::NotProxy)),
        Err(_) => {}
    }

    let mut connection = Split {
        data: stream,
        chunk: 1 + usize::from(control) * 4,
    };
    let read = RUNTIME.block_on(proxy_protocol::read_header(
        &mut connection,
        Duration::from_secs(10),
    ));
    match read {
        Ok((Some(header), after)) => {
            let Ok(Some((parsed, consumed))) = &parsed else {
                panic!("the reader found a header the parser did not: {parsed:?}");
            };
            assert_eq!(&header, parsed);
            assert!(stream[*consumed..].starts_with(&after));
        }
        Ok((None, octets)) => {
            assert!(matches!(detection, Detection::NotProxy));
            assert!(stream.starts_with(&octets));
        }
        Err(ProxyError::Closed) => assert!(matches!(parsed, Ok(None))),
        Err(ProxyError::Invalid(_) | ProxyError::TooLong) => assert!(parsed.is_err()),
        Err(error @ (ProxyError::Timeout | ProxyError::Io(_))) => {
            panic!("a connection that never stalls or fails: {error}")
        }
    }
});
