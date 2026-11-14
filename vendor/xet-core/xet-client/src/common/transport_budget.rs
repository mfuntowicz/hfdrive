//! HF Drive transport-budget hook (vendored patch; see `vendor/xet-core/README.md`).
//!
//! This module is the only behavioral addition HF Drive makes to `xet-client`
//! 1.8.1: it exposes the actual encoded HTTP body read/write boundaries of
//! this client to an external pacing/counting hook. Xet chunking, CAS,
//! deduplication, reconstruction and authentication are untouched; every call
//! site below is a body stream that already existed.
//!
//! Accounting: the hook is invoked with the **encoded** body bytes of one
//! transport chunk (request body writes at [`Direction::Upload`], response body
//! reads at [`Direction::Download`]) before those bytes cross the boundary.
//! Reconstructed file content never passes through here. With no hook
//! installed traffic is not metered; `hfdrive-hf` installs the hook before any
//! Xet session is built and its integration tests assert the wiring.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use reqwest::Body;

/// Direction of encoded body bytes at this client's transport boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    /// Request bodies leaving the process (xorb/shard/multipart uploads).
    Upload,
    /// Response bodies entering the process (xorb/dedup-shard/multipart
    /// downloads and bounded record reads).
    Download,
}

/// Future returned by [`TransportBudgetHook::gate`].
pub type GateFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

/// External pacing/counting hook over the encoded body bytes of this client.
///
/// `gate` is called once per transport chunk with that chunk's encoded length;
/// the returned future must complete only when the shared budget admits those
/// bytes (the chunk is delivered to/from the wire afterwards).
pub trait TransportBudgetHook: Send + Sync + 'static {
    fn gate(&self, direction: Direction, bytes: u64) -> GateFuture;
}

static HOOK: OnceLock<Arc<dyn TransportBudgetHook>> = OnceLock::new();

/// Install the process-wide transport-budget hook. The first installation
/// wins; later calls return `false` and change nothing (HF Drive runs exactly
/// one shared per-direction budget, so a second hook would be a wiring bug,
/// not a feature).
pub fn install_global_hook(hook: Arc<dyn TransportBudgetHook>) -> bool {
    HOOK.set(hook).is_ok()
}

/// The installed hook, when one exists.
pub fn global_hook() -> Option<Arc<dyn TransportBudgetHook>> {
    HOOK.get().cloned()
}

/// Gate one chunk against the installed hook. With no hook installed this is a
/// pass-through (see the module docs).
pub fn gate(direction: Direction, bytes: u64) -> GateFuture {
    match global_hook() {
        Some(hook) => hook.gate(direction, bytes),
        None => Box::pin(std::future::ready(())),
    }
}

/// Stream adapter: every yielded chunk is gated (counted and paced) before it
/// is delivered. Items are yielded unchanged; nothing is copied. Errors are
/// passed through ungated (they carry no body bytes).
pub struct GatedStream<S, B> {
    inner: S,
    hook: Option<Arc<dyn TransportBudgetHook>>,
    direction: Direction,
    pending: Option<(B, GateFuture)>,
}

impl<S, B> GatedStream<S, B> {
    /// Gate `stream` through an explicit hook (used by tests and by
    /// [`gate_stream`] with the installed hook captured at construction).
    pub fn with_hook(hook: Arc<dyn TransportBudgetHook>, stream: S, direction: Direction) -> Self {
        Self { inner: stream, hook: Some(hook), direction, pending: None }
    }

    fn gate_chunk(&self, bytes: u64) -> GateFuture {
        match &self.hook {
            Some(hook) => hook.gate(self.direction, bytes),
            None => Box::pin(std::future::ready(())),
        }
    }
}

impl<S, B, E> Stream for GatedStream<S, B>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]> + Unpin,
{
    type Item = Result<B, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some((_, gate)) = self.pending.as_mut() {
            match gate.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
            let (chunk, _) = self.pending.take().expect("pending chunk exists");
            return Poll::Ready(Some(Ok(chunk)));
        }
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let bytes = chunk.as_ref().len() as u64;
                let mut gate = self.gate_chunk(bytes);
                match gate.as_mut().poll(cx) {
                    Poll::Ready(()) => Poll::Ready(Some(Ok(chunk))),
                    Poll::Pending => {
                        self.pending = Some((chunk, gate));
                        Poll::Pending
                    }
                }
            }
            other => other,
        }
    }
}

/// Gate every chunk of `stream` through the hook installed at call time.
pub fn gate_stream<S, B, E>(stream: S, direction: Direction) -> GatedStream<S, B>
where
    S: Stream<Item = Result<B, E>> + Unpin,
    B: AsRef<[u8]> + Unpin,
{
    GatedStream { inner: stream, hook: global_hook(), direction, pending: None }
}

/// Collect one response body through the download gate: every encoded chunk is
/// counted and paced before the next one is read. This is the gated equivalent
/// of `reqwest::Response::bytes()` for the bounded collectors in this client.
pub async fn collect_gated(
    response: reqwest::Response,
    direction: Direction,
) -> std::result::Result<Bytes, reqwest::Error> {
    collect_gated_with_hook(global_hook(), response, direction).await
}

/// [`collect_gated`] with an explicit hook (tests).
pub async fn collect_gated_with_hook(
    hook: Option<Arc<dyn TransportBudgetHook>>,
    response: reqwest::Response,
    direction: Direction,
) -> std::result::Result<Bytes, reqwest::Error> {
    use futures::TryStreamExt;
    let mut stream = match hook {
        Some(hook) => GatedStream::with_hook(hook, response.bytes_stream(), direction),
        None => gate_stream(response.bytes_stream(), direction),
    };
    let mut out = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(out))
}

/// A static request body whose encoded bytes are gated at the upload boundary
/// as the transport sends them.
pub fn gated_static_body(data: impl Into<Bytes>, direction: Direction) -> Body {
    Body::wrap_stream(gate_stream(
        futures::stream::iter([Ok::<_, std::io::Error>(data.into())]),
        direction,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recording {
        calls: Mutex<Vec<(Direction, u64)>>,
        release: Arc<std::sync::atomic::AtomicBool>,
    }

    /// Deterministic gate future: pending until the test flips `release`.
    struct ReleaseGate {
        release: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Future for ReleaseGate {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.release.load(std::sync::atomic::Ordering::Relaxed) {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct RecordingHook {
        recording: Arc<Recording>,
    }

    impl TransportBudgetHook for RecordingHook {
        fn gate(&self, direction: Direction, bytes: u64) -> GateFuture {
            self.recording.calls.lock().unwrap().push((direction, bytes));
            Box::pin(ReleaseGate { release: self.recording.release.clone() })
        }
    }

    #[test]
    fn hook_sees_every_encoded_chunk_in_order_and_chunks_pass_unchanged() {
        let recording = Arc::new(Recording {
            calls: Mutex::new(Vec::new()),
            release: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        });
        let hook = Arc::new(RecordingHook { recording: recording.clone() });
        let source = futures::stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"de")),
        ]);
        let mut gated = GatedStream::with_hook(hook, source, Direction::Upload);
        let first = futures::executor::block_on(gated.next()).unwrap().unwrap();
        let second = futures::executor::block_on(gated.next()).unwrap().unwrap();
        assert_eq!(first, Bytes::from_static(b"abc"));
        assert_eq!(second, Bytes::from_static(b"de"));
        assert!(futures::executor::block_on(gated.next()).is_none());
        assert_eq!(*recording.calls.lock().unwrap(), vec![(Direction::Upload, 3), (Direction::Upload, 2)]);
    }

    #[test]
    fn chunks_are_not_delivered_before_the_hook_admits_them() {
        let recording = Arc::new(Recording {
            calls: Mutex::new(Vec::new()),
            release: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let hook = Arc::new(RecordingHook { recording: recording.clone() });
        let source = futures::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"xy"))]);
        let mut gated = GatedStream::with_hook(hook, source, Direction::Download);
        // Not admitted yet: the future does not complete.
        let mut polled = std::pin::pin!(gated.next());
        assert!(futures::poll!(&mut polled).is_pending());
        recording.release.store(true, std::sync::atomic::Ordering::Relaxed);
        let chunk = futures::executor::block_on(polled).unwrap().unwrap();
        assert_eq!(chunk, Bytes::from_static(b"xy"));
        assert_eq!(*recording.calls.lock().unwrap(), vec![(Direction::Download, 2)]);
    }

    #[test]
    fn gated_collector_counts_response_body_bytes() {
        let recording = Arc::new(Recording {
            calls: Mutex::new(Vec::new()),
            release: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        });
        let hook = RecordingHook { recording: recording.clone() };
        let chunks: Vec<std::result::Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"wire")),
        ];
        let body = Body::wrap_stream(futures::stream::iter(chunks));
        let response: reqwest::Response =
            http::Response::builder().status(200).body(body).unwrap().into();
        let collected = futures::executor::block_on(collect_gated_with_hook(
            Some(Arc::new(hook)),
            response,
            Direction::Download,
        ))
        .unwrap();
        assert_eq!(collected, Bytes::from_static(b"hello wire"));
        let calls = recording.calls.lock().unwrap().clone();
        let total: u64 = calls.iter().map(|(_, bytes)| bytes).sum();
        assert_eq!(total, 10, "every encoded body byte is gated exactly once");
    }
}
