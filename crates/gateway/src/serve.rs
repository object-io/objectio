//! Serving a listener: HTTP/1.1 and HTTP/2 connections, with the timeouts
//! that keep a slow or stalled client from holding the gateway's resources.
//!
//! - A request's headers must arrive within the header timeout, and an idle
//!   keep-alive connection waits that long for its next request (HTTP/1.1):
//!   a client that opens connections and trickles headers (slowloris) is cut
//!   off.
//! - A write to a client that has stopped reading is given up after the send
//!   timeout, and the connection closed: a stalled download would otherwise
//!   hold its request slot and its read-ahead in the memory budget for ever.
//!
//! A request body that stops arriving is the admission layer's
//! (`crate::admission::body_layer`), so it can answer `RequestTimeout`.
//! This is `axum::serve`, which offers neither, with them added.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::Request;
use axum::response::Response;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::convert::Infallible;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Sleep;
use tower::ServiceExt as _;
use tracing::debug;

use crate::admission::Timeouts;

/// A connection whose writes fail once one has waited `limit` for the peer
/// to take bytes.
struct SendTimeout<T> {
    inner: T,
    limit: Duration,
    /// Set while a write is waiting: when it gives up.
    waiting: Option<Pin<Box<Sleep>>>,
}

impl<T> SendTimeout<T> {
    const fn new(inner: T, limit: Duration) -> Self {
        Self {
            inner,
            limit,
            waiting: None,
        }
    }

    /// A write that returned `Pending`: an error once it has waited too long.
    fn on_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let limit = self.limit;
        let sleep = self
            .waiting
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(limit)));
        if sleep.as_mut().poll(cx).is_ready() {
            self.waiting = None;
            crate::admission::record_timeout("send");
            debug!("client took no bytes for {limit:?}: connection closed");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "client stopped reading",
            )));
        }
        Poll::Pending
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for SendTimeout<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for SendTimeout<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Pending => self.on_pending(cx).map(|r| r.map(|()| 0)),
            ready => {
                self.waiting = None;
                ready
            }
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
            Poll::Pending => self.on_pending(cx).map(|r| r.map(|()| 0)),
            ready => {
                self.waiting = None;
                ready
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => self.on_pending(cx),
            ready => {
                self.waiting = None;
                ready
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serve `app` on `listener` until `shutdown` resolves, then let the
/// connections finish what they are doing (closing idle ones at once) and
/// return when they have. Each request carries its connection's peer
/// address (`crate::origin::ClientAddr`).
pub async fn serve<S, F>(listener: TcpListener, app: S, timeouts: Timeouts, shutdown: F)
where
    S: tower::Service<Request, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    F: Future<Output = ()> + Send,
{
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(timeouts.header);
    builder.http2().timer(TokioTimer::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let (stream, addr): (TcpStream, SocketAddr) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(a) => a,
                Err(e) => {
                    // Out of file descriptors, say: as axum::serve does,
                    // pause rather than spin.
                    debug!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        // Nagle holding back the tail of a response while the client delays
        // its ACK stalls a lone request by ~40 ms on Linux.
        if let Err(e) = stream.set_nodelay(true) {
            debug!("TCP_NODELAY on accepted connection: {e}");
        }
        let svc = crate::origin::WithClientAddr {
            inner: app.clone(),
            addr,
        }
        .map_request(|req: http::Request<hyper::body::Incoming>| req.map(axum::body::Body::new));
        let io = TokioIo::new(SendTimeout::new(stream, timeouts.send));
        let conn = builder
            .serve_connection_with_upgrades(io, TowerToHyperService::new(svc))
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("connection from {addr}: {e}");
            }
        });
    }
    drop(listener);
    graceful.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[tokio::test(start_paused = true)]
    async fn a_write_the_peer_never_takes_fails_after_the_send_timeout() {
        // A pipe whose reader never reads: writes fill it, then wait.
        let (a, _b) = tokio::io::duplex(1024);
        let mut io = SendTimeout::new(a, Duration::from_secs(30));
        let started = tokio::time::Instant::now();
        let err = io
            .write_all(&vec![0u8; 1 << 20])
            .await
            .expect_err("the peer reads nothing");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_keeps_reading_is_never_cut_off() {
        let (a, mut b) = tokio::io::duplex(1024);
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let mut got = 0;
            while got < (1 << 16) {
                // Slower than the writer, faster than the timeout.
                tokio::time::sleep(Duration::from_secs(1)).await;
                got += tokio::io::AsyncReadExt::read(&mut b, &mut buf)
                    .await
                    .unwrap();
            }
            got
        });
        let mut io = SendTimeout::new(a, Duration::from_secs(5));
        io.write_all(&vec![0u8; 1 << 16])
            .await
            .expect("never stalls 5 s");
        assert!(reader.await.unwrap() >= 1 << 16);
    }
}
