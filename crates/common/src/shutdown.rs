//! Stopping on a signal: SIGTERM, which Kubernetes, systemd and
//! `docker stop` send, or SIGINT (Ctrl-C).

use std::future::Future;

/// A future that resolves on the first SIGTERM or SIGINT, for a service's
/// `run(args, shutdown)`.
///
/// The handlers are installed by this call, not when the future is first
/// polled: a service takes it before it starts, so a signal that comes
/// while it is still starting waits for it rather than being lost. (A
/// process running as PID 1 in a container has no default action for
/// SIGTERM: with no handler, the signal is ignored and the kubelet kills
/// the pod when its grace period ends, with no shutdown at all.)
///
/// Once it has resolved, a second signal exits the process at once, with
/// status 128 + the signal's number: a shutdown that hangs can always be
/// cut short.
///
/// # Errors
/// When a handler cannot be installed.
///
/// # Panics
/// Outside a Tokio runtime.
pub fn shutdown_signal() -> std::io::Result<impl Future<Output = ()> + Send + 'static> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        Ok(async move {
            let name = tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = int.recv() => "SIGINT",
            };
            tracing::info!("{name} received: shutting down (a second signal exits at once)");
            tokio::spawn(async move {
                let (name, code) = tokio::select! {
                    _ = term.recv() => ("SIGTERM", 128 + 15),
                    _ = int.recv() => ("SIGINT", 128 + 2),
                };
                tracing::warn!("second signal ({name}): exiting before the shutdown finished");
                std::process::exit(code);
            });
        })
    }
    #[cfg(not(unix))]
    {
        Ok(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Ctrl-C received: shutting down");
        })
    }
}
