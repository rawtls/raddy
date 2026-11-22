use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeNoise {
    Closed,
    InvalidContentType,
}

fn classify(error: &io::Error) -> Option<HandshakeNoise> {
    match error.kind() {
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => Some(HandshakeNoise::Closed),
        _ if matches!(
            error
                .get_ref()
                .and_then(|e| e.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidMessage(
                rustls::InvalidMessage::InvalidContentType
            ))
        ) =>
        {
            Some(HandshakeNoise::InvalidContentType)
        }
        _ => None,
    }
}

#[derive(Default)]
pub(crate) struct HandshakeLog {
    closed: AtomicU64,
    invalid_content_type: AtomicU64,
    timed_out: AtomicU64,
}

impl HandshakeLog {
    pub(crate) fn failed(&self, peer: SocketAddr, error: io::Error) {
        let counter = match classify(&error) {
            Some(HandshakeNoise::Closed) => &self.closed,
            Some(HandshakeNoise::InvalidContentType) => &self.invalid_content_type,
            None => {
                tracing::warn!(%peer, %error, "TLS handshake failed");
                return;
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, %error, "TLS handshake failed");
    }

    pub(crate) fn timeout(&self, peer: SocketAddr) {
        self.timed_out.fetch_add(1, Ordering::Relaxed);
        tracing::debug!(%peer, "TLS handshake timed out");
    }

    fn take_counts(&self) -> [u64; 3] {
        [&self.closed, &self.invalid_content_type, &self.timed_out]
            .map(|n| n.swap(0, Ordering::Relaxed))
    }

    pub(crate) fn start(self: &Arc<Self>, address: SocketAddr, stop: CancellationToken) {
        let log = self.clone();
        tokio::spawn(async move {
            loop {
                let stopped = tokio::select! {
                    biased;
                    _ = stop.cancelled() => true,
                    _ = tokio::time::sleep(Duration::from_secs(60)) => false,
                };
                let [closed, invalid_content_type, timed_out] = log.take_counts();
                if closed != 0 || invalid_content_type != 0 || timed_out != 0 {
                    tracing::info!(%address, closed, invalid_content_type, timed_out, "TLS handshake summary");
                }
                if stopped {
                    return;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_expected_handshake_noise_is_aggregated() {
        let peer = "127.0.0.1:1234".parse().unwrap();
        let log = HandshakeLog::default();
        for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::ConnectionReset] {
            log.failed(peer, io::Error::from(kind));
        }
        log.failed(
            peer,
            io::Error::new(
                io::ErrorKind::InvalidData,
                rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
            ),
        );
        log.timeout(peer);
        assert_eq!(log.take_counts(), [2, 1, 1]);
        assert_eq!(log.take_counts(), [0; 3]);
        for error in [
            io::Error::new(io::ErrorKind::InvalidData, rustls::Error::DecryptError),
            io::Error::other("InvalidContentType"),
        ] {
            assert_eq!(classify(&error), None);
        }
    }
}
