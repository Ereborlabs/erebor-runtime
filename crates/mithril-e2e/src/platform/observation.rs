use std::{path::PathBuf, time::Duration};

use erebor_runtime_client::MithrilObservationClient;
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;

use super::TestResult;
use crate::error::TimeoutSnafu;

pub(super) struct Observation {
    path: PathBuf,
    client: MithrilObservationClient,
    limit: Duration,
}

impl Observation {
    pub(super) fn new(path: PathBuf) -> Self {
        Self {
            client: MithrilObservationClient::new(path.clone(), "/".to_owned()),
            path,
            limit: Duration::from_secs(30),
        }
    }

    pub(super) fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = runtime
            .block_on(async { tokio::time::timeout(self.limit, self.client.snapshot()).await })
            .map_err(|_elapsed| {
                TimeoutSnafu {
                    path: &self.path,
                    operation: "Mithril observation snapshot",
                    limit: self.limit,
                    diagnostic: "last state: request pending; peer did not complete snapshot",
                }
                .build()
            })?;
        Ok(result?)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Read as _, os::unix::net::UnixListener, time::Instant};

    use super::*;

    #[test]
    fn stalled_peer_is_bounded() -> TestResult<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("observation.sock");
        let listener = UnixListener::bind(&path)?;
        listener.set_nonblocking(true)?;
        let mut observation = Observation::new(path.clone());
        observation.limit = Duration::from_millis(50);
        let started = Instant::now();
        let error = observation
            .snapshot()
            .err()
            .ok_or("stalled snapshot succeeded")?;
        assert!(started.elapsed() < Duration::from_secs(1));
        let Some(crate::Error::Timeout {
            path: resource,
            operation,
            limit,
            diagnostic,
            ..
        }) = error.downcast_ref::<crate::Error>()
        else {
            return Err(error);
        };
        assert_eq!(resource, &path);
        assert_eq!(operation, "Mithril observation snapshot");
        assert_eq!(*limit, observation.limit);
        assert!(diagnostic.contains("request pending"));

        // The SDK connects, sends bytes, and closes the socket after timeout.
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(1)))?;
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes)?;
        assert!(!bytes.is_empty(), "the SDK sent no request bytes");
        drop(socket);
        drop(listener);
        directory.close()?;
        assert!(!path.exists());
        Ok(())
    }
}
