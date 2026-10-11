use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::Duration;

use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::super::PackageAuthorization;

pub(super) struct AuthorityWatch {
    stop: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}

impl AuthorityWatch {
    pub(super) fn start(
        authority: Arc<dyn PackageAuthorization>,
        control: Arc<AnalysisReadControl>,
    ) -> Result<Self> {
        let changes = authority.changes();
        let (stop, stopped) = mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("analysis-authority".into())
            .spawn(move || {
                while matches!(
                    stopped.recv_timeout(Duration::from_millis(10)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    if changes.has_changed().unwrap_or(true) {
                        let _cancelled = control.cancel();
                        break;
                    }
                }
            })
            .context(crate::IoSnafu {
                path: "<analysis-authority>",
            })?;
        Ok(Self {
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for AuthorityWatch {
    fn drop(&mut self) {
        let _stopped = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tests::{Fixture, TestResult};

    #[test]
    fn authority_change_cancels_computation() -> TestResult {
        let fixture = Fixture::new()?;
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(5))?);
        let watch = AuthorityWatch::start(fixture.authority.clone(), control.clone())?;
        fixture.authority.set_revision(0);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while control.check().is_ok() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(matches!(
            control.check(),
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
        drop(watch);
        Ok(())
    }

    #[test]
    fn watch_drop_preserves_control() -> TestResult {
        let fixture = Fixture::new()?;
        let control = Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(5))?);
        drop(AuthorityWatch::start(
            fixture.authority.clone(),
            control.clone(),
        )?);
        control.check()?;
        Ok(())
    }
}
