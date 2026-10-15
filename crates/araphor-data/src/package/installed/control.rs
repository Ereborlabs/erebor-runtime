use std::sync::Arc;
use std::thread::JoinHandle;
#[cfg(test)]
use std::time::Duration;

use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result};

use super::super::PackageAuthorization;

pub(super) struct AuthorityWatch {
    stop: tokio::sync::watch::Sender<bool>,
    worker: Option<JoinHandle<()>>,
}

impl AuthorityWatch {
    pub(super) fn start(
        authority: Arc<dyn PackageAuthorization>,
        control: Arc<AnalysisReadControl>,
    ) -> Result<Self> {
        let mut changes = authority.changes();
        let (stop, mut stopped) = tokio::sync::watch::channel(false);
        let observe = async move {
            tokio::select! {
                biased;
                _stopped = stopped.changed() => {},
                _changed = changes.changed() => {
                    let _cancelled = control.cancel();
                }
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .context(crate::IoSnafu {
                path: "<analysis-authority>",
            })?;
        let worker = Some(
            std::thread::Builder::new()
                .name("analysis-authority".into())
                .spawn(move || runtime.block_on(observe))
                .context(crate::IoSnafu {
                    path: "<analysis-authority>",
                })?,
        );
        Ok(Self { stop, worker })
    }
}

impl Drop for AuthorityWatch {
    fn drop(&mut self) {
        self.stop.send_replace(true);
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

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_runtime_cancels() -> TestResult {
        authority_change_cancels_computation()
    }
}
