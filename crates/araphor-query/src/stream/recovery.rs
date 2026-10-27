use std::sync::{Arc, Mutex};

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisTableRequests, ManagedRead};
use datafusion::common::DataFusionError;
use snafu::Snafu;

use super::progress::{Progress, Wake};
use super::Run;
use crate::execution::Session;
use crate::sources::SourceSnapshot;
use crate::{Error, Failure, Result};

/// Wait for a source change after a failed managed capture has joined.
pub struct SourceRecovery {
    run: Arc<Run>,
    selection: AnalysisSelectionV1,
    managed: Option<ManagedRead>,
    requests: AnalysisTableRequests,
    revision: u64,
    now: u64,
    progress: Option<Progress>,
    invalidated: bool,
}

impl std::fmt::Debug for SourceRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRecovery")
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("Managed source capture failed"))]
struct CaptureFailure {
    source: Error,
    recovery: Mutex<Option<SourceRecovery>>,
}

impl SourceRecovery {
    pub(crate) fn new(
        run: Arc<Run>,
        session: &Session,
        now: u64,
        requests: AnalysisTableRequests,
    ) -> Self {
        Self {
            revision: *session.engine().store().subscribe_revision().borrow(),
            run,
            selection: session.selection().clone(),
            managed: session.managed.clone(),
            requests,
            now,
            progress: None,
            invalidated: false,
        }
    }

    pub(crate) fn invalidated(mut self) -> Self {
        self.invalidated = true;
        self
    }

    pub(crate) fn failed(self, source: Error) -> Error {
        if matches!(
            Failure::from(&source),
            Failure::Busy | Failure::Denied | Failure::Cancelled
        ) {
            return source;
        }
        Error::Sql {
            source: DataFusionError::External(Box::new(CaptureFailure {
                source,
                recovery: Mutex::new(Some(self)),
            })),
        }
    }

    fn failure<'a>(mut error: &'a (dyn std::error::Error + 'static)) -> Option<&'a CaptureFailure> {
        loop {
            if let Some(error) = error.downcast_ref::<CaptureFailure>() {
                return Some(error);
            }
            error = error.source()?;
        }
    }

    pub(crate) fn attach(error: &Error, progress: &Progress) {
        if let Some(failure) = Self::failure(error) {
            if let Some(recovery) = failure
                .recovery
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_mut()
            {
                recovery.progress = Some(progress.clone());
            }
        }
    }

    /// Take this handle only after the failed subscription has joined.
    pub fn take(error: &(dyn std::error::Error + 'static)) -> Option<Self> {
        Self::failure(error)?
            .recovery
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }

    pub async fn changed(mut self, control: &AnalysisReadControl) -> Result<()> {
        control.check()?;
        if self.invalidated {
            return Ok(());
        }
        let mut progress = self.progress.take().ok_or_else(|| {
            crate::InvalidSnafu {
                field: "source recovery progress",
            }
            .build()
        })?;
        let mut session = self.run.session.engine().session_on(
            self.selection.clone(),
            control,
            self.now,
            Arc::clone(self.run.session.memory()),
        )?;
        session.managed = self.managed;
        let selection = SourceSnapshot::selection(&self.selection, &self.requests)?;
        let (meta, revision) = self
            .run
            .dependencies(&session, selection.clone(), None, None)
            .await?;
        if revision > self.revision {
            return Ok(());
        }
        progress.checked(meta.commit_revision);
        loop {
            match control.query_async(progress.next(control, None)).await? {
                Wake::Clock if progress.expired(progress.now()?) => return Ok(()),
                Wake::Clock => {}
                Wake::Source => {
                    let (meta, revision) = self
                        .run
                        .dependencies(&session, selection.clone(), None, None)
                        .await?;
                    if revision > self.revision {
                        return Ok(());
                    }
                    progress.checked(meta.commit_revision);
                }
            }
        }
    }
}
