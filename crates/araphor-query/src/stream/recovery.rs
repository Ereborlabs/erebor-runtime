use std::sync::{Arc, Mutex};

use araphor_data::AnalysisReadControl;
use datafusion::common::DataFusionError;
use snafu::Snafu;

use super::progress::{Progress, Wake};
use super::Run;
use crate::execution::Session;
use crate::{Error, Failure, Result};

/// Wait for a source change after a failed managed capture has joined.
pub struct SourceRecovery {
    run: Arc<Run>,
    progress: Option<Progress>,
    source_index: Option<Arc<crate::sources::SourceIndex>>,
    invalidated: bool,
    captured: Option<araphor_data::StorePositionV1>,
}

impl std::fmt::Debug for SourceRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRecovery")
            .field("position", &self.progress.as_ref().map(Progress::observed))
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
    pub(crate) fn new(run: Arc<Run>) -> Self {
        Self {
            run,
            progress: None,
            source_index: None,
            invalidated: false,
            captured: None,
        }
    }

    pub(crate) fn captured(&mut self, revision: u64) {
        self.captured = Some(araphor_data::StorePositionV1 {
            commit_revision: revision,
            ordinal: u32::MAX,
        });
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

    pub(crate) fn attach(
        error: &Error,
        progress: &Progress,
        source_index: Option<&Arc<crate::sources::SourceIndex>>,
    ) {
        if let Some(failure) = Self::failure(error) {
            if let Some(recovery) = failure
                .recovery
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_mut()
            {
                recovery.progress = Some(progress.clone());
                recovery.source_index = source_index.cloned();
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

    /// Reuse the committed source index with the same native plan and memory owner.
    pub fn resume(
        mut self,
        mut session: Session,
        definition: &crate::definition::PreparedDefinition,
    ) -> Session {
        let original = self
            .run
            .managed
            .as_ref()
            .and_then(|(definition, _)| definition.executable(session.engine()));
        let prepared = definition.executable(session.engine());
        if Arc::ptr_eq(self.run.session.memory(), session.memory())
            && original
                .zip(prepared)
                .is_some_and(|(original, prepared)| Arc::ptr_eq(&original, &prepared))
        {
            session.source_index = self.source_index.take();
            session.input_changes = self.progress.as_ref().and_then(Progress::subscription);
        }
        session
    }

    pub async fn changed(mut self, control: &AnalysisReadControl) -> Result<Self> {
        control.check()?;
        if self.invalidated {
            return Ok(self);
        }
        let mut progress = self.progress.take().ok_or_else(|| {
            crate::InvalidSnafu {
                field: "source recovery progress",
            }
            .build()
        })?;
        let failed = self.captured.unwrap_or_else(|| progress.observed());
        if progress.source_position() > failed {
            self.progress = Some(progress);
            return Ok(self);
        }
        loop {
            match control
                .query_async(progress.next_after(control, failed, None))
                .await?
            {
                Wake::Clock if progress.expired(progress.now()?) => {
                    self.progress = Some(progress);
                    return Ok(self);
                }
                Wake::Clock => {}
                Wake::Source | Wake::Control => {
                    self.progress = Some(progress);
                    return Ok(self);
                }
            }
        }
    }
}
