use std::path::PathBuf;

use erebor_runtime_audit::{FilteredAuditSink, JsonlAuditSink};
use erebor_runtime_core::{AuditRecord, AuditSink, RuntimeAuditConfig};
use erebor_runtime_telemetry::warn;

#[derive(Clone, Debug)]
pub(super) struct CdpAuditRecorder {
    sink: FilteredAuditSink<JsonlAuditSink>,
}

impl CdpAuditRecorder {
    pub(super) fn new(path: impl Into<PathBuf>, audit: RuntimeAuditConfig) -> Self {
        let path = path.into();
        Self {
            sink: FilteredAuditSink::new(JsonlAuditSink::new(path), audit),
        }
    }

    pub(super) fn record(&self, record: &AuditRecord) {
        if let Err(error) = self.sink.record(record) {
            warn!(
                error;
                "failed to append CDP audit record",
                path = %self.sink.inner().path().display(),
                session_id = %record.event.session_id.as_str(),
                event_id = %record.event.id.as_str()
            );
        }
    }

    pub(super) fn record_optional(recorder: Option<&Self>, record: Option<&AuditRecord>) {
        let (Some(recorder), Some(record)) = (recorder, record) else {
            return;
        };

        recorder.record(record);
    }
}
