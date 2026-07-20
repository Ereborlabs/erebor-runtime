use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use erebor_runtime_core::SessionHelperHandoff;
use serde_json::Value;
use snafu::ResultExt;

use crate::{
    error::session_helper::OutputSnafu, DurableStreamStore, SessionHelperError, StreamKind,
};

pub(super) struct HelperOutput {
    pub(super) stdout: Arc<DurableStreamStore>,
    pub(super) stderr: Arc<DurableStreamStore>,
    events: DurableStreamStore,
    evidence: DurableStreamStore,
    continuity: DurableStreamStore,
}

impl HelperOutput {
    pub(super) fn open(handoff: &SessionHelperHandoff) -> Result<Self, SessionHelperError> {
        let maximum = handoff.spec.output().maximum_bytes() / 5;
        let rotation = handoff.spec.output().rotation_bytes().min(maximum);
        Ok(Self {
            stdout: Arc::new(
                DurableStreamStore::open(
                    &handoff.stdout_path,
                    StreamKind::Stdout,
                    maximum,
                    rotation,
                    false,
                )
                .context(OutputSnafu)?,
            ),
            stderr: Arc::new(
                DurableStreamStore::open(
                    &handoff.stderr_path,
                    StreamKind::Stderr,
                    maximum,
                    rotation,
                    false,
                )
                .context(OutputSnafu)?,
            ),
            events: DurableStreamStore::open(
                &handoff.events_path,
                StreamKind::Events,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
            evidence: DurableStreamStore::open(
                &handoff.evidence_path,
                StreamKind::Evidence,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
            continuity: DurableStreamStore::open(
                &handoff.journal_path,
                StreamKind::Continuity,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
        })
    }

    pub(super) fn record_event(
        &self,
        kind: &str,
        payload: Value,
    ) -> Result<(), SessionHelperError> {
        let timestamp = unix_time_ms();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "kind": kind,
            "payload": payload,
        }))
        .map_err(|source| SessionHelperError::Protocol {
            source,
            location: snafu::Location::default(),
        })?;
        self.continuity
            .append(timestamp, "session-helper", encoded.clone())
            .context(OutputSnafu)?;
        self.events
            .append(timestamp, kind, encoded)
            .context(OutputSnafu)?;
        self.evidence
            .append(
                timestamp,
                "session-helper",
                format!("event:{kind}").into_bytes(),
            )
            .context(OutputSnafu)?;
        Ok(())
    }

    pub(super) fn finish(
        &self,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<(), SessionHelperError> {
        self.record_event(
            "workload_exited",
            serde_json::json!({"exit_code": exit_code, "signal": signal}),
        )
    }
}

pub(super) fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_millis() as u64)
}
