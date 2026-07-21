use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use snafu::ResultExt;

use crate::{
    error::session_controller::OutputSnafu,
    runners::{docker::DockerControllerHandoff, linux::LinuxControllerHandoff},
    DurableStreamStore, SessionControllerError, StreamKind,
};

pub(crate) struct HelperOutput {
    pub(crate) stdout: Arc<DurableStreamStore>,
    pub(crate) stderr: Arc<DurableStreamStore>,
    events: DurableStreamStore,
    evidence: DurableStreamStore,
    continuity: DurableStreamStore,
}

impl HelperOutput {
    pub(crate) fn open(handoff: &LinuxControllerHandoff) -> Result<Self, SessionControllerError> {
        Self::open_paths(
            &handoff.spec,
            &handoff.stdout_path,
            &handoff.stderr_path,
            &handoff.events_path,
            &handoff.evidence_path,
            &handoff.journal_path,
        )
    }

    pub(crate) fn open_docker(
        handoff: &DockerControllerHandoff,
    ) -> Result<Self, SessionControllerError> {
        Self::open_paths(
            &handoff.spec,
            &handoff.stdout_path,
            &handoff.stderr_path,
            &handoff.events_path,
            &handoff.evidence_path,
            &handoff.journal_path,
        )
    }

    fn open_paths(
        spec: &erebor_runtime_core::SessionSpec,
        stdout_path: &std::path::Path,
        stderr_path: &std::path::Path,
        events_path: &std::path::Path,
        evidence_path: &std::path::Path,
        journal_path: &std::path::Path,
    ) -> Result<Self, SessionControllerError> {
        let maximum = spec.output().maximum_bytes() / 5;
        let rotation = spec.output().rotation_bytes().min(maximum);
        Ok(Self {
            stdout: Arc::new(
                DurableStreamStore::open(
                    stdout_path,
                    StreamKind::Stdout,
                    maximum,
                    rotation,
                    spec.output().requirements().stdout_required(),
                )
                .context(OutputSnafu)?,
            ),
            stderr: Arc::new(
                DurableStreamStore::open(
                    stderr_path,
                    StreamKind::Stderr,
                    maximum,
                    rotation,
                    spec.output().requirements().stderr_required(),
                )
                .context(OutputSnafu)?,
            ),
            events: DurableStreamStore::open(
                events_path,
                StreamKind::Events,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
            evidence: DurableStreamStore::open(
                evidence_path,
                StreamKind::Evidence,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
            continuity: DurableStreamStore::open(
                journal_path,
                StreamKind::Continuity,
                maximum,
                rotation,
                true,
            )
            .context(OutputSnafu)?,
        })
    }

    pub(crate) fn record_event(
        &self,
        kind: &str,
        payload: Value,
    ) -> Result<(), SessionControllerError> {
        let timestamp = unix_time_ms();
        let encoded = serde_json::to_vec(&serde_json::json!({
            "kind": kind,
            "payload": payload,
        }))
        .map_err(|source| SessionControllerError::Protocol {
            source,
            location: snafu::Location::default(),
        })?;
        self.continuity
            .append(timestamp, "session-controller", encoded.clone())
            .context(OutputSnafu)?;
        self.events
            .append(timestamp, kind, encoded)
            .context(OutputSnafu)?;
        self.evidence
            .append(
                timestamp,
                "session-controller",
                format!("event:{kind}").into_bytes(),
            )
            .context(OutputSnafu)?;
        Ok(())
    }

    pub(crate) fn finish(
        &self,
        exit_code: Option<i32>,
        signal: Option<i32>,
    ) -> Result<(), SessionControllerError> {
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
