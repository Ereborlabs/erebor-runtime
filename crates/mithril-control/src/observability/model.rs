use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{error::InvalidConfigurationSnafu, DiscoveryDigestV1, Result, WorkloadTargetFactV1};

pub const MAX_TRACE_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_TRACE_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_TRACE_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TRACE_TARGETS: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSourceV1 {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

impl TraceSourceV1 {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let source = Self {
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<()> {
        TraceRequestV1::require(
            !self.bytes.is_empty()
                && self.bytes.len() <= MAX_TRACE_SOURCE_BYTES
                && !self.bytes.contains(&0)
                && std::str::from_utf8(&self.bytes).is_ok()
                && self.sha256 == <[u8; 32]>::from(Sha256::digest(&self.bytes)),
            "trace source is empty, invalid, too large, or changed",
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceTargetV1 {
    pub fact: WorkloadTargetFactV1,
    pub fact_digest: DiscoveryDigestV1,
    pub runtime_container_id: String,
    pub node_boot_id: [u8; 16],
    pub cgroup_id: u64,
    pub binding_id: [u8; 16],
    pub binding_nonce: [u8; 16],
    pub root_cgroup_live_interval_id: [u8; 16],
    pub container_generation: u64,
    pub label_epoch: u64,
}

impl TraceTargetV1 {
    pub fn validate(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.fact).map_err(|_| {
            InvalidConfigurationSnafu {
                reason: "trace workload facts cannot be encoded",
            }
            .build()
        })?;
        TraceRequestV1::require(
            bytes.len() <= 32 * 1024,
            "trace workload facts exceed 32 KiB",
        )?;
        TraceRequestV1::require(
            self.node_boot_id != [0; 16]
                && self.binding_id != [0; 16]
                && self.cgroup_id != 0
                && self.binding_nonce != [0; 16]
                && self.root_cgroup_live_interval_id != [0; 16]
                && self.label_epoch != 0
                && self.fact_digest == DiscoveryDigestV1::of(&self.fact)?,
            "trace target lifetime or fact digest is invalid",
        )?;
        for identity in [
            &self.runtime_container_id,
            &self.fact.node_id,
            &self.fact.cluster_uid,
            &self.fact.namespace_uid,
            &self.fact.pod_uid,
            &self.fact.container_id,
            &self.fact.workload_binding_generation_digest,
        ] {
            TraceRequestV1::require(
                !identity.is_empty()
                    && identity.len() <= 256
                    && !identity.chars().any(char::is_control),
                "trace target identity is missing or too large",
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceRequestV1 {
    pub tenant_id: [u8; 16],
    pub request_id: [u8; 16],
    pub source: TraceSourceV1,
    pub targets: Vec<TraceTargetV1>,
    #[serde(default)]
    pub unresolved: Vec<crate::TraceParticipantV1>,
    pub collection_seconds: u16,
}

impl TraceRequestV1 {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        Self::require(bytes.len() <= 1024 * 1024, "trace request exceeds 1 MiB")?;
        let value: Self = serde_json::from_slice(bytes).map_err(|_| {
            InvalidConfigurationSnafu {
                reason: "trace request schema is invalid",
            }
            .build()
        })?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        Self::require(
            self.tenant_id != [0; 16]
                && self.request_id != [0; 16]
                && (1..=300).contains(&self.collection_seconds)
                && !self.targets.is_empty()
                && self.targets.len() + self.unresolved.len() <= MAX_TRACE_TARGETS,
            "trace request identity, duration, or target count is invalid",
        )?;
        self.source.validate()?;
        let mut identities = std::collections::BTreeSet::new();
        let mut facts = std::collections::BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            Self::require(
                identities.insert((&target.fact.node_id, target.node_boot_id, target.binding_id))
                    && facts.insert(&target.fact_digest),
                "trace request contains a duplicate target",
            )?;
        }
        for unresolved in &self.unresolved {
            Self::require(
                unresolved.state != crate::TraceParticipantStateV1::Resolved
                    && unresolved.target.is_none()
                    && unresolved.fact_digest.0 != [0; 32]
                    && facts.insert(&unresolved.fact_digest),
                "trace unresolved participant is invalid or duplicated",
            )?;
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DiscoveryDigestV1> {
        self.validate()?;
        DiscoveryDigestV1::of(self)
    }

    pub(crate) fn require(valid: bool, reason: &'static str) -> Result<()> {
        if valid {
            Ok(())
        } else {
            InvalidConfigurationSnafu { reason }.fail()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceFrameKindV1 {
    Metadata,
    Data,
    Diagnostic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceFrameV1 {
    pub execution_id: [u8; 16],
    pub sequence: u64,
    pub kind: TraceFrameKindV1,
    pub bytes: Vec<u8>,
}

impl TraceFrameV1 {
    pub fn validate(&self) -> Result<()> {
        TraceRequestV1::require(
            self.execution_id != [0; 16]
                && self.sequence != 0
                && !self.bytes.is_empty()
                && self.bytes.len() <= MAX_TRACE_FRAME_BYTES,
            "trace output identity, sequence, or frame size is invalid",
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceTerminalReasonV1 {
    Completed,
    Cancelled,
    Deadline,
    PreparationFailed,
    TargetChanged,
    OutputLimit,
    ConsumerSlow,
    NodeRestarted,
    StorageFailure,
    BackendFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceCleanupV1 {
    Verified,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceTerminalV1 {
    pub execution_id: [u8; 16],
    pub reason: TraceTerminalReasonV1,
    pub last_sequence: u64,
    pub output_bytes: u64,
    pub output_incomplete: bool,
    pub kernel_lost_events: Option<u64>,
    pub ready_at_unix_ns: Option<u64>,
    pub exit_code: Option<i32>,
    pub forced_kill: bool,
    pub cleanup: TraceCleanupV1,
}

impl TraceTerminalV1 {
    pub fn validate(&self) -> Result<()> {
        TraceRequestV1::require(
            self.execution_id != [0; 16]
                && self.last_sequence <= 4096
                && self.output_bytes >= self.last_sequence
                && self.output_bytes <= MAX_TRACE_OUTPUT_BYTES
                && !(self.forced_kill && !self.output_incomplete),
            "trace terminal identity, output size, or loss state is invalid",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_backend_source_pins_exact_bytes() -> Result<()> {
        let mut source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        source.bytes.push(b' ');
        assert!(source.validate().is_err());
        assert!(TraceSourceV1::new(vec![b'x'; MAX_TRACE_SOURCE_BYTES + 1]).is_err());
        assert!(TraceSourceV1::new(vec![0xff]).is_err());
        assert!(TraceSourceV1::new(vec![0]).is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_output_limits_and_unknown_loss() -> Result<()> {
        let mut terminal = TraceTerminalV1 {
            execution_id: [1; 16],
            reason: TraceTerminalReasonV1::Completed,
            last_sequence: 0,
            output_bytes: 0,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        terminal.validate()?;
        terminal.forced_kill = true;
        assert!(terminal.validate().is_err());
        assert!(TraceFrameV1 {
            execution_id: [1; 16],
            sequence: 0,
            kind: TraceFrameKindV1::Data,
            bytes: vec![1]
        }
        .validate()
        .is_err());
        Ok(())
    }
}
