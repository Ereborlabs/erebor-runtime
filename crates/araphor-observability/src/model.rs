use serde::{Deserialize, Serialize};

use crate::{error::InvalidConfigurationSnafu, DiscoveryDigestV1, Result, WorkloadTargetFactV1};

pub use araphor_data::{
    TraceBatchV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceMeasurementV1, TraceSourceV1, TraceTerminalReasonV1, TraceTerminalV1,
    MAX_TRACE_FRAME_BYTES, MAX_TRACE_OUTPUT_BYTES, MAX_TRACE_SOURCE_BYTES, MAX_TRACE_TARGETS,
};

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
        DiscoveryDigestV1::of(self).map_err(Into::into)
    }

    pub(crate) fn require(valid: bool, reason: &'static str) -> Result<()> {
        if valid {
            Ok(())
        } else {
            InvalidConfigurationSnafu { reason }.fail()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_contract_shared_types() {
        macro_rules! same_type {
            ($($name:ident),+ $(,)?) => {
                $(assert_eq!(std::any::TypeId::of::<$name>(), std::any::TypeId::of::<araphor_data::$name>());)+
            };
        }
        same_type!(
            TraceSourceV1,
            TraceFrameKindV1,
            TraceFrameV1,
            TraceTerminalReasonV1,
            TraceCleanupV1,
            TraceTerminalV1,
            TraceBatchV1,
            TraceMeasurementV1,
            TraceIdentityV1,
        );
    }

    #[test]
    fn observability_contract_error_class() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use erebor_runtime_error::{ErrorExt as _, StatusCode};

        let source = TraceSourceV1::new(Vec::new())
            .err()
            .ok_or("empty source must fail")?;
        let error = crate::Error::from(source);
        assert_eq!(error.status_code(), StatusCode::InvalidArguments);
        assert!(matches!(error, crate::Error::DataStore { source, .. }
            if matches!(*source, araphor_data::Error::TraceInvalid { .. })));
        Ok(())
    }

    #[test]
    fn observability_contract_storage_errors() {
        use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};

        let errors = [
            (
                araphor_data::Error::AnalysisConflict {
                    location: snafu::Location::default(),
                },
                StatusCode::AlreadyExists,
                RetryHint::NonRetryable,
            ),
            (
                araphor_data::Error::RetainedRangeExpired {
                    first_cursor: 1,
                    last_cursor: 2,
                    location: snafu::Location::default(),
                },
                StatusCode::NotFound,
                RetryHint::NonRetryable,
            ),
            (
                araphor_data::Error::StorageCapacity {
                    resource: "diagnostic bytes",
                    location: snafu::Location::default(),
                },
                StatusCode::Unavailable,
                RetryHint::Retryable,
            ),
            (
                araphor_data::Error::ProtectedInputCapacity {
                    resource: "reserved bytes",
                    location: snafu::Location::default(),
                },
                StatusCode::Unavailable,
                RetryHint::Retryable,
            ),
            (
                araphor_data::Error::AnalysisBusy {
                    resource: "writer",
                    location: snafu::Location::default(),
                },
                StatusCode::Unavailable,
                RetryHint::Retryable,
            ),
        ];
        for (source, status, retry) in errors {
            let error = crate::Error::from(source);
            assert_eq!(error.status_code(), status);
            assert_eq!(error.retry_hint(), retry);
            assert!(std::error::Error::source(&error).is_some());
        }
    }
}
