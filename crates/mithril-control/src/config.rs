use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, JsonSnafu};
use crate::{
    AdministrativeHttpConfigV1, AllowedNodeIdentity, ControlPlane, ControlServerTls, ControlStore,
    EvidenceIntakeOwner, KubernetesAdmissionHttpConfigV1, KubernetesNodeControlConfigV1,
    KubernetesNodeReadinessOwner, PolicyDesiredStateConfigV1, PolicyDesiredStateOwner, Result,
    SystemIntakeClock, TrustGenerationV1,
};

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EvidenceAdmissionLimits {
    pub total_slots: usize,
    pub slots_per_node: usize,
}

impl Default for EvidenceAdmissionLimits {
    fn default() -> Self {
        Self {
            total_slots: 8,
            slots_per_node: 2,
        }
    }
}

impl EvidenceAdmissionLimits {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(
            (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.total_slots)
                && (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&self.slots_per_node),
            InvalidConfigurationSnafu {
                reason: "evidence admission slots must be positive and fit a semaphore",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub tls: ControlServerTls,
    pub allowed_nodes: Vec<AllowedNodeIdentity>,
    pub trust: TrustGenerationV1,
    pub administrative_exec: Option<AdministrativeHttpConfigV1>,
    pub evidence_directory: PathBuf,
    #[serde(default)]
    pub evidence_admission: EvidenceAdmissionLimits,
    #[serde(default)]
    pub data_retention: araphor_data::RetentionLimitsV1,
    #[serde(default)]
    pub data_storage: araphor_data::StorageLimitsV1,
    #[serde(default)]
    pub data_retirements: Vec<araphor_data::ProcessorRetirementV1>,
    #[serde(default)]
    pub control_store_directory: Option<PathBuf>,
    #[serde(default)]
    pub kubernetes_policy: Option<PolicyDesiredStateConfigV1>,
    #[serde(default)]
    pub kubernetes_nodes: Option<KubernetesNodeControlConfigV1>,
    #[serde(default)]
    pub kubernetes_admission: Option<KubernetesAdmissionHttpConfigV1>,
}

pub struct ControlRuntimeParts {
    pub listen: SocketAddr,
    pub tls: ControlServerTls,
    pub control: ControlPlane,
    pub administrative_exec: Option<AdministrativeHttpConfigV1>,
    pub kubernetes_nodes: Option<KubernetesNodeReadinessOwner>,
    pub kubernetes_admission: Option<KubernetesAdmissionHttpConfigV1>,
    pub data_error: Option<crate::Error>,
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        let config: Self = serde_json::from_slice(&bytes).context(JsonSnafu { path })?;
        config.validate()?;
        Ok(config)
    }

    pub fn into_parts(self) -> Result<ControlRuntimeParts> {
        self.validate()?;
        let store_directory = self
            .control_store_directory
            .as_ref()
            .unwrap_or(&self.evidence_directory);
        let store = ControlStore::open(store_directory)?;
        let (mut control, data_error) = match self.open_analysis() {
            Ok(data) => (
                ControlPlane::from_intake(
                    self.allowed_nodes,
                    self.trust.clone(),
                    EvidenceIntakeOwner::new(store.clone(), data, Arc::new(SystemIntakeClock))?,
                )?,
                None,
            ),
            Err(error) => (
                ControlPlane::without_intake(
                    self.allowed_nodes,
                    self.trust.clone(),
                    store.clone(),
                )?,
                Some(error),
            ),
        };
        control = control.with_evidence_limits(self.evidence_admission)?;
        if let Some(policy) = self.kubernetes_policy {
            let owner = PolicyDesiredStateOwner::open(policy, store.clone())?;
            let (key_id, public_key, issuer_epoch) = owner.signer_identity();
            // Control must trust its configured candidate signer before it starts reconciliation.
            ensure!(
                self.trust.policy_issuer_sequence_epoch == issuer_epoch
                    && self.trust.policy_signers.iter().any(|signer| {
                        signer.signing_key_id == key_id
                            && signer.ed25519_public_key_hex == public_key
                            && !signer.revoked
                    }),
                InvalidConfigurationSnafu {
                    reason: "the Kubernetes policy signer is absent, revoked, or outside the current trust epoch",
                }
            );
            control = control.with_policy_desired_state(owner);
        }
        let kubernetes_nodes = self
            .kubernetes_nodes
            .map(KubernetesNodeReadinessOwner::new)
            .transpose()?;
        Ok(ControlRuntimeParts {
            listen: self.listen,
            tls: self.tls,
            control,
            administrative_exec: self.administrative_exec,
            kubernetes_nodes,
            kubernetes_admission: self.kubernetes_admission,
            data_error,
        })
    }

    fn validate(&self) -> Result<()> {
        self.evidence_admission.validate()?;
        ensure!(
            !self.allowed_nodes.is_empty(),
            InvalidConfigurationSnafu {
                reason: "allowed_nodes must not be empty",
            }
        );
        ensure!(
            self.evidence_directory.is_absolute(),
            InvalidConfigurationSnafu {
                reason: "evidence_directory must be absolute",
            }
        );
        let mut retired_scopes = BTreeSet::new();
        ensure!(
            self.data_retirements.len() <= 32,
            InvalidConfigurationSnafu {
                reason: "data_retirements exceeds 32 requests",
            }
        );
        for request in &self.data_retirements {
            let scope = &request.scope;
            ensure!(request.valid()
                && retired_scopes.insert((scope.processor_id.as_str(), scope.method_version, &scope.identity))
                && self.allowed_nodes.iter().any(|node| node.node_id == scope.identity.node_id
                    && uuid::Uuid::parse_str(&node.tenant_id).is_ok_and(|tenant| tenant.as_bytes() == &scope.identity.tenant_id)),
                InvalidConfigurationSnafu {
                    reason: "a data retirement must name one unique valid processor scope on an allowed Node and tenant",
                });
        }
        ensure!(
            self.data_storage.valid(),
            InvalidConfigurationSnafu {
                reason: "data storage capacity limits are invalid"
            }
        );
        ensure!(
            self.data_retention.raw_max_age_ns > 0 && self.data_retention.raw_max_bytes > 0,
            InvalidConfigurationSnafu {
                reason: "data retention limits must be positive"
            }
        );
        ensure!(
            self.control_store_directory
                .as_ref()
                .is_none_or(|path| path.is_absolute()),
            InvalidConfigurationSnafu {
                reason: "control_store_directory must be absolute when it is set",
            }
        );
        if let Some(policy) = &self.kubernetes_policy {
            policy.validate()?;
        }
        if let Some(nodes) = &self.kubernetes_nodes {
            nodes.validate()?;
        }
        if let Some(admission) = &self.kubernetes_admission {
            admission.validate()?;
            // Admission cannot run without both policy state and DaemonSet-derived node state.
            ensure!(
                self.kubernetes_policy.is_some() && self.kubernetes_nodes.is_some(),
                InvalidConfigurationSnafu {
                    reason: "Kubernetes admission requires policy and DaemonSet node control",
                }
            );
        }
        ensure!(
            self.trust.generation > 0
                && is_sha256_hex(&self.trust.bundle_digest)
                && self
                    .trust
                    .policy_signers
                    .windows(2)
                    .all(|pair| pair[0].signing_key_id < pair[1].signing_key_id)
                && self.trust.policy_signers.iter().all(|signer| {
                    !signer.signing_key_id.is_empty()
                        && signer.signing_key_id.len() <= 128
                        && is_sha256_hex(&signer.ed25519_public_key_hex)
                })
                && (self.trust.policy_signers.is_empty()
                    || (self.trust.policy_issuer_sequence_epoch > 0
                        && self.trust.computed_bundle_digest() == self.trust.bundle_digest)),
            InvalidConfigurationSnafu {
                reason: "trust generation must be nonzero and its digest must be SHA-256 hex",
            }
        );
        let mut node_ids = BTreeSet::new();
        for identity in &self.allowed_nodes {
            let tenant_id = uuid::Uuid::parse_str(&identity.tenant_id).ok();
            ensure!(
                crate::node_id_is_valid(&identity.node_id)
                    && is_sha256_hex(&identity.certificate_sha256)
                    && tenant_id.is_some_and(|tenant| tenant.hyphenated().to_string() == identity.tenant_id)
                    && node_ids.insert(identity.node_id.as_str()),
                InvalidConfigurationSnafu {
                    reason: "every node needs a canonical tenant UUID, unique clean ID, and lowercase certificate SHA-256 digest",
                }
            );
        }
        if let Some(config) = &self.administrative_exec {
            config.validate()?;
        }
        Ok(())
    }

    fn open_analysis(&self) -> Result<Arc<araphor_data::AnalysisStore>> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.evidence_directory)
            .context(IoSnafu {
                path: &self.evidence_directory,
            })?;
        araphor_data::AnalysisStore::open_with_limits(
            self.evidence_directory.join("analysis"),
            self.data_retention,
            self.data_storage,
        )
        .and_then(|data| {
            for request in &self.data_retirements {
                data.retire_required(request)?;
            }
            Ok(Arc::new(data))
        })
        .map_err(|source| crate::Error::DataStore {
            source: Box::new(source),
            location: snafu::Location::default(),
        })
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_startup_is_independent() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("control.json");
        let mut source = serde_json::json!({
            "listen": "127.0.0.1:0",
            "tls": {
                "certificate_path": directory.path().join("control.pem"),
                "private_key_path": directory.path().join("control-key.pem"),
                "node_ca_path": directory.path().join("node-ca.pem")
            },
            "allowed_nodes": [{
                "node_id": "node-a", "certificate_sha256": "a".repeat(64),
                "tenant_id": "00000000-0000-0001-0000-000000000002"
            }],
            "trust": { "generation": 1, "bundle_digest": "b".repeat(64),
                "policy_issuer_sequence_epoch": 0, "policy_signers": [] },
            "administrative_exec": null,
            "evidence_directory": directory.path()
        });
        fs::write(&path, serde_json::to_vec(&source)?)?;
        let config = ControlConfig::load(&path)?;
        assert_eq!(config.evidence_admission.total_slots, 8);
        assert_eq!(config.evidence_admission.slots_per_node, 2);
        let parts = config.into_parts()?;
        assert!(parts.data_error.is_none());
        assert!(parts
            .control
            .clone()
            .with_evidence_limits(EvidenceAdmissionLimits::default())
            .is_err());
        let initial = parts
            .control
            .analysis_store()
            .ok_or("data owner absent")?
            .meta()?;
        drop(parts);
        let parts = ControlConfig::load(&path)?.into_parts()?;
        assert!(parts.data_error.is_none());
        assert_eq!(
            parts
                .control
                .analysis_store()
                .ok_or("data owner absent")?
                .meta()?,
            initial
        );
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        drop(parts);

        source["evidence_admission"] = serde_json::json!({
            "total_slots": 12, "slots_per_node": 3
        });
        fs::write(&path, serde_json::to_vec(&source)?)?;
        let config = ControlConfig::load(&path)?;
        assert_eq!(config.evidence_admission.total_slots, 12);
        assert_eq!(config.evidence_admission.slots_per_node, 3);
        drop(config.into_parts()?);
        for field in ["total_slots", "slots_per_node"] {
            let previous = source["evidence_admission"][field].clone();
            for invalid in [0, usize::MAX] {
                source["evidence_admission"][field] = serde_json::json!(invalid);
                fs::write(&path, serde_json::to_vec(&source)?)?;
                assert!(ControlConfig::load(&path).is_err());
            }
            source["evidence_admission"][field] = previous;
        }
        fs::write(&path, serde_json::to_vec(&source)?)?;
        let database = directory.path().join("analysis/analysis.duckdb");
        fs::write(&database, b"invalid database")?;
        let parts = ControlConfig::load(&path)?.into_parts()?;
        assert!(parts.data_error.is_some());
        assert!(parts.control.analysis_store().is_none());
        assert_eq!(parts.control.allowed_nodes().len(), 1);
        assert_eq!(fs::read(&database)?, b"invalid database");
        drop(parts);

        source["discovery"] = serde_json::json!({});
        fs::write(&path, serde_json::to_vec(&source)?)?;
        assert!(ControlConfig::load(&path).is_err());
        Ok(())
    }
}
