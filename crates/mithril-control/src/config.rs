use std::collections::BTreeSet;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidConfigurationSnafu, IoSnafu, JsonSnafu};
use crate::{
    AdministrativeHttpConfigV1, AllowedNodeIdentity, ControlPlane, ControlServerTls, ControlStore,
    DiscoveryRuntimeConfigV1, EvidenceStoreLimitsV1, KubernetesAdmissionHttpConfigV1,
    KubernetesNodeControlConfigV1, KubernetesNodeReadinessOwner, PolicyDesiredStateConfigV1,
    PolicyDesiredStateOwner, Result, TrustGenerationV1,
};

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
    pub evidence_store: EvidenceStoreLimitsV1,
    #[serde(default)]
    pub control_store_directory: Option<PathBuf>,
    #[serde(default)]
    pub kubernetes_policy: Option<PolicyDesiredStateConfigV1>,
    #[serde(default)]
    pub kubernetes_nodes: Option<KubernetesNodeControlConfigV1>,
    #[serde(default)]
    pub kubernetes_admission: Option<KubernetesAdmissionHttpConfigV1>,
    #[serde(default)]
    pub discovery: Option<DiscoveryRuntimeConfigV1>,
    #[serde(default)]
    pub diagnostics: Option<TraceSignerConfigV1>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSignerConfigV1 {
    pub signing_key_id: String,
    pub signing_key_path: PathBuf,
    pub issuer_epoch: u64,
}

pub struct ControlRuntimeParts {
    pub listen: SocketAddr,
    pub tls: ControlServerTls,
    pub control: ControlPlane,
    pub administrative_exec: Option<AdministrativeHttpConfigV1>,
    pub kubernetes_nodes: Option<KubernetesNodeReadinessOwner>,
    pub kubernetes_admission: Option<KubernetesAdmissionHttpConfigV1>,
    pub discovery: Option<(DiscoveryRuntimeConfigV1, ControlStore)>,
}

impl ControlConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).context(IoSnafu { path })?;
        let config: Self = serde_json::from_slice(&bytes).context(JsonSnafu { path })?;
        config.validate()?;
        Ok(config)
    }

    pub fn into_parts(self) -> Result<ControlRuntimeParts> {
        // Policy metadata and evidence references share one atomic current state.
        let store_directory = self
            .control_store_directory
            .unwrap_or_else(|| self.evidence_directory.clone());
        let store = ControlStore::open_with_evidence_limits(store_directory, self.evidence_store)?;
        let mut control = ControlPlane::with_control_store(
            self.allowed_nodes,
            self.trust.clone(),
            store.clone(),
        )?;
        if let Some(signer) = self.diagnostics {
            control = control.with_trace_signer(
                signer.signing_key_id,
                signer.issuer_epoch,
                crate::policy::read_signing_key(&signer.signing_key_path)?,
            )?;
        }
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
            discovery: self.discovery.map(|config| (config, store)),
        })
    }

    fn validate(&self) -> Result<()> {
        if let Some(signer) = &self.diagnostics {
            ensure!(self.discovery.is_some() && signer.signing_key_path.is_absolute()
                && !signer.signing_key_id.is_empty() && signer.signing_key_id.len() <= 128 && signer.issuer_epoch > 0,
                InvalidConfigurationSnafu { reason: "diagnostics require Discovery storage and an absolute trusted signing key path" });
        }
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
        self.evidence_store.validate()?;
        if let Some(discovery) = &self.discovery {
            discovery.validate()?;
        }
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
    fn discovery_derivation_configuration_is_disabled_until_selected(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
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
        assert!(config.discovery.is_none());
        let parts = config.into_parts()?;
        assert!(parts.discovery.is_none());
        drop(parts);
        source["discovery"] = serde_json::json!({});
        fs::write(&path, serde_json::to_vec(&source)?)?;
        let parts = ControlConfig::load(&path)?.into_parts()?;
        assert_eq!(
            parts
                .discovery
                .as_ref()
                .ok_or("configuration absent")?
                .0
                .checkpoint_seconds,
            60
        );
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        drop(parts);
        source["discovery"] = serde_json::json!({ "checkpoint_seconds": 0 });
        fs::write(&path, serde_json::to_vec(&source)?)?;
        assert!(ControlConfig::load(&path).is_err());
        source["discovery"] = serde_json::Value::Null;
        fs::write(&path, serde_json::to_vec(&source)?)?;
        assert!(ControlConfig::load(&path)?
            .into_parts()?
            .discovery
            .is_none());
        assert!(!directory.path().join("discovery-index.sqlite").exists());
        Ok(())
    }
}
