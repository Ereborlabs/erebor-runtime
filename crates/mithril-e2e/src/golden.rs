use std::collections::BTreeSet;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::Path;

use erebor_interceptor_abi::{
    ChassisPolicyDocumentV1, RollbackAuthorizationV1, SignedCompiledProfileV1,
};
#[cfg(test)]
use serde::Serialize;
use snafu::ensure;
#[cfg(test)]
use snafu::ResultExt as _;

use crate::error::InvalidInputSnafu;
#[cfg(test)]
use crate::error::{IoSnafu, JsonSnafu};
use crate::Result;

pub struct QualificationContractValidator;

impl QualificationContractValidator {
    pub fn policy(policy: &ChassisPolicyDocumentV1) -> Result<()> {
        ensure!(
            policy.schema_version == 1
                && !policy.policy_id.is_empty()
                && policy.effect_prevention_rules.is_empty(),
            InvalidInputSnafu {
                path: "CFG-V1-GOLDEN-002",
                reason: "kernel qualification policy must be the closed chassis-only schema",
            }
        );
        Ok(())
    }

    pub fn compiled(profile: &SignedCompiledProfileV1) -> Result<()> {
        ensure!(
            profile.schema_version == 1
                && profile.owner_generation > 0
                && !profile.effect_prevention_enabled
                && is_digest(&profile.source_policy_digest)
                && is_digest(&profile.program_digest)
                && is_digest(&profile.capability_bundle_digest)
                && profile.signature_hex.len() == 128,
            InvalidInputSnafu {
                path: "CFG-V1-GOLDEN-002",
                reason:
                    "compiled kernel qualification profile is invalid or claims effect prevention",
            }
        );
        Ok(())
    }
}

pub struct RollbackGuard {
    active_generation: u64,
    used_authorizations: BTreeSet<String>,
}

impl RollbackGuard {
    #[must_use]
    pub fn new(active_generation: u64) -> Self {
        Self {
            active_generation,
            used_authorizations: BTreeSet::new(),
        }
    }

    pub fn authorize(&mut self, authorization: &RollbackAuthorizationV1) -> Result<()> {
        ensure!(
            authorization.schema_version == 1
                && authorization.from_generation == self.active_generation
                && authorization.to_generation > 0
                && authorization.to_generation < authorization.from_generation
                && is_digest(&authorization.compiled_profile_digest)
                && authorization.signature_hex.len() == 128,
            InvalidInputSnafu {
                path: "CFG-ROLLBACK-GOLDEN-002",
                reason: "rollback authorization does not target the active generation",
            }
        );
        ensure!(
            self.used_authorizations
                .insert(authorization.signature_hex.clone()),
            InvalidInputSnafu {
                path: "CFG-ROLLBACK-GOLDEN-002",
                reason: "rollback authorization was replayed",
            }
        );
        self.active_generation = authorization.to_generation;
        Ok(())
    }
}

#[cfg(test)]
pub fn load_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path).context(IoSnafu { path })?;
    serde_json::from_slice(&bytes).context(JsonSnafu { path })
}

#[cfg(test)]
pub fn canonical_json<T>(path: &Path, value: &T) -> Result<Vec<u8>>
where
    T: Serialize,
{
    let mut bytes = serde_json::to_vec_pretty(value).context(JsonSnafu { path })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use erebor_interceptor_abi::{
        BindingLifecycleStateV1, ChassisPolicyDocumentV1, EffectDecisionKeyV1,
        PhysicalDecisionKindV1, PhysicalDecisionV1, RollbackAuthorizationV1,
        SignedCompiledProfileV1,
    };
    use snafu::ResultExt as _;

    use super::{canonical_json, load_json, QualificationContractValidator, RollbackGuard};
    use crate::error::IoSnafu;

    #[test]
    fn cfg_v1_golden_is_closed_deterministic_and_chassis_only() -> crate::Result<()> {
        let directory = goldens();
        let policy_path = directory.join("cfg-v1.json");
        let policy: ChassisPolicyDocumentV1 = load_json(&policy_path)?;
        QualificationContractValidator::policy(&policy)?;
        assert_eq!(
            canonical_json(&policy_path, &policy)?,
            fs::read(&policy_path).context(IoSnafu { path: &policy_path })?
        );
        let profile_path = directory.join("compiled-profile-v1.json");
        let profile: SignedCompiledProfileV1 = load_json(&profile_path)?;
        QualificationContractValidator::compiled(&profile)?;
        assert_eq!(
            canonical_json(&profile_path, &profile)?,
            fs::read(&profile_path).context(IoSnafu {
                path: &profile_path,
            })?
        );
        let unknown =
            br#"{"schema_version":1,"policy_id":"x","effect_prevention_rules":[],"unknown":true}"#;
        assert!(serde_json::from_slice::<ChassisPolicyDocumentV1>(unknown).is_err());
        Ok(())
    }

    #[test]
    fn cfg_rollback_golden_rejects_replay_and_corruption() -> crate::Result<()> {
        let path = goldens().join("cfg-rollback-v1.json");
        let authorization: RollbackAuthorizationV1 = load_json(&path)?;
        assert_eq!(
            canonical_json(&path, &authorization)?,
            fs::read(&path).context(IoSnafu { path: &path })?
        );
        let mut guard = RollbackGuard::new(2);
        guard.authorize(&authorization)?;
        assert!(guard.authorize(&authorization).is_err());
        let mut corrupt = authorization;
        corrupt.compiled_profile_digest = "not-a-digest".to_owned();
        assert!(RollbackGuard::new(2).authorize(&corrupt).is_err());
        Ok(())
    }

    #[test]
    fn decision_set_golden_matches_closed_rust_and_c_layout() -> crate::Result<()> {
        let key = EffectDecisionKeyV1 {
            profile_generation_ref_id: 1,
            active_role_id: 2,
            entry_kind: 3,
            effect_family: 4,
            operation: 5,
            reserved: 0,
            reserved_alignment: [0; 4],
            composite_atom_id: 6,
            exact_object_key_id: 7,
            process_state_vector_id: 8,
            binding_lifecycle_state: BindingLifecycleStateV1::Active,
            reserved_tail: [0; 3],
        };
        let missing = PhysicalDecisionV1 {
            decision: PhysicalDecisionKindV1::Deny,
            reserved: 0,
            errno: -13,
            evidence_class_id: 0,
            transition_id: 0,
            exception_numeric_handle: 0,
        };
        let expected = format!(
            "{}\n{}\n",
            hex::encode(key.encode_le()),
            hex::encode(missing.encode_le())
        );
        let path = goldens().join("decision-set-v1.hex");
        assert_eq!(
            expected,
            fs::read_to_string(&path).context(IoSnafu { path })?
        );
        Ok(())
    }

    fn goldens() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/qualification/v1/goldens")
    }
}
