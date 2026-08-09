use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityStateV1 {
    Supported,
    Unsupported,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRecordV1 {
    pub capability_id: String,
    pub state: CapabilityStateV1,
    pub reason_code: String,
    pub evidence_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBundleV1 {
    pub schema_version: u32,
    pub architecture_revision_digest: String,
    pub product_build_digest: String,
    pub records: Vec<CapabilityRecordV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChassisPolicyDocumentV1 {
    pub schema_version: u32,
    pub policy_id: String,
    pub effect_prevention_rules: Vec<UnsupportedEffectRuleV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum UnsupportedEffectRuleV1 {}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedCompiledProfileV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub owner_generation: u64,
    pub source_policy_digest: String,
    pub program_digest: String,
    pub capability_bundle_digest: String,
    pub signer_key_id: String,
    pub signature_hex: String,
    pub effect_prevention_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackAuthorizationV1 {
    pub schema_version: u32,
    pub profile_id: String,
    pub from_generation: u64,
    pub to_generation: u64,
    pub compiled_profile_digest: String,
    pub signer_key_id: String,
    pub signature_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualificationResultV1 {
    Pass,
    Fail,
    Unsupported,
    Degraded,
}
