use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderV1 {
    Kubernetes,
    Aws,
    Gcp,
    Github,
    InternalConnector,
    OciRegistry,
    Mesh,
    Connector,
    Other,
}

pub use araphor_data::{
    FindingStateV1, LocalSubjectBindingV1, OperationResultAuthorityV1, ProofIntegrityV1,
    ProofQualityV1, RemoteSubjectBindingV1, SourceAuthorityV1, TemporalCoverageV1,
};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofQualityPredicateV1 {
    pub source_authority: Vec<SourceAuthorityV1>,
    pub local_subject_binding: Vec<LocalSubjectBindingV1>,
    pub remote_subject_binding: Vec<RemoteSubjectBindingV1>,
    pub operation_result_authority: Vec<OperationResultAuthorityV1>,
    pub temporal_coverage: Vec<TemporalCoverageV1>,
    pub integrity: Vec<ProofIntegrityV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResourceSelectorV1 {
    pub resource_kind_id: u16,
    pub provider_canonical_resource_bytes: String,
    pub immutable_revision_digest: Option<String>,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuntimeOperationV1 {
    ContainerStart,
    ExecSync,
    StreamingExec,
    LifecycleExec,
    EphemeralContainer,
    CheckpointRestore,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthoritativeResultV1 {
    Admitted,
    Rejected,
    Allowed,
    Denied,
    Succeeded,
    Failed,
    Unknown,
}
