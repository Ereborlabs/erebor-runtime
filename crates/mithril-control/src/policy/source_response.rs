use serde::{Deserialize, Serialize};

use super::source::SeverityV1;
use super::source_proof::{ProofQualityPredicateV1, ProviderV1};
use crate::{EvidenceFieldKeyV1, EvidenceSensitivityV1};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationSinkV1 {
    Pager,
    Chat,
    Email,
    Siem,
    Webhook,
    Ticket,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingGroupingFieldV1 {
    FindingId,
    ReasonCode,
    ProcessLineageId,
    AuthorityDomainId,
    ExecutionSetId,
    ExactObjectId,
    ProviderPrincipalId,
    ProviderResourceId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryFailureActionV1 {
    RecordRouteFailure,
    AlertLocalOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationRouteV1 {
    pub route_id: String,
    pub sink: NotificationSinkV1,
    pub sink_binding_id: String,
    pub minimum_severity: SeverityV1,
    pub grouping_fields: Vec<FindingGroupingFieldV1>,
    pub dedupe_window: String,
    pub allowed_evidence_fields: Vec<EvidenceFieldKeyV1>,
    pub maximum_sensitivity: EvidenceSensitivityV1,
    pub delivery_failure_action: DeliveryFailureActionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseActionSpecV1 {
    RestrictLineage,
    FenceSockets,
    FreezeCgroup,
    TerminateProcessPidfd,
    RejectKubernetesReplacement {
        admission_capability_id: String,
    },
    RevokeCredential {
        provider: ProviderV1,
        credential_kind: String,
        actuator_capability_id: String,
        typed_request_schema_digest: String,
    },
    DisableMeshDevice {
        provider: ProviderV1,
        actuator_capability_id: String,
        typed_request_schema_digest: String,
    },
    QuarantineArtifact {
        store_capability_id: String,
        typed_request_schema_digest: String,
    },
    SuspendInstallation {
        provider: ProviderV1,
        actuator_capability_id: String,
        typed_request_schema_digest: String,
    },
    ProviderSpecific {
        provider: ProviderV1,
        canonical_action_id: String,
        actuator_capability_id: String,
        typed_request_schema_digest: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResponseApprovalV1 {
    Automatic,
    Preapproved,
    Human,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlastRadiusLimitV1 {
    Local {
        permitted_target_selector_ids: Vec<String>,
        process_count: u32,
        execution_set_count: u32,
        socket_count: u32,
        node_count: u32,
    },
    Kubernetes {
        permitted_namespace_uids: Vec<String>,
        object_count: u32,
        controller_count: u32,
        node_count: u32,
    },
    Credential {
        permitted_provider_account_ids: Vec<String>,
        session_count: u32,
        principal_count: u32,
        role_count: u32,
        account_count: u32,
    },
    Mesh {
        permitted_tailnet_or_tenant_ids: Vec<String>,
        device_count: u32,
        route_count: u32,
        auth_key_count: u32,
    },
    SourceControl {
        permitted_organization_ids: Vec<String>,
        installation_count: u32,
        repository_count: u32,
        ref_or_pr_count: u32,
    },
    Artifact {
        permitted_store_ids: Vec<String>,
        artifact_count: u32,
        consumer_count: u32,
    },
    ProviderResources {
        permitted_provider_account_ids: Vec<String>,
        permitted_resource_selector_ids: Vec<String>,
        resource_count: u32,
        principal_count: u32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TargetRevalidationV1 {
    ProcessPidfdTaskCookieStarttimeCgroupBinding,
    LineageRootAndCompleteEffectiveResponseSet,
    SocketCookieProvenanceAndLiveBinding,
    CgroupFdNonceAndMemberSet,
    KubernetesUidResourceVersion,
    ProviderStableIdRevisionAndAuthority,
    ArtifactImmutableDigestAndStoreRevision,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PhysicalPostconditionV1 {
    ResponseSetInstalledAndDescendantsReconciled,
    ProcessStoppedViaPidfd,
    SocketSetFencedAndExistingFlowOraclePassed,
    CgroupFrozenAndPacketFenceActive,
    ReplacementRejectedThroughWatchWatermark,
    ProviderCredentialActionReadBack,
    MeshDeviceDisabledAndHandshakeRejected,
    ArtifactQuarantinedAndConsumerLoadRejected,
    ProviderOperationSpecificPostcondition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseBindingV1 {
    pub binding_id: String,
    pub action_spec: ResponseActionSpecV1,
    pub approval: ResponseApprovalV1,
    pub required_proof: ProofQualityPredicateV1,
    pub maximum_blast_radius: BlastRadiusLimitV1,
    pub target_revalidation: TargetRevalidationV1,
    pub physical_postcondition: PhysicalPostconditionV1,
    pub watch_interval: String,
}
