use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceAuthorityV1 {
    KernelDecision,
    SignedCoordinator,
    AuthoritativeProvider,
    AuthenticatedMeasurement,
    Unauthenticated,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LocalSubjectBindingV1 {
    ExactTask,
    ExactProcess,
    ExactExecutionSet,
    Contextual,
    None,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemoteSubjectBindingV1 {
    ExactRequest,
    ExactSession,
    ExactObject,
    PrincipalOnly,
    Contextual,
    None,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationResultAuthorityV1 {
    PreEffectDecision,
    AuthoritativeSucceeded,
    AuthoritativeDenied,
    ObservedAttempt,
    Contextual,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TemporalCoverageV1 {
    Complete,
    Gapped,
    Unknown,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofIntegrityV1 {
    Signed,
    AuthenticatedChannel,
    LocalAttested,
    Unverified,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProofQualityV1 {
    pub source_authority: SourceAuthorityV1,
    pub local_subject_binding: LocalSubjectBindingV1,
    pub remote_subject_binding: RemoteSubjectBindingV1,
    pub operation_result_authority: OperationResultAuthorityV1,
    pub temporal_coverage: TemporalCoverageV1,
    pub integrity: ProofIntegrityV1,
}

impl ProofQualityV1 {
    #[must_use]
    pub const fn kernel_decision(temporal_coverage: TemporalCoverageV1) -> Self {
        Self {
            source_authority: SourceAuthorityV1::KernelDecision,
            local_subject_binding: LocalSubjectBindingV1::ExactTask,
            remote_subject_binding: RemoteSubjectBindingV1::None,
            operation_result_authority: OperationResultAuthorityV1::PreEffectDecision,
            temporal_coverage,
            integrity: ProofIntegrityV1::LocalAttested,
        }
    }
}

#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStateV1 {
    Provisional,
    Confirmed,
    Superseded,
    Retracted,
    CoverageInsufficient,
}

impl ProofQualityV1 {
    pub fn qualified_result(self) -> bool {
        matches!(
            self.source_authority,
            SourceAuthorityV1::KernelDecision
                | SourceAuthorityV1::AuthoritativeProvider
                | SourceAuthorityV1::SignedCoordinator
                | SourceAuthorityV1::AuthenticatedMeasurement
        ) && matches!(
            self.local_subject_binding,
            LocalSubjectBindingV1::ExactTask | LocalSubjectBindingV1::ExactProcess
        ) && self.temporal_coverage == TemporalCoverageV1::Complete
            && matches!(
                self.integrity,
                ProofIntegrityV1::Signed
                    | ProofIntegrityV1::AuthenticatedChannel
                    | ProofIntegrityV1::LocalAttested
            )
    }

    pub fn parent_qualified(self) -> bool {
        self.temporal_coverage == TemporalCoverageV1::Complete
            && matches!(
                self.integrity,
                ProofIntegrityV1::Signed
                    | ProofIntegrityV1::AuthenticatedChannel
                    | ProofIntegrityV1::LocalAttested
            )
    }

    pub fn authority_contextual(self) -> bool {
        matches!(
            self.source_authority,
            SourceAuthorityV1::AuthoritativeProvider | SourceAuthorityV1::SignedCoordinator
        ) && matches!(
            self.integrity,
            ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
        )
    }

    pub fn authority_direct(self) -> bool {
        self.source_authority == SourceAuthorityV1::AuthoritativeProvider
            && matches!(
                self.remote_subject_binding,
                RemoteSubjectBindingV1::ExactRequest | RemoteSubjectBindingV1::ExactSession
            )
            && matches!(
                self.operation_result_authority,
                OperationResultAuthorityV1::AuthoritativeSucceeded
                    | OperationResultAuthorityV1::AuthoritativeDenied
            )
            && self.qualified_result()
    }

    pub fn succeeded(self) -> bool {
        self.qualified_result()
            && self.operation_result_authority == OperationResultAuthorityV1::AuthoritativeSucceeded
    }

    pub fn kubernetes_qualified(self) -> bool {
        self.source_authority == SourceAuthorityV1::AuthoritativeProvider
            && self.temporal_coverage == TemporalCoverageV1::Complete
            && matches!(
                self.integrity,
                ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
            )
    }
}
