mod audit_log;
mod evidence_trace;
mod session_review;

pub use audit_log::AuditLogError;
pub use evidence_trace::EvidenceTraceError;
pub use session_review::SessionReviewError;

pub(crate) use audit_log::{
    InvalidRecordSnafu as AuditInvalidRecordSnafu, OpenSnafu as AuditOpenSnafu,
    ReadSnafu as AuditReadSnafu, SerializeRecordSnafu as AuditSerializeRecordSnafu,
    WriteSnafu as AuditWriteSnafu,
};
pub(crate) use evidence_trace::{
    AuditLogSnafu as EvidenceAuditLogSnafu, InvalidJsonSnafu as EvidenceInvalidJsonSnafu,
    MissingConfigArtifactSnafu as EvidenceMissingConfigArtifactSnafu,
    MissingPolicyArtifactSnafu as EvidenceMissingPolicyArtifactSnafu,
    NoSessionRecordsSnafu as EvidenceNoSessionRecordsSnafu, ReadFileSnafu as EvidenceReadFileSnafu,
    SessionRegistrySnafu as EvidenceSessionRegistrySnafu,
    UnknownSessionSnafu as EvidenceUnknownSessionSnafu, WriteFileSnafu as EvidenceWriteFileSnafu,
};
pub(crate) use session_review::{
    AuditLogSnafu as ReviewAuditLogSnafu, ContextRepositorySnafu as ReviewContextRepositorySnafu,
    EncodeJsonSnafu as ReviewEncodeJsonSnafu,
    InvalidRuntimeConfigSnafu as ReviewInvalidRuntimeConfigSnafu,
    MissingConfigArtifactSnafu as ReviewMissingConfigArtifactSnafu,
    MissingContextRepositorySnafu as ReviewMissingContextRepositorySnafu,
    MissingPolicyArtifactSnafu as ReviewMissingPolicyArtifactSnafu,
    NoSessionRecordsSnafu as ReviewNoSessionRecordsSnafu, ReadFileSnafu as ReviewReadFileSnafu,
    SessionRegistrySnafu as ReviewSessionRegistrySnafu,
    UnknownSessionSnafu as ReviewUnknownSessionSnafu,
};
