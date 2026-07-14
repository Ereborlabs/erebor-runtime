mod error;
mod repository;
mod write_boundary;

#[cfg(feature = "test-support")]
pub use write_boundary::api as test_support;

pub use error::{ContextRepositoryError, Result};
pub use repository::{
    CommitMetadata, CommitMetadataSource, CommitMetadataSourceError, CommitSignature, CommitTime,
    ContextCommit, ContextObject, ContextObjectFormat, ContextObjectId, ContextObjectKind,
    ContextRepository, ContextTree, ContextTreeEntry, ContextTreeEntryKind, ContextVerification,
    ForkParentAppend, ForkResult, ForkTarget, ScopeRef, ScopeStart, Snapshot, TreeEdit,
};
