use std::{any::Any, error::Error, io, path::PathBuf};

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::{Location, Snafu};

pub(crate) type BoxedError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ContextRepositoryError {
    #[snafu(display("context repository does not exist at `{}`", path.display()))]
    MissingRepository {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to inspect context repository path `{}`: {source}", path.display()))]
    InspectRepository {
        path: PathBuf,
        source: io::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to initialize context repository at `{}`: {source}", path.display()))]
    InitializeRepository {
        path: PathBuf,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to open context repository at `{}`: {source}", path.display()))]
    OpenRepository {
        path: PathBuf,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context repository at `{}` is not bare", path.display()))]
    UnsupportedRepositoryKind {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context repository at `{}` uses unsupported object format `{actual}`; expected `sha256`",
        path.display()
    ))]
    UnsupportedObjectFormat {
        path: PathBuf,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context repository at `{}` uses Git alternates, which are unsupported",
        path.display()
    ))]
    UnsupportedAlternates {
        path: PathBuf,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Git commit metadata field `{field}` is invalid: {reason}"))]
    InvalidCommitMetadata {
        field: &'static str,
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Git commit metadata source failed: {source}"))]
    CommitMetadataSource {
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context object id `{value}` is invalid: {source}"))]
    InvalidObjectId {
        value: String,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context object id `{id}` uses unsupported object format `{actual}`; expected `sha256`"
    ))]
    UnsupportedObjectIdFormat {
        id: String,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context object `{id}` was not found"))]
    ObjectNotFound {
        id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read context object `{id}`: {source}"))]
    ReadObject {
        id: String,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context object `{id}` has unsupported Git object kind `{actual}`"))]
    UnsupportedObjectKind {
        id: String,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context object `{id}` has kind `{actual}` but `{expected}` was required"))]
    WrongObjectKind {
        id: String,
        expected: &'static str,
        actual: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Git trees cannot contain context object kind `{kind}`"))]
    InvalidTreeEntryKind {
        kind: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to write Git {kind} object: {source}"))]
    WriteObject {
        kind: &'static str,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to edit Git tree: {source}"))]
    EditTree {
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("a context commit cannot have {count} parents; at most two are supported"))]
    InvalidParentCount {
        count: usize,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref {component} `{value}` is invalid: {reason}"))]
    InvalidScopeRef {
        component: &'static str,
        value: String,
        reason: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope id `{scope_id}` is reserved"))]
    ReservedScopeName {
        scope_id: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref `{scope}` was not found"))]
    ScopeNotFound {
        scope: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref `{scope}` already exists"))]
    ScopeAlreadyExists {
        scope: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref `{scope}` is symbolic; direct refs are required"))]
    SymbolicScopeRef {
        scope: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "scope ref `{scope}` points to `{target}`, a `{actual}` object instead of a commit"
    ))]
    ScopeTargetNotCommit {
        scope: String,
        target: String,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref `{scope}` conflicts with existing ref `{existing}`"))]
    ScopeRefPrefixConflict {
        scope: String,
        existing: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to read scope ref `{scope}`: {source}"))]
    ReadScopeRef {
        scope: String,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("failed to update scope ref `{scope}`: {source}"))]
    UpdateScopeRef {
        scope: String,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("scope ref `{scope}` advanced from expected `{expected}` to `{actual}`"))]
    StaleScopeHead {
        scope: String,
        expected: String,
        actual: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("tree edit path `{path}` is invalid: {reason}"))]
    InvalidTreeEdit {
        path: String,
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("snapshot contains duplicate tree edit path `{path}`"))]
    DuplicateTreeEditPath {
        path: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("selected tree for parent commit `{parent}` is unchanged"))]
    SelectedTreeUnchanged {
        parent: String,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "failed to read tree entry `{path}` in tree `{tree}` pointing to object `{entry}`: {source}"
    ))]
    TreeEntryRead {
        tree: Box<str>,
        path: Box<str>,
        entry: Box<str>,
        source: BoxedError,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "tree entry `{path}` in tree `{tree}` points to `{entry}`, a `{actual}` object instead of `{expected}`"
    ))]
    TreeEntryWrongKind {
        tree: Box<str>,
        path: Box<str>,
        entry: Box<str>,
        expected: Box<str>,
        actual: Box<str>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context pin path `{path}` is invalid: {reason}"))]
    InvalidContextPinPath {
        path: Box<str>,
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context pin contains duplicate selected path `{path}`"))]
    DuplicateContextPinPath {
        path: Box<str>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context pin path `{path}` was not found in the selected commit tree"))]
    ContextPinPathNotFound {
        path: Box<str>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context pin path `{path}` selected a {actual}, but a blob was required"))]
    ContextPinPathNotBlob {
        path: Box<str>,
        actual: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display(
        "context pin path `{path}` selected blob `{actual}`, but `{expected}` was declared"
    ))]
    ContextPinBlobMismatch {
        path: Box<str>,
        expected: Box<str>,
        actual: Box<str>,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("context pin is invalid: {reason}"))]
    InvalidContextPin {
        reason: &'static str,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, ContextRepositoryError>;

impl ContextRepositoryError {
    fn context_source(&self) -> Option<&Self> {
        let mut source = self.source();
        while let Some(current) = source {
            if let Some(context_error) = current.downcast_ref::<Self>() {
                return Some(context_error);
            }
            source = current.source();
        }
        None
    }

    fn io_source(&self) -> Option<&io::Error> {
        let mut source = self.source();
        while let Some(current) = source {
            if let Some(io_error) = current.downcast_ref::<io::Error>() {
                return Some(io_error);
            }
            source = current.source();
        }
        None
    }
}

impl ErrorExt for ContextRepositoryError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingRepository { .. } | Self::ObjectNotFound { .. } => StatusCode::NotFound,
            Self::UnsupportedRepositoryKind { .. }
            | Self::UnsupportedObjectFormat { .. }
            | Self::UnsupportedAlternates { .. }
            | Self::UnsupportedObjectIdFormat { .. }
            | Self::UnsupportedObjectKind { .. } => StatusCode::Unsupported,
            Self::InvalidCommitMetadata { .. }
            | Self::InvalidObjectId { .. }
            | Self::WrongObjectKind { .. }
            | Self::InvalidTreeEntryKind { .. }
            | Self::EditTree { .. }
            | Self::InvalidParentCount { .. }
            | Self::InvalidScopeRef { .. }
            | Self::ReservedScopeName { .. }
            | Self::InvalidTreeEdit { .. }
            | Self::DuplicateTreeEditPath { .. }
            | Self::SelectedTreeUnchanged { .. }
            | Self::InvalidContextPinPath { .. }
            | Self::DuplicateContextPinPath { .. }
            | Self::InvalidContextPin { .. } => StatusCode::InvalidArguments,
            Self::ScopeNotFound { .. } => StatusCode::NotFound,
            Self::ScopeAlreadyExists { .. } | Self::ScopeRefPrefixConflict { .. } => {
                StatusCode::AlreadyExists
            }
            Self::SymbolicScopeRef { .. } => StatusCode::Unsupported,
            Self::ScopeTargetNotCommit { .. }
            | Self::TreeEntryWrongKind { .. }
            | Self::StaleScopeHead { .. }
            | Self::ContextPinPathNotBlob { .. }
            | Self::ContextPinBlobMismatch { .. } => StatusCode::IllegalState,
            Self::ContextPinPathNotFound { .. } => StatusCode::NotFound,
            Self::ReadObject { .. } if self.io_source().is_some() => StatusCode::External,
            Self::ReadObject { .. } => StatusCode::InvalidSyntax,
            Self::InspectRepository { .. }
            | Self::InitializeRepository { .. }
            | Self::OpenRepository { .. }
            | Self::CommitMetadataSource { .. }
            | Self::WriteObject { .. }
            | Self::ReadScopeRef { .. }
            | Self::UpdateScopeRef { .. } => StatusCode::External,
            Self::TreeEntryRead { .. } => self
                .context_source()
                .map_or(StatusCode::External, ErrorExt::status_code),
        }
    }

    fn retry_hint(&self) -> RetryHint {
        if matches!(self, Self::StaleScopeHead { .. }) {
            return RetryHint::Retryable;
        }
        self.io_source()
            .map_or(RetryHint::NonRetryable, RetryHint::from_io_error)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
