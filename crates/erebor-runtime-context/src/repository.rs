use std::{error::Error, path::Path, path::PathBuf};

use gix::{
    create::{Kind as RepositoryKind, Options as CreateOptions},
    hash::Kind as HashKind,
    open::Options as OpenOptions,
    ThreadSafeRepository,
};
use snafu::ResultExt;

use crate::error::{
    BoxedError, InspectRepositorySnafu, MissingRepositorySnafu, OpenRepositorySnafu, Result,
    UnsupportedAlternatesSnafu, UnsupportedObjectFormatSnafu, UnsupportedRepositoryKindSnafu,
};

mod object;
pub use object::{ContextObject, ContextObjectId, ContextObjectKind};
mod refs;
pub use refs::{ScopeRef, ScopeStart};
mod tree_edit;
pub use tree_edit::{Snapshot, TreeEdit};
mod transaction;
pub use transaction::{ForkParentAppend, ForkResult, ForkTarget};
mod inspect;
pub use inspect::{
    ContextCommit, ContextTree, ContextTreeEntry, ContextTreeEntryKind, ContextVerification,
};

#[cfg(test)]
mod tests;

pub type CommitMetadataSourceError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitTime {
    seconds: i64,
    offset_seconds: i32,
}

impl CommitTime {
    pub fn new(seconds: i64, offset_seconds: i32) -> Result<Self> {
        if offset_seconds % 60 != 0 || !(-86_400..86_400).contains(&offset_seconds) {
            return crate::error::InvalidCommitMetadataSnafu {
                field: "time offset",
                reason: "must be minute-aligned and less than 24 hours from UTC",
            }
            .fail();
        }
        Ok(Self {
            seconds,
            offset_seconds,
        })
    }

    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    #[must_use]
    pub const fn offset_seconds(self) -> i32 {
        self.offset_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSignature {
    name: String,
    email: String,
    time: CommitTime,
}

impl CommitSignature {
    pub fn new(
        name: impl Into<String>,
        email: impl Into<String>,
        time: CommitTime,
    ) -> Result<Self> {
        let name = name.into();
        let email = email.into();
        Self::validate_token("author or committer name", &name)?;
        Self::validate_token("author or committer email", &email)?;
        Ok(Self { name, email, time })
    }

    fn validate_token(field: &'static str, value: &str) -> Result<()> {
        if value.is_empty() {
            return crate::error::InvalidCommitMetadataSnafu {
                field,
                reason: "must not be empty",
            }
            .fail();
        }
        if value
            .bytes()
            .any(|byte| matches!(byte, b'<' | b'>' | b'\n' | 0))
        {
            return crate::error::InvalidCommitMetadataSnafu {
                field,
                reason: "must not contain `<`, `>`, newline, or NUL",
            }
            .fail();
        }
        Ok(())
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    #[must_use]
    pub const fn time(&self) -> CommitTime {
        self.time
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitMetadata {
    author: CommitSignature,
    committer: CommitSignature,
}

impl CommitMetadata {
    #[must_use]
    pub const fn new(author: CommitSignature, committer: CommitSignature) -> Self {
        Self { author, committer }
    }

    #[must_use]
    pub const fn author(&self) -> &CommitSignature {
        &self.author
    }

    #[must_use]
    pub const fn committer(&self) -> &CommitSignature {
        &self.committer
    }
}

pub trait CommitMetadataSource: Send + Sync {
    fn metadata(&self) -> std::result::Result<CommitMetadata, CommitMetadataSourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextObjectFormat {
    Sha256,
}

pub struct ContextRepository {
    path: PathBuf,
    repository: ThreadSafeRepository,
    metadata_source: Box<dyn CommitMetadataSource>,
    object_format: ContextObjectFormat,
}

impl ContextRepository {
    pub fn init(
        path: impl AsRef<Path>,
        metadata_source: impl CommitMetadataSource + 'static,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        Self::ensure_no_alternates(&path)?;
        let repository = ThreadSafeRepository::init_opts(
            &path,
            RepositoryKind::Bare,
            CreateOptions {
                object_hash: Some(HashKind::Sha256),
                ..CreateOptions::default()
            },
            Self::open_options(),
        )
        .map_err(|source| Box::new(source) as BoxedError)
        .context(crate::error::InitializeRepositorySnafu { path: &path })?;
        Self::from_repository(path, repository, metadata_source)
    }

    pub fn open(
        path: impl AsRef<Path>,
        metadata_source: impl CommitMetadataSource + 'static,
    ) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        match path
            .try_exists()
            .context(InspectRepositorySnafu { path: &path })?
        {
            true => {}
            false => return MissingRepositorySnafu { path }.fail(),
        }
        Self::ensure_no_alternates(&path)?;
        let repository = ThreadSafeRepository::open_opts(&path, Self::open_options())
            .map_err(|source| Box::new(source) as BoxedError)
            .context(OpenRepositorySnafu { path: &path })?;
        Self::from_repository(path, repository, metadata_source)
    }

    fn from_repository(
        path: PathBuf,
        repository: ThreadSafeRepository,
        metadata_source: impl CommitMetadataSource + 'static,
    ) -> Result<Self> {
        let local = repository.to_thread_local();
        if !local.is_bare() || local.common_dir() != local.git_dir() {
            return UnsupportedRepositoryKindSnafu { path }.fail();
        }
        if local.object_hash() != HashKind::Sha256 {
            return UnsupportedObjectFormatSnafu {
                path,
                actual: format!("{:?}", local.object_hash()).to_lowercase(),
            }
            .fail();
        }
        drop(local);
        let context = Self {
            path,
            repository,
            metadata_source: Box::new(metadata_source),
            object_format: ContextObjectFormat::Sha256,
        };
        context.validate_scope_refs()?;
        Ok(context)
    }

    fn open_options() -> OpenOptions {
        OpenOptions::isolated()
            .open_path_as_is(true)
            .strict_config(true)
    }

    fn ensure_no_alternates(path: &Path) -> Result<()> {
        for name in ["alternates", "http-alternates"] {
            let alternate = path.join("objects").join("info").join(name);
            if alternate
                .try_exists()
                .context(InspectRepositorySnafu { path: &alternate })?
            {
                return UnsupportedAlternatesSnafu {
                    path: path.to_path_buf(),
                }
                .fail();
            }
        }
        Ok(())
    }

    fn repository(&self) -> gix::Repository {
        self.repository.to_thread_local()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn object_format(&self) -> ContextObjectFormat {
        self.object_format
    }
}
