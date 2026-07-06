use std::{fs, path::Path};

use ::ostree::prelude::Cast;
use snafu::ResultExt;

use crate::{
    error::{OstreeCommandFailedSnafu, OstreeInitFailedSnafu, PromotionIoSnafu, StartOstreeSnafu},
    Result,
};

pub(crate) trait OstreeRepository {
    fn initialize(&self, repo: &Path) -> Result<()>;
    fn commit_tree(&self, commit: &OstreeTreeCommit<'_>) -> Result<()>;
    fn checkout_tree(&self, checkout: &OstreeTreeCheckout<'_>) -> Result<()>;
    fn list_refs(&self, repo: &Path) -> Result<Vec<String>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemOstreeRepository;

impl OstreeRepository for SystemOstreeRepository {
    fn initialize(&self, repo_path: &Path) -> Result<()> {
        fs::create_dir_all(repo_path).context(PromotionIoSnafu {
            action: "create ostree repo directory",
            path: repo_path,
        })?;
        let repo = ::ostree::Repo::new_for_path(repo_path);
        repo.create(
            ::ostree::RepoMode::BareUserOnly,
            ::ostree::gio::Cancellable::NONE,
        )
        .map_err(|error| {
            OstreeInitFailedSnafu {
                repo: repo_path.to_path_buf(),
                code: None,
                stderr: error.to_string(),
            }
            .build()
        })?;
        repo.open(::ostree::gio::Cancellable::NONE)
            .map_err(|error| {
                OstreeInitFailedSnafu {
                    repo: repo_path.to_path_buf(),
                    code: None,
                    stderr: error.to_string(),
                }
                .build()
            })?;
        let config = repo.copy_config();
        config.set_string("core", "min-free-space-percent", "0");
        repo.write_config(&config).map_err(|error| {
            OstreeCommandFailedSnafu {
                repo: repo_path.to_path_buf(),
                operation: "configure ostree minimum free space",
                code: None,
                stderr: error.to_string(),
            }
            .build()
        })
    }

    fn commit_tree(&self, commit: &OstreeTreeCommit<'_>) -> Result<()> {
        let repo = Self::open_repo(commit.repo, commit.operation)?;
        let transaction = repo
            .auto_transaction(::ostree::gio::Cancellable::NONE)
            .map_err(|error| {
                OstreeCommandFailedSnafu {
                    repo: commit.repo.to_path_buf(),
                    operation: commit.operation,
                    code: None,
                    stderr: error.to_string(),
                }
                .build()
            })?;
        let tree = ::ostree::MutableTree::new();
        repo.write_directory_to_mtree(
            &::ostree::gio::File::for_path(commit.tree),
            &tree,
            None::<&::ostree::RepoCommitModifier>,
            ::ostree::gio::Cancellable::NONE,
        )
        .map_err(|error| commit.error(error))?;
        let root = repo
            .write_mtree(&tree, ::ostree::gio::Cancellable::NONE)
            .map_err(|error| commit.error(error))?
            .downcast::<::ostree::RepoFile>()
            .map_err(|_| commit.error("libostree returned non-repository root file"))?;
        let checksum = repo
            .write_commit(
                None,
                Some(commit.subject),
                None,
                None::<&::ostree::glib::Variant>,
                &root,
                ::ostree::gio::Cancellable::NONE,
            )
            .map_err(|error| commit.error(error))?;
        repo.transaction_set_ref(None, commit.ref_name, Some(checksum.as_str()));
        transaction
            .commit(::ostree::gio::Cancellable::NONE)
            .map_err(|error| commit.error(error))?;
        Ok(())
    }

    fn checkout_tree(&self, checkout: &OstreeTreeCheckout<'_>) -> Result<()> {
        checkout.reset_destination()?;
        let repo = Self::open_repo(checkout.repo, checkout.operation)?;
        let options = ::ostree::RepoCheckoutAtOptions {
            mode: ::ostree::RepoCheckoutMode::User,
            overwrite_mode: ::ostree::RepoCheckoutOverwriteMode::None,
            ..Default::default()
        };
        repo.checkout_at(
            Some(&options),
            ::ostree::AT_FDCWD,
            checkout.destination,
            checkout.ref_name,
            ::ostree::gio::Cancellable::NONE,
        )
        .map_err(|error| checkout.error(error))
    }

    fn list_refs(&self, repo_path: &Path) -> Result<Vec<String>> {
        let repo = Self::open_repo(repo_path, "list promotion refs")?;
        let mut refs = repo
            .list_refs(None, ::ostree::gio::Cancellable::NONE)
            .map_err(|error| {
                OstreeCommandFailedSnafu {
                    repo: repo_path.to_path_buf(),
                    operation: "list promotion refs",
                    code: None,
                    stderr: error.to_string(),
                }
                .build()
            })?
            .into_keys()
            .collect::<Vec<_>>();
        refs.sort();
        Ok(refs)
    }
}

impl SystemOstreeRepository {
    fn open_repo(repo_path: &Path, operation: &'static str) -> Result<::ostree::Repo> {
        let repo = ::ostree::Repo::new_for_path(repo_path);
        repo.open(::ostree::gio::Cancellable::NONE)
            .map_err(|source| {
                std::io::Error::other(format!("libostree {operation} failed: {source}"))
            })
            .context(StartOstreeSnafu {
                repo: repo_path.to_path_buf(),
            })?;
        Ok(repo)
    }
}

pub(crate) struct OstreeTreeCommit<'a> {
    repo: &'a Path,
    ref_name: &'a str,
    tree: &'a Path,
    operation: &'static str,
    subject: &'a str,
}

impl<'a> OstreeTreeCommit<'a> {
    pub(crate) const fn new(
        repo: &'a Path,
        ref_name: &'a str,
        tree: &'a Path,
        operation: &'static str,
        subject: &'a str,
    ) -> Self {
        Self {
            repo,
            ref_name,
            tree,
            operation,
            subject,
        }
    }

    pub(crate) fn commit(&self, repository: &impl OstreeRepository) -> Result<()> {
        repository.commit_tree(self)
    }

    #[cfg(test)]
    pub(crate) const fn repo(&self) -> &Path {
        self.repo
    }

    #[cfg(test)]
    pub(crate) const fn ref_name(&self) -> &str {
        self.ref_name
    }

    #[cfg(test)]
    pub(crate) const fn tree(&self) -> &Path {
        self.tree
    }

    #[cfg(test)]
    pub(crate) const fn operation(&self) -> &'static str {
        self.operation
    }

    #[cfg(test)]
    pub(crate) const fn subject(&self) -> &str {
        self.subject
    }

    fn error(&self, source: impl ToString) -> crate::FilesystemError {
        OstreeCommandFailedSnafu {
            repo: self.repo.to_path_buf(),
            operation: self.operation,
            code: None,
            stderr: source.to_string(),
        }
        .build()
    }
}

pub(crate) struct OstreeTreeCheckout<'a> {
    repo: &'a Path,
    ref_name: &'a str,
    destination: &'a Path,
    operation: &'static str,
}

impl<'a> OstreeTreeCheckout<'a> {
    pub(crate) const fn new(
        repo: &'a Path,
        ref_name: &'a str,
        destination: &'a Path,
        operation: &'static str,
    ) -> Self {
        Self {
            repo,
            ref_name,
            destination,
            operation,
        }
    }

    pub(crate) fn checkout(&self, repository: &impl OstreeRepository) -> Result<()> {
        repository.checkout_tree(self)
    }

    #[cfg(test)]
    pub(crate) const fn repo(&self) -> &Path {
        self.repo
    }

    #[cfg(test)]
    pub(crate) const fn ref_name(&self) -> &str {
        self.ref_name
    }

    #[cfg(test)]
    pub(crate) const fn destination(&self) -> &Path {
        self.destination
    }

    #[cfg(test)]
    pub(crate) const fn operation(&self) -> &'static str {
        self.operation
    }

    fn reset_destination(&self) -> Result<()> {
        if self.destination.exists() {
            fs::remove_dir_all(self.destination).context(PromotionIoSnafu {
                action: "remove ostree checkout destination",
                path: self.destination,
            })?;
        }
        let parent = self
            .destination
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        fs::create_dir_all(&parent).context(PromotionIoSnafu {
            action: "create ostree checkout parent",
            path: parent.as_path(),
        })
    }

    fn error(&self, source: impl ToString) -> crate::FilesystemError {
        OstreeCommandFailedSnafu {
            repo: self.repo.to_path_buf(),
            operation: self.operation,
            code: None,
            stderr: source.to_string(),
        }
        .build()
    }
}
