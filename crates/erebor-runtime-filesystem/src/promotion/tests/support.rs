use std::{
    cell::RefCell,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use crate::ostree::OstreePruneSummary;
use crate::{
    checkpoint::FilesystemCheckpointCommit,
    metadata::FilesystemPathMetadataCopier,
    ostree::{OstreeRepository, OstreeTreeCheckout, OstreeTreeCommit},
    promotion::{
        FilesystemPromotion, FilesystemPromotionOptions, PromotionHook, PromotionWorkflow,
    },
    storage::FilesystemStoragePreparer,
    FilesystemError, FilesystemLayerManifest, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) struct Fixture {
    pub storage: crate::FilesystemSessionStorage,
    root: PathBuf,
    host_path: PathBuf,
}

impl Fixture {
    pub(super) fn upper(&self) -> &Path {
        self.storage.volumes()[0].overlay().upper_path()
    }

    pub(super) fn host(&self) -> &Path {
        &self.host_path
    }

    pub(super) fn seed_host(&self, relative: &str, source: &str) -> TestResult {
        let path = self.host_path.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("seed path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(path, source)?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

pub(super) fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "erebor-filesystem-promotion-{}-{}",
        std::process::id(),
        nonce()
    ));
    let _result = fs::remove_dir_all(&root);
    let host_path = root.join("host/project");
    let session_path = root.join("workspace/project");
    fs::create_dir_all(&host_path)?;
    fs::create_dir_all(&session_path)?;
    let request = FilesystemVolumeStorageRequest::new(
        "project",
        &host_path,
        &session_path,
        FilesystemVolumeMode::Writable,
    )?;
    let storage =
        FilesystemStoragePreparer::new(&root.join("session"), vec![request]).prepare(|_| Ok(()))?;
    Ok(Fixture {
        storage,
        root,
        host_path,
    })
}

pub(super) fn commit_checkpoint(
    fixture: &Fixture,
    manifests: &[FilesystemLayerManifest],
    repository: &FakeOstreeRepository,
) -> crate::Result<()> {
    FilesystemCheckpointCommit::commit_normalized_using_repository(
        &fixture.storage,
        "session-1",
        manifests,
        repository,
    )?;
    Ok(())
}

pub(super) struct PromotionTestWorkflow<'a, H>
where
    H: PromotionHook,
{
    storage: &'a FilesystemSessionStorage,
    manifests: &'a [FilesystemLayerManifest],
    options: FilesystemPromotionOptions,
    repository: &'a FakeOstreeRepository,
    hook: &'a H,
}

impl<'a, H> PromotionTestWorkflow<'a, H>
where
    H: PromotionHook,
{
    pub(super) fn new(
        storage: &'a FilesystemSessionStorage,
        manifests: &'a [FilesystemLayerManifest],
        options: FilesystemPromotionOptions,
        repository: &'a FakeOstreeRepository,
        hook: &'a H,
    ) -> Self {
        Self {
            storage,
            manifests,
            options,
            repository,
            hook,
        }
    }

    pub(super) fn promote(&self) -> crate::Result<FilesystemPromotion> {
        PromotionWorkflow::new(
            self.storage,
            "session-1",
            "erebor/checkpoints/session-1/manifest",
            self.manifests,
            self.options,
            self.repository,
            self.hook,
        )
        .promote()
    }
}

fn nonce() -> u64 {
    static NEXT_NONCE: AtomicU64 = AtomicU64::new(0);

    NEXT_NONCE.fetch_add(1, Ordering::Relaxed)
}

#[test]
fn temporary_path_nonces_are_unique_under_parallel_allocation() -> TestResult {
    let values = std::thread::scope(|scope| {
        let handles = (0..16)
            .map(|_| scope.spawn(|| (0..256).map(|_| nonce()).collect::<Vec<_>>()))
            .collect::<Vec<_>>();

        handles
            .into_iter()
            .try_fold(Vec::new(), |mut values, handle| {
                values.extend(
                    handle
                        .join()
                        .map_err(|_| std::io::Error::other("nonce worker panicked"))?,
                );
                Ok::<_, std::io::Error>(values)
            })
    })?;
    let unique = values
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(values.len(), unique.len());
    Ok(())
}

pub(super) struct FakeOstreeRepository {
    pub commands: RefCell<Vec<Vec<String>>>,
    outcomes: RefCell<Vec<FakeOstreeOutcome>>,
    refs: RefCell<Vec<String>>,
    root: PathBuf,
}

impl FakeOstreeRepository {
    pub(super) fn successful() -> Self {
        Self::from_outcomes(Vec::new())
    }

    pub(super) fn from_outcomes(outcomes: Vec<FakeOstreeOutcome>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "erebor-fake-ostree-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        Self {
            commands: RefCell::new(Vec::new()),
            outcomes: RefCell::new(outcomes),
            refs: RefCell::new(Vec::new()),
            root,
        }
    }

    fn commit_path(&self, ref_name: &str) -> PathBuf {
        self.root.join("commits").join(ref_name)
    }

    pub(super) fn committed_tree(&self, ref_name: &str) -> PathBuf {
        self.commit_path(ref_name)
    }

    pub(super) fn forget_ref(&self, ref_name: &str) {
        self.refs
            .borrow_mut()
            .retain(|existing| existing != ref_name);
    }

    fn next_outcome(&self) -> FakeOstreeOutcome {
        let mut outcomes = self.outcomes.borrow_mut();
        if outcomes.is_empty() {
            FakeOstreeOutcome::success()
        } else {
            outcomes.remove(0)
        }
    }

    fn record_commit(&self, commit: &OstreeTreeCommit<'_>) {
        self.commands.borrow_mut().push(vec![
            String::from("commit"),
            format!("--branch={}", commit.ref_name()),
            format!("--tree=dir={}", commit.tree().display()),
            format!("--subject={}", commit.subject()),
        ]);
    }

    fn mirror_commit(&self, commit: &OstreeTreeCommit<'_>) -> crate::Result<()> {
        let mut refs = self.refs.borrow_mut();
        if !refs.iter().any(|existing| existing == commit.ref_name()) {
            refs.push(commit.ref_name().to_owned());
        }
        copy_tree(commit.tree(), &self.commit_path(commit.ref_name()))
    }

    fn record_checkout(&self, checkout: &OstreeTreeCheckout<'_>) {
        self.commands.borrow_mut().push(vec![
            String::from("checkout"),
            String::from("--user-mode"),
            checkout.ref_name().to_owned(),
            checkout.destination().display().to_string(),
        ]);
    }

    fn record_delete_ref(&self, repo: &Path, ref_name: &str) {
        self.commands.borrow_mut().push(vec![
            String::from("delete-ref"),
            format!("--repo={}", repo.display()),
            ref_name.to_owned(),
        ]);
    }

    fn record_prune(&self, repo: &Path) {
        self.commands.borrow_mut().push(vec![
            String::from("prune"),
            format!("--repo={}", repo.display()),
        ]);
    }

    fn mirror_checkout(&self, checkout: &OstreeTreeCheckout<'_>) -> crate::Result<()> {
        copy_tree(
            &self.commit_path(checkout.ref_name()),
            checkout.destination(),
        )
    }

    fn failure(
        repo: &Path,
        operation: &'static str,
        outcome: FakeOstreeOutcome,
    ) -> FilesystemError {
        FilesystemError::OstreeCommandFailed {
            repo: repo.to_path_buf(),
            operation,
            code: outcome.code,
            stderr: outcome.stderr,
            location: snafu::Location::default(),
        }
    }
}

impl Drop for FakeOstreeRepository {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

impl OstreeRepository for FakeOstreeRepository {
    fn initialize(&self, _repo: &Path) -> crate::Result<()> {
        Ok(())
    }

    fn commit_tree(&self, commit: &OstreeTreeCommit<'_>) -> crate::Result<()> {
        self.record_commit(commit);
        let outcome = self.next_outcome();
        if outcome.success {
            self.mirror_commit(commit)
        } else {
            Err(Self::failure(commit.repo(), commit.operation(), outcome))
        }
    }

    fn checkout_tree(&self, checkout: &OstreeTreeCheckout<'_>) -> crate::Result<()> {
        self.record_checkout(checkout);
        let outcome = self.next_outcome();
        if outcome.success {
            self.mirror_checkout(checkout)
        } else {
            Err(Self::failure(
                checkout.repo(),
                checkout.operation(),
                outcome,
            ))
        }
    }

    fn list_refs(&self, _repo: &Path) -> crate::Result<Vec<String>> {
        let mut refs = self.refs.borrow().clone();
        refs.sort();
        Ok(refs)
    }

    fn delete_ref(&self, repo: &Path, ref_name: &str) -> crate::Result<()> {
        self.record_delete_ref(repo, ref_name);
        let outcome = self.next_outcome();
        if !outcome.success {
            return Err(Self::failure(repo, "delete retained ref", outcome));
        }
        self.refs
            .borrow_mut()
            .retain(|existing| existing != ref_name);
        let commit_path = self.commit_path(ref_name);
        if commit_path.exists() {
            fs::remove_dir_all(&commit_path)
                .map_err(|error| test_io_source("remove fake ref tree", &commit_path, error))?;
        }
        Ok(())
    }

    fn prune(&self, repo: &Path) -> crate::Result<OstreePruneSummary> {
        self.record_prune(repo);
        let outcome = self.next_outcome();
        if outcome.success {
            Ok(OstreePruneSummary::new(0, 0, 0))
        } else {
            Err(Self::failure(repo, "prune retained objects", outcome))
        }
    }
}

#[derive(Clone)]
pub(super) struct FakeOstreeOutcome {
    success: bool,
    code: Option<i32>,
    stderr: String,
}

impl FakeOstreeOutcome {
    pub(super) fn success() -> Self {
        Self {
            success: true,
            code: Some(0),
            stderr: String::new(),
        }
    }

    pub(super) fn failed(code: Option<i32>, stderr: &str) -> Self {
        Self {
            success: false,
            code,
            stderr: stderr.to_owned(),
        }
    }
}

fn copy_tree(source: &Path, target: &Path) -> crate::Result<()> {
    if target.exists() {
        fs::remove_dir_all(target)
            .map_err(|error| test_io_source("remove fake tree", target, error))?;
    }
    fs::create_dir_all(target)
        .map_err(|error| test_io_source("create fake tree", target, error))?;
    for entry in
        fs::read_dir(source).map_err(|error| test_io_source("read fake tree", source, error))?
    {
        let entry = entry.map_err(|error| test_io_source("read fake tree entry", source, error))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|source| test_io_source("inspect fake tree", &source_path, source))?;
        if metadata.is_dir() {
            copy_tree(&source_path, &target_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &target_path)
                .map_err(|source| test_io_source("copy fake tree file", &source_path, source))?;
            FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
        } else if metadata.file_type().is_symlink() {
            let link = fs::read_link(&source_path)
                .map_err(|source| test_io_source("read fake tree symlink", &source_path, source))?;
            symlink(link, &target_path)
                .map_err(|source| test_io_source("copy fake tree symlink", &target_path, source))?;
            FilesystemPathMetadataCopier::new(&source_path, &target_path).copy()?;
        }
    }
    FilesystemPathMetadataCopier::new(source, target).copy()
}

fn test_io_source(action: &'static str, path: &Path, source: std::io::Error) -> FilesystemError {
    FilesystemError::PromotionIo {
        action,
        path: path.to_path_buf(),
        source,
        location: snafu::Location::default(),
    }
}
