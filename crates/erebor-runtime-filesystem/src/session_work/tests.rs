use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    error::FilesystemError,
    ostree::{OstreePruneSummary, OstreeRepository, OstreeTreeCheckout, OstreeTreeCommit},
    session_work::{
        FilesystemSessionWorkCatalog, FilesystemSessionWorkCommitRequest,
        FilesystemSessionWorkCommitter, FilesystemSessionWorkRename, FilesystemSessionWorkRollback,
    },
    storage::FilesystemStoragePreparer,
    FilesystemSessionStorage, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn commits_user_and_autocommit_session_work_with_lineage() -> TestResult {
    let fixture = Fixture::new()?;
    let repository = FakeOstreeRepository::new();
    fs::write(fixture.upper().join("first.txt"), "one\n")?;

    let mut user = FilesystemSessionWorkCommitRequest::user("session-1")?;
    user.set_name("first useful work")?;
    let first = FilesystemSessionWorkCommitter::commit_using_repository(
        &fixture.storage,
        user,
        &repository,
    )?;

    fs::write(fixture.upper().join("second.txt"), "two\n")?;
    let mut autocommit =
        FilesystemSessionWorkCommitRequest::autocommit("session-1", "session_finish")?;
    autocommit.set_action_request_id("action-2")?;
    let second = FilesystemSessionWorkCommitter::commit_using_repository(
        &fixture.storage,
        autocommit,
        &repository,
    )?;

    assert_eq!(first.handle(), "work@{0}");
    assert_eq!(first.transaction_id(), "session-1.work-000001");
    assert_eq!(second.transaction_id(), "session-1.work-000002");
    assert!(second
        .manifest_ref()
        .ends_with("/session-1.work-000002/manifest"));
    let catalog = FilesystemSessionWorkCatalog::load_using_repository(
        &fixture.storage,
        "session-1",
        &repository,
    )?;
    assert_eq!(catalog.transactions().len(), 2);
    assert_eq!(catalog.transactions()[0].handle(), "work@{0}");
    assert_eq!(catalog.transactions()[0].source(), "autocommit");
    assert_eq!(catalog.transactions()[1].name(), Some("first useful work"));
    assert_eq!(
        catalog.transactions()[1].state(),
        crate::FilesystemSessionWorkTransactionState::Available
    );

    FilesystemSessionWorkRename::rename_using_repository(
        &fixture.storage,
        "session-1",
        "work@{0}",
        "auto",
        &repository,
    )?;
    let renamed = FilesystemSessionWorkCatalog::load_using_repository(
        &fixture.storage,
        "session-1",
        &repository,
    )?;
    assert_eq!(renamed.transactions()[0].name(), Some("auto"));
    Ok(())
}

#[test]
fn rollback_restores_selected_session_work_upperdir() -> TestResult {
    let fixture = Fixture::new()?;
    let repository = FakeOstreeRepository::new();
    fs::write(fixture.upper().join("settings.txt"), "light\n")?;
    FilesystemSessionWorkCommitter::commit_using_repository(
        &fixture.storage,
        FilesystemSessionWorkCommitRequest::user("session-1")?,
        &repository,
    )?;
    fs::write(fixture.upper().join("settings.txt"), "dark\n")?;
    fs::write(fixture.upper().join("generated.txt"), "token\n")?;
    FilesystemSessionWorkCommitter::commit_using_repository(
        &fixture.storage,
        FilesystemSessionWorkCommitRequest::user("session-1")?,
        &repository,
    )?;

    let rollback = FilesystemSessionWorkRollback::rollback_using_repository(
        &fixture.storage,
        "session-1",
        "work@{1}",
        &repository,
    )?;

    assert_eq!(rollback.restored_volumes(), &[String::from("project")]);
    assert_eq!(
        fs::read_to_string(fixture.upper().join("settings.txt"))?,
        "light\n"
    );
    assert!(!fixture.upper().join("generated.txt").exists());
    let catalog = FilesystemSessionWorkCatalog::load_using_repository(
        &fixture.storage,
        "session-1",
        &repository,
    )?;
    assert_eq!(
        catalog.transactions()[1].state(),
        crate::FilesystemSessionWorkTransactionState::Current
    );
    Ok(())
}

#[test]
fn active_writer_refuses_session_work_commit() -> TestResult {
    let fixture = Fixture::new()?;
    let repository = FakeOstreeRepository::new();
    let _writer = fs::File::create(fixture.upper().join("live.txt"))?;

    let result = FilesystemSessionWorkCommitter::commit_using_repository(
        &fixture.storage,
        FilesystemSessionWorkCommitRequest::user("session-1")?,
        &repository,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::ActiveLayerWriter { .. })
    ));
    assert!(repository.refs.borrow().is_empty());
    Ok(())
}

struct Fixture {
    storage: FilesystemSessionStorage,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "erebor-session-work-test-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        let host = root.join("host/project");
        let session = root.join("workspace/project");
        fs::create_dir_all(&host)?;
        fs::create_dir_all(&session)?;
        let request = FilesystemVolumeStorageRequest::new(
            "project",
            host,
            session,
            FilesystemVolumeMode::Writable,
        )?;
        let storage = FilesystemStoragePreparer::new(&root.join("session"), vec![request])
            .prepare(|_| Ok(()))?;
        Ok(Self { storage, root })
    }

    fn upper(&self) -> &Path {
        self.storage.volumes()[0].overlay().upper_path()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

struct FakeOstreeRepository {
    refs: RefCell<Vec<String>>,
    root: PathBuf,
}

impl FakeOstreeRepository {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "erebor-session-work-fake-ostree-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        Self {
            refs: RefCell::new(Vec::new()),
            root,
        }
    }

    fn commit_path(&self, ref_name: &str) -> PathBuf {
        self.root.join("commits").join(ref_name)
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
        if !self
            .refs
            .borrow()
            .iter()
            .any(|value| value == commit.ref_name())
        {
            self.refs.borrow_mut().push(commit.ref_name().to_owned());
        }
        CopyTree::new(commit.tree(), self.commit_path(commit.ref_name())).copy()
    }

    fn checkout_tree(&self, checkout: &OstreeTreeCheckout<'_>) -> crate::Result<()> {
        CopyTree::new(
            self.commit_path(checkout.ref_name()),
            checkout.destination(),
        )
        .copy()
    }

    fn list_refs(&self, _repo: &Path) -> crate::Result<Vec<String>> {
        Ok(self.refs.borrow().clone())
    }

    fn delete_ref(&self, _repo: &Path, ref_name: &str) -> crate::Result<()> {
        self.refs.borrow_mut().retain(|value| value != ref_name);
        Ok(())
    }

    fn prune(&self, _repo: &Path) -> crate::Result<OstreePruneSummary> {
        Ok(OstreePruneSummary::new(0, 0, 0))
    }
}

struct CopyTree {
    source: PathBuf,
    target: PathBuf,
}

impl CopyTree {
    fn new(source: impl Into<PathBuf>, target: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }

    fn copy(&self) -> crate::Result<()> {
        if self.target.exists() {
            fs::remove_dir_all(&self.target).map_err(crate::FilesystemError::from_test_io)?;
        }
        fs::create_dir_all(&self.target).map_err(crate::FilesystemError::from_test_io)?;
        for entry in fs::read_dir(&self.source).map_err(crate::FilesystemError::from_test_io)? {
            let entry = entry.map_err(crate::FilesystemError::from_test_io)?;
            CopyTreeEntry::new(entry.path(), self.target.join(entry.file_name())).copy()?;
        }
        Ok(())
    }
}

struct CopyTreeEntry {
    source: PathBuf,
    target: PathBuf,
}

impl CopyTreeEntry {
    const fn new(source: PathBuf, target: PathBuf) -> Self {
        Self { source, target }
    }

    fn copy(&self) -> crate::Result<()> {
        let metadata =
            fs::symlink_metadata(&self.source).map_err(crate::FilesystemError::from_test_io)?;
        if metadata.is_dir() {
            CopyTree::new(&self.source, &self.target).copy()
        } else if metadata.is_file() {
            fs::copy(&self.source, &self.target).map_err(crate::FilesystemError::from_test_io)?;
            Ok(())
        } else if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(
                fs::read_link(&self.source).map_err(crate::FilesystemError::from_test_io)?,
                &self.target,
            )
            .map_err(crate::FilesystemError::from_test_io)
        } else {
            Ok(())
        }
    }
}

trait TestIoError {
    fn from_test_io(source: std::io::Error) -> Self;
}

impl TestIoError for FilesystemError {
    fn from_test_io(source: std::io::Error) -> Self {
        FilesystemError::SessionWorkIo {
            action: "copy fake ostree tree",
            path: PathBuf::from("<test>"),
            source,
            location: snafu::Location::default(),
        }
    }
}
