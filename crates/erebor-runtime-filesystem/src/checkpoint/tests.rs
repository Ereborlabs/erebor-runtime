use std::{
    cell::RefCell,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

use crate::{
    checkpoint::{CheckpointId, FilesystemCheckpointCommit, FilesystemCheckpointManifest},
    manifest::{FilesystemLayerManifest, LAYER_MANIFEST_FILE},
    ostree::{OstreeRepository, OstreeTreeCheckout, OstreeTreeCommit},
    storage::FilesystemStoragePreparer,
    FilesystemError, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};
use rustix::fs::{lsetxattr, XattrFlags};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn checkpoint_refs_are_hierarchical_and_do_not_create_base_ref() -> TestResult {
    assert_eq!(
        CheckpointId::new("session-1")?.manifest_ref(),
        "erebor/checkpoints/session-1/manifest"
    );
    assert_eq!(
        CheckpointId::new("session-1")?.volume_layer_ref("project"),
        "erebor/checkpoints/session-1/volumes/project/layer"
    );
    assert!(matches!(
        CheckpointId::new("bad/id").map(CheckpointId::manifest_ref),
        Err(FilesystemError::InvalidCheckpointId { .. })
    ));
    Ok(())
}

#[test]
fn stages_layer_content_and_commits_checkpoint_refs() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_lower("settings.json", "{\"theme\":\"light\"}\n")?;
    fixture.seed_lower("old-cache.txt", "old\n")?;
    fs::write(
        fixture.upper().join("settings.json"),
        "{\"theme\":\"dark\"}\n",
    )?;
    set_existing_marker(fixture.upper().join("settings.json"), "user.overlay.origin")?;
    fs::create_dir_all(fixture.upper().join("generated"))?;
    fs::write(fixture.upper().join("generated/token.txt"), "token\n")?;
    symlink(
        "generated/token.txt",
        fixture.upper().join("generated-token-shortcut"),
    )?;
    fs::write(fixture.upper().join(".wh.old-cache.txt"), "")?;
    let manifests = fixture.storage.normalize_layers()?;
    let repository = FakeOstreeRepository::successful();

    let commit = FilesystemCheckpointCommit::commit_normalized_using_repository(
        &fixture.storage,
        "session-1",
        &manifests,
        &repository,
    )?;

    assert_eq!(commit.checkpoint_id(), "session-1");
    assert_eq!(
        commit.checkpoint_ref(),
        "erebor/checkpoints/session-1/manifest"
    );
    assert_eq!(commit.volumes()[0].volume_id, "project");
    assert_eq!(
        commit.volumes()[0].layer_ref,
        "erebor/checkpoints/session-1/volumes/project/layer"
    );
    let layer_stage = fixture
        .storage
        .work_path()
        .join("checkpoints/session-1/volumes/project/layer");
    assert_eq!(
        fs::read_to_string(layer_stage.join("files/settings.json"))?,
        "{\"theme\":\"dark\"}\n"
    );
    assert_eq!(
        fs::read_to_string(layer_stage.join("files/generated/token.txt"))?,
        "token\n"
    );
    assert_eq!(
        fs::read_link(layer_stage.join("files/generated-token-shortcut"))?,
        PathBuf::from("generated/token.txt")
    );
    assert!(layer_stage.join("erebor-layer.json").is_file());
    let layer_manifest: FilesystemLayerManifest =
        serde_json::from_str(&fs::read_to_string(layer_stage.join(LAYER_MANIFEST_FILE))?)?;
    assert!(layer_manifest.metadata_sidecars.iter().any(|sidecar| {
        sidecar.path == "settings.json" && sidecar.name == "user.overlay.origin"
    }));
    assert!(!storage_tree_contains_file_named(
        &layer_stage,
        ".wh.old-cache.txt"
    )?);
    let manifest: FilesystemCheckpointManifest =
        serde_json::from_str(&fs::read_to_string(commit.manifest_path())?)?;
    assert_eq!(manifest.checkpoint_id, "session-1");
    assert_eq!(manifest.volumes[0].layer_ref, commit.volumes()[0].layer_ref);
    let commands = repository.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().flatten().all(|arg| !arg.contains("/base")));
    let layer_stage_arg = format!("--tree=dir={}", layer_stage.display());
    assert!(commands
        .iter()
        .any(|args| args.iter().any(|arg| arg == &layer_stage_arg)));
    assert!(commands.iter().any(|args| {
        args.iter()
            .any(|arg| arg == "--branch=erebor/checkpoints/session-1/volumes/project/layer")
    }));
    assert!(commands.iter().any(|args| {
        args.iter()
            .any(|arg| arg == "--branch=erebor/checkpoints/session-1/manifest")
    }));
    Ok(())
}

#[test]
fn layer_commit_failure_is_typed() -> TestResult {
    let fixture = fixture()?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let repository = FakeOstreeRepository::from_outcomes(vec![FakeOstreeOutcome::failed(
        Some(42),
        "commit failed",
    )]);

    let result = FilesystemCheckpointCommit::commit_normalized_using_repository(
        &fixture.storage,
        "session-1",
        &manifests,
        &repository,
    );

    match result {
        Err(FilesystemError::OstreeCommandFailed {
            operation,
            code,
            stderr,
            ..
        }) => {
            assert_eq!(operation, "commit checkpoint layer");
            assert_eq!(code, Some(42));
            assert_eq!(stderr, "commit failed");
        }
        other => return Err(format!("expected ostree command failure, got {other:?}").into()),
    }
    Ok(())
}

#[test]
fn manifest_commit_failure_is_typed() -> TestResult {
    let fixture = fixture()?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let repository = FakeOstreeRepository::from_outcomes(vec![
        FakeOstreeOutcome::success(),
        FakeOstreeOutcome::failed(Some(43), "manifest commit failed"),
    ]);

    let result = FilesystemCheckpointCommit::commit_normalized_using_repository(
        &fixture.storage,
        "session-1",
        &manifests,
        &repository,
    );

    match result {
        Err(FilesystemError::OstreeCommandFailed {
            operation,
            code,
            stderr,
            ..
        }) => {
            assert_eq!(operation, "commit checkpoint manifest");
            assert_eq!(code, Some(43));
            assert_eq!(stderr, "manifest commit failed");
        }
        other => return Err(format!("expected manifest commit failure, got {other:?}").into()),
    }
    Ok(())
}

struct Fixture {
    storage: crate::FilesystemSessionStorage,
    root: PathBuf,
    host_path: PathBuf,
}

impl Fixture {
    fn upper(&self) -> &std::path::Path {
        self.storage.volumes()[0].overlay().upper_path()
    }

    fn seed_lower(&self, relative: &str, source: &str) -> TestResult {
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

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "erebor-filesystem-checkpoint-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
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

fn set_existing_marker(path: PathBuf, name: &str) -> TestResult {
    lsetxattr(&path, name, b"y", XattrFlags::empty()).map_err(std::io::Error::from)?;
    Ok(())
}

fn storage_tree_contains_file_named(root: &Path, name: &str) -> Result<bool, std::io::Error> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() && storage_tree_contains_file_named(&path, name)? {
            return Ok(true);
        }
        if path.file_name().is_some_and(|file_name| file_name == name) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct FakeOstreeRepository {
    commands: RefCell<Vec<Vec<String>>>,
    outcomes: RefCell<Vec<FakeOstreeOutcome>>,
}

impl FakeOstreeRepository {
    fn successful() -> Self {
        Self::from_outcomes(Vec::new())
    }

    fn from_outcomes(outcomes: Vec<FakeOstreeOutcome>) -> Self {
        Self {
            commands: RefCell::new(Vec::new()),
            outcomes: RefCell::new(outcomes),
        }
    }

    fn next_outcome(&self) -> FakeOstreeOutcome {
        let mut outcomes = self.outcomes.borrow_mut();
        if outcomes.is_empty() {
            FakeOstreeOutcome::success()
        } else {
            outcomes.remove(0)
        }
    }
}

impl OstreeRepository for FakeOstreeRepository {
    fn initialize(&self, _repo: &Path) -> crate::Result<()> {
        Ok(())
    }

    fn commit_tree(&self, commit: &OstreeTreeCommit<'_>) -> crate::Result<()> {
        self.commands.borrow_mut().push(vec![
            String::from("commit"),
            format!("--branch={}", commit.ref_name()),
            format!("--tree=dir={}", commit.tree().display()),
            format!("--subject={}", commit.subject()),
        ]);
        let outcome = self.next_outcome();
        if outcome.success {
            Ok(())
        } else {
            Err(FilesystemError::OstreeCommandFailed {
                repo: commit.repo().to_path_buf(),
                operation: commit.operation(),
                code: outcome.code,
                stderr: outcome.stderr,
                location: snafu::Location::default(),
            })
        }
    }

    fn checkout_tree(&self, _checkout: &OstreeTreeCheckout<'_>) -> crate::Result<()> {
        Ok(())
    }

    fn list_refs(&self, _repo: &Path) -> crate::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct FakeOstreeOutcome {
    success: bool,
    code: Option<i32>,
    stderr: String,
}

impl FakeOstreeOutcome {
    fn success() -> Self {
        Self {
            success: true,
            code: Some(0),
            stderr: String::new(),
        }
    }

    fn failed(code: Option<i32>, stderr: &str) -> Self {
        Self {
            success: false,
            code,
            stderr: stderr.to_owned(),
        }
    }
}
