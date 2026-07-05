use std::{cell::RefCell, fs, path::PathBuf};

use crate::{
    checkpoint::{
        checkpoint_manifest_ref, commit_normalized_session_checkpoint_with_runner,
        volume_layer_ref, FilesystemCheckpointManifest,
    },
    normalizer::normalize_session_layers,
    ostree::{OstreeCommandOutput, OstreeCommandRunner},
    storage::prepare_with_initializer,
    FilesystemError, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn checkpoint_refs_are_hierarchical_and_do_not_create_base_ref() -> TestResult {
    assert_eq!(
        checkpoint_manifest_ref("session-1")?,
        "erebor/checkpoints/session-1/manifest"
    );
    assert_eq!(
        volume_layer_ref("session-1", "project")?,
        "erebor/checkpoints/session-1/volumes/project/layer"
    );
    assert!(matches!(
        checkpoint_manifest_ref("bad/id"),
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
    fs::create_dir_all(fixture.upper().join("generated"))?;
    fs::write(fixture.upper().join("generated/token.txt"), "token\n")?;
    fs::write(fixture.upper().join(".wh.old-cache.txt"), "")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();

    let commit = commit_normalized_session_checkpoint_with_runner(
        &fixture.storage,
        "session-1",
        &manifests,
        &runner,
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
    assert!(layer_stage.join("erebor-layer.json").is_file());
    assert!(!storage_tree_contains_file_named(
        &layer_stage,
        ".wh.old-cache.txt"
    )?);
    let manifest: FilesystemCheckpointManifest =
        serde_json::from_str(&fs::read_to_string(commit.manifest_path())?)?;
    assert_eq!(manifest.checkpoint_id, "session-1");
    assert_eq!(manifest.volumes[0].layer_ref, commit.volumes()[0].layer_ref);
    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().flatten().all(|arg| !arg.contains("/base")));
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
fn ostree_command_failure_is_typed() -> TestResult {
    let fixture = fixture()?;
    fs::write(fixture.upper().join("settings.json"), "changed\n")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::with_outputs(vec![OstreeCommandOutput::new(
        false,
        Some(42),
        "commit failed",
    )]);

    let result = commit_normalized_session_checkpoint_with_runner(
        &fixture.storage,
        "session-1",
        &manifests,
        &runner,
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
        "erebor-filesystem-checkpoint-{}",
        std::process::id()
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
    let storage = prepare_with_initializer(&root.join("session"), vec![request], |_| Ok(()))?;
    Ok(Fixture {
        storage,
        root,
        host_path,
    })
}

fn storage_tree_contains_file_named(
    root: &std::path::Path,
    name: &str,
) -> Result<bool, std::io::Error> {
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

struct FakeOstreeRunner {
    commands: RefCell<Vec<Vec<String>>>,
    outputs: RefCell<Vec<OstreeCommandOutput>>,
}

impl FakeOstreeRunner {
    fn successful() -> Self {
        Self::with_outputs(Vec::new())
    }

    fn with_outputs(outputs: Vec<OstreeCommandOutput>) -> Self {
        Self {
            commands: RefCell::new(Vec::new()),
            outputs: RefCell::new(outputs),
        }
    }
}

impl OstreeCommandRunner for FakeOstreeRunner {
    fn run(&self, _repo: &std::path::Path, args: &[String]) -> crate::Result<OstreeCommandOutput> {
        self.commands.borrow_mut().push(args.to_owned());
        let mut outputs = self.outputs.borrow_mut();
        if outputs.is_empty() {
            Ok(OstreeCommandOutput::new(true, Some(0), ""))
        } else {
            Ok(outputs.remove(0))
        }
    }
}
