use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use crate::{
    metadata::FilesystemMetadataReader,
    ostree::OstreeTreeCommit,
    promotion::{
        ids::PromotionId, io::PromotionManifestStore, FilesystemPromotionManifest,
        FilesystemPromotionOptions, FilesystemPromotionState, FilesystemPromotionVolume,
        FilesystemRollback, PREIMAGE_MANIFEST_FILE,
    },
    FilesystemError, FilesystemHostMetadata, FilesystemPreimageBackendKind,
    FilesystemPreimageEntry, FilesystemPreimageEntryState, FilesystemPreimageEntryType,
    FilesystemPreimageManifest, FilesystemRegularPreimage,
};

use super::{
    support::{
        commit_checkpoint, fixture, FakeOstreeRepository, PromotionTestWorkflow, TestResult,
    },
    NoopHook,
};

#[test]
fn large_preimage_blocks_without_reflink_before_host_mutation() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_host("large.bin", &large_text("original"))?;
    fs::write(fixture.upper().join("large.bin"), large_text("changed"))?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    let result = PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::new(16),
        &runner,
        &NoopHook,
    )
    .promote();

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionPreimageTooLarge { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("original")
    );
    Ok(())
}

#[test]
fn large_preimage_uses_reflink_artifact_when_supported() -> TestResult {
    let fixture = fixture()?;
    if !ReflinkProbe::new(fixture.storage.work_path()).supported()? {
        return Ok(());
    }
    fixture.seed_host("large.bin", &large_text("original"))?;
    fs::write(fixture.upper().join("large.bin"), large_text("changed"))?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::from_parts(16, FilesystemPreimageBackendKind::LinuxReflink),
        &runner,
        &NoopHook,
    )
    .promote()?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("changed")
    );
    let preimage = preimage_manifest(&fixture)?;
    assert_eq!(preimage.total_bytes, 0);
    let artifact = regular_reflink_artifact(&preimage, "large.bin")?;
    assert!(fixture.storage.work_path().join(artifact).is_file());
    assert!(!fixture
        .storage
        .work_path()
        .join("promotions/session-1/volumes/project/preimage/files/large.bin")
        .exists());
    let committed_preimage = runner
        .committed_tree("erebor/promotions/session-1/volumes/project/preimage")
        .join("files/large.bin");
    assert!(!committed_preimage.exists());

    fs::remove_dir_all(fixture.storage.work_path().join("promotions/session-1"))?;
    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;
    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("original")
    );
    Ok(())
}

#[test]
fn reflink_artifact_drift_blocks_rollback_before_host_mutation() -> TestResult {
    let fixture = fixture()?;
    if !ReflinkProbe::new(fixture.storage.work_path()).supported()? {
        return Ok(());
    }
    fixture.seed_host("large.bin", &large_text("original"))?;
    fs::write(fixture.upper().join("large.bin"), large_text("changed"))?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;
    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::from_parts(16, FilesystemPreimageBackendKind::LinuxReflink),
        &runner,
        &NoopHook,
    )
    .promote()?;
    let preimage = preimage_manifest(&fixture)?;
    let artifact = fixture
        .storage
        .work_path()
        .join(regular_reflink_artifact(&preimage, "large.bin")?);
    fs::write(&artifact, "drifted")?;

    let result = FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionPreimageArtifactInvalid { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("changed")
    );
    Ok(())
}

#[test]
fn rollback_restores_from_reflink_artifact_manifest_without_committed_bytes() -> TestResult {
    let fixture = fixture()?;
    let runner = FakeOstreeRepository::successful();
    let prepared = PreparedReflinkRollback::new(&fixture, &runner)?;

    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;

    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("original")
    );
    assert!(!runner
        .committed_tree("erebor/promotions/session-1/volumes/project/preimage")
        .join("files/large.bin")
        .exists());
    assert!(prepared.artifact.is_file());
    Ok(())
}

#[test]
fn missing_reflink_artifact_manifest_blocks_rollback_before_host_mutation() -> TestResult {
    let fixture = fixture()?;
    let runner = FakeOstreeRepository::successful();
    let prepared = PreparedReflinkRollback::new(&fixture, &runner)?;
    fs::remove_file(prepared.artifact)?;

    let result = FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::PromotionPreimageArtifactInvalid { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host().join("large.bin"))?,
        large_text("changed")
    );
    Ok(())
}

#[test]
fn opaque_directory_large_preimage_uses_external_reflink_file_when_supported() -> TestResult {
    let fixture = fixture()?;
    if !ReflinkProbe::new(fixture.storage.work_path()).supported()? {
        return Ok(());
    }
    fixture.seed_host("docs/large.bin", &large_text("original"))?;
    fs::create_dir_all(fixture.upper().join("docs"))?;
    fs::write(fixture.upper().join("docs/.wh..wh..opq"), "")?;
    fs::write(fixture.upper().join("docs/new.txt"), "new\n")?;
    let manifests = fixture.storage.normalize_layers()?;
    let runner = FakeOstreeRepository::successful();
    commit_checkpoint(&fixture, &manifests, &runner)?;

    PromotionTestWorkflow::new(
        &fixture.storage,
        &manifests,
        FilesystemPromotionOptions::from_parts(16, FilesystemPreimageBackendKind::LinuxReflink),
        &runner,
        &NoopHook,
    )
    .promote()?;

    let preimage = preimage_manifest(&fixture)?;
    assert_eq!(preimage.total_bytes, 0);
    let artifact = directory_reflink_artifact(&preimage, "docs", "docs/large.bin")?;
    assert!(fixture.storage.work_path().join(artifact).is_file());
    assert!(!runner
        .committed_tree("erebor/promotions/session-1/volumes/project/preimage")
        .join("files/docs/large.bin")
        .exists());

    FilesystemRollback::rollback_promotion_using_repository(
        &fixture.storage,
        "session-1",
        &runner,
    )?;
    assert_eq!(
        fs::read_to_string(fixture.host().join("docs/large.bin"))?,
        large_text("original")
    );
    assert!(!fixture.host().join("docs/new.txt").exists());
    Ok(())
}

fn preimage_manifest(
    fixture: &super::support::Fixture,
) -> Result<FilesystemPreimageManifest, Box<dyn std::error::Error>> {
    let path = fixture
        .storage
        .work_path()
        .join("promotions/session-1/volumes/project/preimage")
        .join(PREIMAGE_MANIFEST_FILE);
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn regular_reflink_artifact<'a>(
    manifest: &'a FilesystemPreimageManifest,
    path: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .ok_or_else(|| std::io::Error::other("missing regular preimage entry"))?;
    match &entry.state {
        FilesystemPreimageEntryState::Present {
            entry_type:
                FilesystemPreimageEntryType::Regular {
                    preimage:
                        FilesystemRegularPreimage::LinuxReflink {
                            artifact,
                            size_bytes,
                            ..
                        },
                    ..
                },
        } => {
            assert!(*size_bytes > 16);
            Ok(artifact)
        }
        other => {
            Err(std::io::Error::other(format!("unexpected preimage entry state: {other:?}")).into())
        }
    }
}

fn directory_reflink_artifact<'a>(
    manifest: &'a FilesystemPreimageManifest,
    directory: &str,
    path: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    let entry = manifest
        .entries
        .iter()
        .find(|entry| entry.path == directory)
        .ok_or_else(|| std::io::Error::other("missing directory preimage entry"))?;
    let FilesystemPreimageEntryState::Present {
        entry_type: FilesystemPreimageEntryType::Directory { external_files },
    } = &entry.state
    else {
        return Err(std::io::Error::other("directory preimage entry has wrong type").into());
    };
    let file = external_files
        .iter()
        .find(|file| file.path == path)
        .ok_or_else(|| std::io::Error::other("missing external file preimage"))?;
    match &file.preimage {
        FilesystemRegularPreimage::LinuxReflink { artifact, .. } => Ok(artifact),
        other => Err(std::io::Error::other(format!(
            "unexpected external preimage backend: {other:?}"
        ))
        .into()),
    }
}

fn large_text(label: &str) -> String {
    format!("{label}:{}\n", "0123456789abcdef".repeat(256))
}

struct PreparedReflinkRollback {
    artifact: PathBuf,
}

impl PreparedReflinkRollback {
    fn new(
        fixture: &super::support::Fixture,
        runner: &FakeOstreeRepository,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        fixture.seed_host("large.bin", &large_text("original"))?;
        let host_file = fixture.host().join("large.bin");
        let host_metadata = host_metadata(&host_file)?;
        let artifact = fixture
            .storage
            .work_path()
            .join("cow-preimages/session-1/volumes/project/files/large.bin");
        let artifact_parent = artifact
            .parent()
            .ok_or_else(|| std::io::Error::other("artifact path has no parent"))?;
        fs::create_dir_all(artifact_parent)?;
        fs::copy(&host_file, &artifact)?;
        let preimage = regular_reflink_preimage(&artifact, fixture.storage.work_path())?;

        fs::write(&host_file, large_text("changed"))?;
        let promotion_id = PromotionId::new("session-1")?;
        let preimage_ref = promotion_id.preimage_ref("project");
        let preimage_stage = fixture.storage.work_path().join("manual-preimage-stage");
        let mut manifest = FilesystemPreimageManifest::new(
            "session-1",
            "project",
            fixture.host().display().to_string(),
        );
        manifest.entries.push(FilesystemPreimageEntry {
            path: String::from("large.bin"),
            state: FilesystemPreimageEntryState::Present {
                entry_type: FilesystemPreimageEntryType::Regular {
                    source: String::from("large.bin"),
                    preimage,
                },
            },
            metadata: Some(host_metadata),
        });
        PromotionManifestStore::new(&preimage_stage).write_preimage(&manifest)?;
        OstreeTreeCommit::new(
            fixture.storage.repo_path(),
            &preimage_ref,
            &preimage_stage,
            "commit promotion preimage",
            "test reflink preimage manifest",
        )
        .commit(runner)?;

        let promotion_ref = promotion_id.manifest_ref();
        let promotion_stage = fixture.storage.work_path().join("manual-promotion-stage");
        let promotion = FilesystemPromotionManifest::new(
            "session-1",
            "erebor/checkpoints/session-1/manifest",
            FilesystemPromotionState::Applied,
            vec![FilesystemPromotionVolume {
                volume_id: String::from("project"),
                layer_ref: String::from("erebor/checkpoints/session-1/volumes/project/layer"),
                preimage_ref,
            }],
        );
        PromotionManifestStore::new(&promotion_stage).write_promotion(&promotion)?;
        OstreeTreeCommit::new(
            fixture.storage.repo_path(),
            &promotion_ref,
            &promotion_stage,
            "commit promotion manifest",
            "test reflink promotion manifest",
        )
        .commit(runner)?;
        Ok(Self { artifact })
    }
}

fn regular_reflink_preimage(
    artifact: &Path,
    work_root: &Path,
) -> Result<FilesystemRegularPreimage, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(artifact)?;
    Ok(FilesystemRegularPreimage::LinuxReflink {
        artifact: artifact
            .strip_prefix(work_root)?
            .to_str()
            .ok_or_else(|| std::io::Error::other("artifact path is not utf-8"))?
            .to_owned(),
        size_bytes: metadata.len(),
        mtime_sec: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn host_metadata(path: &Path) -> Result<FilesystemHostMetadata, Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(FilesystemMetadataReader::new(path, &metadata).host_metadata()?)
}

struct ReflinkProbe<'a> {
    root: &'a Path,
}

impl<'a> ReflinkProbe<'a> {
    const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    fn supported(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let source = self.root.join("reflink-probe-source");
        let target = self.root.join("reflink-probe-target");
        let _result = fs::remove_file(&source);
        let _result = fs::remove_file(&target);
        fs::write(&source, b"probe")?;
        let source_file = File::open(&source)?;
        let target_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        let supported = rustix::fs::ioctl_ficlone(&target_file, &source_file).is_ok();
        let _result = fs::remove_file(&source);
        let _result = fs::remove_file(&target);
        Ok(supported)
    }
}
