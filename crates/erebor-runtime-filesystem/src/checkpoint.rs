use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::{ensure, ResultExt};

use crate::{
    error::{
        CheckpointIoSnafu, EncodeCheckpointManifestSnafu, InvalidCheckpointIdSnafu,
        OstreeCommandFailedSnafu,
    },
    normalizer::normalize_session_layers,
    ostree::{OstreeCommandRunner, SystemOstreeCommandRunner},
    FilesystemLayerManifest, FilesystemSessionStorage, FilesystemVolumeStorage, Result,
};

mod manifest;
mod stage;

pub use manifest::{
    FilesystemCheckpointManifest, FilesystemCheckpointVolume, CHECKPOINT_MANIFEST_FILE,
    CHECKPOINT_MANIFEST_KIND,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilesystemCheckpointCommit {
    checkpoint_id: String,
    checkpoint_ref: String,
    manifest_path: PathBuf,
    volumes: Vec<FilesystemCheckpointVolume>,
}

impl FilesystemCheckpointCommit {
    pub fn checkpoint_id(&self) -> &str {
        &self.checkpoint_id
    }

    pub fn checkpoint_ref(&self) -> &str {
        &self.checkpoint_ref
    }

    pub fn manifest_path(&self) -> &Path {
        &self.manifest_path
    }

    pub fn volumes(&self) -> &[FilesystemCheckpointVolume] {
        &self.volumes
    }
}

pub fn commit_session_checkpoint(
    storage: &FilesystemSessionStorage,
    checkpoint_id: &str,
) -> Result<FilesystemCheckpointCommit> {
    let manifests = normalize_session_layers(storage)?;
    commit_normalized_session_checkpoint_with_runner(
        storage,
        checkpoint_id,
        &manifests,
        &SystemOstreeCommandRunner,
    )
}

pub(crate) fn commit_normalized_session_checkpoint_with_runner(
    storage: &FilesystemSessionStorage,
    checkpoint_id: &str,
    manifests: &[FilesystemLayerManifest],
    runner: &impl OstreeCommandRunner,
) -> Result<FilesystemCheckpointCommit> {
    validate_checkpoint_id(checkpoint_id)?;
    let checkpoint_root = storage.work_path().join("checkpoints").join(checkpoint_id);
    fs::create_dir_all(&checkpoint_root).context(CheckpointIoSnafu {
        action: "create checkpoint work directory",
        path: checkpoint_root.as_path(),
    })?;

    let mut volumes = Vec::new();
    for volume in storage.volumes() {
        let manifest = manifest_for_volume(manifests, volume)?;
        let layer_ref = volume_layer_ref(checkpoint_id, volume.id())?;
        let stage_root = checkpoint_root
            .join("volumes")
            .join(volume.id())
            .join("layer");
        stage::stage_volume_layer(&stage_root, volume, manifest)?;
        commit_tree(
            runner,
            storage.repo_path(),
            &layer_ref,
            &stage_root,
            "commit checkpoint layer",
            &format!(
                "Erebor filesystem checkpoint {checkpoint_id} volume {}",
                volume.id()
            ),
        )?;
        volumes.push(FilesystemCheckpointVolume {
            volume_id: volume.id().to_owned(),
            layer_ref,
        });
    }

    let checkpoint_ref = checkpoint_manifest_ref(checkpoint_id)?;
    let checkpoint_manifest = FilesystemCheckpointManifest::new(checkpoint_id, volumes.clone());
    let manifest_stage = checkpoint_root.join("manifest");
    let manifest_path = write_checkpoint_manifest(&manifest_stage, &checkpoint_manifest)?;
    commit_tree(
        runner,
        storage.repo_path(),
        &checkpoint_ref,
        &manifest_stage,
        "commit checkpoint manifest",
        &format!("Erebor filesystem checkpoint {checkpoint_id} manifest"),
    )?;

    Ok(FilesystemCheckpointCommit {
        checkpoint_id: checkpoint_id.to_owned(),
        checkpoint_ref,
        manifest_path,
        volumes,
    })
}

pub fn checkpoint_manifest_ref(checkpoint_id: &str) -> Result<String> {
    validate_checkpoint_id(checkpoint_id)?;
    Ok(format!("erebor/checkpoints/{checkpoint_id}/manifest"))
}

pub fn volume_layer_ref(checkpoint_id: &str, volume_id: &str) -> Result<String> {
    validate_checkpoint_id(checkpoint_id)?;
    Ok(format!(
        "erebor/checkpoints/{checkpoint_id}/volumes/{volume_id}/layer"
    ))
}

fn manifest_for_volume<'a>(
    manifests: &'a [FilesystemLayerManifest],
    volume: &FilesystemVolumeStorage,
) -> Result<&'a FilesystemLayerManifest> {
    manifests
        .iter()
        .find(|manifest| manifest.volume_id == volume.id())
        .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
            volume_id: volume.id().to_owned(),
            reason: String::from("missing normalized layer manifest for checkpoint commit"),
            location: snafu::Location::default(),
        })
}

fn write_checkpoint_manifest(
    stage_root: &Path,
    manifest: &FilesystemCheckpointManifest,
) -> Result<PathBuf> {
    if stage_root.exists() {
        fs::remove_dir_all(stage_root).context(CheckpointIoSnafu {
            action: "remove checkpoint manifest stage",
            path: stage_root,
        })?;
    }
    fs::create_dir_all(stage_root).context(CheckpointIoSnafu {
        action: "create checkpoint manifest stage",
        path: stage_root,
    })?;
    let path = stage_root.join(CHECKPOINT_MANIFEST_FILE);
    let source = serde_json::to_vec_pretty(manifest)
        .context(EncodeCheckpointManifestSnafu { path: &path })?;
    fs::write(&path, source).context(CheckpointIoSnafu {
        action: "write checkpoint manifest",
        path: path.as_path(),
    })?;
    Ok(path)
}

pub(crate) fn commit_tree(
    runner: &impl OstreeCommandRunner,
    repo: &Path,
    ref_name: &str,
    tree: &Path,
    operation: &'static str,
    subject: &str,
) -> Result<()> {
    let args = vec![
        String::from("commit"),
        format!("--branch={ref_name}"),
        format!("--tree=dir={}", tree.display()),
        format!("--subject={subject}"),
    ];
    let output = runner.run(repo, &args)?;
    ensure!(
        output.success(),
        OstreeCommandFailedSnafu {
            repo: repo.to_path_buf(),
            operation,
            code: output.code(),
            stderr: output.stderr().to_owned(),
        }
    );
    Ok(())
}

fn validate_checkpoint_id(checkpoint_id: &str) -> Result<()> {
    if checkpoint_id.is_empty() {
        return invalid_checkpoint_id(checkpoint_id, "must not be empty");
    }
    if !checkpoint_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid_checkpoint_id(
            checkpoint_id,
            "must contain only ASCII letters, digits, dot, underscore, or dash",
        );
    }
    Ok(())
}

fn invalid_checkpoint_id(checkpoint_id: &str, reason: &str) -> Result<()> {
    InvalidCheckpointIdSnafu {
        checkpoint_id: checkpoint_id.to_owned(),
        reason: reason.to_owned(),
    }
    .fail()
}

#[cfg(test)]
mod tests;
