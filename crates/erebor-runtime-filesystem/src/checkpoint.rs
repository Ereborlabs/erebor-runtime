use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{CheckpointIoSnafu, EncodeCheckpointManifestSnafu, InvalidCheckpointIdSnafu},
    ostree::{OstreeRepository, OstreeTreeCommit, SystemOstreeRepository},
    FilesystemLayerManifest, FilesystemSessionStorage, FilesystemVolumeStorage, Result,
};
use stage::CheckpointLayerStage;

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

impl FilesystemCheckpointCommit {
    pub fn commit(
        storage: &FilesystemSessionStorage,
        checkpoint_id: &str,
    ) -> Result<FilesystemCheckpointCommit> {
        let manifests = storage.normalize_layers()?;
        Self::commit_normalized_using_repository(
            storage,
            checkpoint_id,
            &manifests,
            &SystemOstreeRepository,
        )
    }

    pub(crate) fn commit_normalized_using_repository(
        storage: &FilesystemSessionStorage,
        checkpoint_id: &str,
        manifests: &[FilesystemLayerManifest],
        repository: &impl OstreeRepository,
    ) -> Result<FilesystemCheckpointCommit> {
        CheckpointWorkflow::new(storage, checkpoint_id, manifests, repository)?.commit()
    }
}

struct CheckpointWorkflow<'a, R>
where
    R: OstreeRepository,
{
    storage: &'a FilesystemSessionStorage,
    checkpoint_id: CheckpointId<'a>,
    manifests: &'a [FilesystemLayerManifest],
    repository: &'a R,
    workspace: CheckpointWorkspace<'a>,
}

impl<'a, R> CheckpointWorkflow<'a, R>
where
    R: OstreeRepository,
{
    fn new(
        storage: &'a FilesystemSessionStorage,
        checkpoint_id: &'a str,
        manifests: &'a [FilesystemLayerManifest],
        repository: &'a R,
    ) -> Result<Self> {
        let checkpoint_id = CheckpointId::new(checkpoint_id)?;
        Ok(Self {
            storage,
            checkpoint_id,
            manifests,
            repository,
            workspace: CheckpointWorkspace::new(storage, checkpoint_id),
        })
    }

    fn commit(&self) -> Result<FilesystemCheckpointCommit> {
        let checkpoint_root = self.workspace.root();
        fs::create_dir_all(&checkpoint_root).context(CheckpointIoSnafu {
            action: "create checkpoint work directory",
            path: checkpoint_root.as_path(),
        })?;

        let volumes = self.commit_volume_layers(&checkpoint_root)?;
        let checkpoint_ref = self.checkpoint_id.manifest_ref();
        let checkpoint_manifest =
            FilesystemCheckpointManifest::new(self.checkpoint_id.as_str(), volumes.clone());
        let manifest_stage = self.workspace.manifest_stage(&checkpoint_root);
        let manifest_path =
            CheckpointManifestStage::new(&manifest_stage).write_manifest(&checkpoint_manifest)?;
        let subject = format!(
            "Erebor filesystem checkpoint {} manifest",
            self.checkpoint_id.as_str()
        );
        OstreeTreeCommit::new(
            self.storage.repo_path(),
            &checkpoint_ref,
            &manifest_stage,
            "commit checkpoint manifest",
            &subject,
        )
        .commit(self.repository)?;

        Ok(FilesystemCheckpointCommit {
            checkpoint_id: self.checkpoint_id.as_str().to_owned(),
            checkpoint_ref,
            manifest_path,
            volumes,
        })
    }

    fn commit_volume_layers(
        &self,
        checkpoint_root: &Path,
    ) -> Result<Vec<FilesystemCheckpointVolume>> {
        let mut volumes = Vec::new();
        for volume in self.storage.volumes() {
            let manifest = self.manifest_for_volume(volume)?;
            let layer_ref = self.checkpoint_id.volume_layer_ref(volume.id());
            let stage_root = self
                .workspace
                .volume_layer_stage(checkpoint_root, volume.id());
            CheckpointLayerStage::new(&stage_root, volume, manifest).stage()?;
            let subject = format!(
                "Erebor filesystem checkpoint {} volume {}",
                self.checkpoint_id.as_str(),
                volume.id()
            );
            OstreeTreeCommit::new(
                self.storage.repo_path(),
                &layer_ref,
                &stage_root,
                "commit checkpoint layer",
                &subject,
            )
            .commit(self.repository)?;
            volumes.push(FilesystemCheckpointVolume {
                volume_id: volume.id().to_owned(),
                layer_ref,
            });
        }
        Ok(volumes)
    }

    fn manifest_for_volume(
        &self,
        volume: &FilesystemVolumeStorage,
    ) -> Result<&FilesystemLayerManifest> {
        self.manifests
            .iter()
            .find(|manifest| manifest.volume_id == volume.id())
            .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
                volume_id: volume.id().to_owned(),
                reason: String::from("missing normalized layer manifest for checkpoint commit"),
                location: snafu::Location::default(),
            })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CheckpointId<'a> {
    value: &'a str,
}

impl<'a> CheckpointId<'a> {
    pub(crate) fn new(value: &'a str) -> Result<Self> {
        if value.is_empty() {
            return Self::invalid(value, "must not be empty");
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Self::invalid(
                value,
                "must contain only ASCII letters, digits, dot, underscore, or dash",
            );
        }
        Ok(Self { value })
    }

    pub(crate) const fn as_str(self) -> &'a str {
        self.value
    }

    pub(crate) fn manifest_ref(self) -> String {
        format!("erebor/checkpoints/{}/manifest", self.value)
    }

    pub(crate) fn volume_layer_ref(self, volume_id: &str) -> String {
        format!(
            "erebor/checkpoints/{}/volumes/{volume_id}/layer",
            self.value
        )
    }

    fn invalid<T>(checkpoint_id: &str, reason: &str) -> Result<T> {
        InvalidCheckpointIdSnafu {
            checkpoint_id: checkpoint_id.to_owned(),
            reason: reason.to_owned(),
        }
        .fail()
    }
}

struct CheckpointWorkspace<'a> {
    storage: &'a FilesystemSessionStorage,
    checkpoint_id: CheckpointId<'a>,
}

impl<'a> CheckpointWorkspace<'a> {
    const fn new(storage: &'a FilesystemSessionStorage, checkpoint_id: CheckpointId<'a>) -> Self {
        Self {
            storage,
            checkpoint_id,
        }
    }

    fn root(&self) -> PathBuf {
        self.storage
            .work_path()
            .join("checkpoints")
            .join(self.checkpoint_id.as_str())
    }

    fn volume_layer_stage(&self, checkpoint_root: &Path, volume_id: &str) -> PathBuf {
        checkpoint_root
            .join("volumes")
            .join(volume_id)
            .join("layer")
    }

    fn manifest_stage(&self, checkpoint_root: &Path) -> PathBuf {
        checkpoint_root.join("manifest")
    }
}

struct CheckpointManifestStage<'a> {
    root: &'a Path,
}

impl<'a> CheckpointManifestStage<'a> {
    const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    fn write_manifest(&self, manifest: &FilesystemCheckpointManifest) -> Result<PathBuf> {
        if self.root.exists() {
            fs::remove_dir_all(self.root).context(CheckpointIoSnafu {
                action: "remove checkpoint manifest stage",
                path: self.root,
            })?;
        }
        fs::create_dir_all(self.root).context(CheckpointIoSnafu {
            action: "create checkpoint manifest stage",
            path: self.root,
        })?;
        let path = self.root.join(CHECKPOINT_MANIFEST_FILE);
        let source = serde_json::to_vec_pretty(manifest)
            .context(EncodeCheckpointManifestSnafu { path: &path })?;
        fs::write(&path, source).context(CheckpointIoSnafu {
            action: "write checkpoint manifest",
            path: path.as_path(),
        })?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests;
