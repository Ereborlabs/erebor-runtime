use serde::{Deserialize, Serialize};

pub const CHECKPOINT_MANIFEST_FILE: &str = "erebor-checkpoint.json";
pub const CHECKPOINT_MANIFEST_KIND: &str = "erebor.filesystem.checkpoint";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemCheckpointManifest {
    pub kind: String,
    pub version: u32,
    pub checkpoint_id: String,
    pub volumes: Vec<FilesystemCheckpointVolume>,
}

impl FilesystemCheckpointManifest {
    pub fn new(checkpoint_id: impl Into<String>, volumes: Vec<FilesystemCheckpointVolume>) -> Self {
        Self {
            kind: String::from(CHECKPOINT_MANIFEST_KIND),
            version: 1,
            checkpoint_id: checkpoint_id.into(),
            volumes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemCheckpointVolume {
    pub volume_id: String,
    pub layer_ref: String,
}
