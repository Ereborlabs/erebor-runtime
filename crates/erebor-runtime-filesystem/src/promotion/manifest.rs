use serde::{Deserialize, Serialize};

pub const PREIMAGE_MANIFEST_FILE: &str = "erebor-preimage.json";
pub const PREIMAGE_MANIFEST_KIND: &str = "erebor.filesystem.preimage";
pub const PROMOTION_MANIFEST_FILE: &str = "erebor-promotion.json";
pub const PROMOTION_MANIFEST_KIND: &str = "erebor.filesystem.promotion";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemPromotionManifest {
    pub kind: String,
    pub version: u32,
    pub promotion_id: String,
    pub checkpoint_ref: String,
    pub state: FilesystemPromotionState,
    pub volumes: Vec<FilesystemPromotionVolume>,
}

impl FilesystemPromotionManifest {
    pub fn new(
        promotion_id: impl Into<String>,
        checkpoint_ref: impl Into<String>,
        state: FilesystemPromotionState,
        volumes: Vec<FilesystemPromotionVolume>,
    ) -> Self {
        Self {
            kind: String::from(PROMOTION_MANIFEST_KIND),
            version: 1,
            promotion_id: promotion_id.into(),
            checkpoint_ref: checkpoint_ref.into(),
            state,
            volumes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemPromotionState {
    PreimageCommitted,
    Applied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemPromotionVolume {
    pub volume_id: String,
    pub layer_ref: String,
    pub preimage_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemPreimageManifest {
    pub kind: String,
    pub version: u32,
    pub promotion_id: String,
    pub volume_id: String,
    pub host_path: String,
    pub total_bytes: u64,
    pub entries: Vec<FilesystemPreimageEntry>,
}

impl FilesystemPreimageManifest {
    pub fn new(
        promotion_id: impl Into<String>,
        volume_id: impl Into<String>,
        host_path: impl Into<String>,
    ) -> Self {
        Self {
            kind: String::from(PREIMAGE_MANIFEST_KIND),
            version: 1,
            promotion_id: promotion_id.into(),
            volume_id: volume_id.into(),
            host_path: host_path.into(),
            total_bytes: 0,
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemPreimageEntry {
    pub path: String,
    #[serde(flatten)]
    pub state: FilesystemPreimageEntryState,
    pub metadata: Option<FilesystemHostMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FilesystemPreimageEntryState {
    Absent,
    Present {
        entry_type: FilesystemPreimageEntryType,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "entry_type", rename_all = "snake_case")]
pub enum FilesystemPreimageEntryType {
    Directory,
    Regular { source: String },
    Symlink { target: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemHostMetadata {
    pub file_type: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub device: u64,
    pub inode: u64,
}
