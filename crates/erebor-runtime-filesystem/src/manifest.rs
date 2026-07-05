use serde::{Deserialize, Serialize};

pub const LAYER_MANIFEST_FILE: &str = "erebor-layer.json";
pub const LAYER_MANIFEST_KIND: &str = "erebor.filesystem.layer";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemLayerManifest {
    pub kind: String,
    pub version: u32,
    pub volume_id: String,
    pub promotable: bool,
    pub upperdir: String,
    pub lower_identity_path: String,
    pub operations: Vec<FilesystemLayerOperation>,
    pub metadata_sidecars: Vec<FilesystemLayerMetadataSidecar>,
    pub unsupported: Vec<FilesystemLayerUnsupported>,
}

impl FilesystemLayerManifest {
    pub fn new(
        volume_id: impl Into<String>,
        upperdir: impl Into<String>,
        lower_identity_path: impl Into<String>,
    ) -> Self {
        Self {
            kind: String::from(LAYER_MANIFEST_KIND),
            version: 1,
            volume_id: volume_id.into(),
            promotable: true,
            upperdir: upperdir.into(),
            lower_identity_path: lower_identity_path.into(),
            operations: Vec::new(),
            metadata_sidecars: Vec::new(),
            unsupported: Vec::new(),
        }
    }

    pub fn push_unsupported(&mut self, unsupported: FilesystemLayerUnsupported) {
        self.promotable = false;
        self.unsupported.push(unsupported);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FilesystemLayerOperation {
    Create {
        path: String,
        entry: FilesystemLayerEntry,
    },
    Replace {
        path: String,
        entry: FilesystemLayerEntry,
    },
    Delete {
        path: String,
    },
    OpaqueReplace {
        path: String,
        entry: FilesystemLayerEntry,
        marker: FilesystemOpaqueMarker,
        replacement_entry_count: u64,
    },
}

impl FilesystemLayerOperation {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Create { path, .. }
            | Self::Replace { path, .. }
            | Self::Delete { path }
            | Self::OpaqueReplace { path, .. } => path,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "entry_type", rename_all = "snake_case")]
pub enum FilesystemLayerEntry {
    Regular {
        source: String,
        metadata: FilesystemLayerMetadata,
    },
    Symlink {
        target: String,
        metadata: FilesystemLayerMetadata,
    },
    Directory {
        metadata: FilesystemLayerMetadata,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemLayerMetadata {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime_sec: i64,
    pub mtime_nsec: i64,
    pub xattrs: Vec<FilesystemXattr>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemLayerMetadataSidecar {
    pub path: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemLayerUnsupported {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemXattr {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemOpaqueMarker {
    pub kind: String,
    pub name: String,
    pub value: Vec<u8>,
}
