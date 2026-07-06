use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemBackendKind {
    #[default]
    LinuxOstreeOverlay,
    #[serde(other)]
    Unsupported,
}

impl FilesystemBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxOstreeOverlay => "linux_ostree_overlay",
            Self::Unsupported => "unsupported",
        }
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::LinuxOstreeOverlay)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemPreimageBackendKind {
    #[default]
    OstreeBytes,
    LinuxReflink,
    #[serde(other)]
    Unsupported,
}

impl FilesystemPreimageBackendKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OstreeBytes => "ostree_bytes",
            Self::LinuxReflink => "linux_reflink",
            Self::Unsupported => "unsupported",
        }
    }

    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::OstreeBytes | Self::LinuxReflink)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemVolumeMode {
    #[default]
    Writable,
    ReadOnly,
}

impl FilesystemVolumeMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Writable => "writable",
            Self::ReadOnly => "read_only",
        }
    }
}
