use std::{
    fs,
    path::{Path, PathBuf},
};

use snafu::ResultExt;

use crate::{
    error::{EncodePromotionManifestSnafu, PromotionIoSnafu},
    Result,
};

use super::manifest::{
    FilesystemPreimageManifest, FilesystemPromotionManifest, PREIMAGE_MANIFEST_FILE,
    PROMOTION_MANIFEST_FILE,
};

pub(super) fn write_preimage_manifest(
    stage: &Path,
    manifest: &FilesystemPreimageManifest,
) -> Result<PathBuf> {
    write_json_manifest(stage, PREIMAGE_MANIFEST_FILE, manifest)
}

pub(super) fn write_promotion_manifest(
    stage: &Path,
    manifest: &FilesystemPromotionManifest,
) -> Result<PathBuf> {
    if stage.exists() {
        fs::remove_dir_all(stage).context(PromotionIoSnafu {
            action: "remove promotion manifest stage",
            path: stage,
        })?;
    }
    write_json_manifest(stage, PROMOTION_MANIFEST_FILE, manifest)
}

pub(super) fn read_promotion_manifest(root: &Path) -> Result<FilesystemPromotionManifest> {
    read_json_manifest(&root.join("manifest").join(PROMOTION_MANIFEST_FILE))
}

pub(super) fn read_preimage_manifest(stage: &Path) -> Result<FilesystemPreimageManifest> {
    read_json_manifest(&stage.join(PREIMAGE_MANIFEST_FILE))
}

fn write_json_manifest<T: serde::Serialize>(
    stage: &Path,
    file_name: &str,
    manifest: &T,
) -> Result<PathBuf> {
    fs::create_dir_all(stage).context(PromotionIoSnafu {
        action: "create promotion manifest stage",
        path: stage,
    })?;
    let path = stage.join(file_name);
    let source = serde_json::to_vec_pretty(manifest)
        .context(EncodePromotionManifestSnafu { path: &path })?;
    fs::write(&path, source).context(PromotionIoSnafu {
        action: "write promotion manifest",
        path: path.as_path(),
    })?;
    Ok(path)
}

fn read_json_manifest<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let source = fs::read_to_string(path).context(PromotionIoSnafu {
        action: "read promotion manifest",
        path,
    })?;
    serde_json::from_str(&source).context(EncodePromotionManifestSnafu { path })
}
