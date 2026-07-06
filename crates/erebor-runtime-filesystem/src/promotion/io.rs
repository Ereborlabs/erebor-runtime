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

pub(super) struct PromotionManifestStore<'a> {
    root: &'a Path,
}

impl<'a> PromotionManifestStore<'a> {
    pub(super) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(super) fn write_preimage(&self, manifest: &FilesystemPreimageManifest) -> Result<PathBuf> {
        self.write_json_manifest(PREIMAGE_MANIFEST_FILE, manifest)
    }

    pub(super) fn write_promotion(
        &self,
        manifest: &FilesystemPromotionManifest,
    ) -> Result<PathBuf> {
        if self.root.exists() {
            fs::remove_dir_all(self.root).context(PromotionIoSnafu {
                action: "remove promotion manifest stage",
                path: self.root,
            })?;
        }
        self.write_json_manifest(PROMOTION_MANIFEST_FILE, manifest)
    }

    pub(super) fn read_promotion(&self) -> Result<FilesystemPromotionManifest> {
        self.read_json_manifest(&self.root.join(PROMOTION_MANIFEST_FILE))
    }

    pub(super) fn read_preimage(&self) -> Result<FilesystemPreimageManifest> {
        self.read_json_manifest(&self.root.join(PREIMAGE_MANIFEST_FILE))
    }

    fn write_json_manifest<T: serde::Serialize>(
        &self,
        file_name: &str,
        manifest: &T,
    ) -> Result<PathBuf> {
        fs::create_dir_all(self.root).context(PromotionIoSnafu {
            action: "create promotion manifest stage",
            path: self.root,
        })?;
        let path = self.root.join(file_name);
        let source = serde_json::to_vec_pretty(manifest)
            .context(EncodePromotionManifestSnafu { path: &path })?;
        fs::write(&path, source).context(PromotionIoSnafu {
            action: "write promotion manifest",
            path: path.as_path(),
        })?;
        Ok(path)
    }

    fn read_json_manifest<T: serde::de::DeserializeOwned>(&self, path: &Path) -> Result<T> {
        let source = fs::read_to_string(path).context(PromotionIoSnafu {
            action: "read promotion manifest",
            path,
        })?;
        serde_json::from_str(&source).context(EncodePromotionManifestSnafu { path })
    }
}

pub(super) struct PromotionManifestCheckout<'a> {
    root: &'a Path,
}

impl<'a> PromotionManifestCheckout<'a> {
    pub(super) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    pub(super) fn read_promotion(&self) -> Result<FilesystemPromotionManifest> {
        let manifest_stage = self.root.join("manifest");
        PromotionManifestStore::new(&manifest_stage).read_promotion()
    }
}
