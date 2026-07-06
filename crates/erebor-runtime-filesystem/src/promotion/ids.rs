use snafu::Location;

use crate::{
    error::InvalidPromotionIdSnafu, FilesystemLayerManifest, FilesystemSessionStorage,
    FilesystemVolumeStorage, Result,
};

#[derive(Clone, Copy)]
pub(super) struct PromotionId<'a> {
    value: &'a str,
}

impl<'a> PromotionId<'a> {
    pub(super) fn new(value: &'a str) -> Result<Self> {
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

    pub(super) const fn as_str(self) -> &'a str {
        self.value
    }

    pub(super) fn manifest_ref(self) -> String {
        format!("erebor/promotions/{}/manifest", self.value)
    }

    pub(super) fn preimage_ref(self, volume_id: &str) -> String {
        format!(
            "erebor/promotions/{}/volumes/{volume_id}/preimage",
            self.value
        )
    }

    fn invalid<T>(promotion_id: &str, reason: &str) -> Result<T> {
        InvalidPromotionIdSnafu {
            promotion_id: promotion_id.to_owned(),
            reason: reason.to_owned(),
        }
        .fail()
    }
}

pub(super) struct PromotionStorageLookup<'a> {
    storage: &'a FilesystemSessionStorage,
}

impl<'a> PromotionStorageLookup<'a> {
    pub(super) const fn new(storage: &'a FilesystemSessionStorage) -> Self {
        Self { storage }
    }

    pub(super) fn volume(&self, volume_id: &str) -> Result<&'a FilesystemVolumeStorage> {
        self.storage
            .volumes()
            .iter()
            .find(|volume| volume.id() == volume_id)
            .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
                volume_id: volume_id.to_owned(),
                reason: String::from("promotion references an unknown volume"),
                location: Location::default(),
            })
    }
}

pub(super) struct PromotionLayerLookup<'a> {
    manifests: &'a [FilesystemLayerManifest],
}

impl<'a> PromotionLayerLookup<'a> {
    pub(super) const fn new(manifests: &'a [FilesystemLayerManifest]) -> Self {
        Self { manifests }
    }

    pub(super) fn manifest_for_volume(
        &self,
        volume: &FilesystemVolumeStorage,
    ) -> Result<&'a FilesystemLayerManifest> {
        self.manifests
            .iter()
            .find(|manifest| manifest.volume_id == volume.id())
            .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
                volume_id: volume.id().to_owned(),
                reason: String::from("missing normalized layer manifest for promotion"),
                location: Location::default(),
            })
    }
}
