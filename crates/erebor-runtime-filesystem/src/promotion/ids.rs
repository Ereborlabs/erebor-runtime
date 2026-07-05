use snafu::Location;

use crate::{
    error::InvalidPromotionIdSnafu, FilesystemLayerManifest, FilesystemSessionStorage,
    FilesystemVolumeStorage, Result,
};

pub(super) fn validate_promotion_id(promotion_id: &str) -> Result<()> {
    if promotion_id.is_empty() {
        return invalid_promotion_id(promotion_id, "must not be empty");
    }
    if !promotion_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return invalid_promotion_id(
            promotion_id,
            "must contain only ASCII letters, digits, dot, underscore, or dash",
        );
    }
    Ok(())
}

pub fn promotion_manifest_ref(promotion_id: &str) -> Result<String> {
    validate_promotion_id(promotion_id)?;
    Ok(format!("erebor/promotions/{promotion_id}/manifest"))
}

pub fn promotion_preimage_ref(promotion_id: &str, volume_id: &str) -> Result<String> {
    validate_promotion_id(promotion_id)?;
    Ok(format!(
        "erebor/promotions/{promotion_id}/volumes/{volume_id}/preimage"
    ))
}

pub(super) fn volume_for_id<'a>(
    storage: &'a FilesystemSessionStorage,
    volume_id: &str,
) -> Result<&'a FilesystemVolumeStorage> {
    storage
        .volumes()
        .iter()
        .find(|volume| volume.id() == volume_id)
        .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
            volume_id: volume_id.to_owned(),
            reason: String::from("promotion references an unknown volume"),
            location: Location::default(),
        })
}

pub(super) fn manifest_for_volume<'a>(
    manifests: &'a [FilesystemLayerManifest],
    volume: &FilesystemVolumeStorage,
) -> Result<&'a FilesystemLayerManifest> {
    manifests
        .iter()
        .find(|manifest| manifest.volume_id == volume.id())
        .ok_or_else(|| crate::FilesystemError::UnsupportedLayer {
            volume_id: volume.id().to_owned(),
            reason: String::from("missing normalized layer manifest for promotion"),
            location: Location::default(),
        })
}

fn invalid_promotion_id(promotion_id: &str, reason: &str) -> Result<()> {
    InvalidPromotionIdSnafu {
        promotion_id: promotion_id.to_owned(),
        reason: reason.to_owned(),
    }
    .fail()
}
