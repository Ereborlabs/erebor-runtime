use std::any::Any;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};

use super::FilesystemError;

impl ErrorExt for FilesystemError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidVolumeId { .. }
            | Self::InvalidVolumePath { .. }
            | Self::UnsupportedOverlayPlatform { .. }
            | Self::MissingOverlayCommand { .. }
            | Self::InvalidOverlaySessionView { .. }
            | Self::InvalidReadOnlySessionProjection { .. }
            | Self::InvalidCheckpointId { .. }
            | Self::InvalidPromotionId { .. }
            | Self::InvalidTransactionHandle { .. }
            | Self::InvalidTransactionName { .. }
            | Self::InvalidSessionWorkId { .. }
            | Self::InvalidRetentionTarget { .. }
            | Self::ProtectedRetentionTarget { .. } => StatusCode::InvalidArguments,
            Self::CreateStorageDir { .. }
            | Self::InspectOverlaySessionPath { .. }
            | Self::CreateOverlaySessionDir { .. }
            | Self::WriteOverlayWrapper { .. }
            | Self::SetOverlayWrapperPermissions { .. }
            | Self::InspectReadOnlySessionProjection { .. }
            | Self::WriteReadOnlySessionWrapper { .. }
            | Self::SetReadOnlySessionWrapperPermissions { .. }
            | Self::ReadLayerPath { .. }
            | Self::InspectLayerPath { .. }
            | Self::ActiveLayerWriter { .. }
            | Self::WriteLayerManifest { .. }
            | Self::EncodeLayerManifest { .. }
            | Self::CheckpointIo { .. }
            | Self::PromotionIo { .. }
            | Self::TransactionCatalogIo { .. }
            | Self::SessionWorkIo { .. }
            | Self::RetentionIo { .. }
            | Self::EncodeCheckpointManifest { .. }
            | Self::EncodePromotionManifest { .. }
            | Self::EncodeTransactionCatalog { .. }
            | Self::EncodeSessionWork { .. }
            | Self::EncodeRetention { .. }
            | Self::StartOstree { .. }
            | Self::OstreeInitFailed { .. }
            | Self::OstreeCommandFailed { .. } => StatusCode::External,
            Self::UnsupportedLayer { .. }
            | Self::PromotionPreimageTooLarge { .. }
            | Self::PromotionPreimageBackendUnavailable { .. }
            | Self::PromotionPreimageArtifactInvalid { .. }
            | Self::PromotionHostDrift { .. }
            | Self::IncompletePromotion { .. } => StatusCode::InvalidArguments,
        }
    }

    fn retry_hint(&self) -> RetryHint {
        match self {
            Self::CreateStorageDir { source, .. }
            | Self::InspectOverlaySessionPath { source, .. }
            | Self::CreateOverlaySessionDir { source, .. }
            | Self::WriteOverlayWrapper { source, .. }
            | Self::SetOverlayWrapperPermissions { source, .. }
            | Self::InspectReadOnlySessionProjection { source, .. }
            | Self::WriteReadOnlySessionWrapper { source, .. }
            | Self::SetReadOnlySessionWrapperPermissions { source, .. }
            | Self::ReadLayerPath { source, .. }
            | Self::InspectLayerPath { source, .. }
            | Self::WriteLayerManifest { source, .. }
            | Self::CheckpointIo { source, .. }
            | Self::PromotionIo { source, .. }
            | Self::TransactionCatalogIo { source, .. }
            | Self::SessionWorkIo { source, .. }
            | Self::RetentionIo { source, .. }
            | Self::StartOstree { source, .. } => RetryHint::from_io_error(source),
            Self::InvalidVolumeId { .. }
            | Self::InvalidVolumePath { .. }
            | Self::UnsupportedOverlayPlatform { .. }
            | Self::MissingOverlayCommand { .. }
            | Self::InvalidOverlaySessionView { .. }
            | Self::InvalidReadOnlySessionProjection { .. }
            | Self::InvalidCheckpointId { .. }
            | Self::InvalidPromotionId { .. }
            | Self::InvalidTransactionHandle { .. }
            | Self::InvalidTransactionName { .. }
            | Self::InvalidSessionWorkId { .. }
            | Self::InvalidRetentionTarget { .. }
            | Self::ProtectedRetentionTarget { .. }
            | Self::ActiveLayerWriter { .. }
            | Self::UnsupportedLayer { .. }
            | Self::PromotionPreimageTooLarge { .. }
            | Self::PromotionPreimageBackendUnavailable { .. }
            | Self::PromotionPreimageArtifactInvalid { .. }
            | Self::PromotionHostDrift { .. }
            | Self::IncompletePromotion { .. }
            | Self::EncodeLayerManifest { .. }
            | Self::EncodeCheckpointManifest { .. }
            | Self::EncodePromotionManifest { .. }
            | Self::EncodeTransactionCatalog { .. }
            | Self::EncodeSessionWork { .. }
            | Self::EncodeRetention { .. }
            | Self::OstreeInitFailed { .. }
            | Self::OstreeCommandFailed { .. } => RetryHint::NonRetryable,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
