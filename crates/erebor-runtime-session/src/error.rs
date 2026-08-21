mod execution;
pub(crate) mod session_controller;
pub(crate) mod session_manager;
pub(crate) mod session_output;
pub(crate) mod session_repository;

pub use execution::SessionExecutionError;
pub use session_controller::SessionControllerError;
pub use session_manager::SessionManagerError;
pub use session_output::SessionOutputError;
pub use session_repository::SessionRepositoryError;

pub(crate) use execution::{
    AdoptMatchAmbiguousSnafu, AdoptMatchNotFoundSnafu, DiagnosticFailedSnafu,
    FilesystemSurfaceSnafu, InvalidAdoptTargetSnafu, InvalidConfigSnafu, InvalidPolicySnafu,
    ReadPolicySnafu, RuntimeSnafu, SessionRegistrySnafu,
};
