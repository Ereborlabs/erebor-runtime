mod execution;
mod interception_broker;
pub(crate) mod session_controller;
pub(crate) mod session_manager;
pub(crate) mod session_output;
pub(crate) mod session_repository;

pub use execution::SessionExecutionError;
pub use interception_broker::RuntimeInterceptionBrokerError;
pub use session_controller::SessionControllerError;
pub use session_manager::SessionManagerError;
pub use session_output::SessionOutputError;
pub use session_repository::SessionRepositoryError;

pub(crate) use execution::{
    AdoptMatchAmbiguousSnafu, AdoptMatchNotFoundSnafu, CodexSessionSnafu, DiagnosticFailedSnafu,
    FilesystemSurfaceSnafu, GuardConfigSnafu, GuardIoSnafu, InvalidAdoptTargetSnafu,
    InvalidConfigSnafu, InvalidPolicySnafu, ReadPolicySnafu, RuntimeInterceptionBrokerSnafu,
    RuntimeSnafu, SessionRegistrySnafu, TerminalSurfaceSnafu,
};
#[cfg(windows)]
pub(crate) use interception_broker::UnsupportedTransportSnafu as BrokerUnsupportedTransportSnafu;
pub(crate) use interception_broker::{
    IoSnafu as BrokerIoSnafu, ProtocolSnafu as BrokerProtocolSnafu,
    RejectedHelloSnafu as BrokerRejectedHelloSnafu,
    ServerNotStartedSnafu as BrokerServerNotStartedSnafu,
    SessionAccessConflictSnafu as BrokerSessionAccessConflictSnafu,
    SessionAlreadyRegisteredSnafu as BrokerSessionAlreadyRegisteredSnafu,
    StateLockSnafu as BrokerStateLockSnafu,
};
