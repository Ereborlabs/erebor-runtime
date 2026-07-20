mod execution;
mod interception_broker;
pub(crate) mod session_helper;
pub(crate) mod session_output;
pub(crate) mod session_repository;
pub(crate) mod session_supervisor;

pub use execution::SessionExecutionError;
pub use interception_broker::RuntimeInterceptionBrokerError;
pub use session_helper::SessionHelperError;
pub use session_output::SessionOutputError;
pub use session_repository::SessionRepositoryError;
pub use session_supervisor::SessionSupervisorError;

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
