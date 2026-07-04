mod execution;
mod interception_broker;

pub use execution::SessionExecutionError;
pub use interception_broker::RuntimeInterceptionBrokerError;

pub(crate) use execution::{
    AdoptMatchAmbiguousSnafu, AdoptMatchNotFoundSnafu, DiagnosticFailedSnafu,
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
    SessionAlreadyRegisteredSnafu as BrokerSessionAlreadyRegisteredSnafu,
    StateLockSnafu as BrokerStateLockSnafu,
};
