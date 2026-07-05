mod command;
mod context;
mod decision;
mod event;
mod observer;
mod outcome;

#[cfg(test)]
mod tests;

pub use command::CdpCommandEnforcer;
pub use context::CdpSessionContext;
pub use event::CdpEventEnforcer;
pub use observer::CdpEventObserver;
pub use outcome::{CdpEnforcementAction, CdpEnforcementOutcome};

impl From<erebor_runtime_core::RuntimeError> for crate::CdpError {
    fn from(error: erebor_runtime_core::RuntimeError) -> Self {
        Self::Enforcement {
            source: Box::new(error),
            location: snafu::Location::default(),
        }
    }
}
