mod env;
mod error;
mod guard_rules;
mod mediation;
mod policy;

#[cfg(test)]
mod tests;

pub use error::{Error as TerminalSurfaceError, Result as TerminalSurfaceResult};
pub use guard_rules::{
    TerminalProcessGuardDecision, TerminalProcessGuardRule, TerminalProcessGuardRules,
};
pub use mediation::TerminalProcessMediationCapability;
pub use policy::{
    TerminalProcessExecValidator, TerminalProcessPolicy, TerminalProcessPolicyDecision,
};
