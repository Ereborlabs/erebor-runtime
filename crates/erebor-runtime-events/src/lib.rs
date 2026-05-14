//! Shared event contract for erebor-runtime enforcement surfaces.

#[cfg(test)]
mod tests;
mod types;

pub use types::{
    ActionEnvelope, ActionKind, ActorIdentity, ActorKind, EventId, ExecutionSurface, RiskLevel,
    RiskMetadata, RuntimeEvent, SessionId, TargetRef,
};
