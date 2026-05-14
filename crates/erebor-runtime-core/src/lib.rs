//! Core enforcement loop contracts for erebor-runtime.

use erebor_runtime_events::RuntimeEvent;
use erebor_runtime_policy::{Decision, PolicyError, PolicyEvaluator};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct LocalEnforcementEngine<E> {
    evaluator: E,
}

impl<E> LocalEnforcementEngine<E> {
    #[must_use]
    pub fn new(evaluator: E) -> Self {
        Self { evaluator }
    }
}

impl<E> LocalEnforcementEngine<E>
where
    E: PolicyEvaluator,
{
    pub fn evaluate(&self, event: &RuntimeEvent) -> Result<Decision, RuntimeError> {
        self.evaluator.evaluate(event).map_err(RuntimeError::from)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum RuntimeError {
    #[error("policy evaluation failed: {0}")]
    Policy(#[from] PolicyError),
}
