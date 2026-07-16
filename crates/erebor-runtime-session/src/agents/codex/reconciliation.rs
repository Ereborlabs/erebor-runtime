use std::{collections::VecDeque, sync::Mutex};

use erebor_runtime_ipc::v1::HookEventKind;

use super::CodexSessionError;

const MAX_OBSERVATIONS: usize = 128;

/// Session-local authenticated hook evidence available to the owned App Server
/// transport broker. It is deliberately evidence-only: no hook can create a
/// prompt node or select one by heuristic.
#[derive(Default)]
pub(crate) struct CodexPromptReconciliation {
    observations: Mutex<VecDeque<CodexAuthenticatedHookObservation>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexAuthenticatedHookObservation {
    kind: HookEventKind,
    session_id: Option<String>,
    thread_id: Option<String>,
    turn_id: Option<String>,
}

impl CodexPromptReconciliation {
    pub(crate) fn record_authenticated_hook(
        &self,
        kind: HookEventKind,
        native_event_json: &[u8],
    ) -> Result<(), CodexSessionError> {
        let payload: serde_json::Value =
            serde_json::from_slice(native_event_json).map_err(|error| {
                CodexSessionError::InvalidHookEvent {
                    reason: format!("authenticated hook event could not be parsed: {error}"),
                    location: snafu::Location::default(),
                }
            })?;
        let observation = CodexAuthenticatedHookObservation {
            kind,
            session_id: Self::top_level_string(&payload, &["session_id", "sessionId"]),
            thread_id: Self::top_level_string(&payload, &["thread_id", "threadId"]),
            turn_id: Self::top_level_string(&payload, &["turn_id", "turnId"]),
        };
        let mut observations = self.observations.lock().map_err(|_error| {
            CodexSessionError::PromptReconciliationStateLock {
                location: snafu::Location::default(),
            }
        })?;
        if observations.len() == MAX_OBSERVATIONS {
            observations.pop_front();
        }
        observations.push_back(observation);
        Ok(())
    }

    /// Codex's `UserPromptSubmit.session_id` is the native App Server thread
    /// identifier. The authenticated hook broker is already session/profile
    /// scoped, so a prompt can be corroborated only by that exact thread and
    /// turn pair. Missing IDs are not guessed from timing, prompt text, or
    /// nearby events.
    pub(crate) fn matching_user_prompt_submit(
        &self,
        codex_thread_id: Option<&str>,
        turn_id: Option<&str>,
    ) -> Result<Vec<CodexAuthenticatedHookObservation>, CodexSessionError> {
        let (Some(codex_thread_id), Some(turn_id)) = (codex_thread_id, turn_id) else {
            return Ok(Vec::new());
        };
        let observations = self.observations.lock().map_err(|_error| {
            CodexSessionError::PromptReconciliationStateLock {
                location: snafu::Location::default(),
            }
        })?;
        Ok(observations
            .iter()
            .filter(|observation| observation.kind == HookEventKind::UserPromptSubmit)
            .filter(|observation| {
                observation.session_id.as_deref() == Some(codex_thread_id)
                    || observation.thread_id.as_deref() == Some(codex_thread_id)
            })
            .filter(|observation| observation.turn_id.as_deref() == Some(turn_id))
            .cloned()
            .collect())
    }

    pub(crate) fn matching_subagent_hook(
        &self,
        session_id: Option<&str>,
        thread_id: Option<&str>,
    ) -> Result<Vec<CodexAuthenticatedHookObservation>, CodexSessionError> {
        let observations = self.observations.lock().map_err(|_error| {
            CodexSessionError::PromptReconciliationStateLock {
                location: snafu::Location::default(),
            }
        })?;
        Ok(observations
            .iter()
            .filter(|observation| {
                matches!(
                    observation.kind,
                    HookEventKind::SubagentStart | HookEventKind::SubagentStop
                )
            })
            .filter(|observation| {
                Self::matches_required(session_id, observation.session_id.as_deref())
            })
            .filter(|observation| {
                Self::matches_required(thread_id, observation.thread_id.as_deref())
            })
            .cloned()
            .collect())
    }

    fn matches_required(expected: Option<&str>, observed: Option<&str>) -> bool {
        expected.is_none_or(|expected| observed == Some(expected))
    }

    fn top_level_string(payload: &serde_json::Value, names: &[&str]) -> Option<String> {
        let fields = payload.as_object()?;
        names.iter().find_map(|name| {
            fields
                .get(*name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
    }
}

#[cfg(test)]
mod tests {
    use erebor_runtime_ipc::v1::HookEventKind;

    use super::CodexPromptReconciliation;

    #[test]
    fn only_exact_hook_facts_reconcile_to_a_brokered_prompt(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let reconciliation = CodexPromptReconciliation::default();
        reconciliation.record_authenticated_hook(
            HookEventKind::UserPromptSubmit,
            br#"{"hook_event_name":"UserPromptSubmit","session_id":"thread-1","turn_id":"turn-1"}"#,
        )?;

        assert_eq!(
            reconciliation
                .matching_user_prompt_submit(Some("thread-1"), Some("turn-1"))?
                .len(),
            1
        );
        assert!(reconciliation
            .matching_user_prompt_submit(Some("thread-2"), Some("turn-1"))?
            .is_empty());
        assert!(reconciliation
            .matching_user_prompt_submit(Some("thread-1"), Some("turn-2"))?
            .is_empty());
        assert!(reconciliation
            .matching_user_prompt_submit(Some("thread-1"), None)?
            .is_empty());
        Ok(())
    }
}
