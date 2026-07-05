use std::collections::BTreeMap;

use cdp_protocol::types::CallId;

use super::{BrowserTargetId, ClientSessionId};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientTargetSessions {
    sessions: BTreeMap<ClientSessionId, BrowserTargetId>,
    pending_attach_commands: BTreeMap<CallId, BrowserTargetId>,
}

impl ClientTargetSessions {
    pub fn record_attach_request(&mut self, call_id: CallId, target_id: BrowserTargetId) {
        self.pending_attach_commands.insert(call_id, target_id);
    }

    pub fn record_attach_response(
        &mut self,
        call_id: CallId,
        session_id: impl Into<String>,
    ) -> Option<BrowserTargetId> {
        let target_id = self.pending_attach_commands.remove(&call_id)?;
        self.record_attached(session_id, target_id.clone());
        Some(target_id)
    }

    pub fn record_attached(&mut self, session_id: impl Into<String>, target_id: BrowserTargetId) {
        self.sessions
            .insert(ClientSessionId::new(session_id), target_id);
    }

    pub fn record_detached(&mut self, session_id: impl Into<String>) {
        self.sessions.remove(&ClientSessionId::new(session_id));
    }

    #[must_use]
    pub fn target_for_session(&self, session_id: &str) -> Option<BrowserTargetId> {
        self.sessions
            .get(&ClientSessionId::new(session_id.to_owned()))
            .cloned()
    }

    #[must_use]
    pub fn has_session(&self, session_id: &str) -> bool {
        self.sessions
            .contains_key(&ClientSessionId::new(session_id.to_owned()))
    }
}
