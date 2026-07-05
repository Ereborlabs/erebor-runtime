mod data;
mod page;
mod projection;

#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};

use cdp_protocol::{page as cdp_page, target};
use erebor_runtime_events::TargetRef;
use serde_json::{json, Value};

use self::{data::CdpSessionStateData, projection::SessionStateProjection};
use crate::{BrowserTarget, BrowserTargetId, CdpEvent, ClientTargetSessions, GovernedCdpCommand};
pub use page::{CdpSessionSnapshot, PageStatus, PageStatusKind};

#[derive(Clone, Debug, Default)]
pub struct CdpSessionState {
    inner: Arc<Mutex<CdpSessionStateData>>,
}

impl CdpSessionState {
    #[must_use]
    pub fn from_browser_url(browser_url: &str) -> Self {
        let state = Self::default();
        if let Some(page_id) = SessionStateProjection::page_id_from_browser_url(browser_url) {
            state.ensure_page(page_id);
        }

        state
    }

    #[must_use]
    pub fn snapshot(&self) -> CdpSessionSnapshot {
        self.read_data(CdpSessionStateData::snapshot)
    }

    #[must_use]
    pub fn target_for_command(&self, command: &GovernedCdpCommand) -> Option<TargetRef> {
        self.target_for_client_command(command, None, None)
    }

    #[must_use]
    pub fn target_for_client_command(
        &self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Option<TargetRef> {
        self.read_data(|data| {
            let explicit_target = command.target();
            let browser_target =
                data.browser_target_for_client_session(client_session_id, client_sessions);
            let command_page = data.page_for_command(command);

            match explicit_target {
                Some(target) => Some(SessionStateProjection::merge_target_context(
                    target,
                    browser_target.as_ref(),
                    command_page.as_ref(),
                )),
                None => browser_target
                    .as_ref()
                    .map(BrowserTarget::target_ref)
                    .or_else(|| {
                        command_page
                            .as_ref()
                            .map(SessionStateProjection::page_target)
                    }),
            }
        })
    }

    #[must_use]
    pub fn command_page_payload(&self, command: &GovernedCdpCommand) -> Value {
        self.command_page_payload_for_client(command, None, None)
    }

    #[must_use]
    pub fn command_page_payload_for_client(
        &self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Value {
        self.read_data(|data| {
            let snapshot = data.snapshot();
            let command_page = data.page_for_command(command);
            let browser_target =
                data.browser_target_for_client_session(client_session_id, client_sessions);

            json!({
                "active_page": snapshot.active_page,
                "command_page": command_page,
                "pages": snapshot.pages,
                "browser_targets": snapshot.targets,
                "client_session_id": client_session_id,
                "client_target": browser_target,
            })
        })
    }

    pub fn record_provisional_forwarded_command(&self, command: &GovernedCdpCommand) {
        self.record_provisional_forwarded_command_for_client_session(command, None, None);
    }

    pub fn record_provisional_forwarded_command_for_client_session(
        &self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) {
        self.mutate_data(|data| {
            data.record_provisional_forwarded_command(command, client_session_id, client_sessions);
        });
    }

    pub fn record_browser_event(&self, event: &CdpEvent) {
        self.record_browser_event_for_client_session(event, None);
    }

    pub fn record_browser_event_for_client_session(
        &self,
        event: &CdpEvent,
        client_sessions: Option<&mut ClientTargetSessions>,
    ) {
        self.mutate_data(|data| data.record_protocol_event(event, client_sessions));
    }

    pub fn record_frame_tree(&self, frame_tree: &cdp_page::FrameTree) {
        self.mutate_data(|data| data.record_frame_tree(None, frame_tree));
    }

    pub fn record_frame_tree_for_target(
        &self,
        target_id: BrowserTargetId,
        frame_tree: &cdp_page::FrameTree,
    ) {
        self.mutate_data(|data| data.record_frame_tree(Some(target_id), frame_tree));
    }

    pub fn record_target_info(&self, target_info: &target::TargetInfo) {
        self.mutate_data(|data| data.record_target_info(target_info));
    }

    fn ensure_page(&self, page_id: String) {
        self.mutate_data(|data| {
            data.ensure_page(page_id.clone());
            data.set_active_page(page_id);
        });
    }

    fn read_data<T>(&self, read: impl FnOnce(&CdpSessionStateData) -> T) -> T {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&guard)
    }

    fn mutate_data<T>(&self, write: impl FnOnce(&mut CdpSessionStateData) -> T) -> T {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write(&mut guard)
    }
}
