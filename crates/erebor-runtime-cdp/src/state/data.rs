use std::collections::HashMap;

use cdp_protocol::{page, runtime::ExecutionContextId, target, types::Event as ProtocolEvent};

use super::{projection::SessionStateProjection, CdpSessionSnapshot, PageStatus, PageStatusKind};
use crate::{
    BrowserTarget, BrowserTargetGraph, BrowserTargetId, CdpEvent, ClientTargetSessions,
    GovernedCdpCommand,
};

mod events;

#[derive(Clone, Debug, Default)]
pub(super) struct CdpSessionStateData {
    pages: HashMap<String, PageStatus>,
    active_page_id: Option<String>,
    frame_to_page: HashMap<String, String>,
    execution_context_to_page: HashMap<ExecutionContextId, String>,
    target_graph: BrowserTargetGraph,
}

impl CdpSessionStateData {
    pub(super) fn snapshot(&self) -> CdpSessionSnapshot {
        let mut pages = self.pages.values().cloned().collect::<Vec<_>>();
        pages.sort_by(|left, right| left.id.cmp(&right.id));
        let active_page = self
            .active_page_id
            .as_ref()
            .and_then(|page_id| self.pages.get(page_id))
            .cloned();

        CdpSessionSnapshot {
            active_page,
            pages,
            targets: self.target_graph.targets(),
        }
    }

    pub(super) fn set_active_page(&mut self, page_id: String) {
        self.active_page_id = Some(page_id);
    }

    pub(super) fn ensure_page(&mut self, page_id: String) {
        self.pages
            .entry(page_id.clone())
            .or_insert_with(|| PageStatus::new(page_id.clone()));
        self.target_graph
            .ensure_page_target(BrowserTargetId::new(page_id));
    }

    pub(super) fn record_provisional_forwarded_command(
        &mut self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) {
        if let GovernedCdpCommand::PageNavigate(navigate) = command {
            let target_id = client_session_id
                .and_then(|session_id| client_sessions?.target_for_session(session_id));
            let page = match target_id.as_ref() {
                Some(target_id) => {
                    self.active_page_id = Some(target_id.as_str().to_owned());
                    self.page_mut(target_id.as_str().to_owned())
                }
                None => self.provisional_active_page_mut(),
            };
            page.url = SessionStateProjection::non_empty(&navigate.url);
            page.status = PageStatusKind::ProvisionalNavigation;
            if let Some(target_id) = target_id {
                self.target_graph
                    .record_provisional_navigation(target_id, &navigate.url);
            }
        }
    }

    pub(super) fn record_protocol_event(
        &mut self,
        event: &CdpEvent,
        mut client_sessions: Option<&mut ClientTargetSessions>,
    ) {
        let browser_target_id = event
            .session_id()
            .and_then(|session_id| client_sessions.as_deref()?.target_for_session(session_id));

        match event.protocol_event() {
            ProtocolEvent::PageFrameNavigated(event) => {
                self.record_page_frame_navigated(browser_target_id, &event.params.frame);
            }
            ProtocolEvent::PageNavigatedWithinDocument(event) => {
                self.record_page_navigated_within_document(browser_target_id, event);
            }
            ProtocolEvent::RuntimeExecutionContextCreated(event) => {
                self.record_execution_context(browser_target_id, event);
            }
            ProtocolEvent::AttachedToTarget(event) => {
                let target_id = BrowserTargetId::new(event.params.target_info.target_id.clone());
                if let Some(client_sessions) = client_sessions.as_mut() {
                    (*client_sessions).record_attached(event.params.session_id.clone(), target_id);
                }
                self.record_target_info(&event.params.target_info);
            }
            ProtocolEvent::DetachedFromTarget(event) => {
                if let Some(client_sessions) = client_sessions.as_mut() {
                    (*client_sessions).record_detached(event.params.session_id.clone());
                }
            }
            ProtocolEvent::TargetCreated(event) => {
                self.record_target_info(&event.params.target_info);
            }
            ProtocolEvent::TargetInfoChanged(event) => {
                self.record_target_info(&event.params.target_info);
            }
            ProtocolEvent::TargetDestroyed(event) => {
                self.target_graph
                    .record_target_destroyed(event.params.target_id.clone());
                if let Some(page) = self.pages.get_mut(&event.params.target_id) {
                    page.status = PageStatusKind::Closed;
                }
            }
            ProtocolEvent::TargetCrashed(event) => {
                self.target_graph
                    .record_target_crashed(event.params.target_id.clone());
                if let Some(page) = self.pages.get_mut(&event.params.target_id) {
                    page.status = PageStatusKind::Crashed;
                }
            }
            _ => {}
        }
    }

    pub(super) fn record_frame_tree(
        &mut self,
        target_id: Option<BrowserTargetId>,
        frame_tree: &page::FrameTree,
    ) {
        let page_id = target_id.as_ref().map_or_else(
            || {
                self.active_page_id
                    .clone()
                    .unwrap_or_else(|| frame_tree.frame.id.clone())
            },
            |target_id| target_id.as_str().to_owned(),
        );
        self.active_page_id = Some(page_id.clone());
        self.target_graph.record_frame_tree(
            target_id.unwrap_or_else(|| BrowserTargetId::new(page_id.clone())),
            frame_tree,
        );
        self.record_frame_tree_for_page(&page_id, frame_tree, true);
    }

    pub(super) fn page_for_command(&self, command: &GovernedCdpCommand) -> Option<PageStatus> {
        SessionStateProjection::command_execution_context_id(command)
            .and_then(|context_id| self.execution_context_to_page.get(&context_id))
            .and_then(|page_id| self.pages.get(page_id))
            .cloned()
            .or_else(|| {
                SessionStateProjection::command_execution_context_id(command)
                    .and_then(|context_id| {
                        self.target_graph.target_for_execution_context(context_id)
                    })
                    .and_then(|target| self.pages.get(target.id.as_str()))
                    .cloned()
            })
            .or_else(|| {
                self.active_page_id
                    .as_ref()
                    .and_then(|page_id| self.pages.get(page_id))
                    .cloned()
            })
    }

    pub(super) fn browser_target_for_client_session(
        &self,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Option<BrowserTarget> {
        client_session_id
            .and_then(|session_id| client_sessions?.target_for_session(session_id))
            .and_then(|target_id| self.target_graph.target(&target_id).cloned())
    }

    pub(super) fn record_target_info(&mut self, target_info: &target::TargetInfo) {
        self.target_graph.record_target_info(target_info);
        if target_info.r#type == "page" {
            let page = self.page_mut(target_info.target_id.clone());
            page.url = SessionStateProjection::non_empty(&target_info.url);
            page.title = SessionStateProjection::non_empty(&target_info.title);
            page.status = PageStatusKind::Active;
            self.active_page_id = Some(target_info.target_id.clone());
        }
    }

    fn provisional_active_page_mut(&mut self) -> &mut PageStatus {
        let page_id = self
            .active_page_id
            .clone()
            .unwrap_or_else(|| String::from("active-page"));
        self.active_page_id = Some(page_id.clone());

        self.pages
            .entry(page_id.clone())
            .or_insert_with(|| PageStatus::new(page_id))
    }

    fn record_frame_tree_for_page(
        &mut self,
        page_id: &str,
        frame_tree: &page::FrameTree,
        main_frame: bool,
    ) {
        self.frame_to_page
            .insert(frame_tree.frame.id.clone(), page_id.to_owned());

        if main_frame {
            let page = self.page_mut(page_id.to_owned());
            page.frame_id = Some(frame_tree.frame.id.clone());
            page.url = SessionStateProjection::non_empty(&frame_tree.frame.url);
            page.status = PageStatusKind::Active;
        }

        if let Some(child_frames) = &frame_tree.child_frames {
            for child_frame in child_frames {
                self.record_frame_tree_for_page(page_id, child_frame, false);
            }
        }
    }

    fn page_mut(&mut self, page_id: String) -> &mut PageStatus {
        self.pages
            .entry(page_id.clone())
            .or_insert_with(|| PageStatus::new(page_id))
    }
}
