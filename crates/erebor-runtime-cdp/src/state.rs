use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use cdp_protocol::{page, runtime::ExecutionContextId, target, types::Event as ProtocolEvent};
use erebor_runtime_events::TargetRef;
use serde_json::{json, Value};

use crate::{
    BrowserTarget, BrowserTargetGraph, BrowserTargetId, CdpEvent, ClientTargetSessions,
    GovernedCdpCommand,
};

#[derive(Clone, Debug, Default)]
pub struct CdpSessionState {
    inner: Arc<Mutex<CdpSessionStateData>>,
}

impl CdpSessionState {
    #[must_use]
    pub fn from_browser_url(browser_url: &str) -> Self {
        let state = Self::default();
        if let Some(page_id) = page_id_from_browser_url(browser_url) {
            state.ensure_page(page_id);
        }

        state
    }

    #[must_use]
    pub fn snapshot(&self) -> CdpSessionSnapshot {
        self.with_data(CdpSessionStateData::snapshot)
    }

    #[must_use]
    pub fn target_for_command(&self, command: &GovernedCdpCommand) -> Option<TargetRef> {
        self.target_for_command_with_client_session(command, None, None)
    }

    #[must_use]
    pub fn target_for_command_with_client_session(
        &self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Option<TargetRef> {
        self.with_data(|data| {
            let explicit_target = command.target();
            let browser_target = client_session_id
                .and_then(|session_id| client_sessions?.target_for_session(session_id))
                .and_then(|target_id| data.target_graph.target(&target_id).cloned());
            let command_page = data.page_for_command(command);

            match explicit_target {
                Some(target) => Some(merge_target_with_context(
                    target,
                    browser_target.as_ref(),
                    command_page.as_ref(),
                )),
                None => browser_target
                    .as_ref()
                    .map(BrowserTarget::target_ref)
                    .or_else(|| command_page.as_ref().map(page_target)),
            }
        })
    }

    #[must_use]
    pub fn command_page_payload(&self, command: &GovernedCdpCommand) -> Value {
        self.command_page_payload_with_client_session(command, None, None)
    }

    #[must_use]
    pub fn command_page_payload_with_client_session(
        &self,
        command: &GovernedCdpCommand,
        client_session_id: Option<&str>,
        client_sessions: Option<&ClientTargetSessions>,
    ) -> Value {
        self.with_data(|data| {
            let snapshot = data.snapshot();
            let command_page = data.page_for_command(command);
            let browser_target = client_session_id
                .and_then(|session_id| client_sessions?.target_for_session(session_id))
                .and_then(|target_id| data.target_graph.target(&target_id).cloned());

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
        if let GovernedCdpCommand::PageNavigate(navigate) = command {
            self.with_data_mut(|data| {
                let target_id = client_session_id
                    .and_then(|session_id| client_sessions?.target_for_session(session_id));
                let page = match target_id.as_ref() {
                    Some(target_id) => {
                        data.active_page_id = Some(target_id.as_str().to_owned());
                        data.page_mut(target_id.as_str().to_owned())
                    }
                    None => data.provisional_active_page_mut(),
                };
                page.url = non_empty(&navigate.url);
                page.status = PageStatusKind::ProvisionalNavigation;
                if let Some(target_id) = target_id {
                    data.target_graph
                        .record_provisional_navigation(target_id, &navigate.url);
                }
            });
        }
    }

    pub fn record_browser_event(&self, event: &CdpEvent) {
        self.record_browser_event_for_client_session(event, None);
    }

    pub fn record_browser_event_for_client_session(
        &self,
        event: &CdpEvent,
        client_sessions: Option<&mut ClientTargetSessions>,
    ) {
        self.with_data_mut(|data| data.record_protocol_event(event, client_sessions));
    }

    pub fn record_frame_tree(&self, frame_tree: &page::FrameTree) {
        self.with_data_mut(|data| data.record_frame_tree(None, frame_tree));
    }

    pub fn record_frame_tree_for_target(
        &self,
        target_id: BrowserTargetId,
        frame_tree: &page::FrameTree,
    ) {
        self.with_data_mut(|data| data.record_frame_tree(Some(target_id), frame_tree));
    }

    pub fn record_target_info(&self, target_info: &target::TargetInfo) {
        self.with_data_mut(|data| data.record_target_info(target_info));
    }

    fn ensure_page(&self, page_id: String) {
        self.with_data_mut(|data| {
            data.ensure_page(page_id.clone());
            data.active_page_id = Some(page_id);
        });
    }

    fn with_data<T>(&self, read: impl FnOnce(&CdpSessionStateData) -> T) -> T {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&guard)
    }

    fn with_data_mut<T>(&self, write: impl FnOnce(&mut CdpSessionStateData) -> T) -> T {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write(&mut guard)
    }
}

#[derive(Clone, Debug, Default)]
struct CdpSessionStateData {
    pages: HashMap<String, PageStatus>,
    active_page_id: Option<String>,
    frame_to_page: HashMap<String, String>,
    execution_context_to_page: HashMap<ExecutionContextId, String>,
    target_graph: BrowserTargetGraph,
}

impl CdpSessionStateData {
    fn snapshot(&self) -> CdpSessionSnapshot {
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

    fn ensure_page(&mut self, page_id: String) {
        self.pages
            .entry(page_id.clone())
            .or_insert_with(|| PageStatus::new(page_id.clone()));
        self.target_graph
            .ensure_page_target(BrowserTargetId::new(page_id));
    }

    fn record_protocol_event(
        &mut self,
        event: &CdpEvent,
        mut client_sessions: Option<&mut ClientTargetSessions>,
    ) {
        let browser_target_id = event
            .session_id()
            .and_then(|session_id| client_sessions.as_deref()?.target_for_session(session_id));

        match event.protocol_event() {
            ProtocolEvent::PageFrameNavigated(event) => {
                let frame = &event.params.frame;
                let page_id = frame
                    .parent_id
                    .as_ref()
                    .and_then(|parent_frame_id| self.frame_to_page.get(parent_frame_id))
                    .cloned()
                    .unwrap_or_else(|| {
                        self.active_page_id
                            .clone()
                            .unwrap_or_else(|| frame.id.clone())
                    });
                let page_id = browser_target_id
                    .as_ref()
                    .map_or(page_id, |target_id| target_id.as_str().to_owned());
                let page = self.page_mut(page_id.clone());
                page.frame_id = Some(frame.id.clone());
                page.url = non_empty(&frame.url);
                page.status = PageStatusKind::Active;
                self.frame_to_page.insert(frame.id.clone(), page_id.clone());
                self.active_page_id = Some(page_id);
                self.target_graph.record_frame_navigated(
                    browser_target_id.unwrap_or_else(|| BrowserTargetId::new(frame.id.clone())),
                    frame,
                );
            }
            ProtocolEvent::PageNavigatedWithinDocument(event) => {
                let page_id = self
                    .frame_to_page
                    .get(&event.params.frame_id)
                    .cloned()
                    .unwrap_or_else(|| {
                        self.active_page_id
                            .clone()
                            .unwrap_or_else(|| event.params.frame_id.clone())
                    });
                let page_id = browser_target_id
                    .as_ref()
                    .map_or(page_id, |target_id| target_id.as_str().to_owned());
                let page = self.page_mut(page_id.clone());
                page.frame_id = Some(event.params.frame_id.clone());
                page.url = non_empty(&event.params.url);
                page.status = PageStatusKind::Active;
                self.frame_to_page
                    .insert(event.params.frame_id.clone(), page_id.clone());
                self.active_page_id = Some(page_id);
                self.target_graph.record_navigated_within_document(
                    browser_target_id
                        .unwrap_or_else(|| BrowserTargetId::new(event.params.frame_id.clone())),
                    event.params.frame_id.clone(),
                    &event.params.url,
                );
            }
            ProtocolEvent::RuntimeExecutionContextCreated(event) => {
                let context = &event.params.context;
                if let Some(frame_id) = frame_id_from_aux_data(context.aux_data.as_ref()) {
                    let page_id = self
                        .frame_to_page
                        .get(&frame_id)
                        .cloned()
                        .or_else(|| self.active_page_id.clone())
                        .unwrap_or_else(|| frame_id.clone());
                    self.page_mut(page_id.clone()).frame_id = Some(frame_id.clone());
                    self.frame_to_page.insert(frame_id, page_id.clone());
                    self.execution_context_to_page.insert(context.id, page_id);
                }
                self.target_graph.record_execution_context(
                    browser_target_id.unwrap_or_else(|| {
                        self.active_page_id.clone().map_or_else(
                            || BrowserTargetId::new("active-page"),
                            BrowserTargetId::new,
                        )
                    }),
                    context.id,
                    non_empty(&context.origin),
                    context.aux_data.as_ref(),
                );
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

    fn record_frame_tree(
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
        if let Some(target_id) = target_id {
            self.target_graph.record_frame_tree(target_id, frame_tree);
        } else {
            self.target_graph
                .record_frame_tree(BrowserTargetId::new(page_id.clone()), frame_tree);
        }
        self.record_frame_tree_for_page(&page_id, frame_tree, true);
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
            page.url = non_empty(&frame_tree.frame.url);
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

    fn page_for_command(&self, command: &GovernedCdpCommand) -> Option<PageStatus> {
        command_execution_context_id(command)
            .and_then(|context_id| self.execution_context_to_page.get(&context_id))
            .and_then(|page_id| self.pages.get(page_id))
            .cloned()
            .or_else(|| {
                command_execution_context_id(command)
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

    fn record_target_info(&mut self, target_info: &cdp_protocol::target::TargetInfo) {
        self.target_graph.record_target_info(target_info);
        if target_info.r#type == "page" {
            let page = self.page_mut(target_info.target_id.clone());
            page.url = non_empty(&target_info.url);
            page.title = non_empty(&target_info.title);
            page.status = PageStatusKind::Active;
            self.active_page_id = Some(target_info.target_id.clone());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CdpSessionSnapshot {
    pub active_page: Option<PageStatus>,
    pub pages: Vec<PageStatus>,
    pub targets: Vec<BrowserTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct PageStatus {
    pub id: String,
    pub url: Option<String>,
    pub title: Option<String>,
    pub frame_id: Option<String>,
    pub status: PageStatusKind,
}

impl PageStatus {
    fn new(id: String) -> Self {
        Self {
            id,
            url: None,
            title: None,
            frame_id: None,
            status: PageStatusKind::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageStatusKind {
    Active,
    ProvisionalNavigation,
    Closed,
    Crashed,
    Unknown,
}

fn command_execution_context_id(command: &GovernedCdpCommand) -> Option<ExecutionContextId> {
    match command {
        GovernedCdpCommand::RuntimeEvaluate(command) => command.context_id,
        GovernedCdpCommand::RuntimeCallFunctionOn(command) => command.execution_context_id,
        GovernedCdpCommand::InputDispatchMouseEvent(_)
        | GovernedCdpCommand::InputDispatchKeyEvent(_)
        | GovernedCdpCommand::PageNavigate(_)
        | GovernedCdpCommand::FetchContinueRequest(_)
        | GovernedCdpCommand::TargetManagement(_) => None,
    }
}

fn merge_target_with_context(
    target: TargetRef,
    browser_target: Option<&BrowserTarget>,
    active_page: Option<&PageStatus>,
) -> TargetRef {
    let label = target
        .label
        .or_else(|| browser_target.map(|target| target.id.as_str().to_owned()))
        .or_else(|| active_page.map(|page| page.id.clone()));
    let uri = target
        .uri
        .or_else(|| browser_target.and_then(|target| target.url.clone()))
        .or_else(|| active_page.and_then(|page| page.url.clone()));

    TargetRef { label, uri }
}

fn page_target(page: &PageStatus) -> TargetRef {
    TargetRef {
        label: Some(page.id.clone()),
        uri: page.url.clone(),
    }
}

fn page_id_from_browser_url(browser_url: &str) -> Option<String> {
    browser_url
        .rsplit_once("/devtools/page/")
        .map(|(_, page_id)| page_id)
        .and_then(|page_id| page_id.split('?').next())
        .filter(|page_id| !page_id.is_empty())
        .map(str::to_owned)
}

fn frame_id_from_aux_data(aux_data: Option<&Value>) -> Option<String> {
    aux_data?
        .get("frameId")
        .and_then(Value::as_str)
        .filter(|frame_id| !frame_id.is_empty())
        .map(str::to_owned)
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use cdp_protocol::page;

    use super::{CdpSessionState, PageStatusKind};
    use crate::{decode_cdp_command, GovernedCdpCommand};

    #[test]
    fn command_target_uses_provisional_page_url_for_script_eval(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
        let navigate = decode_cdp_command(
            r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
        )?;
        let Some(GovernedCdpCommand::PageNavigate(navigate)) = navigate.protocol_command() else {
            return Err(std::io::Error::other("expected page navigate command").into());
        };
        state.record_provisional_forwarded_command(&GovernedCdpCommand::PageNavigate(
            navigate.clone(),
        ));
        let evaluate = decode_cdp_command(
            r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
        )?;
        let target = evaluate
            .protocol_command()
            .and_then(|command| state.target_for_command(command));

        assert_eq!(
            target.and_then(|target| target.uri),
            Some(String::from("https://mail.example.test/compose"))
        );
        assert_eq!(
            state.snapshot().active_page.map(|page| page.status),
            Some(PageStatusKind::ProvisionalNavigation)
        );
        Ok(())
    }

    #[test]
    fn frame_tree_refresh_updates_browser_page_url() {
        let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
        let frame_tree = frame_tree("https://browser-state.example.test/compose");

        state.record_frame_tree(&frame_tree);

        assert_eq!(
            state.snapshot().active_page.and_then(|page| page.url),
            Some(String::from("https://browser-state.example.test/compose"))
        );
    }

    #[test]
    fn browser_confirmed_frame_tree_overrides_provisional_command_context(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
        let navigate = decode_cdp_command(
            r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
        )?;
        let Some(GovernedCdpCommand::PageNavigate(navigate)) = navigate.protocol_command() else {
            return Err(std::io::Error::other("expected page navigate command").into());
        };
        state.record_provisional_forwarded_command(&GovernedCdpCommand::PageNavigate(
            navigate.clone(),
        ));
        state.record_frame_tree(&frame_tree("https://calendar.example.test/day"));

        let evaluate = decode_cdp_command(
            r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
        )?;
        let target = evaluate
            .protocol_command()
            .and_then(|command| state.target_for_command(command));

        assert_eq!(
            target.and_then(|target| target.uri),
            Some(String::from("https://calendar.example.test/day"))
        );
        assert_eq!(
            state.snapshot().active_page.map(|page| page.status),
            Some(PageStatusKind::Active)
        );
        Ok(())
    }

    fn frame_tree(url: &str) -> page::FrameTree {
        page::FrameTree {
            frame: page::Frame {
                id: String::from("frame-1"),
                parent_id: None,
                loader_id: String::from("loader-1"),
                name: None,
                url: url.to_owned(),
                url_fragment: None,
                domain_and_registry: String::from("example.test"),
                security_origin: String::from("https://browser-state.example.test"),
                security_origin_details: None,
                mime_type: String::from("text/html"),
                unreachable_url: None,
                ad_frame_status: None,
                secure_context_type: page::SecureContextType::Secure,
                cross_origin_isolated_context_type:
                    page::CrossOriginIsolatedContextType::NotIsolated,
                gated_api_features: vec![],
            },
            child_frames: None,
        }
    }
}
