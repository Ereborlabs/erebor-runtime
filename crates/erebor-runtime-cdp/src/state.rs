use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use cdp_protocol::{runtime::ExecutionContextId, types::Event as ProtocolEvent};
use erebor_runtime_events::TargetRef;
use serde_json::{json, Value};

use crate::{CdpEvent, GovernedCdpCommand};

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
        self.with_data(|data| {
            let explicit_target = command.target();
            let command_page = data.page_for_command(command);

            match explicit_target {
                Some(target) => Some(merge_target_with_page(target, command_page.as_ref())),
                None => command_page.as_ref().map(page_target),
            }
        })
    }

    #[must_use]
    pub fn command_page_payload(&self, command: &GovernedCdpCommand) -> Value {
        self.with_data(|data| {
            let snapshot = data.snapshot();
            let command_page = data.page_for_command(command);

            json!({
                "active_page": snapshot.active_page,
                "command_page": command_page,
                "pages": snapshot.pages,
            })
        })
    }

    pub fn record_forwarded_command(&self, command: &GovernedCdpCommand) {
        if let GovernedCdpCommand::PageNavigate(navigate) = command {
            self.with_data_mut(|data| {
                let page = data.active_page_mut();
                page.url = non_empty(&navigate.url);
                page.status = PageStatusKind::Loading;
            });
        }
    }

    pub fn record_browser_event(&self, event: &CdpEvent) {
        self.with_data_mut(|data| data.record_protocol_event(event.protocol_event()));
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

        CdpSessionSnapshot { active_page, pages }
    }

    fn active_page_mut(&mut self) -> &mut PageStatus {
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
            .or_insert_with(|| PageStatus::new(page_id));
    }

    fn record_protocol_event(&mut self, event: &ProtocolEvent) {
        match event {
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
                let page = self.page_mut(page_id.clone());
                page.frame_id = Some(frame.id.clone());
                page.url = non_empty(&frame.url);
                page.status = PageStatusKind::Active;
                self.frame_to_page.insert(frame.id.clone(), page_id.clone());
                self.active_page_id = Some(page_id);
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
                let page = self.page_mut(page_id.clone());
                page.frame_id = Some(event.params.frame_id.clone());
                page.url = non_empty(&event.params.url);
                page.status = PageStatusKind::Active;
                self.frame_to_page
                    .insert(event.params.frame_id.clone(), page_id.clone());
                self.active_page_id = Some(page_id);
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
            }
            ProtocolEvent::TargetCreated(event) => {
                self.record_target_info(&event.params.target_info);
            }
            ProtocolEvent::TargetInfoChanged(event) => {
                self.record_target_info(&event.params.target_info);
            }
            ProtocolEvent::TargetDestroyed(event) => {
                if let Some(page) = self.pages.get_mut(&event.params.target_id) {
                    page.status = PageStatusKind::Closed;
                }
            }
            ProtocolEvent::TargetCrashed(event) => {
                if let Some(page) = self.pages.get_mut(&event.params.target_id) {
                    page.status = PageStatusKind::Crashed;
                }
            }
            _ => {}
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
                self.active_page_id
                    .as_ref()
                    .and_then(|page_id| self.pages.get(page_id))
                    .cloned()
            })
    }

    fn record_target_info(&mut self, target_info: &cdp_protocol::target::TargetInfo) {
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
    Loading,
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
        | GovernedCdpCommand::FetchContinueRequest(_) => None,
    }
}

fn merge_target_with_page(target: TargetRef, active_page: Option<&PageStatus>) -> TargetRef {
    let label = target
        .label
        .or_else(|| active_page.map(|page| page.id.clone()));
    let uri = target
        .uri
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
    use super::CdpSessionState;
    use crate::{decode_cdp_command, GovernedCdpCommand};

    #[test]
    fn command_target_uses_active_page_url_for_script_eval(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
        let navigate = decode_cdp_command(
            r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
        )?;
        let Some(GovernedCdpCommand::PageNavigate(navigate)) = navigate.protocol_command() else {
            return Err(std::io::Error::other("expected page navigate command").into());
        };
        state.record_forwarded_command(&GovernedCdpCommand::PageNavigate(navigate.clone()));
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
        Ok(())
    }
}
