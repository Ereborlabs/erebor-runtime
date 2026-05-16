use std::collections::BTreeMap;

use cdp_protocol::{page, runtime::ExecutionContextId, target};
use erebor_runtime_events::TargetRef;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct BrowserTargetId(String);

impl BrowserTargetId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClientSessionId(String);

impl ClientSessionId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct FrameId(String);

impl FrameId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BrowserTargetGraph {
    targets: BTreeMap<BrowserTargetId, BrowserTarget>,
    frames: BTreeMap<FrameId, FrameState>,
    execution_contexts: BTreeMap<ExecutionContextId, ExecutionContextState>,
}

impl BrowserTargetGraph {
    #[must_use]
    pub fn targets(&self) -> Vec<BrowserTarget> {
        self.targets.values().cloned().collect()
    }

    #[must_use]
    pub fn target(&self, target_id: &BrowserTargetId) -> Option<&BrowserTarget> {
        self.targets.get(target_id)
    }

    #[must_use]
    pub fn target_for_execution_context(
        &self,
        context_id: ExecutionContextId,
    ) -> Option<&BrowserTarget> {
        self.execution_contexts
            .get(&context_id)
            .and_then(|context| self.targets.get(&context.target_id))
    }

    pub fn ensure_page_target(&mut self, target_id: BrowserTargetId) {
        self.targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::unknown_page(target_id));
    }

    pub fn record_provisional_navigation(&mut self, target_id: BrowserTargetId, url: &str) {
        let target = self
            .targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::unknown_page(target_id));
        target.url = non_empty(url);
        target.status = BrowserTargetStatus::ProvisionalNavigation;
    }

    pub fn record_target_info(&mut self, target_info: &target::TargetInfo) {
        let target_id = BrowserTargetId::new(target_info.target_id.clone());
        let target = self
            .targets
            .entry(target_id.clone())
            .or_insert_with(|| BrowserTarget::new(target_id));
        target.kind = BrowserTargetKind::from_cdp_target_type(&target_info.r#type);
        target.url = non_empty(&target_info.url);
        target.title = non_empty(&target_info.title);
        target.opener = target_info
            .opener_id
            .as_ref()
            .map(|opener_id| BrowserTargetId::new(opener_id.clone()));
        target.attached = target_info.attached;
        target.status = if target.attached {
            BrowserTargetStatus::Attached
        } else {
            BrowserTargetStatus::Created
        };
    }

    pub fn record_target_attached(&mut self, target_info: &target::TargetInfo) {
        self.record_target_info(target_info);
        let target_id = BrowserTargetId::new(target_info.target_id.clone());
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.attached = true;
            target.status = BrowserTargetStatus::Attached;
        }
    }

    pub fn record_target_destroyed(&mut self, target_id: impl Into<String>) {
        let target_id = BrowserTargetId::new(target_id);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.status = BrowserTargetStatus::Closed;
            target.attached = false;
        }
    }

    pub fn record_target_crashed(&mut self, target_id: impl Into<String>) {
        let target_id = BrowserTargetId::new(target_id);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.status = BrowserTargetStatus::Crashed;
            target.attached = false;
        }
    }

    pub fn record_frame_tree(&mut self, target_id: BrowserTargetId, frame_tree: &page::FrameTree) {
        self.record_frame_tree_inner(target_id, frame_tree, None, true);
    }

    pub fn record_frame_navigated(&mut self, target_id: BrowserTargetId, frame: &page::Frame) {
        let frame_id = FrameId::new(frame.id.clone());
        let parent_frame_id = frame.parent_id.as_ref().map(|id| FrameId::new(id.clone()));
        self.frames.insert(
            frame_id.clone(),
            FrameState {
                id: frame_id,
                target_id: target_id.clone(),
                parent_frame_id,
                url: non_empty(&frame.url),
            },
        );
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.url = non_empty(&frame.url);
            target.status = BrowserTargetStatus::Active;
        }
    }

    pub fn record_navigated_within_document(
        &mut self,
        target_id: BrowserTargetId,
        frame_id: impl Into<String>,
        url: &str,
    ) {
        let frame_id = FrameId::new(frame_id);
        let frame = self
            .frames
            .entry(frame_id.clone())
            .or_insert_with(|| FrameState {
                id: frame_id,
                target_id: target_id.clone(),
                parent_frame_id: None,
                url: None,
            });
        frame.url = non_empty(url);
        if let Some(target) = self.targets.get_mut(&target_id) {
            target.url = non_empty(url);
            target.status = BrowserTargetStatus::Active;
        }
    }

    pub fn record_execution_context(
        &mut self,
        fallback_target_id: BrowserTargetId,
        context_id: ExecutionContextId,
        origin: Option<String>,
        aux_data: Option<&Value>,
    ) {
        let frame_id = frame_id_from_aux_data(aux_data).map(FrameId::new);
        let target_id = frame_id
            .as_ref()
            .and_then(|frame_id| self.frames.get(frame_id))
            .map_or(fallback_target_id, |frame| frame.target_id.clone());

        self.execution_contexts.insert(
            context_id,
            ExecutionContextState {
                id: context_id,
                target_id,
                frame_id,
                origin,
            },
        );
    }

    fn record_frame_tree_inner(
        &mut self,
        target_id: BrowserTargetId,
        frame_tree: &page::FrameTree,
        parent_frame_id: Option<FrameId>,
        main_frame: bool,
    ) {
        let frame_id = FrameId::new(frame_tree.frame.id.clone());
        self.frames.insert(
            frame_id.clone(),
            FrameState {
                id: frame_id.clone(),
                target_id: target_id.clone(),
                parent_frame_id,
                url: non_empty(&frame_tree.frame.url),
            },
        );

        if main_frame {
            let target = self
                .targets
                .entry(target_id.clone())
                .or_insert_with(|| BrowserTarget::unknown_page(target_id.clone()));
            target.url = non_empty(&frame_tree.frame.url);
            target.status = BrowserTargetStatus::Active;
        }

        if let Some(child_frames) = &frame_tree.child_frames {
            for child_frame in child_frames {
                self.record_frame_tree_inner(
                    target_id.clone(),
                    child_frame,
                    Some(frame_id.clone()),
                    false,
                );
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrowserTarget {
    pub id: BrowserTargetId,
    pub kind: BrowserTargetKind,
    pub status: BrowserTargetStatus,
    pub url: Option<String>,
    pub title: Option<String>,
    pub opener: Option<BrowserTargetId>,
    pub attached: bool,
}

impl BrowserTarget {
    fn new(id: BrowserTargetId) -> Self {
        Self {
            id,
            kind: BrowserTargetKind::Other(String::new()),
            status: BrowserTargetStatus::Unknown,
            url: None,
            title: None,
            opener: None,
            attached: false,
        }
    }

    fn unknown_page(id: BrowserTargetId) -> Self {
        Self {
            id,
            kind: BrowserTargetKind::Page,
            status: BrowserTargetStatus::Unknown,
            url: None,
            title: None,
            opener: None,
            attached: false,
        }
    }

    #[must_use]
    pub fn target_ref(&self) -> TargetRef {
        TargetRef {
            label: Some(self.id.as_str().to_owned()),
            uri: self.url.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTargetKind {
    Page,
    BackgroundPage,
    ServiceWorker,
    SharedWorker,
    Iframe,
    Other(String),
}

impl BrowserTargetKind {
    #[must_use]
    pub fn from_cdp_target_type(kind: &str) -> Self {
        match kind {
            "page" => Self::Page,
            "background_page" => Self::BackgroundPage,
            "service_worker" => Self::ServiceWorker,
            "shared_worker" => Self::SharedWorker,
            "iframe" => Self::Iframe,
            other => Self::Other(other.to_owned()),
        }
    }

    #[must_use]
    pub const fn is_page_like(&self) -> bool {
        matches!(self, Self::Page | Self::BackgroundPage | Self::Iframe)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTargetStatus {
    Created,
    Attached,
    Active,
    ProvisionalNavigation,
    Closed,
    Crashed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FrameState {
    pub id: FrameId,
    pub target_id: BrowserTargetId,
    pub parent_frame_id: Option<FrameId>,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionContextState {
    pub id: ExecutionContextId,
    pub target_id: BrowserTargetId,
    pub frame_id: Option<FrameId>,
    pub origin: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientTargetSessions {
    sessions: BTreeMap<ClientSessionId, BrowserTargetId>,
}

impl ClientTargetSessions {
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
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

fn frame_id_from_aux_data(aux_data: Option<&Value>) -> Option<String> {
    aux_data?
        .get("frameId")
        .and_then(Value::as_str)
        .filter(|frame_id| !frame_id.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use cdp_protocol::target;

    use super::{BrowserTargetGraph, BrowserTargetId, BrowserTargetKind, BrowserTargetStatus};

    #[test]
    fn target_graph_stores_multiple_page_targets() {
        let mut graph = BrowserTargetGraph::default();

        graph.record_target_info(&target_info("page-1", "page", "https://mail.example.test/"));
        graph.record_target_info(&target_info(
            "page-2",
            "page",
            "https://calendar.example.test/",
        ));

        let targets = graph.targets();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            graph
                .target(&BrowserTargetId::new("page-1"))
                .and_then(|target| target.url.clone()),
            Some(String::from("https://mail.example.test/"))
        );
    }

    #[test]
    fn target_graph_records_popup_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
        let mut graph = BrowserTargetGraph::default();
        let mut popup = target_info("popup-1", "page", "https://popup.example.test/");
        popup.opener_id = Some(String::from("page-1"));

        graph.record_target_info(&popup);
        graph.record_target_destroyed("popup-1");

        let target = graph
            .target(&BrowserTargetId::new("popup-1"))
            .ok_or_else(|| std::io::Error::other("target should exist"))?;
        assert_eq!(target.kind, BrowserTargetKind::Page);
        assert_eq!(
            target.opener.as_ref().map(BrowserTargetId::as_str),
            Some("page-1")
        );
        assert_eq!(target.status, BrowserTargetStatus::Closed);
        Ok(())
    }

    fn target_info(id: &str, kind: &str, url: &str) -> target::TargetInfo {
        target::TargetInfo {
            target_id: id.to_owned(),
            r#type: kind.to_owned(),
            title: String::new(),
            url: url.to_owned(),
            attached: false,
            opener_id: None,
            can_access_opener: false,
            opener_frame_id: None,
            parent_frame_id: None,
            browser_context_id: None,
            subtype: None,
        }
    }
}
