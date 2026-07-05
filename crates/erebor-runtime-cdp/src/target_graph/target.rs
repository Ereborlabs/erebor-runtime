use cdp_protocol::runtime::ExecutionContextId;
use erebor_runtime_events::TargetRef;
use serde::Serialize;

use super::{BrowserTargetId, FrameId};

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
    pub(super) fn new(id: BrowserTargetId) -> Self {
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

    pub(super) fn unknown_page(id: BrowserTargetId) -> Self {
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
