use crate::BrowserTarget;

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
    pub(super) fn new(id: String) -> Self {
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
