mod graph;
mod ids;
mod sessions;
mod target;

#[cfg(test)]
mod tests;

pub use graph::BrowserTargetGraph;
pub use ids::{BrowserTargetId, ClientSessionId, FrameId};
pub use sessions::ClientTargetSessions;
pub use target::{
    BrowserTarget, BrowserTargetKind, BrowserTargetStatus, ExecutionContextState, FrameState,
};

pub(crate) struct TargetGraphValue;

impl TargetGraphValue {
    pub(crate) fn non_empty(value: &str) -> Option<String> {
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    }

    pub(crate) fn frame_id_from_aux_data(aux_data: Option<&serde_json::Value>) -> Option<String> {
        aux_data?
            .get("frameId")
            .and_then(serde_json::Value::as_str)
            .filter(|frame_id| !frame_id.is_empty())
            .map(str::to_owned)
    }
}
