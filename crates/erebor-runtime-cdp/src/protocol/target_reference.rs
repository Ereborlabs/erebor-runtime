use cdp_protocol::target;
use erebor_runtime_events::TargetRef;
use serde_json::Value;

pub(super) struct TargetReferenceDecoder;

impl TargetReferenceDecoder {
    pub(super) fn from_label_uri(label: Option<String>, uri: Option<String>) -> Option<TargetRef> {
        if label.is_none() && uri.is_none() {
            return None;
        }

        Some(TargetRef { label, uri })
    }

    pub(super) fn from_target_info(target_info: &target::TargetInfo) -> Option<TargetRef> {
        Self::from_label_uri(
            Some(target_info.target_id.clone()),
            Self::non_empty(&target_info.url),
        )
    }

    pub(super) fn from_id(target_id: &str) -> Option<TargetRef> {
        (!target_id.is_empty()).then(|| TargetRef {
            label: Some(target_id.to_owned()),
            uri: None,
        })
    }

    pub(super) fn from_params(params: &Value) -> Option<TargetRef> {
        params
            .get("targetId")
            .and_then(Value::as_str)
            .filter(|target_id| !target_id.is_empty())
            .map(|target_id| TargetRef {
                label: Some(target_id.to_owned()),
                uri: None,
            })
    }

    pub(super) fn non_empty(value: &str) -> Option<String> {
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    }
}
