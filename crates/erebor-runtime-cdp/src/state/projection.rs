use cdp_protocol::runtime::ExecutionContextId;
use erebor_runtime_events::TargetRef;
use serde_json::Value;

use super::PageStatus;
use crate::{BrowserTarget, GovernedCdpCommand};

pub(super) struct SessionStateProjection;

impl SessionStateProjection {
    pub(super) fn command_execution_context_id(
        command: &GovernedCdpCommand,
    ) -> Option<ExecutionContextId> {
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

    pub(super) fn merge_target_context(
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

    pub(super) fn page_target(page: &PageStatus) -> TargetRef {
        TargetRef {
            label: Some(page.id.clone()),
            uri: page.url.clone(),
        }
    }

    pub(super) fn page_id_from_browser_url(browser_url: &str) -> Option<String> {
        browser_url
            .rsplit_once("/devtools/page/")
            .map(|(_, page_id)| page_id)
            .and_then(|page_id| page_id.split('?').next())
            .filter(|page_id| !page_id.is_empty())
            .map(str::to_owned)
    }

    pub(super) fn frame_id_from_aux_data(aux_data: Option<&Value>) -> Option<String> {
        aux_data?
            .get("frameId")
            .and_then(Value::as_str)
            .filter(|frame_id| !frame_id.is_empty())
            .map(str::to_owned)
    }

    pub(super) fn non_empty(value: &str) -> Option<String> {
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    }
}
