use cdp_protocol::{fetch, input, page, runtime};
use erebor_runtime_events::TargetRef;
use serde_json::Value;

use super::{target_management::TargetManagementCommand, target_reference::TargetReferenceDecoder};

#[derive(Clone, Debug, PartialEq)]
pub struct CdpCommand {
    pub id: cdp_protocol::types::CallId,
    pub method: String,
    pub session_id: Option<String>,
    params: Option<Value>,
    protocol: Option<GovernedCdpCommand>,
}

impl CdpCommand {
    pub(super) fn new(
        id: cdp_protocol::types::CallId,
        method: String,
        session_id: Option<String>,
        params: Option<Value>,
        protocol: Option<GovernedCdpCommand>,
    ) -> Self {
        Self {
            id,
            method,
            session_id,
            params,
            protocol,
        }
    }

    #[must_use]
    pub fn protocol_command(&self) -> Option<&GovernedCdpCommand> {
        self.protocol.as_ref()
    }

    #[must_use]
    pub fn params(&self) -> Option<&Value> {
        self.params.as_ref()
    }
}

#[allow(deprecated)]
#[derive(Clone, Debug, PartialEq)]
pub enum GovernedCdpCommand {
    RuntimeEvaluate(Box<runtime::Evaluate>),
    RuntimeCallFunctionOn(Box<runtime::CallFunctionOn>),
    InputDispatchMouseEvent(Box<input::DispatchMouseEvent>),
    InputDispatchKeyEvent(Box<input::DispatchKeyEvent>),
    PageNavigate(Box<page::Navigate>),
    FetchContinueRequest(Box<fetch::ContinueRequest>),
    TargetManagement(Box<TargetManagementCommand>),
}

impl GovernedCdpCommand {
    #[must_use]
    pub fn target(&self) -> Option<TargetRef> {
        match self {
            Self::PageNavigate(command) => TargetReferenceDecoder::from_label_uri(
                None,
                TargetReferenceDecoder::non_empty(&command.url),
            ),
            Self::FetchContinueRequest(command) => TargetReferenceDecoder::from_label_uri(
                Some(command.request_id.clone()),
                command.url.clone(),
            ),
            Self::TargetManagement(command) => command.target(),
            Self::RuntimeEvaluate(_)
            | Self::RuntimeCallFunctionOn(_)
            | Self::InputDispatchMouseEvent(_)
            | Self::InputDispatchKeyEvent(_) => None,
        }
    }
}
