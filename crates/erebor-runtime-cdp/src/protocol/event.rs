use cdp_protocol::types::Event as ProtocolEvent;
use erebor_runtime_events::TargetRef;
use serde_json::Value;

use super::{target_reference::TargetReferenceDecoder, wire::ProtocolWire};
use crate::CdpError;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpEvent {
    method: &'static str,
    session_id: Option<String>,
    event_id: String,
    target: Option<TargetRef>,
    params: Value,
    protocol: ProtocolEvent,
}

impl CdpEvent {
    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }

    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    #[must_use]
    pub fn target(&self) -> Option<TargetRef> {
        self.target.clone()
    }

    #[must_use]
    pub const fn params(&self) -> &Value {
        &self.params
    }

    #[must_use]
    pub const fn protocol_event(&self) -> &ProtocolEvent {
        &self.protocol
    }

    pub(super) fn from_protocol(
        protocol: ProtocolEvent,
        session_id: Option<String>,
    ) -> Result<Option<Self>, CdpError> {
        let event = match protocol {
            ProtocolEvent::FetchRequestPaused(event) => Self {
                method: "Fetch.requestPaused",
                session_id,
                event_id: event.params.request_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.request_id.clone()),
                    TargetReferenceDecoder::non_empty(&event.params.request.url),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::FetchRequestPaused(event),
            },
            ProtocolEvent::NetworkRequestWillBeSent(event) => Self {
                method: "Network.requestWillBeSent",
                session_id,
                event_id: event.params.request_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.request_id.clone()),
                    TargetReferenceDecoder::non_empty(&event.params.request.url)
                        .or_else(|| TargetReferenceDecoder::non_empty(&event.params.document_url)),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkRequestWillBeSent(event),
            },
            ProtocolEvent::NetworkResponseReceived(event) => Self {
                method: "Network.responseReceived",
                session_id,
                event_id: event.params.request_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.request_id.clone()),
                    TargetReferenceDecoder::non_empty(&event.params.response.url),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkResponseReceived(event),
            },
            ProtocolEvent::NetworkLoadingFailed(event) => Self {
                method: "Network.loadingFailed",
                session_id,
                event_id: event.params.request_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.request_id.clone()),
                    None,
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkLoadingFailed(event),
            },
            ProtocolEvent::PageFrameNavigated(event) => Self {
                method: "Page.frameNavigated",
                session_id,
                event_id: event.params.frame.id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.frame.id.clone()),
                    TargetReferenceDecoder::non_empty(&event.params.frame.url),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::PageFrameNavigated(event),
            },
            ProtocolEvent::PageNavigatedWithinDocument(event) => Self {
                method: "Page.navigatedWithinDocument",
                session_id,
                event_id: event.params.frame_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.frame_id.clone()),
                    TargetReferenceDecoder::non_empty(&event.params.url),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::PageNavigatedWithinDocument(event),
            },
            ProtocolEvent::RuntimeExecutionContextCreated(event) => Self {
                method: "Runtime.executionContextCreated",
                session_id,
                event_id: event.params.context.id.to_string(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.context.id.to_string()),
                    TargetReferenceDecoder::non_empty(&event.params.context.origin),
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::RuntimeExecutionContextCreated(event),
            },
            ProtocolEvent::AttachedToTarget(event) => Self {
                method: "Target.attachedToTarget",
                session_id,
                event_id: event.params.session_id.clone(),
                target: TargetReferenceDecoder::from_target_info(&event.params.target_info),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::AttachedToTarget(event),
            },
            ProtocolEvent::DetachedFromTarget(event) => {
                #[allow(deprecated)]
                let target_id = event.params.target_id.clone();
                Self {
                    method: "Target.detachedFromTarget",
                    session_id,
                    event_id: event.params.session_id.clone(),
                    target: target_id.and_then(|target_id| {
                        TargetReferenceDecoder::from_label_uri(Some(target_id), None)
                    }),
                    params: ProtocolWire::params_value(&event.params)?,
                    protocol: ProtocolEvent::DetachedFromTarget(event),
                }
            }
            ProtocolEvent::TargetCreated(event) => Self {
                method: "Target.targetCreated",
                session_id,
                event_id: event.params.target_info.target_id.clone(),
                target: TargetReferenceDecoder::from_target_info(&event.params.target_info),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::TargetCreated(event),
            },
            ProtocolEvent::TargetDestroyed(event) => Self {
                method: "Target.targetDestroyed",
                session_id,
                event_id: event.params.target_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.target_id.clone()),
                    None,
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::TargetDestroyed(event),
            },
            ProtocolEvent::TargetCrashed(event) => Self {
                method: "Target.targetCrashed",
                session_id,
                event_id: event.params.target_id.clone(),
                target: TargetReferenceDecoder::from_label_uri(
                    Some(event.params.target_id.clone()),
                    None,
                ),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::TargetCrashed(event),
            },
            ProtocolEvent::TargetInfoChanged(event) => Self {
                method: "Target.targetInfoChanged",
                session_id,
                event_id: event.params.target_info.target_id.clone(),
                target: TargetReferenceDecoder::from_target_info(&event.params.target_info),
                params: ProtocolWire::params_value(&event.params)?,
                protocol: ProtocolEvent::TargetInfoChanged(event),
            },
            _ => return Ok(None),
        };

        Ok(Some(event))
    }
}
