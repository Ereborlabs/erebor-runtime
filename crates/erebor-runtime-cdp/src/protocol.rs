use cdp_protocol::{
    fetch, input, page, runtime,
    types::{CallId, Event as ProtocolEvent, Method},
};
use erebor_runtime_events::TargetRef;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::CdpError;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpCommand {
    pub id: CallId,
    pub method: String,
    params: Option<Value>,
    protocol: Option<GovernedCdpCommand>,
}

impl CdpCommand {
    #[must_use]
    pub fn protocol_command(&self) -> Option<&GovernedCdpCommand> {
        self.protocol.as_ref()
    }

    #[must_use]
    pub fn params(&self) -> Option<&Value> {
        self.params.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CdpEvent {
    method: &'static str,
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

    fn from_protocol(protocol: ProtocolEvent) -> Result<Option<Self>, CdpError> {
        let event = match protocol {
            ProtocolEvent::FetchRequestPaused(event) => Self {
                method: "Fetch.requestPaused",
                event_id: event.params.request_id.clone(),
                target: target_ref(
                    Some(event.params.request_id.clone()),
                    non_empty(&event.params.request.url),
                ),
                params: params_value(&event.params)?,
                protocol: ProtocolEvent::FetchRequestPaused(event),
            },
            ProtocolEvent::NetworkRequestWillBeSent(event) => Self {
                method: "Network.requestWillBeSent",
                event_id: event.params.request_id.clone(),
                target: target_ref(
                    Some(event.params.request_id.clone()),
                    non_empty(&event.params.request.url)
                        .or_else(|| non_empty(&event.params.document_url)),
                ),
                params: params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkRequestWillBeSent(event),
            },
            ProtocolEvent::NetworkResponseReceived(event) => Self {
                method: "Network.responseReceived",
                event_id: event.params.request_id.clone(),
                target: target_ref(
                    Some(event.params.request_id.clone()),
                    non_empty(&event.params.response.url),
                ),
                params: params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkResponseReceived(event),
            },
            ProtocolEvent::NetworkLoadingFailed(event) => Self {
                method: "Network.loadingFailed",
                event_id: event.params.request_id.clone(),
                target: target_ref(Some(event.params.request_id.clone()), None),
                params: params_value(&event.params)?,
                protocol: ProtocolEvent::NetworkLoadingFailed(event),
            },
            _ => return Ok(None),
        };

        Ok(Some(event))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum GovernedCdpCommand {
    RuntimeEvaluate(Box<runtime::Evaluate>),
    RuntimeCallFunctionOn(Box<runtime::CallFunctionOn>),
    InputDispatchMouseEvent(Box<input::DispatchMouseEvent>),
    InputDispatchKeyEvent(Box<input::DispatchKeyEvent>),
    PageNavigate(Box<page::Navigate>),
    FetchContinueRequest(Box<fetch::ContinueRequest>),
}

impl GovernedCdpCommand {
    #[must_use]
    pub fn target(&self) -> Option<TargetRef> {
        match self {
            Self::PageNavigate(command) => target_ref(None, non_empty(&command.url)),
            Self::FetchContinueRequest(command) => {
                target_ref(Some(command.request_id.clone()), command.url.clone())
            }
            Self::RuntimeEvaluate(_)
            | Self::RuntimeCallFunctionOn(_)
            | Self::InputDispatchMouseEvent(_)
            | Self::InputDispatchKeyEvent(_) => None,
        }
    }
}

pub fn decode_cdp_command(source: &str) -> Result<CdpCommand, CdpError> {
    let head: IncomingMethodHead = deserialize_wire(source)?;
    let decoded = decode_governed_command(source, &head.method)?;
    let (id, params, protocol) = match decoded {
        Some(decoded) => (decoded.id, Some(decoded.params), Some(decoded.command)),
        None => (head.id, None, None),
    };

    Ok(CdpCommand {
        id,
        method: head.method,
        params,
        protocol,
    })
}

pub fn decode_cdp_event(source: &str) -> Result<Option<CdpEvent>, CdpError> {
    let head: IncomingEventHead = deserialize_wire(source)?;
    let Some(method) = head.method else {
        return Ok(None);
    };

    if !crate::is_context_method(&method) {
        return Ok(None);
    }

    let event: ProtocolEvent = deserialize_wire(source)?;
    CdpEvent::from_protocol(event)?
        .ok_or_else(|| CdpError::unsupported_method(method))
        .map(Some)
}

fn decode_governed_command(
    source: &str,
    method: &str,
) -> Result<Option<DecodedGovernedCommand>, CdpError> {
    match method {
        runtime::Evaluate::NAME => {
            governed::<runtime::Evaluate>(source, GovernedCdpCommand::RuntimeEvaluate)
        }
        runtime::CallFunctionOn::NAME => {
            governed::<runtime::CallFunctionOn>(source, GovernedCdpCommand::RuntimeCallFunctionOn)
        }
        input::DispatchMouseEvent::NAME => governed::<input::DispatchMouseEvent>(
            source,
            GovernedCdpCommand::InputDispatchMouseEvent,
        ),
        input::DispatchKeyEvent::NAME => {
            governed::<input::DispatchKeyEvent>(source, GovernedCdpCommand::InputDispatchKeyEvent)
        }
        page::Navigate::NAME => {
            governed::<page::Navigate>(source, GovernedCdpCommand::PageNavigate)
        }
        fetch::ContinueRequest::NAME => {
            governed::<fetch::ContinueRequest>(source, GovernedCdpCommand::FetchContinueRequest)
        }
        _ => Ok(None),
    }
}

fn governed<T>(
    source: &str,
    wrap: fn(Box<T>) -> GovernedCdpCommand,
) -> Result<Option<DecodedGovernedCommand>, CdpError>
where
    T: Method + DeserializeOwned + Serialize,
{
    let call = decode_method_call::<T>(source)?;
    let params = params_value(&call.params)?;

    Ok(Some(DecodedGovernedCommand {
        id: call.id,
        params,
        command: wrap(Box::new(call.params)),
    }))
}

fn decode_method_call<T>(source: &str) -> Result<IncomingMethodCall<T>, CdpError>
where
    T: Method + DeserializeOwned,
{
    let call: IncomingMethodCall<T> = deserialize_wire(source)?;
    if call.method != T::NAME {
        return Err(CdpError::unexpected_method(T::NAME, call.method));
    }

    Ok(call)
}

fn deserialize_wire<T>(source: &str) -> Result<T, CdpError>
where
    T: DeserializeOwned,
{
    serde_json::from_str(source).map_err(|error| {
        if error.is_syntax() || error.is_eof() {
            CdpError::invalid_json(error)
        } else {
            CdpError::invalid_protocol(error)
        }
    })
}

fn params_value<T>(params: &T) -> Result<Value, CdpError>
where
    T: Serialize,
{
    serde_json::to_value(params).map_err(CdpError::invalid_protocol)
}

fn target_ref(label: Option<String>, uri: Option<String>) -> Option<TargetRef> {
    if label.is_none() && uri.is_none() {
        return None;
    }

    Some(TargetRef { label, uri })
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_owned())
    }
}

#[derive(Debug, Deserialize)]
struct IncomingMethodHead {
    id: CallId,
    #[serde(rename = "method")]
    method: String,
}

#[derive(Debug, Deserialize)]
struct IncomingEventHead {
    method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IncomingMethodCall<T> {
    id: CallId,
    #[serde(rename = "method")]
    method: String,
    params: T,
}

#[derive(Debug)]
struct DecodedGovernedCommand {
    id: CallId,
    params: Value,
    command: GovernedCdpCommand,
}

#[cfg(test)]
mod tests {
    use cdp_protocol::{page, types::Method};

    use super::{decode_cdp_command, decode_cdp_event, GovernedCdpCommand, IncomingMethodCall};
    use crate::CdpError;

    #[test]
    fn decodes_governed_command_from_protocol_method_call_shape() -> Result<(), CdpError> {
        let navigate = page::Navigate {
            url: String::from("https://example.com/"),
            referrer: None,
            transition_type: None,
            frame_id: None,
            referrer_policy: None,
        };
        let source = serde_json::to_string(&navigate.to_method_call(1))
            .map_err(CdpError::invalid_protocol)?;
        let command = decode_cdp_command(&source)?;

        assert!(matches!(
            command.protocol_command(),
            Some(GovernedCdpCommand::PageNavigate(_))
        ));
        assert_eq!(command.id, 1);
        assert_eq!(
            command
                .protocol_command()
                .and_then(GovernedCdpCommand::target)
                .and_then(|target| target.uri),
            Some(String::from("https://example.com/"))
        );
        assert_eq!(
            command.params().and_then(|params| params.get("url")),
            Some(&serde_json::Value::String(String::from(
                "https://example.com/"
            )))
        );
        Ok(())
    }

    #[test]
    fn rejects_invalid_governed_command_protocol_params() {
        let result = decode_cdp_command(
            r#"
            {
              "id": 1,
              "method": "Input.dispatchMouseEvent",
              "params": {
                "type": "notAMouseEvent",
                "x": 1,
                "y": 1
              }
            }
            "#,
        );

        assert!(matches!(result, Err(CdpError::InvalidProtocol { .. })));
    }

    #[test]
    fn inbound_method_call_mirror_matches_cdp_protocol_method_call_json(
    ) -> Result<(), serde_json::Error> {
        let navigate = page::Navigate {
            url: String::from("https://example.com/"),
            referrer: None,
            transition_type: None,
            frame_id: None,
            referrer_policy: None,
        };
        let value = serde_json::to_string(&navigate.to_method_call(7))?;
        let call: IncomingMethodCall<page::Navigate> = serde_json::from_str(&value)?;

        assert_eq!(call.id, 7);
        assert_eq!(call.method, page::Navigate::NAME);
        assert_eq!(call.params.url, "https://example.com/");
        Ok(())
    }

    #[test]
    fn decodes_context_event_through_protocol_event_enum() -> Result<(), CdpError> {
        let event = decode_cdp_event(
            r#"
            {
              "method": "Network.loadingFailed",
              "params": {
                "requestId": "network-1",
                "timestamp": 1.0,
                "type": "Document",
                "errorText": "net::ERR_FAILED",
                "canceled": false
              }
            }
            "#,
        )?
        .ok_or_else(|| CdpError::unsupported_method("Network.loadingFailed"))?;

        assert_eq!(event.method(), "Network.loadingFailed");
        assert_eq!(event.event_id(), "network-1");
        assert_eq!(
            event.params().get("errorText"),
            Some(&serde_json::Value::String(String::from("net::ERR_FAILED")))
        );
        Ok(())
    }

    #[test]
    fn ignores_cdp_responses_without_event_method() -> Result<(), CdpError> {
        let event = decode_cdp_event(r#"{ "id": 1, "result": {} }"#)?;

        assert_eq!(event, None);
        Ok(())
    }
}
