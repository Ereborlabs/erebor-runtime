use cdp_protocol::{
    fetch, input, network, page, runtime,
    types::{Event as ProtocolEvent, Method},
};
use erebor_runtime_events::TargetRef;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{Map, Value};

use crate::CdpError;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpCommand {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
    protocol: Option<GovernedCdpCommand>,
}

impl CdpCommand {
    #[must_use]
    pub fn protocol_command(&self) -> Option<&GovernedCdpCommand> {
        self.protocol.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CdpEvent {
    pub method: String,
    pub params: Value,
    protocol: ContextCdpEvent,
}

impl CdpEvent {
    #[must_use]
    pub const fn protocol_event(&self) -> &ContextCdpEvent {
        &self.protocol
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

#[derive(Clone, Debug, PartialEq)]
pub enum ContextCdpEvent {
    FetchRequestPaused(Box<fetch::events::RequestPausedEvent>),
    NetworkRequestWillBeSent(Box<network::events::RequestWillBeSentEvent>),
    NetworkResponseReceived(Box<network::events::ResponseReceivedEvent>),
    NetworkLoadingFailed(Box<network::events::LoadingFailedEvent>),
}

impl ContextCdpEvent {
    #[must_use]
    pub fn event_id(&self) -> String {
        match self {
            Self::FetchRequestPaused(event) => event.params.request_id.clone(),
            Self::NetworkRequestWillBeSent(event) => event.params.request_id.clone(),
            Self::NetworkResponseReceived(event) => event.params.request_id.clone(),
            Self::NetworkLoadingFailed(event) => event.params.request_id.clone(),
        }
    }

    #[must_use]
    pub fn target(&self) -> Option<TargetRef> {
        match self {
            Self::FetchRequestPaused(event) => target_ref(
                Some(event.params.request_id.clone()),
                non_empty(&event.params.request.url),
            ),
            Self::NetworkRequestWillBeSent(event) => target_ref(
                Some(event.params.request_id.clone()),
                non_empty(&event.params.request.url)
                    .or_else(|| non_empty(&event.params.document_url)),
            ),
            Self::NetworkResponseReceived(event) => target_ref(
                Some(event.params.request_id.clone()),
                non_empty(&event.params.response.url),
            ),
            Self::NetworkLoadingFailed(event) => {
                target_ref(Some(event.params.request_id.clone()), None)
            }
        }
    }
}

pub fn decode_cdp_command(source: &str) -> Result<CdpCommand, CdpError> {
    let envelope = decode_wire_envelope(source)?;
    let method = envelope.method.ok_or_else(CdpError::missing_method)?;
    let params = envelope.params.unwrap_or(Value::Null);
    let protocol = decode_governed_command(&method, &params)?;

    Ok(CdpCommand {
        id: envelope.id,
        method,
        params,
        protocol,
    })
}

pub fn decode_cdp_event(source: &str) -> Result<Option<CdpEvent>, CdpError> {
    let envelope = decode_wire_envelope(source)?;
    let Some(method) = envelope.method else {
        return Ok(None);
    };

    if !crate::is_context_method(&method) {
        return Ok(None);
    }

    let params = envelope.params.unwrap_or(Value::Null);
    let protocol = decode_context_event(source, &method)?;

    Ok(Some(CdpEvent {
        method,
        params,
        protocol,
    }))
}

fn decode_wire_envelope(source: &str) -> Result<CdpWireEnvelope, CdpError> {
    serde_json::from_str(source).map_err(CdpError::invalid_json)
}

fn decode_governed_command(
    method: &str,
    params: &Value,
) -> Result<Option<GovernedCdpCommand>, CdpError> {
    match method {
        runtime::Evaluate::NAME => deserialize_params(params)
            .map(|command| Some(GovernedCdpCommand::RuntimeEvaluate(Box::new(command)))),
        runtime::CallFunctionOn::NAME => deserialize_params(params)
            .map(|command| Some(GovernedCdpCommand::RuntimeCallFunctionOn(Box::new(command)))),
        input::DispatchMouseEvent::NAME => deserialize_params(params).map(|command| {
            Some(GovernedCdpCommand::InputDispatchMouseEvent(Box::new(
                command,
            )))
        }),
        input::DispatchKeyEvent::NAME => deserialize_params(params)
            .map(|command| Some(GovernedCdpCommand::InputDispatchKeyEvent(Box::new(command)))),
        page::Navigate::NAME => deserialize_params(params)
            .map(|command| Some(GovernedCdpCommand::PageNavigate(Box::new(command)))),
        fetch::ContinueRequest::NAME => deserialize_params(params)
            .map(|command| Some(GovernedCdpCommand::FetchContinueRequest(Box::new(command)))),
        _ => Ok(None),
    }
}

fn decode_context_event(source: &str, method: &str) -> Result<ContextCdpEvent, CdpError> {
    let event: ProtocolEvent = serde_json::from_str(source).map_err(CdpError::invalid_protocol)?;

    match event {
        ProtocolEvent::FetchRequestPaused(event) => {
            Ok(ContextCdpEvent::FetchRequestPaused(Box::new(event)))
        }
        ProtocolEvent::NetworkRequestWillBeSent(event) => {
            Ok(ContextCdpEvent::NetworkRequestWillBeSent(Box::new(event)))
        }
        ProtocolEvent::NetworkResponseReceived(event) => {
            Ok(ContextCdpEvent::NetworkResponseReceived(Box::new(event)))
        }
        ProtocolEvent::NetworkLoadingFailed(event) => {
            Ok(ContextCdpEvent::NetworkLoadingFailed(Box::new(event)))
        }
        _ => Err(CdpError::unsupported_method(method.to_owned())),
    }
}

fn deserialize_params<T>(params: &Value) -> Result<T, CdpError>
where
    T: DeserializeOwned,
{
    let normalized = match params {
        Value::Null => Value::Object(Map::new()),
        value => value.clone(),
    };

    serde_json::from_value(normalized).map_err(CdpError::invalid_protocol)
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

// cdp-protocol 0.3.1 has typed methods/events but no inbound "any command" enum.
// This envelope is only for CDP dispatch and id preservation at the proxy boundary.
#[derive(Debug, Deserialize)]
struct CdpWireEnvelope {
    id: Option<Value>,
    method: Option<String>,
    params: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::{decode_cdp_command, GovernedCdpCommand};
    use crate::CdpError;

    #[test]
    fn decodes_governed_command_with_protocol_type() -> Result<(), CdpError> {
        let command = decode_cdp_command(
            r#"
            {
              "id": 1,
              "method": "Page.navigate",
              "params": {
                "url": "https://example.com/"
              }
            }
            "#,
        )?;

        assert!(matches!(
            command.protocol_command(),
            Some(GovernedCdpCommand::PageNavigate(_))
        ));
        assert_eq!(
            command
                .protocol_command()
                .and_then(GovernedCdpCommand::target)
                .and_then(|target| target.uri),
            Some(String::from("https://example.com/"))
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
}
