use cdp_protocol::{fetch, input, page, runtime, types::Method};

use super::{
    target_decoder::TargetManagementDecoder,
    wire::{DecodedGovernedCommand, IncomingMethodHead, ProtocolWire},
    CdpCommand, GovernedCdpCommand,
};
use crate::CdpError;

pub struct CdpCommandDecoder;

impl CdpCommandDecoder {
    pub fn decode(source: &str) -> Result<CdpCommand, CdpError> {
        let head: IncomingMethodHead = ProtocolWire::deserialize(source)?;
        let decoded = Self::decode_governed_command(source, &head.method)?;
        let (id, params, protocol) = match decoded {
            Some(decoded) => (decoded.id, Some(decoded.params), Some(decoded.command)),
            None => (head.id, None, None),
        };

        Ok(CdpCommand::new(
            id,
            head.method,
            head.session_id,
            params,
            protocol,
        ))
    }

    fn decode_governed_command(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            runtime::Evaluate::NAME | runtime::CallFunctionOn::NAME => {
                Self::decode_runtime_command(source, method)
            }
            input::DispatchMouseEvent::NAME | input::DispatchKeyEvent::NAME => {
                Self::decode_input_command(source, method)
            }
            page::Navigate::NAME => Self::decode_page_command(source, method),
            fetch::ContinueRequest::NAME => Self::decode_fetch_command(source, method),
            method if method.starts_with("Target.") => {
                TargetManagementDecoder::decode(source, method)
            }
            _ => Ok(None),
        }
    }

    #[allow(deprecated)]
    fn decode_runtime_command(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            runtime::Evaluate::NAME => {
                Self::governed::<runtime::Evaluate, _>(source, GovernedCdpCommand::RuntimeEvaluate)
            }
            runtime::CallFunctionOn::NAME => Self::governed::<runtime::CallFunctionOn, _>(
                source,
                GovernedCdpCommand::RuntimeCallFunctionOn,
            ),
            _ => Ok(None),
        }
    }

    fn decode_input_command(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            input::DispatchMouseEvent::NAME => Self::governed::<input::DispatchMouseEvent, _>(
                source,
                GovernedCdpCommand::InputDispatchMouseEvent,
            ),
            input::DispatchKeyEvent::NAME => Self::governed::<input::DispatchKeyEvent, _>(
                source,
                GovernedCdpCommand::InputDispatchKeyEvent,
            ),
            _ => Ok(None),
        }
    }

    fn decode_page_command(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            page::Navigate::NAME => {
                Self::governed::<page::Navigate, _>(source, GovernedCdpCommand::PageNavigate)
            }
            _ => Ok(None),
        }
    }

    fn decode_fetch_command(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            fetch::ContinueRequest::NAME => Self::governed::<fetch::ContinueRequest, _>(
                source,
                GovernedCdpCommand::FetchContinueRequest,
            ),
            _ => Ok(None),
        }
    }

    pub(super) fn governed<T, F>(
        source: &str,
        wrap: F,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError>
    where
        T: Method + serde::de::DeserializeOwned + serde::Serialize,
        F: FnOnce(Box<T>) -> GovernedCdpCommand,
    {
        let call = ProtocolWire::decode_method_call::<T>(source)?;
        let params = ProtocolWire::params_value(&call.params)?;

        Ok(Some(DecodedGovernedCommand {
            id: call.id,
            params,
            command: wrap(Box::new(call.params)),
        }))
    }
}
