use cdp_protocol::{target, types::Method};
use serde_json::{Map, Value};

use super::{
    command_decoder::CdpCommandDecoder,
    target_management::{GenericTargetManagementCommand, TargetManagementCommand},
    target_reference::TargetReferenceDecoder,
    wire::{DecodedGovernedCommand, IncomingGenericMethodCall, ProtocolWire},
    GovernedCdpCommand,
};
use crate::CdpError;

pub(super) struct TargetManagementDecoder;

#[allow(deprecated)]
impl TargetManagementDecoder {
    pub(super) fn decode(
        source: &str,
        method: &str,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        match method {
            target::ActivateTarget::NAME => Self::governed::<target::ActivateTarget, _>(
                source,
                Self::wrap(TargetManagementCommand::ActivateTarget),
            ),
            target::AttachToTarget::NAME => Self::governed::<target::AttachToTarget, _>(
                source,
                Self::wrap(TargetManagementCommand::AttachToTarget),
            ),
            target::AttachToBrowserTarget::NAME => {
                Self::governed_or::<target::AttachToBrowserTarget, _>(
                    source,
                    Value::Null,
                    Self::wrap(TargetManagementCommand::AttachToBrowserTarget),
                )
            }
            target::CloseTarget::NAME => Self::governed::<target::CloseTarget, _>(
                source,
                Self::wrap(TargetManagementCommand::CloseTarget),
            ),
            target::ExposeDevToolsProtocol::NAME => {
                Self::governed::<target::ExposeDevToolsProtocol, _>(
                    source,
                    Self::wrap(TargetManagementCommand::ExposeDevToolsProtocol),
                )
            }
            target::CreateBrowserContext::NAME => {
                Self::governed_using_object_params::<target::CreateBrowserContext, _>(
                    source,
                    Self::wrap(TargetManagementCommand::CreateBrowserContext),
                )
            }
            target::GetBrowserContexts::NAME => Self::governed_or::<target::GetBrowserContexts, _>(
                source,
                Value::Null,
                Self::wrap(TargetManagementCommand::GetBrowserContexts),
            ),
            target::CreateTarget::NAME => {
                Self::governed_using_object_params::<target::CreateTarget, _>(
                    source,
                    Self::wrap(TargetManagementCommand::CreateTarget),
                )
            }
            target::DetachFromTarget::NAME => {
                Self::governed_using_object_params::<target::DetachFromTarget, _>(
                    source,
                    Self::wrap(TargetManagementCommand::DetachFromTarget),
                )
            }
            target::DisposeBrowserContext::NAME => {
                Self::governed::<target::DisposeBrowserContext, _>(
                    source,
                    Self::wrap(TargetManagementCommand::DisposeBrowserContext),
                )
            }
            target::GetTargetInfo::NAME => {
                Self::governed_using_object_params::<target::GetTargetInfo, _>(
                    source,
                    Self::wrap(TargetManagementCommand::GetTargetInfo),
                )
            }
            target::GetTargets::NAME => {
                Self::governed_using_object_params::<target::GetTargets, _>(
                    source,
                    Self::wrap(TargetManagementCommand::GetTargets),
                )
            }
            target::SendMessageToTarget::NAME => {
                Self::governed_using_object_params::<target::SendMessageToTarget, _>(
                    source,
                    Self::wrap(TargetManagementCommand::SendMessageToTarget),
                )
            }
            target::SetAutoAttach::NAME => {
                Self::governed_using_object_params::<target::SetAutoAttach, _>(
                    source,
                    Self::wrap(TargetManagementCommand::SetAutoAttach),
                )
            }
            target::AutoAttachRelated::NAME => Self::governed::<target::AutoAttachRelated, _>(
                source,
                Self::wrap(TargetManagementCommand::AutoAttachRelated),
            ),
            target::SetDiscoverTargets::NAME => {
                Self::governed_using_object_params::<target::SetDiscoverTargets, _>(
                    source,
                    Self::wrap(TargetManagementCommand::SetDiscoverTargets),
                )
            }
            target::SetRemoteLocations::NAME => Self::governed::<target::SetRemoteLocations, _>(
                source,
                Self::wrap(TargetManagementCommand::SetRemoteLocations),
            ),
            target::GetDevToolsTarget::NAME => Self::governed::<target::GetDevToolsTarget, _>(
                source,
                Self::wrap(TargetManagementCommand::GetDevToolsTarget),
            ),
            target::OpenDevTools::NAME => Self::governed::<target::OpenDevTools, _>(
                source,
                Self::wrap(TargetManagementCommand::OpenDevTools),
            ),
            _ => Self::decode_generic(source),
        }
    }

    fn decode_generic(source: &str) -> Result<Option<DecodedGovernedCommand>, CdpError> {
        let call: IncomingGenericMethodCall = ProtocolWire::deserialize(source)?;
        let params = call.params.unwrap_or(Value::Object(Map::new()));
        let target = TargetReferenceDecoder::from_params(&params);
        let command = GenericTargetManagementCommand {
            method: call.method,
            params: params.clone(),
            target,
        };

        Ok(Some(DecodedGovernedCommand {
            id: call.id,
            params,
            command: GovernedCdpCommand::TargetManagement(Box::new(
                TargetManagementCommand::Generic(Box::new(command)),
            )),
        }))
    }

    fn wrap<T>(
        wrap: fn(Box<T>) -> TargetManagementCommand,
    ) -> impl FnOnce(Box<T>) -> GovernedCdpCommand {
        move |command| GovernedCdpCommand::TargetManagement(Box::new(wrap(command)))
    }

    fn governed<T, F>(source: &str, wrap: F) -> Result<Option<DecodedGovernedCommand>, CdpError>
    where
        T: Method + serde::de::DeserializeOwned + serde::Serialize,
        F: FnOnce(Box<T>) -> GovernedCdpCommand,
    {
        CdpCommandDecoder::governed::<T, F>(source, wrap)
    }

    fn governed_using_object_params<T, F>(
        source: &str,
        wrap: F,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError>
    where
        T: Method + serde::de::DeserializeOwned + serde::Serialize,
        F: FnOnce(Box<T>) -> GovernedCdpCommand,
    {
        Self::governed_or::<T, F>(source, Value::Object(Map::new()), wrap)
    }

    fn governed_or<T, F>(
        source: &str,
        fallback_params: Value,
        wrap: F,
    ) -> Result<Option<DecodedGovernedCommand>, CdpError>
    where
        T: Method + serde::de::DeserializeOwned + serde::Serialize,
        F: FnOnce(Box<T>) -> GovernedCdpCommand,
    {
        let call = ProtocolWire::decode_method_call_or::<T>(source, fallback_params)?;
        let params = ProtocolWire::params_value(&call.params)?;

        Ok(Some(DecodedGovernedCommand {
            id: call.id,
            params,
            command: wrap(Box::new(call.params)),
        }))
    }
}
