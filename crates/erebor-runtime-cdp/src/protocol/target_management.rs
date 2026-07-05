use cdp_protocol::{target, types::Method};
use erebor_runtime_events::TargetRef;
use serde_json::Value;

use super::target_reference::TargetReferenceDecoder;

#[allow(deprecated)]
#[derive(Clone, Debug, PartialEq)]
pub enum TargetManagementCommand {
    ActivateTarget(Box<target::ActivateTarget>),
    AttachToTarget(Box<target::AttachToTarget>),
    AttachToBrowserTarget(Box<target::AttachToBrowserTarget>),
    CloseTarget(Box<target::CloseTarget>),
    ExposeDevToolsProtocol(Box<target::ExposeDevToolsProtocol>),
    CreateBrowserContext(Box<target::CreateBrowserContext>),
    GetBrowserContexts(Box<target::GetBrowserContexts>),
    CreateTarget(Box<target::CreateTarget>),
    DetachFromTarget(Box<target::DetachFromTarget>),
    DisposeBrowserContext(Box<target::DisposeBrowserContext>),
    GetTargetInfo(Box<target::GetTargetInfo>),
    GetTargets(Box<target::GetTargets>),
    SendMessageToTarget(Box<target::SendMessageToTarget>),
    SetAutoAttach(Box<target::SetAutoAttach>),
    AutoAttachRelated(Box<target::AutoAttachRelated>),
    SetDiscoverTargets(Box<target::SetDiscoverTargets>),
    SetRemoteLocations(Box<target::SetRemoteLocations>),
    GetDevToolsTarget(Box<target::GetDevToolsTarget>),
    OpenDevTools(Box<target::OpenDevTools>),
    Generic(Box<GenericTargetManagementCommand>),
}

#[allow(deprecated)]
impl TargetManagementCommand {
    #[must_use]
    pub fn method(&self) -> &str {
        match self {
            Self::ActivateTarget(_) => target::ActivateTarget::NAME,
            Self::AttachToTarget(_) => target::AttachToTarget::NAME,
            Self::AttachToBrowserTarget(_) => target::AttachToBrowserTarget::NAME,
            Self::CloseTarget(_) => target::CloseTarget::NAME,
            Self::ExposeDevToolsProtocol(_) => target::ExposeDevToolsProtocol::NAME,
            Self::CreateBrowserContext(_) => target::CreateBrowserContext::NAME,
            Self::GetBrowserContexts(_) => target::GetBrowserContexts::NAME,
            Self::CreateTarget(_) => target::CreateTarget::NAME,
            Self::DetachFromTarget(_) => target::DetachFromTarget::NAME,
            Self::DisposeBrowserContext(_) => target::DisposeBrowserContext::NAME,
            Self::GetTargetInfo(_) => target::GetTargetInfo::NAME,
            Self::GetTargets(_) => target::GetTargets::NAME,
            Self::SendMessageToTarget(_) => target::SendMessageToTarget::NAME,
            Self::SetAutoAttach(_) => target::SetAutoAttach::NAME,
            Self::AutoAttachRelated(_) => target::AutoAttachRelated::NAME,
            Self::SetDiscoverTargets(_) => target::SetDiscoverTargets::NAME,
            Self::SetRemoteLocations(_) => target::SetRemoteLocations::NAME,
            Self::GetDevToolsTarget(_) => target::GetDevToolsTarget::NAME,
            Self::OpenDevTools(_) => target::OpenDevTools::NAME,
            Self::Generic(command) => &command.method,
        }
    }

    #[must_use]
    pub fn target(&self) -> Option<TargetRef> {
        match self {
            Self::ActivateTarget(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::AttachToTarget(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::AttachToBrowserTarget(_) => None,
            Self::CloseTarget(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::ExposeDevToolsProtocol(command) => {
                TargetReferenceDecoder::from_id(&command.target_id)
            }
            Self::CreateBrowserContext(_) | Self::GetBrowserContexts(_) => None,
            Self::CreateTarget(command) => TargetReferenceDecoder::from_label_uri(
                None,
                TargetReferenceDecoder::non_empty(&command.url),
            ),
            Self::DetachFromTarget(command) => {
                #[allow(deprecated)]
                let target_id = command.target_id.as_ref();
                target_id.and_then(|target_id| TargetReferenceDecoder::from_id(target_id))
            }
            Self::DisposeBrowserContext(command) => TargetReferenceDecoder::from_label_uri(
                Some(command.browser_context_id.clone()),
                None,
            ),
            Self::GetTargetInfo(command) => command
                .target_id
                .as_ref()
                .and_then(|target_id| TargetReferenceDecoder::from_id(target_id)),
            Self::GetTargets(_) => None,
            Self::SendMessageToTarget(command) => {
                #[allow(deprecated)]
                let target_id = command.target_id.as_ref();
                target_id.and_then(|target_id| TargetReferenceDecoder::from_id(target_id))
            }
            Self::SetAutoAttach(_) | Self::SetDiscoverTargets(_) | Self::SetRemoteLocations(_) => {
                None
            }
            Self::AutoAttachRelated(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::GetDevToolsTarget(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::OpenDevTools(command) => TargetReferenceDecoder::from_id(&command.target_id),
            Self::Generic(command) => command.target.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct GenericTargetManagementCommand {
    pub method: String,
    pub params: Value,
    pub target: Option<TargetRef>,
}
