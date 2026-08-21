use std::collections::BTreeSet;

use prost::Message as _;
use prost_types::FileDescriptorSet;

const PACKAGE: &str = "erebor.runtime.ipc.v1";

struct ExpectedMethod {
    service: &'static str,
    method: &'static str,
    input: &'static str,
    output: &'static str,
    client_streaming: bool,
    server_streaming: bool,
}

macro_rules! method {
    ($service:literal, $method:literal, $input:literal, $output:literal) => {
        ExpectedMethod {
            service: $service,
            method: $method,
            input: $input,
            output: $output,
            client_streaming: false,
            server_streaming: false,
        }
    };
    ($service:literal, $method:literal, $input:literal, $output:literal, $client:literal, $server:literal) => {
        ExpectedMethod {
            service: $service,
            method: $method,
            input: $input,
            output: $output,
            client_streaming: $client,
            server_streaming: $server,
        }
    };
}

const EXPECTED_METHODS: &[ExpectedMethod] = &[
    method!(
        "DaemonLifecycleService",
        "Status",
        "DaemonStatusRequest",
        "DaemonStatusResponse"
    ),
    method!(
        "DaemonLifecycleService",
        "Logs",
        "DaemonLogsRequest",
        "DaemonLogRecord",
        false,
        true
    ),
    method!(
        "DaemonLifecycleService",
        "Reload",
        "DaemonReloadRequest",
        "DaemonCommandResult"
    ),
    method!(
        "DaemonLifecycleService",
        "Stop",
        "DaemonStopRequest",
        "DaemonCommandResult"
    ),
    method!(
        "AgentService",
        "Install",
        "AgentInstallRequest",
        "AgentInstallResponse"
    ),
    method!(
        "AgentService",
        "RunCodex",
        "CodexRunRequest",
        "SessionCreateResponse"
    ),
    method!(
        "SessionService",
        "Create",
        "SessionCreateRequest",
        "SessionCreateResponse"
    ),
    method!(
        "SessionService",
        "Start",
        "SessionStartRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "Stop",
        "SessionStopRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "Kill",
        "SessionKillRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "Remove",
        "SessionRemoveRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "Inspect",
        "SessionInspectRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "List",
        "SessionListRequest",
        "SessionListResponse"
    ),
    method!(
        "SessionService",
        "Wait",
        "SessionWaitRequest",
        "SessionRecord"
    ),
    method!(
        "SessionService",
        "Logs",
        "SessionLogsRequest",
        "SessionLogStreamItem",
        false,
        true
    ),
    method!(
        "SessionService",
        "Events",
        "SessionEventsRequest",
        "SessionEventStreamItem",
        false,
        true
    ),
    method!(
        "SessionService",
        "Evidence",
        "SessionEvidenceRequest",
        "SessionEvidenceStreamItem",
        false,
        true
    ),
    method!(
        "SessionService",
        "Attach",
        "SessionAttachRequest",
        "SessionAttachResponse"
    ),
    method!(
        "SessionService",
        "RenewInputLease",
        "SessionInputLeaseRenewRequest",
        "SessionInputLeaseResponse"
    ),
    method!(
        "SessionService",
        "ReleaseInputLease",
        "SessionInputLeaseReleaseRequest",
        "SessionInputLeaseResponse"
    ),
    method!(
        "SessionService",
        "Input",
        "SessionInputRequest",
        "SessionInputResponse"
    ),
    method!(
        "SessionService",
        "ResizeTerminal",
        "SessionTerminalResizeRequest",
        "SessionTerminalResizeResponse"
    ),
    method!(
        "SessionService",
        "AttachCodexAppServer",
        "CodexAppServerAttachRequest",
        "CodexAppServerAttachResponse"
    ),
    method!(
        "SessionService",
        "InputCodexAppServer",
        "CodexAppServerInputRequest",
        "CodexAppServerInputResponse"
    ),
    method!(
        "SessionService",
        "CloseCodexAppServerInput",
        "CodexAppServerInputCloseRequest",
        "CodexAppServerInputCloseResponse"
    ),
    method!(
        "SessionService",
        "Prune",
        "SessionPruneRequest",
        "SessionPruneResponse"
    ),
    method!(
        "SessionService",
        "SetAlias",
        "SessionAliasSetRequest",
        "SessionAliasRecord"
    ),
    method!(
        "SessionService",
        "RemoveAlias",
        "SessionAliasRemoveRequest",
        "SessionAliasRecord"
    ),
    method!(
        "SessionService",
        "ListAliases",
        "SessionAliasListRequest",
        "SessionAliasListResponse"
    ),
    method!(
        "FilesystemService",
        "Query",
        "FilesystemQueryRequest",
        "FilesystemOperationResponse"
    ),
    method!(
        "FilesystemService",
        "Mutate",
        "FilesystemMutationRequest",
        "FilesystemOperationResponse"
    ),
    method!(
        "ContextService",
        "DeliveryInbox",
        "ContextDeliveryInboxRequest",
        "ContextDeliveryInboxResponse"
    ),
    method!(
        "ContextService",
        "Graph",
        "ContextGraphRequest",
        "ContextGraphResponse"
    ),
    method!(
        "ContextService",
        "ReceiveDelivery",
        "ContextDeliveryReceiveRequest",
        "ContextDeliveryDecisionResponse"
    ),
    method!(
        "ContextService",
        "RejectDelivery",
        "ContextDeliveryRejectRequest",
        "ContextDeliveryDecisionResponse"
    ),
    method!(
        "AdministrationService",
        "ListSessions",
        "AdminSessionListRequest",
        "SessionListResponse"
    ),
    method!(
        "AdministrationService",
        "InspectSession",
        "AdminSessionInspectRequest",
        "SessionRecord"
    ),
    method!(
        "AdministrationService",
        "StopSession",
        "AdminSessionStopRequest",
        "SessionRecord"
    ),
    method!(
        "AdministrationService",
        "KillSession",
        "AdminSessionKillRequest",
        "SessionRecord"
    ),
    method!(
        "AdministrationService",
        "SetSessionRetentionHold",
        "AdminSessionSetRetentionHoldRequest",
        "SessionRecord"
    ),
    method!(
        "ApprovalService",
        "List",
        "ApprovalListRequest",
        "ApprovalListResponse"
    ),
    method!(
        "ApprovalService",
        "Inspect",
        "ApprovalInspectRequest",
        "ApprovalRecord"
    ),
    method!(
        "ApprovalService",
        "Approve",
        "ApprovalApproveRequest",
        "ApprovalRecord"
    ),
    method!(
        "ApprovalService",
        "Deny",
        "ApprovalDenyRequest",
        "ApprovalRecord"
    ),
    method!(
        "PolicyService",
        "Test",
        "PolicyTestRequest",
        "PolicyTestResponse"
    ),
    method!(
        "PolicyService",
        "ApplyPackage",
        "PolicyPackageApplyRequest",
        "PolicyPackageRecord"
    ),
    method!(
        "PolicyService",
        "ListPackages",
        "PolicyPackageListRequest",
        "PolicyPackageListResponse"
    ),
    method!(
        "PolicyService",
        "InspectPackage",
        "PolicyPackageInspectRequest",
        "PolicyPackageRecord"
    ),
    method!(
        "PolicyService",
        "VerifyPackage",
        "PolicyPackageVerifyRequest",
        "PolicyPackageRecord"
    ),
    method!(
        "PolicyService",
        "CreateSet",
        "PolicySetCreateRequest",
        "PolicySetRecord"
    ),
    method!(
        "PolicyService",
        "ListSets",
        "PolicySetListRequest",
        "PolicySetListResponse"
    ),
    method!(
        "PolicyService",
        "InspectSet",
        "PolicySetInspectRequest",
        "PolicySetRecord"
    ),
    method!(
        "PolicyService",
        "VerifySet",
        "PolicySetVerifyRequest",
        "PolicySetRecord"
    ),
    method!(
        "SurfaceService",
        "Create",
        "SurfaceCreateRequest",
        "SurfaceRecord"
    ),
    method!(
        "SurfaceService",
        "List",
        "SurfaceListRequest",
        "SurfaceListResponse"
    ),
    method!(
        "SurfaceService",
        "Inspect",
        "SurfaceInspectRequest",
        "SurfaceRecord"
    ),
    method!(
        "RunnerService",
        "List",
        "RunnerListRequest",
        "RunnerListResponse"
    ),
    method!(
        "RunnerService",
        "Inspect",
        "RunnerInspectRequest",
        "RunnerCapabilityRecord"
    ),
    method!(
        "HookService",
        "Open",
        "HookClientMessage",
        "HookServerMessage",
        true,
        true
    ),
    method!(
        "RuntimeObservationService",
        "GetSnapshot",
        "MithrilObservationSnapshotRequest",
        "MithrilObservationSnapshotResponse"
    ),
];

#[test]
fn descriptor_has_the_approved_grpc_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = FileDescriptorSet::decode(erebor_runtime_ipc::v1::FILE_DESCRIPTOR_SET)?;
    let files = descriptors
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some(PACKAGE))
        .collect::<Vec<_>>();
    let file_names = files
        .iter()
        .filter_map(|file| file.name.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        file_names,
        BTreeSet::from([
            "erebor/runtime/ipc/v1/daemon.proto",
            "erebor/runtime/ipc/v1/hook.proto",
            "erebor/runtime/ipc/v1/mithril.proto",
        ])
    );

    let actual = files
        .iter()
        .flat_map(|file| &file.service)
        .flat_map(|service| {
            service.method.iter().map(|method| {
                signature(
                    service.name.as_deref().unwrap_or_default(),
                    method.name.as_deref().unwrap_or_default(),
                    method.input_type.as_deref().unwrap_or_default(),
                    method.output_type.as_deref().unwrap_or_default(),
                    method.client_streaming.unwrap_or_default(),
                    method.server_streaming.unwrap_or_default(),
                )
            })
        })
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_METHODS
        .iter()
        .map(|method| {
            signature(
                method.service,
                method.method,
                &format!(".{PACKAGE}.{}", method.input),
                &format!(".{PACKAGE}.{}", method.output),
                method.client_streaming,
                method.server_streaming,
            )
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    Ok(())
}

fn signature(
    service: &str,
    method: &str,
    input: &str,
    output: &str,
    client_streaming: bool,
    server_streaming: bool,
) -> String {
    format!(
        "{service}/{method}:{input}->{output}:client_stream={client_streaming}:server_stream={server_streaming}"
    )
}
