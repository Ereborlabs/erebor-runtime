use std::collections::BTreeSet;

use prost::Message as _;
use prost_types::FileDescriptorSet;

const PACKAGE: &str = "erebor.mithril.control.v1";

#[test]
fn descriptor_has_the_approved_grpc_inventory() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = FileDescriptorSet::decode(mithril_control::FILE_DESCRIPTOR_SET)?;
    let actual = descriptors
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some(PACKAGE))
        .flat_map(|file| &file.service)
        .flat_map(|service| {
            service.method.iter().map(|method| {
                format!(
                    "{}/{}:{}->{}:client_stream={}:server_stream={}",
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
    let expected = [
        method(
            "NodeRegistry",
            "Register",
            "NodeRegistrationRequest",
            "RegistrationAccepted",
            false,
            false,
        ),
        method(
            "NodeRegistry",
            "ReportReadiness",
            "NodeReadinessRequest",
            "RegistrationAccepted",
            false,
            false,
        ),
        method(
            "NodeTrust",
            "Watch",
            "NodeSessionContext",
            "TrustGeneration",
            false,
            true,
        ),
        method(
            "NodeTrust",
            "Acknowledge",
            "TrustGenerationAckRequest",
            "RegistrationAccepted",
            false,
            false,
        ),
        method(
            "NodeEvidence",
            "Upload",
            "EvidenceBatchRequest",
            "EvidenceAck",
            false,
            false,
        ),
        method(
            "NodeEvidence",
            "Open",
            "EvidenceStreamRequest",
            "EvidenceStreamAck",
            true,
            true,
        ),
        method(
            "NodeCoverage",
            "Report",
            "CoverageReportRequest",
            "CoverageAck",
            false,
            false,
        ),
        method(
            "NodePolicy",
            "Inventory",
            "PolicyInventoryRequest",
            "PolicyInventory",
            false,
            false,
        ),
        method(
            "NodePolicy",
            "Fetch",
            "PolicyChunkRequest",
            "PolicyChunk",
            false,
            false,
        ),
        method(
            "NodePolicy",
            "Acknowledge",
            "PolicyAcknowledgementRequest",
            "PolicyAcknowledgementAccepted",
            false,
            false,
        ),
        method(
            "NodePolicy",
            "InventoryExceptions",
            "ExceptionInventoryRequest",
            "ExceptionInventory",
            false,
            false,
        ),
        method(
            "NodePolicy",
            "AcknowledgeException",
            "ExceptionAcknowledgementRequest",
            "PolicyAcknowledgementAccepted",
            false,
            false,
        ),
        method(
            "ControlHealth",
            "Get",
            "NodeSessionContext",
            "ControlConvergenceHealth",
            false,
            false,
        ),
        method(
            "NodeAdministrativeResolution",
            "Open",
            "AdministrativeExecResolutionStreamRequest",
            "ResolveAdministrativeExec",
            true,
            true,
        ),
        method(
            "NodeAdministrativeArm",
            "Open",
            "AdministrativeExecArmStreamRequest",
            "ArmAdministrativeExec",
            true,
            true,
        ),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();

    assert_eq!(actual, expected);
    Ok(())
}

fn method(
    service: &str,
    method: &str,
    input: &str,
    output: &str,
    client_streaming: bool,
    server_streaming: bool,
) -> String {
    format!(
        "{service}/{method}:.{PACKAGE}.{input}->.{PACKAGE}.{output}:client_stream={client_streaming}:server_stream={server_streaming}"
    )
}
