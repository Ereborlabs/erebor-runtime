use std::collections::BTreeSet;

use prost::Message as _;
use prost_types::FileDescriptorSet;

const PACKAGE: &str = "erebor.mithril.control.v1";

#[test]
fn shared_evidence_wire_contract() -> Result<(), Box<dyn std::error::Error>> {
    let descriptors = FileDescriptorSet::decode(mithril_control::FILE_DESCRIPTOR_SET)?;
    let files: Vec<_> = descriptors
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some(PACKAGE))
        .collect();
    let expected = [
        ("EvidenceRecord", concat!(
            "observed_boottime_ns:Uint64 ingested_utc_ns:Sint64 coverage_interval_id:Bytes ",
            "profile_generation_ref_id:Uint64? task_cookie:Uint64 process_lineage_id:Bytes ",
            "authority_domain_id:Bytes execution_set_id:Bytes exact_object_id:Bytes ",
            "destination_id:Uint64 policy_rule_id:Uint64 reason:Uint32 decision:Uint32 ",
            "effect_family:Uint32 operation:Uint32 configured_errno:Sint32 kernel_result:Sint32 ",
            "temporal_coverage:Enum target_task_cookie:Uint64? operation_argument:Uint32? ",
            "decision_context:Message?")),
        ("EvidenceDecisionContext", concat!(
            "schema_version:Uint32 original_kernel_sequence:Uint64 process_instance_id:Bytes ",
            "entry_instance_id:Bytes binding_id:Bytes profile_generation_ref_id:Uint64 ",
            "role_id:Uint32 state_id:Uint32 entry_rule_id:Uint32 exact_file_object:Message? ",
            "exact_object_key_id:Uint64 composite_atom_id:Uint64 catalog_json:Bytes catalog_state:String")),
        ("EvidenceExactFileObject", concat!(
            "profile_generation_ref_id:Uint64 mount_id_unique:Uint64 inode:Uint64 ",
            "inode_generation:Uint64 mount_namespace_inode:Uint32 filesystem_device:Uint32")),
        ("EvidenceRecords", "records:Message*"),
        ("CoverageCounters", concat!(
            "attempted:Uint64 suppressed:Uint64 requested:Uint64 emitted:Uint64 lost:Uint64 ",
            "classifier_miss_count:Uint64 unresolved:Uint64 next_sequence:Uint64")),
        ("CoverageInterval", concat!(
            "interval_id:Bytes source_epoch:Uint64 revision:Uint64 state:String first_sequence:Uint64 ",
            "last_sequence:Uint64? opening_counters:Message closing_counters:Message? ",
            "gap_reasons:String* current:Bool")),
        ("CoverageReport", "source_id:Bytes cpu_id:Uint32 source_epoch:Uint64 revision:Uint64 intervals:Message*"),
    ];
    for (name, expected) in expected {
        let messages: Vec<_> = files
            .iter()
            .flat_map(|file| &file.message_type)
            .filter(|message| message.name() == name)
            .collect();
        assert_eq!(messages.len(), 1, "{name} must have one definition");
        let message = messages[0];
        let mut actual = Vec::new();
        for (index, field) in message.field.iter().enumerate() {
            assert_eq!(field.number(), index as i32 + 1, "{name}.{}", field.name());
            let repeated = field.label() == prost_types::field_descriptor_proto::Label::Repeated;
            actual.push(format!(
                "{}:{:?}{}{}",
                field.name(),
                field.r#type(),
                if repeated { "*" } else { "" },
                if field.proto3_optional() { "?" } else { "" }
            ));
            let target = match (name, field.name()) {
                ("EvidenceRecord", "temporal_coverage") => Some("EvidenceTemporalCoverage"),
                ("EvidenceRecord", "decision_context") => Some("EvidenceDecisionContext"),
                ("EvidenceDecisionContext", "exact_file_object") => Some("EvidenceExactFileObject"),
                ("EvidenceRecords", "records") => Some("EvidenceRecord"),
                ("CoverageInterval", "opening_counters" | "closing_counters") => {
                    Some("CoverageCounters")
                }
                ("CoverageReport", "intervals") => Some("CoverageInterval"),
                _ => None,
            };
            assert_eq!(
                field.type_name.as_deref(),
                target
                    .map(|target| format!(".{PACKAGE}.{target}"))
                    .as_deref()
            );
        }
        assert_eq!(actual.join(" "), expected, "{name}");
    }
    let enums: Vec<_> = files
        .iter()
        .flat_map(|file| &file.enum_type)
        .filter(|value| value.name() == "EvidenceTemporalCoverage")
        .collect();
    assert_eq!(enums.len(), 1);
    let values: Vec<_> = enums[0]
        .value
        .iter()
        .map(|value| (value.name(), value.number()))
        .collect();
    assert_eq!(
        values,
        [
            ("EVIDENCE_TEMPORAL_COVERAGE_UNKNOWN", 0),
            ("EVIDENCE_TEMPORAL_COVERAGE_COMPLETE", 1),
            ("EVIDENCE_TEMPORAL_COVERAGE_GAPPED", 2),
        ]
    );
    Ok(())
}

#[test]
fn shared_record_type_identity() {
    use std::any::TypeId;

    for (data, control) in [
        (
            TypeId::of::<araphor_data::EvidenceRecord>(),
            TypeId::of::<mithril_control::EvidenceRecord>(),
        ),
        (
            TypeId::of::<araphor_data::EvidenceDecisionContext>(),
            TypeId::of::<mithril_control::EvidenceDecisionContext>(),
        ),
        (
            TypeId::of::<araphor_data::EvidenceExactFileObject>(),
            TypeId::of::<mithril_control::EvidenceExactFileObject>(),
        ),
        (
            TypeId::of::<araphor_data::EvidenceRecords>(),
            TypeId::of::<mithril_control::EvidenceRecords>(),
        ),
        (
            TypeId::of::<araphor_data::EvidenceTemporalCoverage>(),
            TypeId::of::<mithril_control::EvidenceTemporalCoverage>(),
        ),
        (
            TypeId::of::<araphor_data::CoverageCounters>(),
            TypeId::of::<mithril_control::CoverageCounters>(),
        ),
        (
            TypeId::of::<araphor_data::CoverageInterval>(),
            TypeId::of::<mithril_control::CoverageInterval>(),
        ),
        (
            TypeId::of::<araphor_data::CoverageReport>(),
            TypeId::of::<mithril_control::CoverageReport>(),
        ),
    ] {
        assert_eq!(data, control);
    }
}

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
            "NodeDiagnostics",
            "Exchange",
            "NodeDiagnosticRequest",
            "NodeDiagnosticReply",
            false,
            false,
        ),
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
            "ReportFloor",
            "EvidenceFloorRequest",
            "EvidenceFloorAccepted",
            false,
            false,
        ),
        method(
            "NodeEvidence",
            "Open",
            "EvidenceStreamRequest",
            "EvidenceAck",
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
            "NodeDecommission",
            "Open",
            "NodeDecommissionStreamRequest",
            "NodeDecommissionCommand",
            true,
            true,
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
