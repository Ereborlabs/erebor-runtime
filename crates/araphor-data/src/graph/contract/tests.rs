use sdk::arrow_array::Array as _;

use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

const REASONS: [FindingReasonV1; 11] = [
    FindingReasonV1::UnexpectedEffect,
    FindingReasonV1::AuditedRoleDeviation,
    FindingReasonV1::LineageCoverageGap,
    FindingReasonV1::CredentialPivot,
    FindingReasonV1::ContextualCredentialPivot,
    FindingReasonV1::MissingAuthorityProof,
    FindingReasonV1::Contradiction,
    FindingReasonV1::KubernetesProofMissing,
    FindingReasonV1::OutsideAuthority,
    FindingReasonV1::InMemoryOnly,
    FindingReasonV1::PayloadUnobservable,
];

#[test]
fn descriptor_preserves_owners() -> TestResult {
    for id in FindingV1::PACKAGES {
        let package = GraphAndFindingOwner::analysis_package(id)?;
        assert_eq!(package.id, id);
        assert_eq!(package.revision, "1");
        assert_eq!(package.exports.len(), 1);
        let model = &package.exports[0];
        assert_eq!(model.name, "detect");
        let expected: &[&str] = match id {
            "HF-PROC-001" => &[
                "UNEXPECTED_EFFECT",
                "AUDITED_ROLE_DEVIATION",
                "LINEAGE_COVERAGE_GAP",
                "CONTRADICTION",
                "OUTSIDE_AUTHORITY",
                "IN_MEMORY_ONLY",
                "PAYLOAD_UNOBSERVABLE",
            ],
            "HF-DW-001" => &[
                "CREDENTIAL_PIVOT",
                "CONTEXTUAL_CREDENTIAL_PIVOT",
                "MISSING_AUTHORITY_PROOF",
                "CONTRADICTION",
            ],
            "HF-XNODE-001" => &["KUBERNETES_PROOF_MISSING"],
            _ => return Err("unknown host package".into()),
        };
        assert_eq!(
            model
                .reasons
                .iter()
                .map(|reason| reason.code.as_str())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|reason| format!("{id}.{reason}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            model
                .inputs
                .iter()
                .map(|port| port.name.as_str())
                .collect::<Vec<_>>(),
            ["records", "coverage", "coverage_keys", "facts", "manifest"]
        );
        let subject = &model
            .outputs
            .iter()
            .find(|port| port.name == "subjects")
            .ok_or("subject port")?
            .schema
            .fields()[0];
        assert_eq!(subject.metadata()["araphor.host_type"], "GraphSubjectKeyV1");
        assert_eq!(subject.data_type(), &sdk::DataType::Binary);
        assert!(
            model
                .outputs
                .iter()
                .find(|port| port.name == "findings")
                .ok_or("finding port")?
                .evidence_required
        );
        assert_eq!(model.checkpoint.as_ref().ok_or("checkpoint")?.version, 1);
        let inspected = package.inspect()?;
        assert!(!inspected.contains("GraphSnapshotV1"));
    }
    assert!(GraphAndFindingOwner::analysis_package("outside-package").is_err());
    Ok(())
}

#[test]
fn reason_codes_are_reversible() -> TestResult {
    for id in FindingV1::PACKAGES {
        for reason in REASONS {
            let code = reason.analysis_code(id)?;
            assert_eq!(FindingReasonV1::from_analysis_code(id, &code)?, reason);
            assert!(
                FindingReasonV1::from_analysis_code("HF-PROC-001", &format!("other.{code}"))
                    .is_err()
            );
        }
        assert!(FindingReasonV1::from_analysis_code(id, &format!("{id}.UNKNOWN_REASON")).is_err());
    }
    assert!(FindingReasonV1::UnexpectedEffect
        .analysis_code("other")
        .is_err());
    Ok(())
}

#[test]
fn finding_requires_host_validation() -> TestResult {
    let input = crate::graph::tests::credential_input()?;
    let snapshot = GraphAndFindingOwner::derive(&input)?;
    let finding = snapshot
        .findings
        .iter()
        .find(|finding| finding.package_id == "HF-DW-001")
        .ok_or("current finding")?;
    let original = finding.clone();
    let reason = finding.analysis_reason(7)?;
    assert_eq!(
        reason.output,
        sdk::RowRef {
            dataset: "findings".into(),
            row: 7
        }
    );
    assert_eq!(
        FindingReasonV1::from_analysis_code(&finding.package_id, &reason.code)?,
        finding.reason
    );
    assert_eq!(reason.details.num_rows(), 1);
    let schema = GraphAndFindingOwner::analysis_package(&finding.package_id)?
        .exports
        .remove(0)
        .reasons
        .into_iter()
        .find(|entry| entry.code == reason.code)
        .ok_or("declared reason")?
        .details;
    assert_eq!(reason.details.schema().as_ref(), &schema);
    let subjects = reason
        .details
        .column(1)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("subject detail")?;
    let subject = serde_json::from_slice::<crate::GraphSubjectKeyV1>(subjects.value(0))?;
    assert_eq!(subject, finding.subject_id);
    assert_eq!(finding, &original);
    assert_eq!(finding.evidence, original.evidence);
    assert_eq!(finding.effects, original.effects);
    let actions = reason
        .details
        .column(5)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("action detail")?;
    assert_eq!(actions.is_null(0), finding.required_action.is_none());
    let mut invalid = original;
    invalid.evidence[0].stream.tenant_id = [99; 16];
    assert!(invalid.analysis_reason(0).is_err());
    Ok(())
}
