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
            ["records", "facts", "manifest"]
        );
        let subject = &model
            .outputs
            .iter()
            .find(|port| port.name == "subjects")
            .ok_or("subject port")?
            .schema
            .fields()[0];
        assert_eq!(
            subject.metadata()["araphor.type"],
            "graph.subject-selection.v1"
        );
        assert_eq!(subject.data_type(), &sdk::DataType::Binary);
        let findings = model
            .outputs
            .iter()
            .find(|port| port.name == "findings")
            .ok_or("finding port")?;
        assert!(findings.evidence_required);
        for reason in &model.reasons {
            assert_eq!(reason.details, findings.schema);
        }
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
