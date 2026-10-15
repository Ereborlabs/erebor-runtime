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
                .map(|input| input.port.name.as_str())
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

#[test]
fn declared_reason_preserves_typed_details() -> TestResult {
    use duckdb::arrow::array::UInt64Array;
    use std::sync::Arc;

    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let details =
        sdk::RecordBatch::try_new(Arc::new(schema), vec![Arc::new(UInt64Array::from(vec![3]))])?;
    let value = sdk::ReasonValue {
        output: sdk::RowRef {
            dataset: "findings".into(),
            row: 0,
        },
        code: "example-detector.THRESHOLD".into(),
        details,
    };
    let reason = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(
        &value,
        sdk::Limits::default(),
    )?);
    reason.validate("example-detector")?;
    assert_eq!(reason.label()?, value.code);
    assert_eq!(FindingReasonV1::restore(&reason.storage()?)?, reason);
    assert_eq!(
        serde_json::from_value::<FindingReasonV1>(serde_json::to_value(&reason)?)?,
        reason
    );
    assert!(reason.validate("another-detector").is_err());
    assert_eq!(
        serde_json::to_value(FindingReasonV1::UnexpectedEffect)?,
        "UNEXPECTED_EFFECT"
    );
    assert_eq!(
        FindingReasonV1::restore("UNEXPECTED_EFFECT")?,
        FindingReasonV1::UnexpectedEffect
    );
    Ok(())
}
