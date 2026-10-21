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
    use sdk::arrow_array::UInt64Array;
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

#[test]
fn declared_reason_default_bytes() -> TestResult {
    use sdk::arrow_array::StringArray;
    use std::sync::Arc;

    let value = "x".repeat(4 * 1024 * 1024 + 1);
    let schema = sdk::Schema::new(vec![sdk::Field::new("details", sdk::DataType::Utf8, false)]);
    let details = sdk::RecordBatch::try_new(
        Arc::new(schema),
        vec![Arc::new(StringArray::from(vec![value.as_str()]))],
    )?;
    let value = sdk::ReasonValue {
        output: sdk::RowRef {
            dataset: "findings".into(),
            row: 0,
        },
        code: "example-detector.THRESHOLD".into(),
        details,
    };
    let reason = DeclaredFindingReasonV1::from_value(&value, sdk::Limits::default())?;
    assert!(reason.ipc.len() > 4 * 1024 * 1024);
    reason.validate("example-detector")?;
    assert!(reason.validate("another-detector").is_err());
    assert!(DeclaredFindingReasonV1::from_value(
        &value,
        sdk::Limits {
            max_bytes: 4 * 1024 * 1024,
            ..sdk::Limits::default()
        }
    )
    .is_err());
    Ok(())
}
