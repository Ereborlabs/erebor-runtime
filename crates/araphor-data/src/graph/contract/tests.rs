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
            assert_eq!(label(&reason)?, reason.label()?);
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
    let reason = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(&value)?);
    validate(&reason, "example-detector")?;
    assert_eq!(reason.label()?, value.code);
    assert_eq!(restore(&storage(&reason)?)?, reason);
    assert_eq!(
        serde_json::from_value::<FindingReasonV1>(serde_json::to_value(&reason)?)?,
        reason
    );
    assert!(validate(&reason, "another-detector").is_err());
    assert_eq!(
        serde_json::to_value(FindingReasonV1::UnexpectedEffect)?,
        "UNEXPECTED_EFFECT"
    );
    assert_eq!(
        restore("UNEXPECTED_EFFECT")?,
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
    let reason = DeclaredFindingReasonV1::from_value(&value)?;
    assert!(reason.ipc.len() > 4 * 1024 * 1024);
    validate_declared(&reason, "example-detector")?;
    assert!(validate_declared(&reason, "another-detector").is_err());
    Ok(())
}

#[test]
fn declared_errors_keep_types() -> TestResult {
    use sdk::arrow_array::{LargeStringArray, UInt64Array};
    use std::sync::Arc;

    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let mut value = sdk::ReasonValue {
        output: sdk::RowRef {
            dataset: "findings".into(),
            row: 0,
        },
        code: "example-detector.THRESHOLD".into(),
        details: sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![3]))],
        )?,
    };
    let valid = DeclaredFindingReasonV1::from_value(&value)?;
    valid.validate("example-detector")?;
    validate_declared(&valid, "example-detector")?;
    assert!(matches!(
        validate_declared(&valid, "another-detector"),
        Err(crate::Error::GraphInvalid {
            field: "finding reason namespace",
            ..
        })
    ));
    for rows in [0, 2] {
        value.details = sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![3; rows]))],
        )?;
        let reason = DeclaredFindingReasonV1::from_value(&value)?;
        assert!(matches!(
            validate_declared(&reason, "example-detector"),
            Err(crate::Error::GraphInvalid {
                field: "finding reason details",
                ..
            })
        ));
    }
    let mut malformed = valid.clone();
    malformed.ipc = vec![0, 1, 2, 3];
    assert!(matches!(
        validate_declared(&malformed, "example-detector"),
        Err(crate::Error::AnalysisContract { .. })
    ));
    let mut mismatched = valid;
    mismatched.schema =
        sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::Utf8, false)]);
    assert!(matches!(
        validate_declared(&mismatched, "example-detector"),
        Err(crate::Error::AnalysisContract {
            source: sdk::Error::Contract { code: sdk::ErrorCode::Invalid, field, .. }, ..
        }) if field == "dataset schema"
    ));
    value.details = sdk::RecordBatch::try_new(
        Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "count",
            sdk::DataType::LargeUtf8,
            false,
        )])),
        vec![Arc::new(LargeStringArray::from(vec!["details"]))],
    )?;
    let unsupported = DeclaredFindingReasonV1::from_value(&value)?;
    assert!(matches!(
        validate_declared(&unsupported, "example-detector"),
        Err(crate::Error::AnalysisContract {
            source: sdk::Error::Contract { code: sdk::ErrorCode::Incompatible, field, .. }, ..
        }) if field == "count"
    ));
    Ok(())
}
