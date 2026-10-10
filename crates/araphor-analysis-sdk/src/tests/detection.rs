use arrow_array::cast::AsArray as _;
use arrow_array::types::UInt64Type;

use super::{sensitive_access::SensitiveAccess, TestResult};
use crate::{CoverageState, ErrorCode};

#[test]
fn detector_matches_exact_baseline() -> TestResult {
    let package = SensitiveAccess::package();
    let fixture = SensitiveAccess::fixture()?;
    let report = package.test(&fixture, SensitiveAccess::evaluate)?;
    let batch = &report.output.datasets[0].batches[0];
    let ids = batch
        .column_by_name("event_id")
        .and_then(|column| column.as_primitive_opt::<UInt64Type>())
        .ok_or("finding event IDs")?;
    assert_eq!(ids.values().as_ref(), &[2, 3]);
    let subjects = batch
        .column_by_name("subject")
        .and_then(|column| column.as_string_opt::<i32>())
        .ok_or("finding subjects")?;
    let resources = batch
        .column_by_name("resource")
        .and_then(|column| column.as_string_opt::<i32>())
        .ok_or("finding resources")?;
    assert_eq!(
        subjects.iter().collect::<Vec<_>>(),
        [Some("subject.1"), Some("subject.2")]
    );
    assert_eq!(
        resources.iter().collect::<Vec<_>>(),
        [Some("hf.token"), Some("model.weights")]
    );
    assert_eq!(report.output.reasons.len(), 2);
    for (row, reason) in report.output.reasons.iter().enumerate() {
        assert_eq!(reason.code, "sensitive-access.OUTSIDE_BASELINE");
        assert_eq!(reason.output.dataset, "findings");
        assert_eq!(reason.output.row, row as u64);
        assert_eq!(
            reason.details.schema().as_ref(),
            &package.exports[0].reasons[0].details
        );
        let baseline = reason
            .details
            .column_by_name("baseline_revision")
            .and_then(|column| column.as_string_opt::<i32>())
            .ok_or("baseline revision detail")?;
        assert_eq!(baseline.value(0), "audited-baseline.4");
        let resource = reason
            .details
            .column_by_name("resource")
            .and_then(|column| column.as_string_opt::<i32>())
            .ok_or("resource detail")?;
        assert_eq!(resource.value(0), resources.value(row));
    }
    assert_eq!(
        report.inputs["baseline"].0,
        fixture.evaluation.input("baseline")?.revision
    );
    Ok(())
}

#[test]
fn clean_access_has_none() -> TestResult {
    let package = SensitiveAccess::package();
    let mut fixture = SensitiveAccess::fixture()?;
    fixture.evaluation.inputs[0].data.batches[0] =
        fixture.evaluation.inputs[0].data.batches[0].slice(0, 1);
    let report = package.test(&fixture, SensitiveAccess::evaluate)?;
    assert_eq!(report.output.datasets[0].batches[0].num_rows(), 0);
    assert!(report.output.reasons.is_empty());
    assert!(report.output.evidence.is_empty());
    Ok(())
}

#[test]
fn detection_evidence_spans_batches() -> TestResult {
    let package = SensitiveAccess::package();
    let mut fixture = SensitiveAccess::fixture()?;
    let batch = fixture.evaluation.inputs[0].data.batches.remove(0);
    fixture.evaluation.inputs[0].data.batches = (0..batch.num_rows())
        .map(|row| batch.slice(row, 1))
        .collect();
    let report = package.test(&fixture, SensitiveAccess::evaluate)?;
    let links: Vec<_> = report
        .output
        .evidence
        .iter()
        .map(|link| {
            (
                link.output.dataset.as_str(),
                link.output.row,
                link.input.dataset.as_str(),
                link.input.row,
            )
        })
        .collect();
    assert_eq!(
        links,
        [
            ("findings", 0, "sensitive_reads", 1),
            ("findings", 1, "sensitive_reads", 2)
        ]
    );
    Ok(())
}

#[test]
fn incomplete_baseline_blocks_detection() -> TestResult {
    let package = SensitiveAccess::package();
    for (state, limits) in [
        (CoverageState::Gapped, vec![]),
        (CoverageState::Unknown, vec![]),
        (CoverageState::Complete, vec!["ROW_LIMIT".into()]),
    ] {
        let mut fixture = SensitiveAccess::fixture()?;
        fixture.evaluation.inputs[1].coverage.state = state;
        fixture.evaluation.inputs[1].coverage.limits = limits;
        let error = package
            .test(&fixture, SensitiveAccess::evaluate)
            .err()
            .ok_or("incomplete baseline accepted")?;
        assert_eq!(error.code(), ErrorCode::Incomplete);
    }
    Ok(())
}

#[test]
fn empty_baseline_retains_revision() -> TestResult {
    let package = SensitiveAccess::package();
    let mut fixture = SensitiveAccess::fixture()?;
    fixture.evaluation.inputs[1].data.batches.clear();
    let revision = fixture.evaluation.input("baseline")?.revision.clone();
    let report = package.test(&fixture, SensitiveAccess::evaluate)?;
    assert_eq!(report.output.reasons.len(), 3);
    assert_eq!(report.inputs["baseline"].0, revision);
    for reason in &report.output.reasons {
        let baseline = reason
            .details
            .column_by_name("baseline_revision")
            .and_then(|column| column.as_string_opt::<i32>())
            .ok_or("baseline revision detail")?;
        assert_eq!(baseline.value(0), revision.id);
    }
    Ok(())
}

#[test]
fn named_inputs_ignore_order() -> TestResult {
    let package = SensitiveAccess::package();
    let mut fixture = SensitiveAccess::fixture()?;
    let revision = fixture.evaluation.input("baseline")?.revision.clone();
    fixture.evaluation.inputs.swap(0, 1);
    assert_eq!(fixture.evaluation.input("baseline")?.revision, revision);
    let report = package.test(&fixture, SensitiveAccess::evaluate)?;
    assert_eq!(report.output.reasons.len(), 2);
    Ok(())
}

#[test]
fn missing_input_is_structured() -> TestResult {
    let fixture = SensitiveAccess::fixture()?;
    let error = fixture
        .evaluation
        .input("missing")
        .err()
        .ok_or("missing input accepted")?;
    assert_eq!(error.code(), ErrorCode::Incomplete);
    assert!(error.to_string().contains("input missing"));
    Ok(())
}
