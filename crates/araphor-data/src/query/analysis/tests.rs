use super::*;
use crate::graph::tests::native_storage::CommitFixture;
use crate::QueryLimits;
use sdk::arrow_array::{BinaryArray, BooleanArray, StringArray, UInt64Array};

mod computation;
mod fixture;

use fixture::{column, control, NativeFixture};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn graph_sdk_native_rows() -> TestResult {
    let fixture = NativeFixture::new(false)?;
    let owner = fixture.owner(QueryLimits {
        output_rows: 1,
        ..Default::default()
    })?;
    let result = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    assert_eq!(
        result.traversal.result_ids,
        vec![fixture.stored.request.result_id.clone()]
    );
    assert_eq!(result.meta, fixture.stored.store.meta()?);
    assert_eq!(result.inputs().len(), 3);
    for input in &result.inputs()[..2] {
        assert!(input
            .data
            .batches
            .iter()
            .all(|batch| batch.column_by_name("graph_revision").is_none()));
    }
    assert_eq!(
        computation::evaluate(&result)?,
        vec![(fixture.stored.request.result_id.clone(), 1)]
    );
    let subjects = &result.inputs()[0].data.batches[0];
    assert_eq!(subjects.num_rows(), 2);
    let keys = column::<BinaryArray>(subjects, "subject_id")?;
    assert_eq!(
        serde_json::from_slice::<crate::GraphSubjectKeyV1>(keys.value(0))?,
        fixture.subjects[0]
    );
    let manifest = &result.inputs()[2].data.batches[0];
    assert_eq!(manifest.num_rows(), 1);
    assert_eq!(
        serde_json::from_slice::<crate::EvidenceIntakeIdentityV1>(
            column::<BinaryArray>(manifest, "source_key")?.value(0)
        )?,
        fixture.stored.snapshot.scope.identity
    );
    assert_eq!(column::<UInt64Array>(manifest, "first_cursor")?.value(0), 1);
    assert_eq!(column::<UInt64Array>(manifest, "last_cursor")?.value(0), 1);
    assert!(column::<BooleanArray>(manifest, "hop_boundary")?.value(0));
    assert_eq!(
        result.inputs()[0].coverage.state,
        sdk::CoverageState::Unknown
    );
    assert_eq!(result.inputs()[2].revision.window, None);
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &fixture.request, &control()?),
        Err(crate::Error::AnalysisBusy { .. })
    ));
    let revision = result.inputs()[0].revision.clone();
    drop(result);
    let request = GraphTraversalV1 {
        max_hops: 2,
        ..fixture.request.clone()
    };
    let result = owner.graph_inputs(&fixture.selection, &request, &control()?)?;
    assert_eq!(
        computation::evaluate(&result)?,
        vec![(fixture.stored.request.result_id.clone(), 2)]
    );
    assert_eq!(result.inputs()[0].data.batches[0].num_rows(), 3);
    assert_ne!(result.inputs()[0].revision, revision);
    assert!(!result.traversal.hop_boundary);
    Ok(())
}

#[test]
fn graph_sdk_empty_history() -> TestResult {
    let fixture = NativeFixture::new(false)?;
    let replacement = fixture.replace_empty()?;
    let owner = fixture.owner(QueryLimits::default())?;
    let result = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    assert_eq!(result.traversal.result_ids, vec![replacement.clone()]);
    assert_eq!(
        computation::evaluate(&result)?,
        vec![(replacement.clone(), 0)]
    );
    assert_eq!(result.inputs()[0].data.batches[0].num_rows(), 0);
    assert_eq!(result.inputs()[1].data.batches[0].num_rows(), 0);
    let manifest = &result.inputs()[2].data.batches[0];
    assert_eq!(
        column::<UInt64Array>(manifest, "subject_count")?.value(0),
        0
    );
    assert_eq!(
        column::<UInt64Array>(manifest, "relationship_count")?.value(0),
        0
    );
    assert_eq!(
        column::<StringArray>(manifest, "previous_result_id")?.value(0),
        fixture.stored.request.result_id
    );
    drop(result);
    let request = GraphTraversalV1 {
        result_ids: vec![fixture.stored.request.result_id.clone()],
        ..fixture.request.clone()
    };
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &request, &control()?),
        Err(crate::Error::QueryDenied { .. })
    ));
    let mut selection = fixture.selection.clone();
    selection.results = request.result_ids.clone();
    let result = owner.graph_inputs(&selection, &request, &control()?)?;
    assert_eq!(
        computation::evaluate(&result)?,
        vec![(fixture.stored.request.result_id.clone(), 1)]
    );
    drop(result);
    let request = GraphTraversalV1 {
        result_ids: vec![replacement],
        ..request
    };
    assert!(matches!(
        owner.graph_inputs(&selection, &request, &control()?),
        Err(crate::Error::QueryDenied { .. })
    ));
    Ok(())
}

#[test]
fn graph_sdk_scope_sensitivity() -> TestResult {
    let fixture = NativeFixture::new(true)?;
    let owner = fixture.owner(QueryLimits::default())?;
    let result = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    for input in result.inputs() {
        for batch in &input.data.batches {
            assert!(column::<StringArray>(batch, "graph_sensitivity")?
                .iter()
                .flatten()
                .all(|value| value == "host_restricted"));
        }
    }
    let manifest = &result.inputs()[2].data.batches[0];
    let revision: crate::GraphRevisionV1 =
        serde_json::from_slice(column::<BinaryArray>(manifest, "graph_revision")?.value(0))?;
    assert_eq!(revision, fixture.stored.snapshot.input_manifest);
    drop(result);
    let mut denied = fixture.request.clone();
    denied.seeds[0].tenant_id = [99; 16];
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &denied, &control()?),
        Err(crate::Error::QueryDenied { .. })
    ));
    for (nodes, bindings) in [
        (vec!["foreign-node".into()], vec![]),
        (vec![], vec![[99; 16]]),
    ] {
        let selection = AnalysisSelectionV1 {
            nodes,
            binding_ids: bindings,
            ..fixture.selection.clone()
        };
        let result = owner.graph_inputs(&selection, &fixture.request, &control()?)?;
        assert!(result.traversal.result_ids.is_empty());
        assert_eq!(computation::evaluate(&result)?, vec![]);
        assert_eq!(
            result.inputs()[0].coverage.state,
            sdk::CoverageState::Unknown
        );
    }
    Ok(())
}

#[test]
fn graph_sdk_resource_limits() -> TestResult {
    let fixture = NativeFixture::new(false)?;
    let owner = fixture.owner(QueryLimits::default())?;
    let limited = GraphTraversalV1 {
        max_subjects: 1,
        ..fixture.request.clone()
    };
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &limited, &control()?),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let small = fixture.owner(QueryLimits {
        input_bytes: 1024,
        ..Default::default()
    })?;
    assert!(matches!(
        small.graph_inputs(&fixture.selection, &fixture.request, &control()?),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let cancelled = control()?;
    cancelled.cancel()?;
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &fixture.request, &cancelled),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    let expired = AnalysisReadControl::with_timeout(std::time::Duration::from_nanos(1))?;
    assert!(matches!(
        owner.graph_inputs(&fixture.selection, &fixture.request, &expired),
        Err(crate::Error::AnalysisReadDeadline { .. })
    ));
    let result = owner.graph_inputs(&fixture.selection, &fixture.request, &control()?)?;
    assert_eq!(
        computation::evaluate(&result)?,
        vec![(fixture.stored.request.result_id.clone(), 1)]
    );
    Ok(())
}

#[test]
fn graph_sdk_offset_limit() -> TestResult {
    ArrowRows::check_offsets(i32::MAX as usize)?;
    assert!(matches!(
        ArrowRows::check_offsets(i32::MAX as usize + 1),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    Ok(())
}
