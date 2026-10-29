use super::super::*;
use super::{fixture, TestResult};
use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore, InputRevision};
use araphor_query::definition::{DefinitionOutput, Invocation};
use araphor_query::execution::{Engine, Limits};
use araphor_query::Failure;
use std::{sync::Arc, time::Duration};

mod baseline;
mod runtime;
pub(in crate::graph) use runtime::Fixture;
use runtime::Target;

#[tokio::test]
async fn sql_graph_adapter() -> TestResult {
    parity(Target::Sql).await
}

#[tokio::test]
async fn wasm_graph_adapter() -> TestResult {
    parity(Target::Wasm).await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_graph_adapter() -> TestResult {
    parity(Target::Native).await
}

async fn parity(target: Target) -> TestResult {
    let comparisons = if matches!(target, Target::Native) {
        let input = fixture::credential_input()?.normalized()?;
        Some(
            detectors()
                .into_iter()
                .map(|detector| {
                    let evaluation = evaluation(&input, detector)?;
                    let expected = detector.evaluate(&evaluation)?;
                    Ok((
                        detector,
                        Fixture::new(detector, Target::Native, &evaluation, &expected, None)?,
                        Fixture::new(detector, Target::Wasm, &evaluation, &expected, None)?,
                    ))
                })
                .collect::<TestResult<Vec<_>>>()?,
        )
    } else {
        None
    };
    for detector in detectors() {
        let selected = selected(detector)?;
        let mut gapped = selected.clone();
        gapped.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
        gapped.coverage[0].gap_reasons.push("FIXTURE_GAP".into());
        gapped.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
        gapped.coverage_keys[0]
            .gap_reasons
            .push("FIXTURE_GAP".into());
        for input in [selected, gapped] {
            let input = input.normalized()?;
            let package = detector.descriptor();
            let mut evaluation = evaluation(&input, detector)?;
            let trusted = detector.evaluate(&evaluation)?;
            assert!(!trusted.reasons.is_empty());
            assert!(!trusted.evidence.is_empty());
            let fixture = Fixture::new(detector, target, &evaluation, &trusted, None)?;
            let (call, actual) = fixture.run(&evaluation).await?;
            let result = actual.calls.get(&call.id()).ok_or("complete call")?;
            fixture.compare(&evaluation, &trusted, result)?;
            let mut expected = Graph::new(&input)?;
            expected.apply_output(&package, &evaluation, &trusted, false, None)?;
            let expected = expected.finish()?;
            assert_eq!(expected.input_positions, input.input_positions);
            let actual_graph = Graph::new(&input)?.apply(&call, result)?.finish()?;
            assert_eq!(
                serde_json::to_value(actual_graph)?,
                serde_json::to_value(&expected)?
            );
            if let Some(comparisons) = &comparisons {
                let native = captured_graph(
                    &input,
                    comparisons
                        .iter()
                        .map(|(detector, native, _)| (*detector, native)),
                )
                .await?;
                let wasm = captured_graph(
                    &input,
                    comparisons
                        .iter()
                        .map(|(detector, _, wasm)| (*detector, wasm)),
                )
                .await?;
                assert_eq!(serde_json::to_value(native)?, serde_json::to_value(wasm)?);
            }
            evaluation.checkpoint = result.output().checkpoint.clone();
            evaluation.previous_outputs = normalized_prior(result.output(), &package.id)?;
            evaluation.inputs.reverse();
            drop(actual);
            drop(call);
            evaluation = package
                .check_evaluation(&evaluation)?
                .encode()?
                .decode(&package)?;
            let (call, replay) = fixture.run(&evaluation).await?;
            fixture.compare(
                &evaluation,
                &detector.evaluate(&evaluation)?,
                replay.calls.get(&call.id()).ok_or("replayed call")?,
            )?;
            let mut replay_graph = Graph::new(&input)?;
            replay_graph.apply_output(
                &package,
                &evaluation,
                replay
                    .calls
                    .get(&call.id())
                    .ok_or("original replay")?
                    .output(),
                false,
                None,
            )?;
            assert_eq!(
                serde_json::to_value(replay_graph.finish()?)?,
                serde_json::to_value(&expected)?
            );
            drop(replay);
            drop(call);
            fixture.released()?;
        }
    }
    let input = fixture::credential_input()?.normalized()?;
    let mut actual = Graph::new(&input)?;
    for detector in detectors() {
        let evaluation = evaluation(&input, detector)?;
        let expected = detector.evaluate(&evaluation)?;
        let fixture = Fixture::new(detector, target, &evaluation, &expected, None)?;
        let (call, result) = fixture.run(&evaluation).await?;
        actual = actual.apply(&call, result.calls.get(&call.id()).ok_or("graph call")?)?;
        drop(result);
        drop(call);
        fixture.released()?;
    }
    assert_eq!(
        serde_json::to_value(actual.finish()?)?,
        serde_json::to_value(super::derive(&input)?)?
    );
    large(target).await
}

async fn captured_graph<'a>(
    input: &GraphReplayInputV1,
    fixtures: impl Iterator<Item = (algorithm::Detector, &'a Fixture)>,
) -> TestResult<GraphSnapshotV1> {
    let mut graph = Graph::new(input)?;
    for (detector, fixture) in fixtures {
        let evaluation = evaluation(input, detector)?;
        let trusted = detector.evaluate(&evaluation)?;
        let (call, returned) = fixture.run(&evaluation).await?;
        let result = returned
            .calls
            .get(&call.id())
            .ok_or("complete graph call")?;
        fixture.compare(&evaluation, &trusted, result)?;
        graph = graph.apply(&call, result)?;
        drop(returned);
        drop(call);
        fixture.released()?;
    }
    Ok(graph.finish()?)
}

async fn large(target: Target) -> TestResult {
    let input = large_input()?;
    let detector = algorithm::Detector::Process;
    let package = detector.descriptor();
    let evaluation = evaluation(&input, detector)?;
    assert_eq!(evaluation.input("records")?.data.rows(), 185);
    let expected = detector.evaluate(&evaluation)?;
    assert_eq!(expected.reasons.len(), 185);
    assert!(!expected.evidence.is_empty());
    assert!(expected.checkpoint.is_some());
    let fixture = Fixture::new(detector, target, &evaluation, &expected, None)?;
    let (call, actual) = fixture.run(&evaluation).await?;
    let result = actual.calls.get(&call.id()).ok_or("large call")?;
    assert_eq!(result.output().reasons.len(), 185);
    fixture.compare(&evaluation, &expected, result)?;
    Graph::new(&input)?.apply(&call, result)?.finish()?;
    drop(actual);
    drop(call);
    fixture.released()?;
    let (call, actual) = fixture.run(&evaluation).await?;
    fixture.compare(
        &evaluation,
        &expected,
        actual.calls.get(&call.id()).ok_or("after limit")?,
    )?;
    drop(actual);
    drop(call);
    fixture.released()?;
    let mut prior = evaluation.clone();
    prior.previous_outputs = normalized_prior(&expected, &package.id)?;
    prior.checkpoint = expected.checkpoint;
    package.check_evaluation(&prior)?;
    Ok(())
}

#[tokio::test]
async fn sql_graph_pressure() -> TestResult {
    pressure(Target::Sql).await
}

#[tokio::test]
async fn wasm_graph_pressure() -> TestResult {
    pressure(Target::Wasm).await
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_graph_pressure() -> TestResult {
    pressure(Target::Native).await
}

async fn pressure(target: Target) -> TestResult {
    const OUTPUT: usize = 16 * 1024 * 1024;
    let input = large_input()?;
    let detector = algorithm::Detector::Process;
    let package = detector.descriptor();
    let mut evaluation = evaluation(&input, detector)?;
    let expected = detector.evaluate(&evaluation)?;
    let fixture = Fixture::new(detector, target, &evaluation, &expected, Some(OUTPUT))?;
    let (call, actual) = fixture.run(&evaluation).await?;
    let result = actual.calls.get(&call.id()).ok_or("retained call")?;
    fixture.compare(&evaluation, &expected, result)?;
    evaluation.checkpoint = result.output().checkpoint.clone();
    evaluation.previous_outputs = normalized_prior(result.output(), &package.id)?;
    assert!(evaluation.checkpoint.is_some());
    assert!(fixture.engine.memory().reserve_output(OUTPUT).is_err());
    let detached = package
        .check_evaluation(&evaluation)?
        .encode()?
        .decode(&package)?;
    drop(actual);
    drop(call);
    assert!(fixture.engine.memory().reserve_output(OUTPUT).is_err());
    drop(evaluation);
    let held = fixture.engine.memory().reserve_output(OUTPUT)?;
    let error = fixture
        .run(&detached)
        .await
        .err()
        .ok_or("held output capacity must reject")?;
    let error = error
        .downcast_ref::<araphor_query::Error>()
        .ok_or("typed Query pressure")?;
    assert_eq!(Failure::from(error), Failure::Busy, "{error:?}");
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(error);
    let mut output = false;
    while let Some(error) = source {
        output |= matches!(
            error.downcast_ref::<araphor_query::Error>(),
            Some(araphor_query::Error::Capacity {
                resource: "shared output",
                ..
            })
        );
        source = error.source();
    }
    assert!(output, "{error:?}");
    drop(held);
    let (call, replay) = fixture.run(&detached).await?;
    fixture.compare(
        &detached,
        &detector.evaluate(&detached)?,
        replay.calls.get(&call.id()).ok_or("pressure replay")?,
    )?;
    drop(replay);
    drop(call);
    drop(detached);
    fixture.released()?;
    let _available = fixture.engine.memory().reserve_output(OUTPUT)?;
    Ok(())
}

fn detectors() -> [algorithm::Detector; 3] {
    [
        algorithm::Detector::Process,
        algorithm::Detector::Credentials,
        algorithm::Detector::Kubernetes,
    ]
}

pub(super) fn normalized_prior(
    output: &sdk::Output,
    package_id: &str,
) -> TestResult<Vec<sdk::Dataset>> {
    let mut datasets = output.datasets.clone();
    let data = datasets
        .iter_mut()
        .find(|data| data.name == "findings")
        .ok_or("Graph findings output")?;
    let mut findings = algorithm::FindingChange::decode(data)?;
    for finding in &mut findings {
        finding.prior_reason = Some(algorithm::FindingReasonV1::from_analysis_code(
            package_id,
            &finding.reason_code,
        )?);
    }
    *data = algorithm::FindingChange::encode(&findings)?;
    Ok(datasets)
}

fn evaluation(
    input: &GraphReplayInputV1,
    detector: algorithm::Detector,
) -> TestResult<sdk::Evaluation> {
    let package = detector.descriptor();
    let mut evaluation = Graph::new(input)?.evaluation_for(&package.exports[0])?;
    let times = input
        .records
        .iter()
        .map(|record| record.decode().map(|wire| wire.ingested_utc_ns))
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let revision = sdk::Revision {
        owner: GRAPH_PROCESSOR.into(),
        id: InputRevision::of(&(
            &input.source,
            &input.records,
            &input.coverage,
            &input.coverage_keys,
            &input.facts,
            &input.missing_ranges,
        ))?,
        window: Some(sdk::SourceWindow {
            source: serde_json::to_vec(&input.source)?,
            start_utc_ns: times.iter().copied().min().unwrap_or(0),
            end_utc_ns: times.iter().copied().max().unwrap_or(0),
        }),
    };
    let state = if !input.missing_ranges.is_empty()
        || input
            .coverage
            .iter()
            .any(|range| range.state == DiscoveryCoverageStateV1::Gapped)
    {
        sdk::CoverageState::Gapped
    } else if algorithm::Observation::decode(&evaluation.input("records")?.data)?
        .iter()
        .any(|record| record.proof_quality.temporal_coverage != TemporalCoverageV1::Complete)
    {
        sdk::CoverageState::Unknown
    } else {
        sdk::CoverageState::Complete
    };
    for input in &mut evaluation.inputs {
        input.revision = revision.clone();
        input.coverage = sdk::Coverage {
            state,
            limits: if state == sdk::CoverageState::Complete {
                Vec::new()
            } else {
                vec!["SOURCE_COVERAGE_INSUFFICIENT".into()]
            },
        };
    }
    evaluation.context.id = revision.id;
    evaluation.context.time_utc_ns = times.into_iter().max().unwrap_or(0);
    evaluation.context.seed = Some(9_007_199_254_740_999);
    Ok(evaluation)
}

fn selected(detector: algorithm::Detector) -> TestResult<GraphReplayInputV1> {
    let mut input = fixture::credential_input()?;
    match detector {
        algorithm::Detector::Process => {
            let mut wire = input.records[0].decode()?;
            wire.decision = EffectPhysicalResultV1::DeniedBeforeEffect as u32;
            wire.kernel_result = -13;
            wire.configured_errno = -13;
            input.records[0].wire_record = Vec::<u8>::try_from(&wire)?;
        }
        algorithm::Detector::Kubernetes => {
            let (index, mut fact) = input
                .facts
                .iter()
                .enumerate()
                .map(|(index, version)| GraphFactV1::try_from(version).map(|fact| (index, fact)))
                .collect::<araphor_data::Result<Vec<_>>>()?
                .into_iter()
                .find(|(_, fact)| matches!(fact.value, GraphFactValueV1::Credential { .. }))
                .ok_or("credential fixture fact")?;
            let GraphFactValueV1::Credential { proof_quality, .. } = fact.value else {
                return Err("credential fixture fact".into());
            };
            fact.value = GraphFactValueV1::Kubernetes(araphor_data::KubernetesStageProofV1 {
                cluster_id: "cluster".into(),
                carried_request_id: Some("request".into()),
                audit_id: Some("audit".into()),
                object_uid: Some("object".into()),
                resource_version: Some("version".into()),
                owner_uid: Some("owner".into()),
                pod_uid: Some("pod".into()),
                node_id: Some("remote-node".into()),
                full_container_id: Some("container".into()),
                remote_admission_id: Some("admission".into()),
                proof_quality,
            });
            input.facts[index].body = serde_json::to_vec(&fact)?;
        }
        algorithm::Detector::Credentials => {}
    }
    Ok(input)
}

fn large_input() -> TestResult<GraphReplayInputV1> {
    let first = fixture::credential_input()?.records[0].clone();
    let records = (1..=185)
        .map(|cursor| {
            let mut record = first.clone();
            record.id.durable_cursor = cursor;
            record.original_kernel_sequence = Some(cursor);
            let mut wire = first.decode()?;
            wire.task_cookie = cursor;
            wire.observed_boottime_ns = cursor * 1_000;
            wire.ingested_utc_ns = cursor as i64;
            wire.decision = EffectPhysicalResultV1::DeniedBeforeEffect as u32;
            wire.kernel_result = -13;
            wire.configured_errno = -13;
            wire.decision_context
                .as_mut()
                .ok_or("decision context")?
                .original_kernel_sequence = cursor;
            record.wire_record = Vec::<u8>::try_from(&wire)?;
            Ok(record)
        })
        .collect::<TestResult<Vec<_>>>()?;
    Ok(fixture::input(records).normalized()?)
}
