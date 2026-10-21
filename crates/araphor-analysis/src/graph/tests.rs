use super::*;

mod baseline;
mod binding;
mod contract;
mod defaults;
mod domain;
mod execution;
mod fixture;
mod traversal;
mod windows;

use araphor_data::RemoteSubjectBindingV1;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

impl Graph<'_> {
    fn evaluation(&self) -> Result<sdk::Evaluation> {
        self.evaluation_for(&algorithm::Detector::Credentials.descriptor().exports[0])
    }

    fn evaluation_for(&self, model: &sdk::Model) -> Result<sdk::Evaluation> {
        let inputs = model
            .inputs
            .iter()
            .zip(self.projection())
            .map(|(input, values)| {
                Rows::encode(&input.port, values, model.limits).map(|data| sdk::Input {
                    data,
                    revision: sdk::Revision {
                        owner: "captured".into(),
                        id: "fixture".into(),
                        window: None,
                    },
                    coverage: sdk::Coverage {
                        state: sdk::CoverageState::Complete,
                        limits: Vec::new(),
                    },
                })
            })
            .collect::<sdk::Result<Vec<_>>>()
            .context(AnalysisContractSnafu)?;
        Ok(sdk::Evaluation {
            export: model.name.clone(),
            inputs,
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "fixture".into(),
                time_utc_ns: 10,
                seed: None,
                limits: model.limits,
            },
        })
    }
}

fn derive(input: &GraphReplayInputV1) -> Result<GraphSnapshotV1> {
    let input = input.normalized()?;
    let mut graph = Graph::new(&input)?;
    for detector in [
        algorithm::Detector::Process,
        algorithm::Detector::Credentials,
        algorithm::Detector::Kubernetes,
    ] {
        let package = detector.descriptor();
        let evaluation = graph.evaluation_for(&package.exports[0])?;
        let output = detector
            .evaluate(&evaluation)
            .context(AnalysisContractSnafu)?;
        graph.check_inputs(&package.exports[0], &evaluation)?;
        graph.apply_output(&package, &evaluation, &output)?;
    }
    graph.finish()
}

fn input() -> Result<GraphReplayInputV1> {
    let mut input = fixture::credential_input()?;
    input.facts.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(input)
}

fn computation(
    input: &GraphReplayInputV1,
) -> TestResult<(Graph<'_>, sdk::Evaluation, sdk::Output)> {
    let owner = Graph::new(input)?;
    let evaluation = owner.evaluation()?;
    let output = algorithm::Detector::Credentials.evaluate(&evaluation)?;
    Ok((owner, evaluation, output))
}

#[test]
fn candidate_reason_matches_contract() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    output.datasets.reverse();
    output.reasons.reverse();
    output.evidence.reverse();
    let package = algorithm::Detector::Credentials.descriptor();
    package.validate_output(&evaluation, &output)?;
    assert!(!output.reasons.is_empty());
    for reason in &output.reasons {
        let declared = package.exports[0]
            .reasons
            .iter()
            .find(|declared| declared.code == reason.code)
            .ok_or("declared reason")?;
        assert_eq!(reason.details.schema().as_ref(), &declared.details);
    }
    owner.apply_output(
        &algorithm::Detector::Credentials.descriptor(),
        &evaluation,
        &output,
    )?;
    let expected = derive(&input)?;
    let findings: Vec<_> = expected
        .findings
        .iter()
        .filter(|finding| finding.package_id == "HF-DW-001")
        .collect();
    assert_eq!(owner.findings.values().collect::<Vec<_>>(), findings);
    Ok(())
}

#[test]
fn candidate_requires_host_validation() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[0];
    let mut subjects: Vec<algorithm::Subject> =
        Rows::decode(port, &output.datasets[0], evaluation.context.limits)?;
    subjects.first_mut().ok_or("subject candidate")?.record = u64::from(u32::MAX) + 1;
    output.datasets[0] = Rows::encode(port, &subjects, evaluation.context.limits)?;
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(
            &algorithm::Detector::Credentials.descriptor(),
            &evaluation,
            &output
        ),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph output record",
            ..
        })
    ));
    Ok(())
}

#[test]
fn candidate_reason_is_exact() -> TestResult {
    let input = input()?;
    let (_, evaluation, output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[2];
    let mut missing = output.clone();
    missing.reasons.clear();
    let mut wrong_code = output.clone();
    let reason = wrong_code.reasons.first_mut().ok_or("candidate reason")?;
    reason.code = if reason.code.ends_with(".CONTRADICTION") {
        "HF-DW-001.MISSING_AUTHORITY_PROOF"
    } else {
        "HF-DW-001.CONTRADICTION"
    }
    .into();
    let mut wrong_detail = output.clone();
    let reason = wrong_detail.reasons.first_mut().ok_or("candidate reason")?;
    let mut details: Vec<algorithm::Finding> = Rows::decode(
        port,
        &sdk::Dataset {
            name: port.name.clone(),
            batches: vec![reason.details.clone()],
        },
        evaluation.context.limits,
    )?;
    let finding = details.first_mut().ok_or("candidate detail")?;
    finding.confirmed = !finding.confirmed;
    reason.details = Rows::encode(port, &details, evaluation.context.limits)?
        .batches
        .remove(0);
    for altered in [missing, wrong_code, wrong_detail] {
        package.validate_output(&evaluation, &altered)?;
        let mut owner = Graph::new(&input)?;
        assert!(matches!(
            owner.apply_output(
                &algorithm::Detector::Credentials.descriptor(),
                &evaluation,
                &altered
            ),
            Err(araphor_data::Error::GraphInvalid {
                field: "graph candidate reason",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn candidate_evidence_is_exact() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    output.evidence.pop().ok_or("candidate evidence")?;
    let package = algorithm::Detector::Credentials.descriptor();
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(
            &algorithm::Detector::Credentials.descriptor(),
            &evaluation,
            &output
        ),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph candidate evidence",
            ..
        })
    ));
    Ok(())
}

#[test]
fn candidate_rejects_authority_upgrade() -> TestResult {
    let mut input = input()?;
    for version in &mut input.facts {
        let mut fact: GraphFactV1 = serde_json::from_slice(&version.body)?;
        if let GraphFactValueV1::AuthorityUse { proof_quality, .. } = &mut fact.value {
            proof_quality.remote_subject_binding = RemoteSubjectBindingV1::Contextual;
            version.body = serde_json::to_vec(&fact)?;
        }
    }
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[1];
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == port.name)
        .ok_or("relationships")?;
    let mut edges: Vec<algorithm::Relationship> =
        Rows::decode(port, data, evaluation.context.limits)?;
    let edge = edges
        .iter_mut()
        .find(|edge| matches!(edge.kind, algorithm::EdgeKind::Authority))
        .ok_or("authority edge")?;
    assert!(matches!(edge.cause, algorithm::Cause::Contextual));
    edge.cause = algorithm::Cause::Direct;
    *data = Rows::encode(port, &edges, evaluation.context.limits)?;
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph direct cause proof",
            ..
        })
    ));
    Ok(())
}

#[test]
fn candidate_rejects_missing_coverage() -> TestResult {
    let mut input = input()?;
    input.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    input.coverage[0].gap_reasons = vec!["HOST_GAP".into()];
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[2];
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == port.name)
        .ok_or("findings")?;
    let mut findings: Vec<algorithm::Finding> =
        Rows::decode(port, data, evaluation.context.limits)?;
    for finding in &mut findings {
        finding.confirmed = true;
    }
    *data = Rows::encode(port, &findings, evaluation.context.limits)?;
    for reason in &mut output.reasons {
        let finding = findings
            .get(reason.output.row as usize)
            .ok_or("finding detail")?;
        reason.details = Rows::encode(
            port,
            std::slice::from_ref(finding),
            evaluation.context.limits,
        )?
        .batches
        .remove(0);
    }
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph confirmed finding proof",
            ..
        })
    ));
    Ok(())
}

#[test]
fn declared_detector_retains_details() -> TestResult {
    declared_reason("example-detector", "THRESHOLD")?;
    declared_reason("HF-DW-001", "THRESHOLD")?;
    declared_reason("HF-DW-001", "CREDENTIAL_PIVOT")
}

fn declared_reason(package_id: &str, reason: &str) -> TestResult {
    use sdk::arrow_array::UInt64Array;
    use std::sync::Arc;

    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let mut package = algorithm::Detector::Credentials.descriptor();
    package.id = package_id.into();
    let model = &mut package.exports[0];
    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let code = format!("{package_id}.{reason}");
    model.reasons = vec![sdk::Reason {
        code: code.clone(),
        details: schema.clone(),
    }];
    let port = &model.outputs[2];
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == port.name)
        .ok_or("findings")?;
    let mut findings: Vec<algorithm::Finding> =
        Rows::decode(port, data, evaluation.context.limits)?;
    for finding in &mut findings {
        finding.reason = reason.into();
    }
    *data = Rows::encode(port, &findings, evaluation.context.limits)?;
    for value in &mut output.reasons {
        value.code = code.clone();
        value.details = sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![3]))],
        )?;
    }
    package.validate_output(&evaluation, &output)?;
    owner.apply_output(&package, &evaluation, &output)?;
    let snapshot = owner.finish()?;
    assert!(!snapshot.findings.is_empty());
    for finding in snapshot.findings {
        assert_eq!(finding.reason.label()?, code);
        let FindingReasonV1::Declared(reason) = finding.reason else {
            return Err("declared reason lost".into());
        };
        assert_eq!(reason.schema, schema);
        assert!(!reason.ipc.is_empty());
    }
    Ok(())
}
