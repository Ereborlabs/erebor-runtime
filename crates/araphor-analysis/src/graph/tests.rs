use super::*;

mod baseline;
mod binding;
mod contract;
mod defaults;
mod domain;
pub(in crate::graph) mod execution;
pub(super) mod fixture;
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
            .zip(self.projection()?)
            .map(|(_, values)| {
                Ok(sdk::Input {
                    data: values.clone(),
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
            previous_outputs: Vec::new(),
            export: model.name.clone(),
            inputs,
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "fixture".into(),
                time_utc_ns: 10,
                seed: None,
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
        graph.apply_output(&package, &evaluation, &output, false, None)?;
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
fn checkpoint_requires_one_state() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let checkpoint = output.checkpoint.as_mut().ok_or("checkpoint")?;
    checkpoint.datasets[0] = GraphPackageStateV1::encode(&[])?;
    let package = algorithm::Detector::Credentials.descriptor();
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output, false, None),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph checkpoint rows",
            ..
        })
    ));
    Ok(())
}

#[test]
fn candidate_reason_matches_contract() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    output.datasets.reverse();
    output.reasons.reverse();
    output.evidence.reverse();
    output
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .datasets
        .reverse();
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
        false,
        None,
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
    let mut subjects = algorithm::SubjectChange::decode(&output.datasets[0])?;
    subjects
        .first_mut()
        .ok_or("subject candidate")?
        .anchor
        .record
        .durable_cursor = u64::MAX;
    output.datasets[0] = algorithm::SubjectChange::encode(&subjects)?;
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(
            &algorithm::Detector::Credentials.descriptor(),
            &evaluation,
            &output,
            false,
            None
        ),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph anchor record",
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
    let mut details = algorithm::ReasonDetails::decode(&sdk::Dataset {
        name: algorithm::ReasonDetails::port().name,
        batches: vec![reason.details.clone()],
    })?;
    let finding = details.first_mut().ok_or("candidate detail")?;
    finding.confirmed = !finding.confirmed;
    reason.details = algorithm::ReasonDetails::encode(&details)?
        .batches
        .remove(0);
    for altered in [missing, wrong_code, wrong_detail] {
        package.validate_output(&evaluation, &altered)?;
        let mut owner = Graph::new(&input)?;
        assert!(matches!(
            owner.apply_output(
                &algorithm::Detector::Credentials.descriptor(),
                &evaluation,
                &altered,
                false,
                None
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
            &output,
            false,
            None
        ),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph candidate evidence",
            ..
        })
    ));
    Ok(())
}

#[test]
fn resolved_output_preserves_authority() -> TestResult {
    let input = input()?;
    let (_, evaluation, output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    for field in ["graph effect evidence", "graph policy provenance authority"] {
        let mut altered = output.clone();
        let data = altered
            .datasets
            .iter_mut()
            .find(|data| data.name == "findings")
            .ok_or("findings")?;
        let mut rows = algorithm::FindingChange::decode(data)?;
        let finding = rows.first_mut().ok_or("finding")?;
        if field == "graph effect evidence" {
            assert!(!finding.effects.is_empty());
            finding.effects.clear();
        } else {
            assert!(!finding.policy_provenance.is_empty());
            finding.policy_provenance.clear();
        }
        *data = algorithm::FindingChange::encode(&rows)?;
        package.validate_output(&evaluation, &altered)?;
        let mut owner = Graph::new(&input)?;
        let result = owner.apply_output(&package, &evaluation, &altered, false, None);
        assert!(
            matches!(&result, Err(araphor_data::Error::GraphInvalid { field: actual, .. }) if *actual == field),
            "{field}: {result:?}"
        );
    }
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
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == "relationships")
        .ok_or("relationships")?;
    let mut edges = algorithm::RelationshipChange::decode(data)?;
    let edge = edges
        .iter_mut()
        .find(|edge| edge.key.edge_type == GraphEdgeTypeV1::CredentialAuthority)
        .ok_or("authority edge")?;
    assert!(edge.key.cause == GraphCauseV1::Contextual);
    edge.key.cause = GraphCauseV1::Direct;
    *data = algorithm::RelationshipChange::encode(&edges)?;
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output, false, None),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph direct cause proof",
            ..
        })
    ));
    Ok(())
}

#[test]
fn resolved_output_keeps_provenance_limits() -> TestResult {
    let mut input = input()?;
    let mut contexts = Vec::new();
    for context in input.facts {
        let fact: GraphFactV1 = serde_json::from_slice(&context.body)?;
        if !matches!(fact.value, GraphFactValueV1::Policy(_)) {
            contexts.push(context);
        }
    }
    input.facts = contexts;
    let input = input.normalized()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    owner.apply_output(&package, &evaluation, &output, false, None)?;
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == "findings")
        .ok_or("findings")?;
    let mut findings = algorithm::FindingChange::decode(data)?;
    let finding = findings.first_mut().ok_or("finding")?;
    assert!(finding
        .limits
        .iter()
        .any(|limit| limit == "POLICY_PROVENANCE_MISSING"));
    finding
        .limits
        .retain(|limit| limit != "POLICY_PROVENANCE_MISSING");
    *data = algorithm::FindingChange::encode(&findings)?;
    for reason in &mut output.reasons {
        let mut details = algorithm::ReasonDetails::decode(&sdk::Dataset {
            name: algorithm::ReasonDetails::port().name,
            batches: vec![reason.details.clone()],
        })?;
        details[0]
            .limits
            .retain(|limit| limit != "POLICY_PROVENANCE_MISSING");
        reason.details = algorithm::ReasonDetails::encode(&details)?
            .batches
            .remove(0);
    }
    package.validate_output(&evaluation, &output)?;
    let mut owner = Graph::new(&input)?;
    let result = owner.apply_output(&package, &evaluation, &output, false, None);
    assert!(
        matches!(
            &result,
            Err(araphor_data::Error::GraphInvalid {
                field: "graph policy provenance limits",
                ..
            })
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn candidate_rejects_missing_coverage() -> TestResult {
    let mut input = input()?;
    input.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    input.coverage[0].gap_reasons = vec!["HOST_GAP".into()];
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == "findings")
        .ok_or("findings")?;
    let mut findings = algorithm::FindingChange::decode(data)?;
    for finding in &mut findings {
        finding.state = FindingStateV1::Confirmed;
    }
    *data = algorithm::FindingChange::encode(&findings)?;
    for reason in &mut output.reasons {
        let mut details = algorithm::ReasonDetails::decode(&sdk::Dataset {
            name: algorithm::ReasonDetails::port().name,
            batches: vec![reason.details.clone()],
        })?;
        details[0].confirmed = true;
        reason.details = algorithm::ReasonDetails::encode(&details)?
            .batches
            .remove(0);
    }
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output, false, None),
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
    let checkpoint = model.checkpoint.as_mut().ok_or("declared checkpoint")?;
    checkpoint.resume_input_changes = false;
    checkpoint.datasets.truncate(1);
    let state = checkpoint.datasets[0].name.clone();
    output
        .checkpoint
        .as_mut()
        .ok_or("declared output checkpoint")?
        .datasets
        .retain(|data| data.name == state);
    assert!(Graph::supports(model));
    let data = output
        .datasets
        .iter_mut()
        .find(|data| data.name == "findings")
        .ok_or("findings")?;
    let mut findings = algorithm::FindingChange::decode(data)?;
    for finding in &mut findings {
        finding.reason_code = code.clone();
        finding.package_id = package_id.into();
        finding.finding_id =
            FindingV1::identity(package_id, &finding.anchor.record, &finding.subject_id)?;
    }
    *data = algorithm::FindingChange::encode(&findings)?;
    for data in &mut output.datasets {
        match data.name.as_str() {
            "relationships" => {
                let mut rows = algorithm::RelationshipChange::decode(data)?;
                for row in &mut rows {
                    row.key.package_id = package_id.into();
                }
                *data = algorithm::RelationshipChange::encode(&rows)?;
            }
            _ => {}
        }
    }
    for value in &mut output.reasons {
        value.code = code.clone();
        value.details = sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![3]))],
        )?;
    }
    package.validate_output(&evaluation, &output)?;
    owner.apply_output(&package, &evaluation, &output, false, None)?;
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
