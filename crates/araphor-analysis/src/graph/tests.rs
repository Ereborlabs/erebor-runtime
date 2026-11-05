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
        let source = self.projection()?;
        let records = algorithm::Observation::decode(&source[0]).context(AnalysisContractSnafu)?;
        let facts = self
            .input
            .facts
            .iter()
            .zip(&self.facts)
            .map(|(context, fact)| {
                let record = records
                    .binary_search_by(|record| record.id.cmp(&fact.record_id))
                    .ok()
                    .and_then(|row| u32::try_from(row).ok())
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "fixture fact record",
                        }
                        .build()
                    })?;
                Ok(algorithm::Fact {
                    record,
                    key: context.key.clone(),
                    sensitivity: context.sensitivity,
                    value: fact.value.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let restricted = self
            .input
            .facts
            .iter()
            .any(|fact| fact.sensitivity == ContextSensitivityV1::HostRestricted);
        let units = records
            .iter()
            .map(|record| algorithm::Unit {
                record: record.id.clone(),
                window_ns: GRAPH_WINDOW_NS,
                restricted,
                support: records
                    .iter()
                    .filter(|candidate| candidate.position <= record.position)
                    .map(|candidate| algorithm::UnitSupport {
                        record: candidate.id.clone(),
                        proof: candidate.proof_quality,
                        facts: facts
                            .iter()
                            .filter(|fact| records[fact.record as usize].id == candidate.id)
                            .map(|fact| fact.key.clone())
                            .collect(),
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let data = vec![
            algorithm::Unit::encode(&units).context(AnalysisContractSnafu)?,
            algorithm::Unit::encode_removals(&[]).context(AnalysisContractSnafu)?,
            model
                .change_inputs
                .as_ref()
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "fixture changes",
                    }
                    .build()
                })?
                .reset_input(true)
                .context(AnalysisContractSnafu)?,
            source[0].clone(),
            algorithm::Fact::encode(&facts).context(AnalysisContractSnafu)?,
            algorithm::Unit::encode_affected(
                &units
                    .iter()
                    .map(|unit| unit.record.clone())
                    .collect::<Vec<_>>(),
            )
            .context(AnalysisContractSnafu)?,
            algorithm::Unit::window_data(
                &self.input.source.key(),
                self.input
                    .records
                    .first()
                    .map_or(1, |record| record.id.durable_cursor),
                u64::MAX,
                false,
            )
            .context(AnalysisContractSnafu)?,
        ];
        let inputs = data
            .into_iter()
            .map(|data| sdk::Input {
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
            .collect();
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
fn output_requires_one_state() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    *output
        .datasets
        .iter_mut()
        .find(|data| data.name == "state")
        .ok_or("state")? = GraphPackageStateV1::encode(&[])?;
    let package = algorithm::Detector::Credentials.descriptor();
    assert!(matches!(
        owner.apply_output(&package, &evaluation, &output),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph checkpoint rows",
            ..
        })
    ));
    Ok(())
}

#[test]
fn rejects_invalid_contributions() -> TestResult {
    let input = input()?;
    let package = algorithm::Detector::Credentials.descriptor();
    for fault in 0..6 {
        let (mut owner, evaluation, mut output) = computation(&input)?;
        let data = output
            .datasets
            .iter_mut()
            .find(|data| data.name == "contributions")
            .ok_or("contributions")?;
        let mut rows = algorithm::Contribution::decode(data)?;
        match fault {
            0 => rows[0].record.durable_cursor = u64::MAX,
            1 => rows.push(rows[0].clone()),
            2 => {
                rows.iter_mut()
                    .find_map(|row| row.state.as_mut())
                    .ok_or("unit state")?
                    .position
                    .commit_revision = 0
            }
            3 => {
                let state = rows
                    .iter_mut()
                    .find_map(|row| row.state.as_mut())
                    .ok_or("unit state")?;
                state.fact = Some(araphor_data::AnalysisContextKeyV1 {
                    tenant_id: input.source.tenant_id,
                    owner_id: "absent".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![1],
                    owner_revision: 1,
                });
            }
            4 => {
                let index = *rows
                    .iter()
                    .find_map(|row| row.subjects.first())
                    .ok_or("owned subject")?;
                rows[0].subjects.push(index);
            }
            5 => rows
                .iter_mut()
                .find(|row| !row.subjects.is_empty())
                .ok_or("owned subject")?
                .subjects
                .clear(),
            _ => return Err("contribution fault".into()),
        }
        *data = algorithm::Contribution::encode(&rows)?;
        package.validate_output(&evaluation, &output)?;
        assert!(
            owner.apply_output(&package, &evaluation, &output).is_err(),
            "accepted fault {fault}"
        );
    }
    Ok(())
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
            &output
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
    let remove = output
        .evidence
        .iter()
        .position(|candidate| {
            output
                .evidence
                .iter()
                .filter(|link| link.output == candidate.output)
                .count()
                > 1
        })
        .ok_or("finding with multiple evidence links")?;
    output.evidence.remove(remove);
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
        let result = owner.apply_output(&package, &evaluation, &altered);
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
        let mut fact = GraphFactV1::decode_context(&version.body)?;
        if let GraphFactValueV1::AuthorityUse { proof_quality, .. } = &mut fact.value {
            proof_quality.remote_subject_binding = RemoteSubjectBindingV1::Contextual;
            version.body = fact.encode_context()?;
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
        owner.apply_output(&package, &evaluation, &output),
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
        let fact = GraphFactV1::decode_context(&context.body)?;
        if !matches!(fact.value, GraphFactValueV1::Policy(_)) {
            contexts.push(context);
        }
    }
    input.facts = contexts;
    let input = input.normalized()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    owner.apply_output(&package, &evaluation, &output)?;
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
    for reason in output
        .reasons
        .iter_mut()
        .filter(|reason| reason.output.dataset == "findings" && reason.output.row == 0)
    {
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
    let result = owner.apply_output(&package, &evaluation, &output);
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
        if data.name == "relationships" {
            let mut rows = algorithm::RelationshipChange::decode(data)?;
            for row in &mut rows {
                row.key.package_id = package_id.into();
            }
            *data = algorithm::RelationshipChange::encode(&rows)?;
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
