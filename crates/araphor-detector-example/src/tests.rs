use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn threshold_retains_evidence_and_state() -> TestResult {
    let package = BurstDetector::package();
    let model = &package.exports[0];
    let first = Observation {
        id: araphor_analysis_builtins::discovery::DiscoveryRecordIdV1 {
            stream: araphor_analysis_builtins::discovery::EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "example".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            cpu_id: 0,
            durable_cursor: 1,
        },
        position: Position {
            commit_revision: 1,
            ordinal: 0,
        },
        effect: araphor_analysis_builtins::discovery::DiscoveryEffectKeyV1 {
            task_cookie: 7,
            target_task_cookie: None,
            process_lineage_id: vec![2; 16],
            authority_domain_id: vec![3; 16],
            execution_set_id: vec![4; 16],
            exact_object_id: vec![5; 16],
            destination_id: 0,
            policy_rule_id: 0,
            reason: 0,
            decision: 0,
            effect_family: 0,
            operation: 0,
            operation_argument: None,
            configured_errno: 0,
            kernel_result: 0,
            exact_file_object: None,
        },
        ingested_utc_ns: 10,
        observed_boottime_ns: 10,
        profile_generation_ref_id: None,
        original_kernel_sequence: None,
        coverage_interval_id: vec![6; 16],
        process_instance_id: Some([2; 16]),
        entry_instance_id: None,
        binding_id: None,
        role_id: None,
        state_id: None,
        entry_rule_id: None,
        proof_quality: ProofQualityV1::kernel_decision(TemporalCoverageV1::Complete),
    };
    let mut separate = first.clone();
    separate.id.stream.node_boot_id = [9; 16];
    separate.position.commit_revision = 2;
    let mut last = first.clone();
    last.id.durable_cursor = 3;
    last.position.commit_revision = 3;
    let expected = vec![first.id.clone(), last.id.clone()];
    let records = [first, separate, last];
    let record_count = records.len();
    let facts = records
        .iter()
        .enumerate()
        .map(|(row, record)| Fact {
            record: row as u32,
            key: AnalysisContextKeyV1 {
                tenant_id: record.id.stream.tenant_id,
                owner_id: "fixture".into(),
                entity_key: (row as u32).to_be_bytes().to_vec(),
                lifetime_key: record.id.stream.key(),
                owner_revision: 1,
            },
            sensitivity: ContextSensitivityV1::Tenant,
            value: GraphFactValueV1::Context {
                subject: GraphSubjectKeyV1::native(
                    &record.id.stream,
                    GraphSubjectKindV1::Task,
                    record.effect.task_cookie.to_be_bytes().to_vec(),
                ),
                action_id: "example".into(),
                classification: GraphContextActionV1::InMemory,
                proof_quality: record.proof_quality,
            },
        })
        .collect::<Vec<_>>();
    let units = records
        .iter()
        .map(|record| Unit {
            record: record.id.clone(),
            window_ns: 100,
            restricted: false,
        })
        .collect::<Vec<_>>();
    let inputs = vec![
        Unit::encode(&units)?,
        Unit::encode_removals(&[])?,
        model
            .change_inputs
            .as_ref()
            .ok_or("change inputs")?
            .reset_input(true)?,
        Observation::encode(&records)?,
        Fact::encode(&facts)?,
        Unit::encode_affected(
            &units
                .iter()
                .map(|unit| unit.record.clone())
                .collect::<Vec<_>>(),
        )?,
        Unit::window_data(
            &records[0].id.stream.key(),
            records[0].id.durable_cursor,
            u64::MAX,
            false,
        )?,
    ];
    let mut evaluation = sdk::Evaluation {
        previous_outputs: Vec::new(),
        export: "detect".into(),
        inputs: inputs
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            })
            .collect(),
        parameters: Some(sdk::RecordBatch::try_new(
            Arc::new(model.parameters.clone()),
            vec![Arc::new(UInt64Array::from(vec![2]))],
        )?),
        context: sdk::EvaluationContext {
            id: "example".into(),
            time_utc_ns: 10,
            seed: Some(3),
        },
        checkpoint: None,
    };
    let first = BurstFixture::run(&evaluation)?;
    let output = &first.output;
    assert_eq!(output.datasets.len(), 1);
    assert!(output.checkpoint.is_none());
    assert!(model.checkpoint.is_none());
    assert!(output.evidence.is_empty());
    assert!(output.reasons.is_empty());
    let findings = &first.findings;
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].value.evidence, expected);
    assert_eq!(
        findings[0].value.state,
        FindingStateV1::CoverageInsufficient
    );
    assert_eq!(findings[0].anchor.record, units[0].record);
    let FindingReasonV1::Declared(reason) = &findings[0].value.reason else {
        return Err("declared reason".into());
    };
    assert_eq!(reason.code, "example-burst.THRESHOLD");
    let details = sdk::wire::Dataset::decode_ipc("details", &reason.ipc, Some(&reason.schema))?;
    assert_eq!(
        details.batches[0]
            .column(1)
            .as_primitive::<UInt64Type>()
            .value(0),
        2
    );
    let state = first
        .states
        .iter()
        .find(|state| state.record.is_some())
        .ok_or("unit state")?;
    assert_eq!(
        state.state,
        GraphPackageStateV1::Declared(record_count.to_string())
    );
    let last = records
        .iter()
        .max_by_key(|record| &record.id)
        .ok_or("last record")?;
    assert_eq!(state.record.as_ref(), Some(&last.id));
    assert_eq!(state.position, Some(last.position));
    assert_eq!(
        first
            .states
            .iter()
            .filter(|state| state.record.is_some())
            .count(),
        1
    );
    assert!(first
        .states
        .iter()
        .any(|state| state.record.is_none()
            && state.state == GraphPackageStateV1::Declared("0".into())));
    let encoded = sdk::wire::Output::encode(&package, &evaluation, output)?;
    let decoded = encoded.decode(&package, &evaluation)?;
    assert_eq!(decoded.datasets[0].batches, output.datasets[0].batches);
    for order in [[0, 1, 2], [2, 1, 0], [1, 2, 0], [2, 0, 1]] {
        for reverse_facts in [false, true] {
            for reverse_units in [false, true] {
                let selected = order.map(|row| records[row].clone());
                let mut delivered = facts.clone();
                for fact in &mut delivered {
                    fact.record = order
                        .iter()
                        .position(|&row| row == fact.record as usize)
                        .ok_or("permuted record")? as u32;
                }
                if reverse_facts {
                    delivered.reverse();
                }
                let mut changed = units.clone();
                if reverse_units {
                    changed.reverse();
                }
                let mut permuted = evaluation.clone();
                permuted.inputs[0].data = Unit::encode(&changed)?;
                permuted.inputs[3].data = Observation::encode(&selected)?;
                permuted.inputs[4].data = Fact::encode(&delivered)?;
                let actual = BurstFixture::run(&permuted)?;
                assert_eq!(
                    SubjectChange::decode(&actual.output.datasets[0])?,
                    SubjectChange::decode(&output.datasets[0])?
                );
                assert_eq!(actual.findings.len(), findings.len());
                for (actual, expected) in actual.findings.iter().zip(findings) {
                    assert_eq!(actual.anchor, expected.anchor);
                    assert_eq!(actual.value, expected.value);
                }
                assert_eq!(actual.states, first.states);
            }
        }
    }
    evaluation.inputs[0].data = Unit::encode(&units[1..])?;
    let partial = BurstFixture::run(&evaluation)?;
    assert!(partial.findings.is_empty());
    assert!(SubjectChange::decode(&partial.output.datasets[0])?.is_empty());
    evaluation.inputs[0].data = Unit::encode(&units[..1])?;
    let owner = BurstFixture::run(&evaluation)?;
    assert_eq!(owner.findings[0].value, findings[0].value);
    assert!(owner.states.iter().all(|state| state.record.is_none()));
    evaluation.inputs[0].data = Unit::encode(&[])?;
    evaluation.inputs[3].data = Observation::encode(&[])?;
    evaluation.inputs[4].data = Fact::encode(&[])?;
    let empty = BurstFixture::run(&evaluation)?;
    assert!(empty.findings.is_empty());
    assert!(SubjectChange::decode(&empty.output.datasets[0])?.is_empty());
    assert_eq!(empty.states.len(), 1);
    assert_eq!(
        empty.states[0].state,
        GraphPackageStateV1::Declared("0".into())
    );
    evaluation.parameters = Some(sdk::RecordBatch::try_new(
        Arc::new(model.parameters.clone()),
        vec![Arc::new(UInt64Array::from(vec![1]))],
    )?);
    assert_eq!(
        BurstFixture::run(&evaluation)
            .err()
            .ok_or("invalid threshold")?
            .code(),
        sdk::ErrorCode::Invalid
    );
    Ok(())
}

#[derive(Default)]
struct BurstFixture {
    commands: std::cell::RefCell<Vec<sdk::Dataset>>,
}

struct BurstRun {
    output: sdk::Output,
    findings: Vec<araphor_analysis_types::FindingMember>,
    states: Vec<araphor_analysis_types::GraphStateMember>,
}

impl sdk::InvocationHost for BurstFixture {
    fn read(&self, _: &str, _: &sdk::Dataset) -> sdk::Result<sdk::Input> {
        Err(sdk::Error::contract(
            sdk::ErrorCode::Invalid,
            "unexpected graph read",
        ))
    }
    fn stage(&self, commands: &sdk::Dataset) -> sdk::Result<()> {
        let package = BurstDetector::declaration();
        let spec = package.exports[0]
            .graph
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "Graph spec"))?;
        assert_eq!(
            commands.batches[0].schema().as_ref(),
            &spec.command_schema(&commands.name)?
        );
        self.commands.borrow_mut().push(commands.clone());
        Ok(())
    }
}

impl BurstFixture {
    fn run(evaluation: &sdk::Evaluation) -> sdk::Result<BurstRun> {
        let host = Self::default();
        let mut checked = BurstDetector::declaration().check_evaluation(evaluation)?;
        checked.bind_host(&host)?;
        let output = checked.evaluate(<BurstDetector as sdk::Guest>::compute)?;
        let findings = araphor_analysis_types::FindingMember::decode(
            &host.properties(araphor_analysis_types::FindingMember::port())?,
        )?;
        let states = araphor_analysis_types::GraphStateMember::decode(
            &host.properties(araphor_analysis_types::GraphStateMember::port())?,
        )?;
        Ok(BurstRun {
            output,
            findings,
            states,
        })
    }
    fn properties(&self, port: sdk::Port) -> sdk::Result<sdk::Dataset> {
        let mut batches = Vec::new();
        for command in self
            .commands
            .borrow()
            .iter()
            .filter(|command| command.name == port.name)
        {
            for batch in &command.batches {
                let properties = batch
                    .column_by_name("properties")
                    .and_then(|array| {
                        array
                            .as_any()
                            .downcast_ref::<sdk::arrow_array::StructArray>()
                    })
                    .ok_or_else(|| {
                        sdk::Error::contract(sdk::ErrorCode::Invalid, "Graph properties")
                    })?;
                batches.push(sdk::RecordBatch::try_new(
                    Arc::new(port.schema.clone()),
                    properties.columns().to_vec(),
                )?);
            }
        }
        Ok(sdk::Dataset {
            name: port.name,
            batches,
        })
    }
}
