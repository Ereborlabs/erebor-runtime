use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    metadata: GraphManifest,
    records: Vec<Observation>,
    subject: GraphSubjectKeyV1,
    pin: crate::ManagedCall,
    window: u64,
}

impl Fixture {
    fn new() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let snapshot: crate::GraphSnapshotV1 =
            serde_json::from_slice(include_bytes!("../tests/graph.json"))?;
        let mut metadata = GraphManifest::from_snapshot(&snapshot);
        metadata.facts.clear();
        metadata.input_manifest.context.clear();
        let first = metadata.input_manifest.evidence[0].clone();
        let mut second = first.clone();
        second.durable_cursor += 1;
        metadata.input_manifest.evidence = vec![first.clone(), second.clone()];
        metadata.last_cursor = second.durable_cursor;
        let effect = crate::DiscoveryEffectKeyV1 {
            task_cookie: 0,
            target_task_cookie: None,
            process_lineage_id: Vec::new(),
            authority_domain_id: Vec::new(),
            execution_set_id: Vec::new(),
            exact_object_id: Vec::new(),
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
        };
        let records: Vec<Observation> = [first, second]
            .into_iter()
            .enumerate()
            .map(|(ordinal, id)| Observation {
                id,
                position: Position {
                    commit_revision: 1,
                    ordinal: ordinal as u32,
                },
                effect: effect.clone(),
                ingested_utc_ns: 1,
                observed_boottime_ns: 1,
                profile_generation_ref_id: None,
                original_kernel_sequence: None,
                coverage_interval_id: Vec::new(),
                process_instance_id: None,
                entry_instance_id: None,
                binding_id: None,
                role_id: None,
                state_id: None,
                entry_rule_id: None,
                proof_quality: snapshot.graph.edges[0].proof_quality,
            })
            .collect();
        metadata.input_positions = records
            .iter()
            .map(|record| {
                (
                    record.id.clone(),
                    crate::StorePositionV1 {
                        commit_revision: record.position.commit_revision,
                        ordinal: record.position.ordinal,
                    },
                )
            })
            .collect();
        metadata.validate()?;
        let window = metadata
            .packages
            .iter()
            .find(|package| package.package_id == Detector::Process.id())
            .ok_or("fixture package")?
            .window_ns;
        let package = crate::PackageRefV1 {
            package_id: Detector::Process.id().into(),
            revision: "1".into(),
        };
        let pin = crate::ManagedCall {
            image: araphor_discovery_definition::ImagePin {
                image: package.clone(),
                digest: "image".into(),
            },
            package,
            export: "detect".into(),
            arguments: Vec::new(),
            target: "target".into(),
            artifact: None,
            dependencies: BTreeSet::new(),
        };
        Ok(Self {
            metadata,
            records,
            subject: snapshot.graph.subjects[0].clone(),
            pin,
            window,
        })
    }

    fn schema(&self, writer: &Connection) -> TestResult {
        writer.execute_batch(&GraphRows::schema())?;
        writer.execute_batch(
            "CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER)",
        )?;
        let source = &self.metadata.scope.identity;
        writer.execute(
            "INSERT INTO source_receipts VALUES(?,?,?)",
            params![
                source.key(),
                source.tenant_id.as_slice(),
                self.records[0].id.cpu_id
            ],
        )?;
        let source = GraphRows::source_id(writer, source)?;
        GraphRows::new_scope(
            writer,
            &self.metadata,
            source,
            0,
            Some(super::super::history::ProducerPin {
                instance: "instance",
                call: 1,
                declaration: &self.pin,
            }),
            1,
        )?;
        Ok(())
    }

    fn unit(&self, index: usize) -> Unit {
        let record = &self.records[index];
        Unit {
            record: record.id.clone(),
            window_ns: self.window,
            restricted: false,
            support: vec![UnitSupport {
                record: record.id.clone(),
                proof: record.proof_quality,
                facts: Vec::new(),
            }],
        }
    }

    fn evaluation(
        &self,
        after: &[usize],
        before: &[usize],
        reset: bool,
    ) -> std::result::Result<sdk::Evaluation, Box<dyn std::error::Error>> {
        let input = |data| sdk::Input {
            data,
            revision: sdk::Revision {
                owner: "graph".into(),
                id: "cut".into(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        };
        let changes = sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                affected: "affected".into(),
                before: "unit_removals".into(),
                after: "units".into(),
            }],
        };
        let mut removed = Unit::encode(
            &before
                .iter()
                .map(|index| self.unit(*index))
                .collect::<Vec<_>>(),
        )?;
        removed.name = "unit_removals".into();
        Ok(sdk::Evaluation {
            export: "detect".into(),
            inputs: vec![
                input(Unit::encode(
                    &after
                        .iter()
                        .map(|index| self.unit(*index))
                        .collect::<Vec<_>>(),
                )?),
                input(removed),
                input(changes.reset_input(reset)?),
                input(Observation::encode(
                    &after
                        .iter()
                        .map(|index| self.records[*index].clone())
                        .collect::<Vec<_>>(),
                )?),
                input(Fact::encode(&[])?),
            ],
            parameters: None,
            context: sdk::EvaluationContext {
                id: "units".into(),
                time_utc_ns: 1,
                seed: None,
            },
            checkpoint: None,
            previous_outputs: Vec::new(),
        })
    }

    fn output(
        &self,
        after: &[usize],
        empty: bool,
    ) -> std::result::Result<sdk::Output, Box<dyn std::error::Error>> {
        let subjects = if empty {
            Vec::new()
        } else {
            after
                .iter()
                .map(|index| SubjectChange {
                    anchor: Anchor {
                        record: self.records[*index].id.clone(),
                        fact: None,
                    },
                    key: self.subject.clone(),
                })
                .collect()
        };
        let rows = after
            .iter()
            .enumerate()
            .map(|(row, index)| Contribution {
                record: self.records[*index].id.clone(),
                subjects: if empty { Vec::new() } else { vec![row as u64] },
                relationships: Vec::new(),
                findings: Vec::new(),
                state: (!empty).then(|| UnitState {
                    state: if *index == 0 {
                        GraphPackageStateV1::NativeEffect
                    } else {
                        GraphPackageStateV1::CredentialObserved
                    },
                    position: self.records[*index].position,
                    fact: None,
                }),
            })
            .collect::<Vec<_>>();
        Ok(sdk::Output {
            datasets: vec![
                SubjectChange::encode(&subjects)?,
                RelationshipChange::encode(&[])?,
                FindingChange::encode(&[])?,
                Contribution::encode(&rows)?,
                GraphPackageStateV1::encode(&[GraphPackageStateV1::Waiting])?,
            ],
            ..Default::default()
        })
    }

    fn returned<'a>(
        evaluation: &'a sdk::Evaluation,
        output: &'a sdk::Output,
    ) -> crate::ManagedReturn<'a> {
        crate::ManagedReturn {
            call: 1,
            evaluation,
            output,
            retained: None,
            changes: None,
        }
    }
}

#[test]
fn units_keep_shared_state() -> TestResult {
    let mut fixture = Fixture::new()?;
    let writer = Connection::open_in_memory()?;
    fixture.schema(&writer)?;
    for (revision, after, before, reset, empty, expected, count) in [
        (
            1,
            vec![0, 1],
            Vec::new(),
            true,
            false,
            GraphPackageStateV1::CredentialObserved,
            1,
        ),
        (
            2,
            Vec::new(),
            vec![0],
            false,
            false,
            GraphPackageStateV1::CredentialObserved,
            1,
        ),
        (
            3,
            vec![1],
            vec![1],
            false,
            true,
            GraphPackageStateV1::Waiting,
            0,
        ),
        (
            4,
            vec![0],
            Vec::new(),
            true,
            false,
            GraphPackageStateV1::NativeEffect,
            1,
        ),
    ] {
        let evaluation = fixture.evaluation(&after, &before, reset)?;
        let output = fixture.output(&after, empty)?;
        if revision == 2 {
            fixture.metadata.input_manifest.evidence = vec![fixture.records[1].id.clone()];
        }
        if revision == 4 {
            fixture.metadata.input_manifest.evidence = vec![fixture.records[0].id.clone()];
        }
        fixture.metadata.input_positions = fixture
            .records
            .iter()
            .filter(|record| {
                fixture
                    .metadata
                    .input_manifest
                    .evidence
                    .binary_search(&record.id)
                    .is_ok()
            })
            .map(|record| {
                (
                    record.id.clone(),
                    crate::StorePositionV1 {
                        commit_revision: record.position.commit_revision,
                        ordinal: record.position.ordinal,
                    },
                )
            })
            .collect();
        fixture.metadata.validate()?;
        GraphRows::version(
            &writer,
            &format!("version-{revision}"),
            1,
            revision,
            (revision > 1)
                .then(|| format!("version-{}", revision - 1))
                .as_deref(),
        )?;
        let effects = GraphRows::apply_units(
            &writer,
            std::path::Path::new("units"),
            1,
            revision,
            &fixture.metadata,
            &Fixture::returned(&evaluation, &output),
            &fixture.pin,
        )?;
        assert_eq!(effects.state, expected);
        assert_eq!(writer.query_row("SELECT subject_count FROM graph_producer_versions WHERE scope_id=1 AND commit_revision=?",params![revision],|row|row.get::<_,u64>(0))?,count);
        assert_eq!(writer.query_row("SELECT state_count FROM graph_producer_versions WHERE scope_id=1 AND commit_revision=?",params![revision],|row|row.get::<_,u64>(0))?,match revision {1=>2,3=>0,_=>1});
    }
    assert_eq!(
        writer.query_row("SELECT count(*) FROM graph_subject_values", [], |row| row
            .get::<_, u64>(
            0
        ))?,
        1
    );
    araphor_graph::StateRows::validate(&writer)?;
    assert_eq!(
        araphor_graph::StateRows::current(&writer, 1, 1, GraphPackageStateV1::Waiting)?,
        GraphPackageStateV1::CredentialObserved
    );
    Ok(())
}

#[test]
fn historical_call_members_require_unit_anchors() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut third = fixture.records[1].clone();
    third.id.durable_cursor += 1;
    third.position.ordinal += 1;
    fixture.records.push(third);
    let mut writer = Connection::open_in_memory()?;
    fixture.schema(&writer)?;
    writer.execute_batch("CREATE TABLE analysis_results(result_id VARCHAR PRIMARY KEY,tenant_id BLOB,processor_id VARCHAR,stream_key BLOB,commit_revision UBIGINT); CREATE TABLE managed_edges(tenant_id BLOB,result_id VARCHAR,dependency_id VARCHAR,commit_revision UBIGINT,kind VARCHAR)")?;
    let scope = writer.query_row("SELECT scope_id FROM graph_producer_scopes", [], |row| {
        row.get::<_, u64>(0)
    })?;
    let source = &fixture.metadata.scope.identity;
    let records = fixture
        .records
        .iter()
        .map(|row| row.id.clone())
        .collect::<Vec<_>>();
    let record_ids = GraphRows::intern_records(&writer, source, &records)?;
    let key = crate::AnalysisContextKeyV1 {
        tenant_id: source.tenant_id,
        owner_id: "owner".into(),
        entity_key: vec![1],
        lifetime_key: vec![1],
        owner_revision: 1,
    };
    let fact = FactAnchor {
        record: records[1].clone(),
        key: key.clone(),
        sensitivity: ContextSensitivityV1::Tenant,
        value: crate::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: true,
            reviewed_policy_revision: "policy".into(),
        },
    };
    let mut outside = fact.clone();
    outside.record = records[2].clone();
    outside.key.entity_key = vec![2];
    let mut evaluation = fixture.evaluation(&[0, 1, 2], &[], true)?;
    let mut units = Unit::decode(&evaluation.inputs[0].data)?;
    units[1].support[0].facts = vec![key];
    let support = units[1].support[0].clone();
    units[0].support.push(support);
    units[2].support[0].facts = vec![outside.key.clone()];
    evaluation.inputs[0].data = Unit::encode(&units)?;
    evaluation.inputs[4].data = Fact::encode(&[
        Fact {
            record: 1,
            key: fact.key.clone(),
            sensitivity: fact.sensitivity,
            value: fact.value.clone(),
        },
        Fact {
            record: 2,
            key: outside.key.clone(),
            sensitivity: outside.sensitivity,
            value: outside.value.clone(),
        },
    ])?;
    let graph: crate::GraphSnapshotV1 =
        serde_json::from_slice(include_bytes!("../tests/graph.json"))?;
    let subjects = GraphRows::intern_subjects(&writer, &graph.graph.subjects)?;
    let edge = &graph.graph.edges[0];
    let edge = EdgeValue {
        key: RelationshipIdentity::from_keys(
            &edge.key,
            &graph.graph.subjects,
            &graph.input_manifest.evidence,
        )?,
        proof_quality: edge.proof_quality,
        required_coverage_interval_ids: edge.required_coverage_interval_ids.clone(),
        first_boottime_ns: edge.first_boottime_ns,
        last_boottime_ns: edge.last_boottime_ns,
    };
    let edge_id =
        GraphRows::intern_edges(&writer, &subjects, &record_ids, std::slice::from_ref(&edge))?[0];
    let findings = GraphRows::intern_findings(&writer, &subjects, &record_ids, &graph.findings)?;
    let finding = &graph.findings[0];
    let reason = finding.reason.analysis_code(&finding.package_id)?;
    let bytes = GraphRows::encode_value(&fact)?;
    let members = [
        (
            2,
            GraphRows::member_key(&graph.graph.subjects[0])?,
            subjects[&graph.graph.subjects[0]],
        ),
        (3, GraphRows::member_key(&edge.key)?, edge_id),
        (
            4,
            GraphRows::member_key(&finding.finding_id)?,
            findings[&finding.finding_id],
        ),
    ]
    .into_iter()
    .map(|(kind, key, value)| araphor_graph::Member {
        kind,
        key,
        value,
        record: Some(record_ids[&records[0]]),
        fact: Some(bytes.clone()),
        reason: (kind == 4).then(|| reason.clone()),
        ordinal: 0,
    })
    .collect();
    for (revision, result, base, members) in [
        (1, "opened", None, members),
        (2, "closed", Some("opened"), Vec::new()),
    ] {
        GraphRows::version(&writer, result, scope, revision, base)?;
        writer.execute(
            "INSERT INTO analysis_results VALUES(?,?,'managed-package-v1',?,?)",
            params![result, source.tenant_id.as_slice(), source.key(), revision],
        )?;
        araphor_graph::Contributions::apply(
            &writer,
            scope,
            revision,
            &[araphor_graph::Replacement {
                unit: Some(record_ids[&records[0]]),
                members,
            }],
            false,
        )?;
    }
    GraphRows::validate_history(&writer, std::path::Path::new("units"))?;
    GraphRows::validate_call_members(&writer, scope, 1, &evaluation)?;
    let empty = fixture.evaluation(&[], &[0], false)?;
    GraphRows::validate_call_members(&writer, scope, 2, &empty)?;
    assert_eq!(writer.query_row("SELECT count(*) FROM graph_producer_members WHERE scope_id=? AND member_kind IN (2,3,4) AND valid_from=1 AND valid_to=2",params![scope],|row|row.get::<_,u64>(0))?,3);
    let mut trailing = bytes.clone();
    trailing.push(0);
    #[derive(serde::Serialize)]
    struct Reordered<'a> {
        key: &'a crate::AnalysisContextKeyV1,
        record: &'a crate::DiscoveryRecordIdV1,
        sensitivity: ContextSensitivityV1,
        value: &'a crate::GraphFactValueV1,
    }
    let reordered = GraphRows::encode_value(&Reordered {
        key: &fact.key,
        record: &fact.record,
        sensitivity: fact.sensitivity,
        value: &fact.value,
    })?;
    assert_ne!(reordered, bytes);
    assert_eq!(GraphRows::decode_value::<FactAnchor>(&reordered)?, fact);
    let mut payload = fact.clone();
    let crate::GraphFactValueV1::Baseline { role_id, .. } = &mut payload.value else {
        return Err("fixture baseline".into());
    };
    *role_id += 1;
    let mut foreign = fact.clone();
    foreign.key.owner_revision += 1;
    let mut sensitive = fact.clone();
    sensitive.sensitivity = ContextSensitivityV1::HostRestricted;
    for anchor in [&payload, &foreign, &sensitive, &outside] {
        crate::GraphFactV1 {
            record_id: anchor.record.clone(),
            value: anchor.value.clone(),
        }
        .validate()?;
        assert!(anchor.key.valid());
    }
    let basis = CallBasis::new(&evaluation)?;
    assert!(basis
        .local(&Anchor {
            record: records[0].clone(),
            fact: Some(outside.clone())
        })
        .is_ok());
    for kind in [2u8, 3, 4] {
        for (name, fault) in [
            ("malformed", vec![0]),
            ("trailing", trailing.clone()),
            ("noncanonical", reordered.clone()),
            ("payload", GraphRows::encode_value(&payload)?),
            ("foreign key", GraphRows::encode_value(&foreign)?),
            ("sensitivity", GraphRows::encode_value(&sensitive)?),
            ("outside support", GraphRows::encode_value(&outside)?),
        ] {
            let transaction = writer.transaction()?;
            assert_eq!(transaction.execute("UPDATE graph_producer_members SET anchor_fact=? WHERE scope_id=? AND member_kind=? AND valid_from=1 AND valid_to=2",params![fault,scope,kind])?,1,"{name} kind {kind}");
            assert!(
                GraphRows::validate_call_members(&transaction, scope, 1, &evaluation).is_err(),
                "accepted {name} kind {kind}"
            );
            GraphRows::validate_call_members(&transaction, scope, 2, &empty)?;
        }
        let transaction = writer.transaction()?;
        assert_eq!(transaction.execute("UPDATE graph_producer_members SET anchor_record_id=? WHERE scope_id=? AND member_kind=? AND valid_from=1 AND valid_to=2",params![record_ids[&records[2]],scope,kind])?,1);
        assert!(
            GraphRows::validate_call_members(&transaction, scope, 1, &evaluation).is_err(),
            "accepted outside record kind {kind}"
        );
        drop(transaction);
        let transaction = writer.transaction()?;
        assert_eq!(transaction.execute("UPDATE graph_producer_members SET unit_ref=? WHERE scope_id=? AND member_kind=? AND valid_from=1 AND valid_to=2",params![record_ids[&records[2]],scope,kind])?,1);
        assert!(
            GraphRows::validate_call_members(&transaction, scope, 1, &evaluation).is_err(),
            "accepted outside unit kind {kind}"
        );
    }
    GraphRows::validate_call_members(&writer, scope, 1, &evaluation)?;
    Ok(())
}

#[test]
fn units_reject_forged_outputs() -> TestResult {
    let fixture = Fixture::new()?;
    let writer = Connection::open_in_memory()?;
    fixture.schema(&writer)?;
    for fault in 0..7 {
        let mut evaluation = fixture.evaluation(&[0, 1], &[], true)?;
        let mut output = fixture.output(&[0, 1], false)?;
        match fault {
            0 => {
                let mut rows = Contribution::decode(&output.datasets[3])?;
                rows[1].subjects = rows[0].subjects.clone();
                output.datasets[3] = Contribution::encode(&rows)?;
            }
            1 => {
                let mut rows = SubjectChange::decode(&output.datasets[0])?;
                rows[0].anchor.record = fixture.records[1].id.clone();
                output.datasets[0] = SubjectChange::encode(&rows)?;
            }
            2 => {
                evaluation.inputs[3].data = Observation::encode(&fixture.records[..1])?;
            }
            3 => {
                let mut rows = Unit::decode(&evaluation.inputs[0].data)?;
                rows[0].support[0].proof.temporal_coverage =
                    if rows[0].support[0].proof.temporal_coverage == TemporalCoverageV1::Unknown {
                        TemporalCoverageV1::Complete
                    } else {
                        TemporalCoverageV1::Unknown
                    };
                evaluation.inputs[0].data = Unit::encode(&rows)?;
            }
            4 => {
                let mut rows = Contribution::decode(&output.datasets[3])?;
                rows[0].state.as_mut().ok_or("state")?.position.ordinal += 1;
                output.datasets[3] = Contribution::encode(&rows)?;
            }
            5 => {
                let mut rows = Unit::decode(&evaluation.inputs[0].data)?;
                rows[0].restricted = true;
                evaluation.inputs[0].data = Unit::encode(&rows)?;
            }
            _ => {
                let mut rows = Contribution::decode(&output.datasets[3])?;
                rows[0].subjects.clear();
                output.datasets[3] = Contribution::encode(&rows)?;
            }
        }
        assert!(
            UnitBatch::new(
                &writer,
                std::path::Path::new("units"),
                &fixture.metadata,
                &Fixture::returned(&evaluation, &output),
                &fixture.pin,
                true
            )
            .and_then(|batch| batch
                .subjects
                .iter()
                .enumerate()
                .try_for_each(|(index, row)| batch.anchor(batch.owners[0][index], &row.anchor)))
            .is_err(),
            "accepted fault {fault}"
        );
    }
    Ok(())
}

#[test]
fn units_require_current_context() -> TestResult {
    let mut fixture = Fixture::new()?;
    let mut writer = Connection::open_in_memory()?;
    fixture.schema(&writer)?;
    writer.execute_batch("CREATE TABLE context_versions(tenant_id BLOB,owner_id VARCHAR,entity_key BLOB,lifetime_key BLOB,owner_revision UBIGINT,valid_from_utc_ns BIGINT,valid_until_utc_ns BIGINT,sensitivity VARCHAR,body BLOB,commit_revision UBIGINT)")?;
    let key = crate::AnalysisContextKeyV1 {
        tenant_id: fixture.metadata.scope.identity.tenant_id,
        owner_id: "owner".into(),
        entity_key: vec![1],
        lifetime_key: vec![2],
        owner_revision: 1,
    };
    let value = crate::GraphFactV1 {
        record_id: fixture.records[0].id.clone(),
        value: crate::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: true,
            reviewed_policy_revision: "policy".into(),
        },
    };
    writer.execute(
        "INSERT INTO context_versions VALUES(?,?,?,?,?,NULL,NULL,'tenant',?,1)",
        params![
            key.tenant_id.as_slice(),
            key.owner_id,
            key.entity_key,
            key.lifetime_key,
            key.owner_revision,
            value.encode_context()?
        ],
    )?;
    fixture.metadata.input_manifest.context = vec![key.clone()];
    fixture.metadata.facts = vec![value.clone()];
    let mut evaluation = fixture.evaluation(&[0], &[], true)?;
    let mut units = Unit::decode(&evaluation.inputs[0].data)?;
    units[0].support[0].facts = vec![key.clone()];
    evaluation.inputs[0].data = Unit::encode(&units)?;
    let fact = Fact {
        record: 0,
        key: key.clone(),
        sensitivity: ContextSensitivityV1::Tenant,
        value: value.value.clone(),
    };
    evaluation.inputs[4].data = Fact::encode(std::slice::from_ref(&fact))?;
    let output = fixture.output(&[0], false)?;
    UnitBatch::new(
        &writer,
        std::path::Path::new("units"),
        &fixture.metadata,
        &Fixture::returned(&evaluation, &output),
        &fixture.pin,
        true,
    )?;
    for fault in 0..5 {
        let mut evaluation = evaluation.clone();
        let mut output = output.clone();
        match fault {
            0 => {
                let mut fact = fact.clone();
                fact.value = crate::GraphFactValueV1::Baseline {
                    role_id: 2,
                    state_id: 1,
                    outside_reviewed_baseline: true,
                    reviewed_policy_revision: "policy".into(),
                };
                evaluation.inputs[4].data = Fact::encode(&[fact])?;
            }
            1 => {
                let mut fact = fact.clone();
                fact.sensitivity = ContextSensitivityV1::HostRestricted;
                evaluation.inputs[4].data = Fact::encode(&[fact])?;
            }
            2 => {
                let mut fact = fact.clone();
                fact.key.owner_revision += 1;
                evaluation.inputs[4].data = Fact::encode(&[fact])?;
            }
            3 => {
                let mut rows = SubjectChange::decode(&output.datasets[0])?;
                let mut changed = fact.clone();
                changed.sensitivity = ContextSensitivityV1::HostRestricted;
                rows[0].anchor.fact = Some(FactAnchor {
                    record: fixture.records[0].id.clone(),
                    key: changed.key,
                    sensitivity: changed.sensitivity,
                    value: changed.value,
                });
                output.datasets[0] = SubjectChange::encode(&rows)?;
            }
            _ => {
                let mut rows = Unit::decode(&evaluation.inputs[0].data)?;
                rows[0].support[0].facts.clear();
                evaluation.inputs[0].data = Unit::encode(&rows)?;
            }
        }
        assert!(
            UnitBatch::new(
                &writer,
                std::path::Path::new("units"),
                &fixture.metadata,
                &Fixture::returned(&evaluation, &output),
                &fixture.pin,
                true
            )
            .and_then(|batch| batch
                .subjects
                .iter()
                .enumerate()
                .try_for_each(|(index, row)| batch.anchor(batch.owners[0][index], &row.anchor)))
            .is_err(),
            "accepted context fault {fault}"
        );
    }
    {
        let transaction = writer.transaction()?;
        transaction.execute_batch("UPDATE context_versions SET sensitivity='host_restricted'")?;
        assert!(UnitBatch::new(
            &transaction,
            std::path::Path::new("units"),
            &fixture.metadata,
            &Fixture::returned(&evaluation, &output),
            &fixture.pin,
            true
        )
        .is_err());
        let mut unrelated = fixture.evaluation(&[1], &[], true)?;
        let unrelated_output = fixture.output(&[1], false)?;
        assert!(UnitBatch::new(
            &transaction,
            std::path::Path::new("units"),
            &fixture.metadata,
            &Fixture::returned(&unrelated, &unrelated_output),
            &fixture.pin,
            true,
        )
        .is_err());
        let mut units = Unit::decode(&unrelated.inputs[0].data)?;
        units[0].restricted = true;
        unrelated.inputs[0].data = Unit::encode(&units)?;
        UnitBatch::new(
            &transaction,
            std::path::Path::new("units"),
            &fixture.metadata,
            &Fixture::returned(&unrelated, &unrelated_output),
            &fixture.pin,
            true,
        )?;
    }
    Ok(())
}
