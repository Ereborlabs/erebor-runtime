mod source;

use super::*;
use araphor_data::{
    CoverageCounters, CoverageInterval, CoverageReport, DiscoveryCoverageStateV1,
    DiscoveryCoverageV1, GraphCoverageKeyV1, GraphReplayInputV1, InputRevision,
    ValidatedCoverageV1,
};
use prost::Message as _;

#[test]
fn native_projection_requires_admission() -> TestResult {
    let mut input = crate::graph::tests::fixture::credential_input_from(1)?;
    let ids = input
        .records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    for context in &mut input.facts {
        let mut fact: araphor_data::GraphFactV1 = serde_json::from_slice(&context.body)?;
        if let araphor_data::GraphFactValueV1::Policy(policy) = &mut fact.value {
            policy.observations = ids.clone();
            policy.limits = vec!["NATIVE_NESTED_LIMIT".repeat(256)];
            context.body = serde_json::to_vec(&fact)?;
        }
    }
    let input = input.normalized()?;
    for mode in 0..3 {
        let graph = Graph::new(&input)?;
        assert!(graph.projection.get().is_none());
        let limits = araphor_query::execution::Limits {
            input_bytes: if mode == 0 { 1 } else { usize::MAX },
            input_capacity: match mode {
                0 => None,
                1 => Some(1),
                _ => Some(usize::MAX),
            },
            ..Default::default()
        };
        let memory = araphor_query::memory::Memory::new(limits.input_capacity, None);
        let frames = memory.reserve_input(0)?;
        let retained = memory.reserve_input(0)?;
        let projection = super::super::Projection {
            tenant: input.source.tenant_id,
            facts: Arc::new(Facts::default()),
            ports: araphor_analysis_builtins::graph::Detector::Process
                .descriptor()
                .exports[0]
                .inputs
                .iter()
                .map(|input| input.port.clone())
                .collect(),
            memory: Arc::clone(&memory),
            limits,
            projections: Default::default(),
            observed: Default::default(),
        };
        let result = projection.inputs(
            &graph,
            &sdk::Revision {
                owner: "captured".into(),
                id: "native-admission".into(),
                window: None,
            },
            &sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
            &retained,
            &frames,
        );
        if mode < 2 {
            if mode == 0 {
                assert!(
                    matches!(&result, Err(DataFusionError::External(source))
                    if matches!(source.downcast_ref::<araphor_data::Error>(),
                        Some(araphor_data::Error::Package {
                            code: araphor_data::PackageErrorCodeV1::Limit,
                            field: "graph input bytes", ..
                        }))),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(&result, Err(DataFusionError::ResourcesExhausted(_))),
                    "{result:?}"
                );
            }
            assert!(graph.projection.get().is_some());
            drop(result);
            drop(retained);
            drop(frames);
            drop(graph);
            assert_eq!(memory.input_reserved(), 0);
        } else {
            let inputs = result?;
            let expected = graph.observations.clone();
            assert!(graph.projection.get().is_some());
            let facts = araphor_analysis_builtins::graph::Fact::decode(&inputs[1].data)?;
            assert!(facts.iter().any(|fact| matches!(&fact.value,
                araphor_data::GraphFactValueV1::Policy(policy)
                    if policy.observations == ids && policy.limits.iter()
                        .any(|value| value.len() > 4096))));
            drop(retained);
            drop(frames);
            drop(graph);
            assert!(memory.input_reserved() > 0);
            assert_eq!(
                araphor_analysis_builtins::graph::Observation::decode(&inputs[0].data)?,
                expected
            );
            drop(inputs);
            assert_eq!(memory.input_reserved(), 0);
        }
    }
    Ok(())
}

fn records(
    temporal: i32,
    intervals: [[u8; 16]; 3],
) -> TestResult<Vec<araphor_data::DiscoveryRecordV1>> {
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    manifest
        .records
        .into_iter()
        .take(3)
        .enumerate()
        .map(|(index, record)| {
            let mut wire = record.decode()?;
            wire.temporal_coverage = temporal;
            wire.profile_generation_ref_id = Some(1);
            wire.decision_context = Some(araphor_data::EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: (index + 1) as u64,
                process_instance_id: vec![8; 16],
                entry_instance_id: vec![9; 16],
                binding_id: vec![10; 16],
                profile_generation_ref_id: 1,
                role_id: 1,
                state_id: 1,
                entry_rule_id: 1,
                ..Default::default()
            });
            wire.coverage_interval_id = intervals[index].to_vec().into();
            let bytes = Vec::<u8>::try_from(&wire)?;
            Ok(araphor_data::DiscoveryRecordV1::try_from((
                record.id,
                bytes.as_slice(),
            ))?)
        })
        .collect()
}

pub(super) fn report(
    fixture: &Fixture,
    revision: u64,
    intervals: &[([u8; 16], u64, &str)],
) -> TestResult {
    let last = fixture
        .records
        .iter()
        .map(|record| {
            record.decode().map(|wire| {
                wire.decision_context
                    .as_ref()
                    .map_or(0, |context| context.original_kernel_sequence)
            })
        })
        .collect::<araphor_data::Result<Vec<_>>>()?
        .into_iter()
        .max()
        .ok_or("coverage sequence")?;
    let next = last.checked_add(1).ok_or("coverage sequence overflow")?;
    let intervals = intervals
        .iter()
        .map(|(id, version, state)| CoverageInterval {
            interval_id: id.to_vec(),
            source_epoch: fixture.source.source_epoch,
            revision: *version,
            state: (*state).into(),
            first_sequence: 1,
            last_sequence: Some(last),
            opening_counters: Some(Default::default()),
            closing_counters: Some(CoverageCounters {
                attempted: last,
                requested: last,
                emitted: last,
                next_sequence: next,
                ..Default::default()
            }),
            ..Default::default()
        })
        .collect();
    fixture
        .query
        .store()
        .accept_validated_coverage(ValidatedCoverageV1 {
            identity: fixture.source.clone(),
            cpu_id: fixture.records[0].id.cpu_id,
            revision,
            encoded_report: CoverageReport {
                source_id: fixture.source.source_id.to_vec(),
                source_epoch: fixture.source.source_epoch,
                cpu_id: fixture.records[0].id.cpu_id,
                revision,
                intervals,
            }
            .encode_to_vec(),
        })?;
    Ok(())
}

fn range(
    fixture: &Fixture,
    revision: u64,
    index: usize,
    interval: [u8; 16],
    state: DiscoveryCoverageStateV1,
    reasons: Vec<String>,
) -> DiscoveryCoverageV1 {
    DiscoveryCoverageV1 {
        stream: fixture.source.clone(),
        cpu_id: fixture.records[index].id.cpu_id,
        first_cursor: fixture.records[index].id.durable_cursor,
        last_cursor: fixture.records[index].id.durable_cursor,
        expected_records: 1,
        coverage_revision: revision,
        coverage_interval_id: interval,
        state,
        gap_reasons: reasons,
    }
}

async fn payload(
    fixture: &Fixture,
    expected: GraphReplayInputV1,
    state: sdk::CoverageState,
    instance_id: &str,
    filter: &str,
) -> TestResult<Arc<crate::Instance>> {
    let expected = expected.normalized()?;
    let revision = InputRevision::of(&(
        &expected.source,
        &expected.records,
        &expected.coverage,
        &expected.coverage_keys,
        &expected.facts,
        &expected.missing_ranges,
    ))?;
    let expected_graph = Graph::new(&expected)?;
    assert_eq!(expected.source, fixture.source);
    let publication = fixture.prepare(filter).await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let events = format!("SELECT * FROM events {filter}");
    let owner = fixture
        .managed_graph(&grant, &definition, instance_id, &events)
        .await?;
    let held = fixture.query.memory().input_reserved();
    let projection = &owner
        .graph_owner()
        .ok_or("admitted Graph owner")?
        .projection;
    let observed = projection.observe_capture();
    let before_instance = owner.admitted().clone();
    let before = fixture.query.store().meta()?;
    let receipt = owner
        .run(managed::request("payload")?, &fixture.control)
        .await?;
    let captured = observed.try_recv()?;
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
    assert_eq!(captured.inputs.len(), 3);
    let canonical = Detector::inputs();
    assert_eq!(captured.inputs.len(), canonical.len());
    for (index, input) in captured.inputs.iter().enumerate() {
        assert!(input
            .data
            .batches
            .iter()
            .all(|batch| batch.schema().as_ref() == &canonical[index].schema));
        assert_eq!(input.revision.owner, araphor_data::GRAPH_PROCESSOR);
        assert_eq!(input.revision.id, revision);
        assert_eq!(
            input.revision.window,
            Some(sdk::SourceWindow {
                source: serde_json::to_vec(&fixture.source)?,
                start_utc_ns: fixture.times.0,
                end_utc_ns: fixture.times.1,
            })
        );
        assert_eq!(input.coverage.state, state);
        assert_eq!(
            input.coverage.limits,
            if state == sdk::CoverageState::Complete {
                Vec::new()
            } else {
                vec!["SOURCE_COVERAGE_INSUFFICIENT".to_owned()]
            }
        );
        match input.data.name.as_str() {
            "records" => assert_eq!(
                araphor_analysis_builtins::graph::Observation::decode(&input.data)?,
                araphor_analysis_builtins::graph::Observation::decode(
                    &expected_graph.projection()?[index]
                )?
            ),
            "facts" => assert_eq!(
                araphor_analysis_builtins::graph::Fact::decode(&input.data)?,
                araphor_analysis_builtins::graph::Fact::decode(
                    &expected_graph.projection()?[index]
                )?
            ),
            "manifest" => assert_eq!(
                araphor_analysis_builtins::graph::Manifest::decode(&input.data)?,
                araphor_analysis_builtins::graph::Manifest::decode(
                    &expected_graph.projection()?[index]
                )?
            ),
            _ => return Err("unexpected Graph input".into()),
        }
    }
    let first = expected
        .records
        .first()
        .ok_or("selected Graph records")?
        .id
        .durable_cursor;
    let last = expected
        .records
        .last()
        .ok_or("selected Graph records")?
        .id
        .durable_cursor;
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let (id, header, revision) = heads
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == first)
        .ok_or("payload Graph window")?;
    assert_eq!(header.last_cursor, last);
    assert_eq!(revision, receipt.commit_revision);
    let actual = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("graph result")?;
    let page = fixture.query.store().read_page(
        &fixture.source,
        expected
            .records
            .first()
            .ok_or("selected Graph records")?
            .id
            .durable_cursor,
    )?;
    let positions = expected
        .records
        .iter()
        .map(|record| {
            page.records
                .iter()
                .find(|accepted| accepted.cursor == record.id.durable_cursor)
                .map(|accepted| (record.id.clone(), accepted.position))
                .ok_or("selected Graph durable position")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(actual.input_positions, positions);
    assert_eq!(actual.input_manifest.coverage, expected.coverage_keys);
    assert_eq!(
        actual.input_manifest.context,
        expected
            .facts
            .iter()
            .map(|fact| fact.key.clone())
            .collect::<Vec<_>>()
    );
    actual.validate()?;
    assert_eq!(receipt.results.len(), 3);
    assert_eq!(
        receipt.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("payload revision overflow")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = receipt.commit_revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = receipt.commit_revision;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(fixture.source.tenant_id, instance_id, &fixture.control)?
            .ok_or("payload instance")?,
        expected_instance
    );
    assert_eq!(
        fixture
            .query
            .store()
            .managed_history(&grant.selection, instance_id, &fixture.control)?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&actual.scope)?
            .ok_or("payload Graph progress")?
            .consumed_cursor,
        last
    );
    drop(captured);
    assert_eq!(fixture.query.memory().input_reserved(), held);
    Ok(owner)
}

#[tokio::test]
async fn graph_complete_port_payloads() -> TestResult {
    for (temporal, report_state, expected_state) in [
        (1, "HEALTHY", sdk::CoverageState::Complete),
        (0, "HEALTHY", sdk::CoverageState::Unknown),
        (1, "GAPPED", sdk::CoverageState::Gapped),
        (0, "GAPPED", sdk::CoverageState::Gapped),
    ] {
        let mut selected = records(temporal, [[7; 16]; 3])?;
        for (index, record) in selected.iter_mut().enumerate() {
            let mut wire = record.decode()?;
            wire.ingested_utc_ns = [-1, 0, 1][index];
            let bytes = Vec::<u8>::try_from(&wire)?;
            *record =
                araphor_data::DiscoveryRecordV1::try_from((record.id.clone(), bytes.as_slice()))?;
        }
        let fixture = Fixture::with_records(Target::Sql, selected)?;
        assert_eq!(fixture.times, (-1, 1));
        report(&fixture, 1, &[([7; 16], 11, report_state)])?;
        let (facts, _) = Facts::default().facts(&[], &fixture.records)?;
        let gapped = report_state == "GAPPED";
        let state = if gapped {
            DiscoveryCoverageStateV1::Gapped
        } else if temporal == 1 {
            DiscoveryCoverageStateV1::Healthy
        } else {
            DiscoveryCoverageStateV1::Unknown
        };
        let reasons = match state {
            DiscoveryCoverageStateV1::Gapped => vec!["SOURCE_COVERAGE_GAPPED".into()],
            DiscoveryCoverageStateV1::Unknown => vec!["COVERAGE_UNQUALIFIED".into()],
            _ => Vec::new(),
        };
        let coverage = vec![DiscoveryCoverageV1 {
            stream: fixture.source.clone(),
            cpu_id: fixture.records[0].id.cpu_id,
            first_cursor: 1,
            last_cursor: 3,
            expected_records: 3,
            coverage_revision: 1,
            coverage_interval_id: [7; 16],
            state,
            gap_reasons: reasons.clone(),
        }];
        let coverage_keys = vec![GraphCoverageKeyV1 {
            source: fixture.source.clone(),
            cpu_id: fixture.records[0].id.cpu_id,
            report_revision: 1,
            interval_id: [7; 16],
            interval_revision: 11,
            state,
            gap_reasons: reasons,
        }];
        drop(
            payload(
                &fixture,
                GraphReplayInputV1 {
                    source: fixture.source.clone(),
                    records: fixture.records.clone(),
                    coverage,
                    coverage_keys,
                    facts,
                    missing_ranges: Vec::new(),
                },
                expected_state,
                "graph:full-payload",
                "",
            )
            .await?,
        );
    }
    Ok(())
}

#[tokio::test]
async fn graph_partial_coverage_reports() -> TestResult {
    let fixture = Fixture::with_records(Target::Sql, records(1, [[7; 16], [8; 16], [7; 16]])?)?;
    report(&fixture, 1, &[([7; 16], 11, "HEALTHY")])?;
    let publication = fixture.prepare("").await?;
    let first_grant = publication.grant.clone();
    let first_definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&first_grant, &first_definition)?;
    drop(publication);
    let first_owner = fixture
        .managed_graph(
            &first_grant,
            &first_definition,
            "partial-first",
            "SELECT * FROM events",
        )
        .await?;
    let first_receipt = first_owner
        .run(managed::request("evaluate")?, &fixture.control)
        .await?;
    assert_eq!(first_receipt.results.len(), 3);
    let (first, _, revision) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("first partial Graph window")?;
    assert_eq!(revision, first_receipt.commit_revision);
    drop(first_owner);
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("first graph")?;
    report(&fixture, 2, &[([8; 16], 22, "HEALTHY")])?;
    let (facts, _) = Facts::default().facts(&[], &fixture.records)?;
    let mut coverage = Vec::new();
    let mut keys = Vec::new();
    for (revision, known, version) in [(1, [7; 16], 11), (2, [8; 16], 22)] {
        for (index, interval) in [[7; 16], [8; 16], [7; 16]].into_iter().enumerate() {
            let matched = interval == known;
            let state = if matched {
                DiscoveryCoverageStateV1::Healthy
            } else {
                DiscoveryCoverageStateV1::Unknown
            };
            let reasons = if matched {
                Vec::new()
            } else {
                vec!["MISSING_COVERAGE_REPORT".into()]
            };
            coverage.push(range(
                &fixture,
                revision,
                index,
                interval,
                state,
                reasons.clone(),
            ));
            keys.push(GraphCoverageKeyV1 {
                source: fixture.source.clone(),
                cpu_id: fixture.records[index].id.cpu_id,
                report_revision: revision,
                interval_id: interval,
                interval_revision: if matched { version } else { 0 },
                state,
                gap_reasons: reasons,
            });
        }
    }
    let expected = GraphReplayInputV1 {
        source: fixture.source.clone(),
        records: fixture.records.clone(),
        coverage,
        coverage_keys: keys,
        facts,
        missing_ranges: Vec::new(),
    }
    .normalized()?;
    assert_eq!(expected.coverage.len(), 6);
    assert_eq!(expected.coverage_keys.len(), 4);
    drop(
        payload(
            &fixture,
            expected,
            sdk::CoverageState::Unknown,
            "graph:partial-second",
            "",
        )
        .await?,
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?,
        Some(retained)
    );
    Ok(())
}

#[tokio::test]
async fn graph_coverage_258_history() -> TestResult {
    let record = records(1, [[7; 16]; 3])?.remove(0);
    let mut wire = record.decode()?;
    wire.decision = erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect as u32;
    wire.effect_family = 2;
    wire.operation = 2;
    wire.configured_errno = -13;
    wire.kernel_result = -13;
    let bytes = Vec::<u8>::try_from(&wire)?;
    let record = araphor_data::DiscoveryRecordV1::try_from((record.id, bytes.as_slice()))?;
    let fixture = Fixture::with_records(Target::Wasm, vec![record])?;
    report(&fixture, 1, &[([7; 16], 1, "HEALTHY")])?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "coverage-history",
            "SELECT * FROM events",
        )
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let first = head.result_id;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("original graph")?;
    assert!(retained
        .findings
        .iter()
        .any(|finding| finding.state == araphor_data::FindingStateV1::Confirmed));
    for revision in 2..=258 {
        report(&fixture, revision, &[([7; 16], revision, "HEALTHY")])?;
    }
    let updated = owner
        .run(managed::request("revision-258")?, &fixture.control)
        .await?;
    let heads = store.graph_window_headers(&fixture.source, None)?;
    let (next, _, revision) = heads
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("native Graph window")?;
    assert_eq!(revision, updated.commit_revision);
    let current = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &next)?
        .ok_or("latest graph")?;
    assert!(current
        .findings
        .iter()
        .any(|finding| finding.state == araphor_data::FindingStateV1::Confirmed));
    assert_eq!(
        current
            .input_manifest
            .coverage
            .iter()
            .map(|key| key.report_revision)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([1, 258])
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?,
        Some(retained.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?
            .ok_or("original graph")?
            .findings,
        retained.findings
    );
    report(&fixture, 259, &[])?;
    let before_domain = fixture.graph_history()?;
    let before_heads = store.graph_window_headers(&fixture.source, None)?;
    let before_head = store.processor_result(&scope)?;
    let before_health = store.processor_health(&scope)?.ok_or("Graph health")?;
    let before_instance = store
        .managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("Graph instance")?;
    let before_history = store.managed_history(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before = fixture.query.store().meta()?;
    let repeated = owner
        .run(managed::request("unrelated-259")?, &fixture.control)
        .await?;
    assert_eq!(before_heads.len(), 1);
    assert_eq!(before_heads[0].0, next);
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        store.graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(store.processor_result(&scope)?, before_head);
    assert_eq!(
        repeated.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("native Graph revision")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = repeated.commit_revision;
    assert_eq!(store.meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = repeated.commit_revision;
    assert_eq!(
        store.managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        Some(expected_instance)
    );
    let mut expected_history = before_history;
    expected_history.push(repeated.clone());
    assert_eq!(
        store.managed_history(
            &grant.selection,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        expected_history
    );
    let mut expected_health = before_health;
    expected_health.read_revision = repeated.commit_revision;
    assert_eq!(store.processor_health(&scope)?, Some(expected_health));
    Ok(())
}

#[tokio::test]
async fn graph_malformed_report_rejected() -> TestResult {
    const INPUT: usize = 32 * 1024 * 1024;
    let mut fixture = Fixture::with_records(Target::Sql, records(1, [[7; 16]; 3])?)?;
    fixture.query = Engine::new(
        Arc::clone(fixture.query.store()),
        araphor_query::execution::Limits {
            input_capacity: Some(INPUT),
            global_evaluations: Some(1),
            ..Default::default()
        },
    )?;
    report(&fixture, 1, &[([7; 16], 1, "HEALTHY")])?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "malformed-report",
            "SELECT * FROM events",
        )
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let store = fixture.query.store();
    let first_receipt = owner
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    let head = store.processor_result(&scope)?.ok_or("native Graph head")?;
    assert_eq!(head.commit_revision, first_receipt.commit_revision);
    let first = head.result_id;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("original graph")?;
    fixture.query.store().fault_write(
        "UPDATE coverage SET report = '\\xFF'::BLOB WHERE revision = 1",
        &[],
    )?;
    let before_domain = fixture.graph_history()?;
    let before_heads = store.graph_window_headers(&fixture.source, None)?;
    let before_head = store.processor_result(&scope)?;
    let before_health = store.processor_health(&scope)?.ok_or("Graph health")?;
    let before_instance = store
        .managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("Graph instance")?;
    let before_history = store.managed_history(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before_status = store.managed_status(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    assert!(matches!(
        before_status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let before_resume = store.managed_resume(
        fixture.source.tenant_id,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    let before_usage = store.retained_counts(fixture.source.tenant_id)?;
    let before = fixture.query.store().meta()?;
    let calls = fixture.facts.calls.load(Ordering::SeqCst);
    let failure = owner
        .run(managed::request("invalid")?, &fixture.control)
        .await
        .err()
        .ok_or("malformed selected report used fallback")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&failure),
        erebor_runtime_error::StatusCode::IllegalState
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(
        store.graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(store.processor_result(&scope)?, before_head);
    assert_eq!(
        store.managed_instance(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        Some(before_instance)
    );
    assert_eq!(
        store.managed_history(
            &grant.selection,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        before_history
    );
    assert_eq!(store.processor_health(&scope)?, Some(before_health));
    let status = store.managed_status(
        &grant.selection,
        &owner.admitted().spec.id,
        &fixture.control,
    )?;
    assert_eq!(status.instance, before_status.instance);
    assert_eq!(status.status_progress, before_status.status_progress);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    assert_eq!(
        store.managed_resume(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            &fixture.control
        )?,
        before_resume
    );
    assert!(store
        .managed_attempt(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            "invalid",
            &fixture.control
        )?
        .is_none());
    assert!(store
        .managed_selected(
            fixture.source.tenant_id,
            &owner.admitted().spec.id,
            "invalid",
            &fixture.control
        )?
        .is_none());
    assert_eq!(
        store.retained_counts(fixture.source.tenant_id)?,
        before_usage
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?,
        Some(retained)
    );
    drop(owner);
    drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    drop(fixture.query.memory().reserve_input(INPUT)?);
    Ok(())
}

fn call(id: &str, export: &str) -> String {
    format!(
        "SELECT * FROM \"{id}\".\"1\".\"{export}\"('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )
}

fn extra(fixture: &Fixture, id: &str) -> TestResult {
    let mut descriptor = Detector::Process.descriptor();
    descriptor.id = id.into();
    for model in &mut descriptor.exports {
        for reason in &mut model.reasons {
            let local = reason
                .code
                .strip_prefix("HF-PROC-001.")
                .ok_or("reason prefix")?;
            reason.code = format!("{id}.{local}");
        }
    }
    let mut spare = descriptor.exports[0].clone();
    spare.name = "spare".into();
    descriptor.exports.push(spare);
    descriptor.exports.push(sdk::Model::new(
        "aux",
        Vec::new(),
        vec![sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )],
    ));
    let mut implementations = ["detect", "spare"]
        .into_iter()
        .map(|export| {
            let model = descriptor
                .exports
                .iter()
                .find(|model| model.name == export)
                .ok_or("extra Graph export")?;
            Ok(PackageImplementationV1::Sql {
                export: export.into(),
                program: Fixture::sql(model)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    implementations.push(PackageImplementationV1::Sql {
        export: "aux".into(),
        program: araphor_package::SqlModelV1 {
            outputs: BTreeMap::from([(
                "data".into(),
                "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
            )]),
            ..Default::default()
        },
    });
    let artifact = PackageArtifactV1 {
        descriptor,
        implementations,
        fixtures: Vec::new(),
    };
    fixture.query.store().install_package_image(
        fixture.source.tenant_id,
        &araphor_data::PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?,
        || Ok(()),
    )?;
    Ok(())
}

#[tokio::test]
async fn graph_extra_export_order() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    extra(&fixture, "ZZ-extra")?;
    extra(&fixture, "AA-extra")?;
    let mut order = [
        "ZZ-extra",
        araphor_data::FindingV1::PACKAGES[2],
        "AA-extra",
        araphor_data::FindingV1::PACKAGES[0],
        araphor_data::FindingV1::PACKAGES[1],
    ];
    let sql = order
        .iter()
        .map(|id| call(id, "detect"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let publication = fixture.prepare_sql("*", "", sql).await?;
    let first_grant = publication.grant.clone();
    let first_definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&first_grant, &first_definition)?;
    drop(publication);
    let first_owner = fixture
        .managed_graph(
            &first_grant,
            &first_definition,
            "extras-first",
            "SELECT * FROM events",
        )
        .await?;
    let first_receipt = first_owner
        .run(managed::request("evaluate")?, &fixture.control)
        .await?;
    assert_eq!(
        first_owner
            .graph_owner()
            .ok_or("extra Graph owner")?
            .calls
            .len(),
        5
    );
    assert_eq!(first_receipt.results.len(), 5);
    let first = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("first extra Graph window")?
        .0;
    drop(first_owner);
    let first = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("extra graph")?;
    let expected = araphor_data::FindingV1::PACKAGES
        .iter()
        .copied()
        .chain(["AA-extra", "ZZ-extra"])
        .collect::<Vec<_>>();
    assert_eq!(
        first
            .packages
            .iter()
            .map(|state| state.package_id.as_str())
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(first.packages.len(), 5);
    order.reverse();
    let sql = order
        .iter()
        .map(|id| call(id, "detect"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let publication = fixture.prepare_sql("*", "", sql).await?;
    let second_grant = publication.grant.clone();
    let second_definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&second_grant, &second_definition)?;
    drop(publication);
    let second_owner = fixture
        .managed_graph(
            &second_grant,
            &second_definition,
            "extras-reversed",
            "SELECT * FROM events",
        )
        .await?;
    let second_receipt = second_owner
        .run(managed::request("evaluate")?, &fixture.control)
        .await?;
    assert_eq!(
        second_owner
            .graph_owner()
            .ok_or("reversed Graph owner")?
            .calls
            .len(),
        5
    );
    assert_eq!(second_receipt.results.len(), 5);
    let second = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("reversed extra Graph window")?
        .0;
    drop(second_owner);
    let second = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &second)?
        .ok_or("reordered graph")?;
    assert_eq!(second.packages, first.packages);
    Ok(())
}

#[tokio::test]
async fn graph_duplicate_exports_rejected() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    extra(&fixture, "extra")?;
    let sql = araphor_data::FindingV1::PACKAGES
        .iter()
        .map(|id| call(id, "detect"))
        .chain([call("extra", "detect"), call("extra", "spare")])
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let before = fixture.query.store().meta()?;
    let failure = fixture
        .prepare_sql("*", "", sql)
        .await
        .err()
        .ok_or("two compatible exports were admitted")?;
    assert!(format!("{failure:?}").contains("multiple graph detector calls"));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn graph_canonical_fields_rejected() -> TestResult {
    let fields = [
        "tenant_id",
        "node_id",
        "node_boot_id",
        "label_epoch",
        "source_id",
        "source_epoch",
        "cpu_id",
        "source_cursor",
        "framed_record",
        "commit_revision",
        "ordinal",
        "temporal_coverage",
        "kernel_sequence",
        "coverage_interval_id",
    ];
    for (field, expression, expected) in [
        (
            "framed_record",
            "decode('00','hex')",
            "graph event differs from capture",
        ),
        (
            "temporal_coverage",
            "CAST(2 AS INT)",
            "graph event differs from capture",
        ),
        (
            "coverage_interval_id",
            "decode('ffffffffffffffffffffffffffffffff','hex')",
            "graph event differs from capture",
        ),
        (
            "ordinal",
            "CAST(4294967295 AS INT UNSIGNED)",
            "uncaptured graph event position",
        ),
    ] {
        let fixture = Fixture::with_records(Target::Sql, records(1, [[7; 16]; 3])?)?;
        let columns = fields
            .iter()
            .map(|name| {
                if *name == field {
                    format!(
                        "CASE WHEN source_cursor > 0 THEN {expression} ELSE {name} END AS {name}"
                    )
                } else {
                    (*name).to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let sql = araphor_data::FindingV1::PACKAGES
            .iter()
            .map(|id| call(id, "detect"))
            .collect::<Vec<_>>()
            .join(" UNION ALL ");
        let events = format!("SELECT {columns} FROM events");
        let publication = fixture.prepare_sql(&columns, "", sql).await?;
        let grant = publication.grant.clone();
        let definition = publication.prepared.resolved().clone();
        fixture.admit_definition(&grant, &definition)?;
        drop(publication);
        let id = "canonical-fields";
        let owner = fixture
            .managed_graph(&grant, &definition, id, &events)
            .await?;
        let store = fixture.query.store();
        let initial = store.managed_status(&grant.selection, id, &fixture.control)?;
        assert_eq!(&initial.instance, owner.admitted());
        assert_eq!(initial.status_progress, 0);
        assert!(matches!(
            initial.readiness,
            araphor_data::PackageReadinessV1::Inactive
        ));
        let before_domain = fixture.graph_history()?;
        assert!(store
            .graph_window_headers(&fixture.source, None)?
            .is_empty());
        let scope = araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: fixture.source.clone(),
        };
        assert!(store.processor_result(&scope)?.is_none());
        let before_health = store.processor_health(&scope)?;
        let before_usage = store.retained_counts(fixture.source.tenant_id)?;
        let before = store.meta()?;
        let input = managed::request("invalid")?;
        let failure = owner
            .run(input.clone(), &fixture.control)
            .await
            .err()
            .ok_or("changed canonical event was published")?;
        assert!(
            format!("{failure:?}").contains(expected),
            "{field}: {failure:?}"
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
        fixture.assert_invalid_graph(
            owner.as_ref(),
            &input,
            &before,
            &before_domain,
            before_health,
            before_usage,
        )?;
        drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    }
    Ok(())
}
