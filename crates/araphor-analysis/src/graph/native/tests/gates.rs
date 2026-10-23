mod source;

use super::*;
use araphor_data::{
    CoverageCounters, CoverageInterval, CoverageReport, DiscoveryCoverageStateV1,
    DiscoveryCoverageV1, GraphCoverageKeyV1, GraphReplayInputV1, InputRevision,
    ValidatedCoverageV1,
};
use prost::Message as _;

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
    result_id: &str,
    filter: &str,
) -> TestResult {
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
    let publication = fixture.prepare(filter).await?;
    let projection = Arc::clone(&publication.projection);
    let observed = projection.observe_capture();
    let (id, _) = publication.refresh(result_id.into()).await?;
    let captured = observed.try_recv()?;
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
    assert_eq!(captured.inputs.len(), 3);
    for (index, input) in captured.inputs.iter().enumerate() {
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
        let actual = araphor_analysis_builtins::Rows::decode::<serde_json::Value>(
            &projection.ports[index],
            &input.data,
        )?;
        assert_eq!(actual, expected_graph.projection()[index]);
    }
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
    Ok(())
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
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn graph_partial_coverage_reports() -> TestResult {
    let fixture = Fixture::with_records(Target::Sql, records(1, [[7; 16], [8; 16], [7; 16]])?)?;
    report(&fixture, 1, &[([7; 16], 11, "HEALTHY")])?;
    let (first, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:partial-first".into())
        .await?;
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
    payload(
        &fixture,
        expected,
        sdk::CoverageState::Unknown,
        "graph:partial-second",
        "",
    )
    .await?;
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
    let (first, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:revision-one".into())
        .await?;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("original graph")?;
    assert!(
        retained
            .findings
            .iter()
            .any(|finding| finding.state == araphor_data::FindingStateV1::Confirmed)
    );
    for revision in 2..=258 {
        report(&fixture, revision, &[([7; 16], revision, "HEALTHY")])?;
    }
    let (next, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:revision-258".into())
        .await?;
    let current = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &next)?
        .ok_or("latest graph")?;
    assert!(
        current
            .findings
            .iter()
            .any(|finding| finding.state == araphor_data::FindingStateV1::Confirmed)
    );
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
    let before = fixture.query.store().meta()?;
    let (unchanged, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:unrelated-259".into())
        .await?;
    assert_eq!(unchanged, next);
    assert_eq!(fixture.query.store().meta()?, before);
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
    let (first, _) = fixture
        .prepare("")
        .await?
        .refresh("graph:before-corruption".into())
        .await?;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &first)?
        .ok_or("original graph")?;
    fixture.query.store().fault_write(
        "UPDATE coverage SET report = '\\xFF'::BLOB WHERE revision = 1",
        &[],
    )?;
    let before = fixture.query.store().meta()?;
    let calls = fixture.facts.calls.load(Ordering::SeqCst);
    let failure = fixture
        .prepare("")
        .await?
        .refresh("graph:corrupt-report".into())
        .await
        .err()
        .ok_or("malformed selected report used fallback")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&failure),
        erebor_runtime_error::StatusCode::IllegalState
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), calls);
    assert_eq!(fixture.query.store().meta()?, before);
    assert!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, "graph:corrupt-report")?
            .is_none()
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &first)?,
        Some(retained)
    );
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
    let implementations = ["detect", "spare"]
        .into_iter()
        .map(|export| {
            let mut program = araphor_package::SqlModelV1::default();
            for name in ["subjects", "relationships", "findings"] {
                program
                    .outputs
                    .insert(name.into(), "SELECT value FROM records WHERE FALSE".into());
            }
            program.checkpoint.insert(
                "state".into(),
                r#"SELECT CAST('{"value":"WAITING"}' AS BYTEA) AS value"#.into(),
            );
            PackageImplementationV1::Sql {
                export: export.into(),
                program,
            }
        })
        .chain(std::iter::once(PackageImplementationV1::Sql {
            export: "aux".into(),
            program: araphor_package::SqlModelV1 {
                outputs: BTreeMap::from([(
                    "data".into(),
                    "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                ..Default::default()
            },
        }))
        .collect();
    let artifact = PackageArtifactV1 {
        descriptor,
        implementations,
        fixtures: Vec::new(),
    };
    fixture.query.store().install_package_image(
        fixture.source.tenant_id,
        &PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        },
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
    let (first, _) = fixture
        .prepare_sql("*", "", sql)
        .await?
        .refresh("graph:extras".into())
        .await?;
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
    let (second, _) = fixture
        .prepare_sql("*", "", sql)
        .await?
        .refresh("graph:reverse-extras".into())
        .await?;
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
        let publication = fixture.prepare_sql(&columns, "", sql).await?;
        let before = fixture.query.store().meta()?;
        let failure = publication
            .refresh("graph:changed-canonical-field".into())
            .await
            .err()
            .ok_or("changed canonical event was published")?;
        assert!(
            format!("{failure:?}").contains(expected),
            "{field}: {failure:?}"
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.query.store().meta()?, before);
        assert!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, "graph:changed-canonical-field")?
                .is_none()
        );
        drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    }
    Ok(())
}
