use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    version: u32,
    proof_kind: DiscoveryProofKindV1,
    splits: BTreeMap<String, Split>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Split {
    workload_id: String,
    start_utc_ns: i64,
    end_utc_ns: i64,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    partition: String,
    groups: Vec<Group>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Group {
    count: u64,
    label: String,
    variation: Variation,
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Variation {
    Routine,
    Denied,
    State,
    Release,
    Entry,
    MissingContext,
    Gapped,
    ReplicaGapped,
    Unknown,
    MissingObject,
    Outbound,
}

#[derive(Deserialize)]
struct Expected {
    accepted: u64,
    atoms: usize,
    unresolved: u64,
    prevented: u64,
    coverage: DiscoveryCoverageStateV1,
}

fn case_input(case: &Case, split: &Split) -> TestResult<DiscoveryInputManifestV1> {
    let mut input = Fixture::input()?;
    let seed = input.records[0].clone();
    let seed_wire = seed.decode()?;
    let mut binding = input.contexts[0].clone();
    binding.subject_revision = format!("{}/revision-1", split.workload_id);
    binding.static_key.workload_selector_id = split.workload_id.clone();
    input.source_revision = format!("synthetic-pilot-v1/{}", case.id);
    input.records.clear();
    input.contexts.clear();
    for (ordinal, group) in case.groups.iter().enumerate() {
        assert!(!group.label.is_empty());
        assert!((1..=10_000).contains(&group.count));
        for _ in 0..group.count {
            let cursor = input.records.len() as u64 + 1;
            let mut record = seed.clone();
            record.id.durable_cursor = cursor;
            record.original_kernel_sequence = Some(cursor + 100);
            let mut wire = seed_wire.clone();
            wire.observed_boottime_ns = cursor + 1000;
            wire.ingested_utc_ns = split
                .start_utc_ns
                .checked_add(cursor.try_into()?)
                .ok_or("timestamp overflow")?;
            assert!(wire.ingested_utc_ns < split.end_utc_ns);
            wire.decision = 0;
            wire.kernel_result = 0;
            wire.configured_errno = 0;
            let mut context = binding.clone();
            context.record_id = record.id.clone();
            match group.variation {
                Variation::Routine | Variation::MissingContext => {}
                Variation::Denied => {
                    wire.decision = 1;
                    wire.kernel_result = -13;
                    wire.configured_errno = -13;
                }
                Variation::State => context.state_id += ordinal as u32 + 1,
                Variation::Release => {
                    context.image_digest = "sha256:replacement-image".into();
                    context.configuration_digest = "replacement-configuration".into();
                    context.subject_revision = format!("{}/revision-2", split.workload_id);
                }
                Variation::Entry => {
                    context.entry_instance_id[15] += 1;
                    context.entry_rule_id += 1;
                }
                Variation::Gapped => wire.temporal_coverage = 2,
                Variation::ReplicaGapped => {
                    record.id.stream.node_id = "node-b".into();
                    context.record_id = record.id.clone();
                    context.subject_revision = format!("{}-replica/revision-1", split.workload_id);
                    context.process_instance_id[15] += 1;
                    context.entry_instance_id[15] += 1;
                    context.binding_id[15] += 1;
                    wire.temporal_coverage = 2;
                }
                Variation::Unknown => wire.temporal_coverage = 0,
                Variation::MissingObject => wire.exact_object_id = Default::default(),
                Variation::Outbound => {
                    wire.effect_family = 3;
                    wire.operation = 12;
                    wire.exact_object_id = Default::default();
                    wire.destination_id = 31;
                    context.static_key.effect_family = 3;
                    context.static_key.operation = 12;
                    context.static_key.operation_id = "CONNECT".into();
                    context.static_key.object_selector = "DESTINATION:fixture-api".into();
                }
            }
            record.wire_record = Vec::<u8>::try_from(&wire)?;
            if !matches!(group.variation, Variation::MissingContext) {
                input.contexts.push(context);
            }
            input.records.push(record);
        }
    }
    let seed = input.coverage[0].clone();
    input.coverage.clear();
    for record in &input.records {
        if let Some(range) = input
            .coverage
            .iter_mut()
            .find(|range| range.stream == record.id.stream)
        {
            range.last_cursor = record.id.durable_cursor;
            range.expected_records += 1;
        } else {
            let mut range = seed.clone();
            range.stream = record.id.stream.clone();
            range.first_cursor = record.id.durable_cursor;
            range.last_cursor = record.id.durable_cursor;
            range.expected_records = 1;
            input.coverage.push(range);
        }
    }
    Ok(input)
}

#[tokio::test]
async fn recorded_pilot_corpus() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let corpus: Corpus = serde_json::from_slice(include_bytes!(
        "../../../../../mithril-e2e/fixtures/discovery/pilot.json"
    ))?;
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.proof_kind, DiscoveryProofKindV1::Synthetic);
    assert_eq!(corpus.cases.len(), 21);
    for case in corpus.cases {
        let mut input = case_input(
            &case,
            corpus.splits.get(&case.partition).ok_or("split absent")?,
        )?;
        let result = fixture
            .recorded(&input)
            .await
            .map_err(|error| format!("{} normal: {error:?}", case.id))?
            .snapshot;
        assert_eq!(
            result.accepted_records, case.expected.accepted,
            "{}",
            case.id
        );
        assert_eq!(result.atoms.len(), case.expected.atoms, "{}", case.id);
        assert_eq!(
            result.unresolved_records, case.expected.unresolved,
            "{}",
            case.id
        );
        assert!(
            result
                .coverage
                .iter()
                .any(|range| range.state == case.expected.coverage),
            "{}",
            case.id
        );
        assert_eq!(
            result.included_records + result.unresolved_records + result.excluded_records,
            result.accepted_records
        );
        assert_eq!(
            result
                .atoms
                .iter()
                .filter(|atom| atom.key.physical_result == DiscoveryPhysicalResultV1::Prevented)
                .map(|atom| atom.count)
                .sum::<u64>(),
            case.expected.prevented,
            "{}",
            case.id
        );
        input.records.reverse();
        input.contexts.reverse();
        input.records.extend(input.records.clone());
        let replay = fixture
            .recorded(&input)
            .await
            .map_err(|error| format!("{} replay: {error:?}", case.id))?;
        assert_eq!(replay.duplicate_deliveries, case.expected.accepted);
        assert_eq!(replay.snapshot, result, "{}", case.id);
        if case.id == "rare-forbidden" {
            rare_exports(&fixture, &input, &result, &replay.snapshot).await?;
        }
    }
    Ok(())
}

async fn rare_exports(
    fixture: &Fixture,
    input: &DiscoveryInputManifestV1,
    normal: &BehaviorSnapshotV1,
    replay: &BehaviorSnapshotV1,
) -> TestResult<()> {
    let prefix = prefix(input)?;
    let groups = groups(input, normal)?;
    assert_eq!(fixture.groups(normal).await?, groups);
    assert_eq!(fixture.groups(replay).await?, groups);
    let routine = groups
        .iter()
        .find(|group| group.key.physical_result == DiscoveryPhysicalResultV1::Unknown)
        .ok_or("routine group absent")?;
    let denied = groups
        .iter()
        .find(|group| group.key.physical_result == DiscoveryPhysicalResultV1::Prevented)
        .ok_or("denied group absent")?;
    assert_eq!(routine.key.static_key, denied.key.static_key);
    let mut previous = routine.clone();
    previous.count = 64;
    previous.coverage = prefix.coverage.clone();
    let baseline = DiscoveryReviewedBaselineV1 {
        snapshot: fixture.recorded(&prefix).await?.snapshot,
        reviewer: "operator".into(),
        reviewed_utc_ns: 3000,
        forbidden: vec![denied.key.static_key.clone()],
    };
    assert_eq!(
        fixture.groups(&baseline.snapshot).await?,
        vec![previous.clone()]
    );
    let expected = DiscoveryComparisonV1 {
        added: vec![denied.clone()],
        removed: Vec::new(),
        changed_counts: vec![DiscoveryGroupChangeV1 {
            before: previous.clone(),
            after: routine.clone(),
        }],
        changed_results: vec![DiscoveryGroupChangeV1 {
            before: previous,
            after: denied.clone(),
        }],
        changed_identities: Vec::new(),
        new_resources: Vec::new(),
        coverage_before: prefix.coverage,
        coverage_after: input.coverage.clone(),
        lifecycle_before: Vec::new(),
        lifecycle_after: Vec::new(),
        forbidden_groups: groups,
    };
    assert_eq!(fixture.comparison(normal, &baseline).await?, expected);
    assert_eq!(fixture.comparison(replay, &baseline).await?, expected);
    Ok(())
}

fn prefix(input: &DiscoveryInputManifestV1) -> TestResult<DiscoveryInputManifestV1> {
    assert_eq!(input.coverage.len(), 1);
    assert_eq!(input.coverage[0].first_cursor, 1);
    assert_eq!(input.coverage[0].last_cursor, 10001);
    assert_eq!(input.coverage[0].expected_records, 10001);
    assert_eq!(input.coverage[0].state, DiscoveryCoverageStateV1::Healthy);
    let mut records = input
        .records
        .iter()
        .filter(|record| record.id.durable_cursor <= 64)
        .cloned()
        .collect::<Vec<_>>();
    records.sort_by(|left, right| left.id.cmp(&right.id));
    records.dedup_by(|left, right| left.id == right.id);
    assert_eq!(records.len(), 64);
    let contexts = input
        .contexts
        .iter()
        .filter(|context| context.record_id.durable_cursor <= 64)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(contexts.len(), 64);
    let mut coverage = input.coverage.clone();
    coverage[0].last_cursor = 64;
    coverage[0].expected_records = 64;
    Ok(DiscoveryInputManifestV1 {
        schema_version: input.schema_version,
        tenant_id: input.tenant_id,
        source_revision: input.source_revision.clone(),
        proof_kind: input.proof_kind,
        records,
        contexts,
        coverage,
        exclusions: input.exclusions.clone(),
        lifecycle: input.lifecycle.clone(),
    })
}

fn groups(
    input: &DiscoveryInputManifestV1,
    snapshot: &BehaviorSnapshotV1,
) -> TestResult<Vec<BehaviorDisplayGroupV1>> {
    assert_eq!(snapshot.atoms.len(), 2);
    let mut groups = Vec::new();
    for (physical, count, cursors) in [
        (
            DiscoveryPhysicalResultV1::Unknown,
            10000,
            (1..=8).collect::<Vec<_>>(),
        ),
        (DiscoveryPhysicalResultV1::Prevented, 1, vec![10001]),
    ] {
        let atom = snapshot
            .atoms
            .iter()
            .find(|atom| atom.key.physical_result == physical)
            .ok_or("rare atom absent")?;
        let samples = cursors
            .into_iter()
            .map(|cursor| {
                input
                    .records
                    .iter()
                    .find(|record| record.id.durable_cursor == cursor)
                    .map(|record| record.id.clone())
                    .ok_or("rare sample absent")
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        groups.push(BehaviorDisplayGroupV1 {
            key: BehaviorDisplayKeyV1::from(&atom.key),
            count,
            members: vec![atom.key.clone()],
            evidence_sample: samples,
            coverage: input.coverage.clone(),
        });
    }
    groups.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(groups)
}
