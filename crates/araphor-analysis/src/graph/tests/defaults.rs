use super::*;
use araphor_data::GraphContextActionV1;

#[test]
fn graph_accepts_large_window() -> TestResult {
    let records = (1..=257)
        .map(|cursor| {
            let cursor = if cursor == 257 { 1_025 } else { cursor };
            fixture::record(
                cursor,
                &fixture::wire(
                    cursor,
                    EffectPhysicalResultV1::DeniedBeforeEffect,
                    2,
                    2,
                    [20; 16],
                ),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let input = fixture::input(records);
    let snapshot = derive(&input)?;
    assert_eq!(snapshot.input_manifest.evidence.len(), 257);
    assert_eq!((snapshot.first_cursor, snapshot.last_cursor), (1, 1_025));
    assert!(!snapshot.findings.is_empty());
    for package in &snapshot.packages {
        assert_eq!(package.window_ns, 300_000_000_000);
    }
    let decoded = GraphSnapshotV1::try_from(serde_json::to_vec(&snapshot)?.as_slice())?;
    assert_eq!(decoded, snapshot);
    Ok(())
}

#[test]
fn graph_omits_record_ceiling() -> TestResult {
    let mut input = fixture::credential_input()?;
    input.facts.retain(|context| {
        !matches!(
            GraphFactV1::try_from(context).map(|fact| fact.value),
            Ok(GraphFactValueV1::AuthorityUse { .. })
        )
    });
    for cursor in 4..=256 {
        input.records.push(fixture::record(
            cursor,
            &fixture::wire(
                cursor,
                EffectPhysicalResultV1::DeniedBeforeEffect,
                2,
                2,
                [20; 16],
            ),
        )?);
    }
    input.coverage[0].last_cursor = 256;
    input.coverage[0].expected_records = 256;
    let snapshot = derive(&input)?;
    let missing = snapshot
        .findings
        .iter()
        .find(|finding| finding.reason == FindingReasonV1::MissingAuthorityProof)
        .ok_or("missing authority finding")?;
    assert!(!missing
        .limits
        .iter()
        .any(|limit| limit == "JOIN_WINDOW_RECORD_LIMIT"));
    assert!(missing
        .limits
        .iter()
        .any(|limit| limit == "AUTHORITATIVE_REMOTE_RESULT_MISSING"));
    Ok(())
}

#[test]
fn graph_accepts_retained_facts() -> TestResult {
    let record = fixture::record(
        1,
        &fixture::wire(
            1,
            EffectPhysicalResultV1::DeniedBeforeEffect,
            2,
            2,
            [20; 16],
        ),
    )?;
    let mut input = fixture::input(vec![record.clone()]);
    for index in 0..257 {
        let mut context = fixture::fact(
            &record,
            index,
            GraphFactValueV1::Context {
                subject: GraphSubjectKeyV1 {
                    tenant_id: input.source.tenant_id,
                    authority: GraphSubjectAuthorityV1::External {
                        authority_id: "a".repeat(257),
                    },
                    kind: GraphSubjectKindV1::External,
                    identity: vec![1; 257],
                },
                action_id: if index == 0 {
                    "a".repeat(32 * 1024 + 1)
                } else {
                    format!("action-{index}")
                },
                classification: GraphContextActionV1::InMemory,
                proof_quality: fixture::authority_proof(),
            },
        )?;
        context.key.owner_id = "owner".repeat(33);
        context.key.entity_key = [index.to_be_bytes().as_slice(), &[1; 257]].concat();
        context.key.lifetime_key = vec![1; 257];
        input.facts.push(context);
    }
    let range = input.coverage[0].clone();
    input.coverage = vec![range; 4_097];
    input.coverage[0].last_cursor = 1_000_001;
    input.coverage[0].expected_records = 1_000_001;
    input.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
    input.coverage[0].gap_reasons = (0..33)
        .map(|index| format!("{index:02}-{}", "x".repeat(129)))
        .collect();
    input.validate()?;
    let graph = Graph::new(&input)?;
    let evaluation = graph.evaluation()?;
    assert_eq!(evaluation.inputs[0].data.rows(), 1);
    assert_eq!(evaluation.inputs[1].data.rows(), 257);
    assert_eq!(evaluation.inputs[2].data.rows(), 1);
    let mut invalid = input;
    invalid.facts[0].key.entity_key.clear();
    assert!(invalid.validate().is_err());
    Ok(())
}

#[test]
fn graph_preserves_boottime_horizon() -> TestResult {
    for (elapsed, reason) in [
        (300_000_000_000, FindingReasonV1::CredentialPivot),
        (300_000_000_001, FindingReasonV1::MissingAuthorityProof),
    ] {
        let mut input = fixture::credential_input()?;
        let mut wire = input.records[2].decode()?;
        wire.observed_boottime_ns = input.records[0].decode()?.observed_boottime_ns + elapsed;
        input.records[2] = fixture::record(3, &wire)?;
        let snapshot = derive(&input)?;
        assert!(
            snapshot
                .findings
                .iter()
                .any(|finding| finding.reason == reason),
            "{elapsed}: {:?}",
            snapshot.findings
        );
    }
    Ok(())
}
