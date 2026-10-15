use std::collections::BTreeSet;

use super::*;

#[test]
fn output_bytes_split() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("analysis"))?);
    let input = dense_input()?;
    assert_eq!(input.records.len(), 256);
    assert_eq!(input.facts.len(), 67);
    input.validate()?;
    let execution = crate::InstalledAnalysis::testing(Some(store.clone()), source().tenant_id)?;
    let owner = GraphAndFindingOwner::new(
        store.clone(),
        Arc::new(Inputs(Mutex::new(input.facts.clone()))),
        execution.clone(),
    )?;
    for batch in input.records.chunks(128) {
        accept(&store, batch)?;
    }
    coverage(&store, 256, 1, "HEALTHY")?;
    let before = store.meta()?;
    let error = GraphAndFindingOwner::derive(&input, &execution).err();
    assert!(
        matches!(
            &error,
            Some(Error::GraphInvalid {
                field: "graph output bytes",
                ..
            })
        ),
        "{error:?}; root: {}",
        match &error {
            Some(Error::PackageWasm { source, .. }) => {
                let mut root: &dyn std::error::Error = source.as_ref();
                while let Some(next) = root.source() {
                    root = next;
                }
                root.to_string()
            }
            _ => String::new(),
        }
    );
    assert_eq!(store.meta()?, before);
    assert!(owner.current_findings(source().tenant_id)?.is_empty());

    super::window_expiry::process_to(&owner, &store, 256, 10)?;
    let health = store
        .processor_health(&GraphAndFindingOwner::scope(&source()))?
        .ok_or("processor health")?;
    assert_eq!(health.consumed_cursor, 256);
    assert_eq!(health.state, ProcessorStateV1::Current);
    assert!(!health.incomplete);
    let current = owner.current_findings(source().tenant_id)?;
    assert_eq!(current.len(), 256);
    let mut results = BTreeSet::new();
    let mut native = BTreeSet::new();
    let mut credential = None;
    for (id, finding) in current {
        if results.insert(id.clone()) {
            let body = store
                .read_result(source().tenant_id, &id)?
                .ok_or("graph result")?;
            assert!(body.len() <= GRAPH_WINDOW_BYTES);
            assert!(body.len() <= crate::analysis::MAX_RESULT_BYTES);
        }
        match finding.package_id.as_str() {
            "HF-PROC-001" => {
                assert_eq!(finding.reason, FindingReasonV1::UnexpectedEffect);
                assert_eq!(finding.evidence.len(), 1);
                assert!(native.insert(finding.evidence[0].clone()));
            }
            "HF-DW-001" => {
                assert!(credential.replace(finding).is_none());
            }
            _ => return Err("unexpected graph package finding".into()),
        }
    }
    assert!(results.len() > 1);
    assert_eq!(
        native,
        input.records[1..]
            .iter()
            .map(|record| record.id.clone())
            .collect()
    );
    let credential = credential.ok_or("credential finding")?;
    assert_eq!(
        credential.reason,
        FindingReasonV1::ContextualCredentialPivot
    );
    assert_eq!(credential.state, FindingStateV1::CoverageInsufficient);
    assert!(credential.evidence.len() > 1);
    let last = credential
        .revision
        .evidence
        .last()
        .ok_or("credential window")?
        .durable_cursor;
    let expected: Vec<_> = input
        .records
        .iter()
        .take_while(|record| record.id.durable_cursor <= last)
        .map(|record| record.id.clone())
        .collect();
    assert_eq!(credential.revision.evidence, expected);
    assert_eq!(credential.evidence, expected);
    Ok(())
}

#[test]
fn final_header_bounds() -> TestResult {
    use crate::analysis::graph_rows::CanonicalGraph;

    let fixture = super::native_storage::CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot.previous_result_id = None;
    snapshot.context_notice_revision = 0;
    snapshot.witness_deadline_utc_ns = 0;
    snapshot.input_positions.clear();
    let body = serde_json::to_vec(&snapshot)?;
    let prepared = CanonicalGraph::bounded(snapshot.clone(), body.len())?;
    assert_eq!(prepared.body(), body);
    let before = fixture.store.meta()?;
    snapshot.previous_result_id = Some(format!("graph:{}", "x".repeat(128)));
    snapshot.context_notice_revision = u64::MAX;
    snapshot.witness_deadline_utc_ns = u64::MAX;
    snapshot.validate()?;
    assert!(matches!(
        CanonicalGraph::bounded(snapshot.clone(), body.len()),
        Err(Error::GraphInvalid {
            field: "graph output bytes",
            ..
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    let final_body = serde_json::to_vec(&snapshot)?;
    assert!(final_body.len() > body.len());
    let prepared = CanonicalGraph::bounded(snapshot, final_body.len())?;
    assert_eq!(prepared.body(), final_body);
    Ok(())
}

fn dense_input() -> TestResult<GraphReplayInputV1> {
    let mut records = vec![record(1, &wire(1, UnknownAfterPreEffect, 2, 4, [20; 16]))?];
    for cursor in 2..=256 {
        records.push(record(
            cursor,
            &wire(cursor, DeniedBeforeEffect, 3, 13, [21; 16]),
        )?);
    }
    let mut input = input(records);
    let template = credential_input()?;
    let values = template
        .facts
        .iter()
        .map(GraphFactV1::try_from)
        .collect::<Result<Vec<_>>>()?;
    let credential = values
        .iter()
        .find(|fact| matches!(&fact.value, GraphFactValueV1::Credential { .. }))
        .ok_or("credential fact")?;
    input
        .facts
        .push(fact(&input.records[0], 1, credential.value.clone())?);
    let authority = values
        .iter()
        .find(|fact| matches!(&fact.value, GraphFactValueV1::AuthorityUse { .. }))
        .ok_or("authority fact")?;
    for index in 2..=67 {
        let mut value = authority.value.clone();
        if let GraphFactValueV1::AuthorityUse { request_id, .. } = &mut value {
            *request_id = Some(format!("request-{index}"));
        }
        input.facts.push(fact(&input.records[1], index, value)?);
    }
    Ok(input)
}
