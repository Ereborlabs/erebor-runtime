use super::*;
use araphor_data::NotificationFindingRefV1;

pub(super) fn reference(
    store: &NativeStore,
    step: u8,
    id: &str,
) -> Result<NotificationFindingRefV1, Box<dyn std::error::Error>> {
    let attempt = store
        .managed_attempt(
            [1; 16],
            "domain",
            &format!("domain-{step}"),
            &AnalysisReadControl::default(),
        )?
        .ok_or("attempt")?;
    Ok(NotificationFindingRefV1 {
        result_id: attempt
            .receipt()
            .ok_or("receipt")?
            .selected
            .result_id
            .clone(),
        finding_id: id.into(),
    })
}

#[test]
fn finding_batch_uses_live_origins_and_retained_publication_cuts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, _, observation) = fixture(&store)?;
    let expected = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    commit(&store, &model, &observation, 0)?;
    let first = reference(&store, 0, &expected.finding_id)?;
    let original = store.graph_finding_batch([1; 16], std::slice::from_ref(&first))?;
    let (revision, findings) = &original[&first.result_id];
    assert_eq!(findings[&expected.finding_id], expected);
    assert_eq!(revision.evidence, vec![observation.id.clone()]);
    assert!(revision.context.iter().any(|key| key.owner_revision == 99));
    revision.validate_finding(&expected)?;
    assert_eq!(
        store.graph_finding([1; 16], &first.result_id, &first.finding_id)?,
        Some((expected.clone(), revision.clone()))
    );
    assert_eq!(
        store.notification_finding([1; 16], &first)?,
        (expected.clone(), revision.clone())
    );
    assert_eq!(
        store.graph_revision_finding([1; 16], &first.finding_id, revision)?,
        Some(expected.clone())
    );
    assert!(store
        .graph_finding([1; 16], &first.result_id, "missing")?
        .is_none());

    commit(&store, &model, &observation, 1)?;
    let second = reference(&store, 1, &expected.finding_id)?;
    let current = store.graph_finding_batch([1; 16], std::slice::from_ref(&second))?;
    assert_eq!(current[&second.result_id], original[&first.result_id]);
    commit(&store, &model, &observation, 2)?;
    let third = reference(&store, 2, &expected.finding_id)?;
    let current = store.graph_finding_batch([1; 16], std::slice::from_ref(&third))?;
    assert_eq!(current[&third.result_id], original[&first.result_id]);
    let requested = vec![first.clone(), second.clone(), third.clone(), third.clone()];
    assert_eq!(store.graph_finding_batch([1; 16], &requested)?.len(), 3);
    assert!(store
        .graph_finding_batch([2; 16], std::slice::from_ref(&third))
        .is_err());
    assert!(store.graph_finding_batch([0; 16], &[]).is_err());
    assert!(store.graph_finding_batch([1; 16], &[])?.is_empty());
    let mut missing = third.clone();
    missing.finding_id = "absent".into();
    assert!(
        store.graph_finding_batch([1; 16], &[missing])?[&third.result_id]
            .1
            .is_empty()
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.graph_finding_batch([1; 16], &[first.clone()])?,
        original
    );
    let current = store.graph_finding_batch([1; 16], &[third.clone()])?;
    assert_eq!(current[&third.result_id], original[&first.result_id]);
    assert_eq!(
        store.notification_finding([1; 16], &first)?,
        (expected.clone(), original[&first.result_id].0.clone())
    );
    assert_eq!(
        store.graph_revision_finding([1; 16], &first.finding_id, &original[&first.result_id].0)?,
        Some(expected)
    );

    Ok(())
}

#[test]
fn finding_basis_follows_exact_historical_reads_after_compaction() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, _, observation) = fixture(&store)?;
    let expected = finding(
        &observation,
        &super::super::publication::output(&model)?.datasets[0].batches[0],
    )?
    .value;
    commit(&store, &model, &observation, 0)?;
    let first = reference(&store, 0, &expected.finding_id)?;
    let prior = store.graph_finding_batch([1; 16], &[first.clone()])?;
    commit(&store, &model, &observation, 1)?;
    commit(&store, &model, &observation, 3)?;
    let current = reference(&store, 3, &expected.finding_id)?;
    let control = AnalysisReadControl::default();
    let attempt = store
        .managed_attempt([1; 16], "domain", "domain-3", &control)?
        .ok_or("current attempt")?;
    let receipt = attempt.receipt().ok_or("current receipt")?;
    let original_attempt = store
        .managed_attempt([1; 16], "domain", "domain-0", &control)?
        .ok_or("original attempt")?;
    let original_receipt = original_attempt.receipt().ok_or("original receipt")?;
    let mapping = store
        .view()?
        .managed_graph([1; 16], "domain", &control)?
        .ok_or("mapping")?;
    let graph = araphor_graph::native::Graph::new(mapping.graph)?.view(
        store.view()?.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    let member = graph
        .member(
            mapping.writers[&20],
            mapping.relations[DomainRelations::FINDINGS].0,
            b"owner",
            &DomainRelations::key(&expected.finding_id)?,
            &|_, _, _| Ok(None),
        )?
        .ok_or("current member")?;
    assert_eq!(member.revision, receipt.commit_revision);
    assert!(member.revision > original_receipt.commit_revision);
    let key = [
        b"\0data/O".as_slice(),
        &member.writer.to_be_bytes(),
        &member.revision.to_be_bytes(),
    ]
    .concat();
    let bytes = store.view()?.snapshot().get(key)?.ok_or("origin")?;
    #[derive(serde::Deserialize)]
    struct ReadRow {
        relation: u64,
        writer: u64,
        owner: Vec<u8>,
        key: Vec<u8>,
        revision: u64,
    }
    #[derive(serde::Deserialize)]
    struct Origin {
        rows: Vec<ReadRow>,
        reads: Vec<(u64, u64, araphor_data::analysis::PackageResultRefV1)>,
    }
    let origin: Origin = rmp_serde::from_slice(&bytes[1..])?;
    assert!(origin.rows.iter().any(|row| row.relation == member.relation
        && row.writer == member.writer
        && row.owner == member.owner
        && row.key == member.key
        && row.revision == original_receipt.commit_revision));
    assert!(origin
        .reads
        .iter()
        .any(|(writer, revision, result)| *writer == member.writer
            && *revision == original_receipt.commit_revision
            && *result == original_receipt.results[&20]));
    drop(member);
    drop(graph);
    let mut empty_producer = false;
    for entry in store.view()?.snapshot().prefix(b"\0data/X") {
        let (key, bytes) = entry?;
        if key.len() != 15 {
            continue;
        }
        #[derive(serde::Deserialize)]
        struct Stored {
            id: String,
            body: serde_value::Value,
        }
        let value: Stored = rmp_serde::from_slice(&bytes[1..])?;
        if !value.id.ends_with("call-20") {
            continue;
        }
        let mut body = value.body;
        let serde_value::Value::Map(variants) = &mut body else {
            continue;
        };
        let record = variants.first_entry().ok_or("body")?.into_mut();
        if *super::super::attempts::field(record, &["attempt"])?
            == serde_value::Value::String("domain-3".into())
        {
            assert_eq!(
                *super::super::attempts::field(record, &["witnesses"])?,
                serde_value::Value::Seq(Vec::new())
            );
            empty_producer = true;
        }
    }
    assert!(empty_producer);
    let actual = store.graph_finding_batch([1; 16], &[current.clone()])?;
    assert_eq!(actual[&current.result_id], prior[&first.result_id]);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.graph_finding_batch([1; 16], &[current])?, actual);
    Ok(())
}

#[test]
fn historical_parent_rejects_a_rebound_selected_receipt() -> TestResult {
    for target in [1, 3] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("data"))?;
        let (_, model, _, observation) = fixture(&store)?;
        let finding = finding(
            &observation,
            &super::super::publication::output(&model)?.datasets[0].batches[0],
        )?;
        commit(&store, &model, &observation, 0)?;
        commit(&store, &model, &observation, 1)?;
        commit(&store, &model, &observation, 3)?;
        let current = reference(&store, 3, &finding.value.finding_id)?;
        let target = reference(&store, target, &finding.value.finding_id)?;
        assert!(
            store.graph_finding_batch([1; 16], &[target.clone()])?[&target.result_id]
                .1
                .contains_key(&finding.value.finding_id)
        );
        let view = store.view()?;
        let mut tx = store.write()?;
        let mut changed = false;
        for entry in view.snapshot().prefix(b"\0data/a") {
            let (key, bytes) = entry?;
            if key.len() != 15 {
                continue;
            }
            let mut value: serde_value::Value = rmp_serde::from_slice(&bytes[1..])?;
            if *super::super::attempts::field(&mut value, &["request", "id"])?
                != serde_value::Value::String("domain-0".into())
            {
                continue;
            }
            *super::super::attempts::field(&mut value, &["receipt", "selected", "result_id"])? =
                serde_value::Value::String(target.result_id.clone());
            tx.native()
                .insert(key, [vec![0], rmp_serde::to_vec(&value)?].concat());
            changed = true;
        }
        assert!(changed);
        tx.commit([])?;
        assert!(matches!(
            store.graph_finding_batch([1; 16], &[current]),
            Err(Error::Package {
                code: Code::Denied,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn finding_basis_rejects_missing_witnesses_coverage_and_context_pins() -> TestResult {
    for fault in [
        "witnesses",
        "graph_proof",
        "context",
        "raw-pin",
        "missing-pin",
        "expired-pin",
        "selected",
    ] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("data"))?;
        let (_, model, _, observation) = fixture(&store)?;
        commit_expiry(
            &store,
            &model,
            &observation,
            0,
            (fault != "expired-pin").then_some(u64::MAX),
        )?;
        let finding = finding(
            &observation,
            &super::super::publication::output(&model)?.datasets[0].batches[0],
        )?;
        let reference = reference(&store, 0, &finding.value.finding_id)?;
        let view = store.view()?;
        let mut tx = store.write()?;
        let mut changed = 0;
        if fault == "context" {
            let key = view
                .snapshot()
                .prefix(b"\0data/ref/context/")
                .next()
                .ok_or("context reference")??
                .0;
            tx.native().insert(key, u64::MAX.to_be_bytes());
            changed = 1;
        } else if matches!(fault, "raw-pin" | "missing-pin" | "expired-pin") {
            for entry in view.snapshot().prefix(b"\0data/ref/evidence/") {
                let (key, value) = entry?;
                if fault != "raw-pin" {
                    tx.native().remove(key);
                } else {
                    let mut changed = key.to_vec();
                    let offset = b"\0data/ref/evidence/".len() + 8;
                    changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
                    tx.native().remove(key);
                    tx.native().insert(changed, value);
                }
                changed += 1;
            }
        } else {
            for entry in view.snapshot().prefix(b"\0data/X") {
                let (key, bytes) = entry?;
                if key.len() != 15 {
                    continue;
                }
                let mut value: serde_value::Value = rmp_serde::from_slice(&bytes[1..])?;
                let body = super::super::attempts::field(&mut value, &["body"])?;
                let serde_value::Value::Map(variants) = body else {
                    return Err("body".into());
                };
                let entry = variants.first_entry().ok_or("kind")?;
                if fault == "selected" {
                    if *entry.key() == serde_value::Value::String("Selected".into()) {
                        tx.native().remove(key);
                        changed += 1;
                    }
                    continue;
                }
                if *entry.key() != serde_value::Value::String("Call".into()) {
                    continue;
                }
                let record = entry.into_mut();
                let field = super::super::attempts::field(record, &[fault])?;
                *field = if fault == "graph_proof" {
                    serde_value::Value::Option(None)
                } else {
                    serde_value::Value::Seq(Vec::new())
                };
                tx.native()
                    .insert(key, [vec![0], rmp_serde::to_vec(&value)?].concat());
                changed += 1;
            }
        }
        assert!(changed > 0);
        tx.commit([])?;
        if fault == "expired-pin" {
            assert!(store.graph_finding_batch([1; 16], &[reference]).is_ok());
            continue;
        }
        let error = store
            .graph_finding_batch([1; 16], &[reference])
            .expect_err(fault);
        let expected = match fault {
            "witnesses" | "raw-pin" => Code::Invalid,
            "context" => Code::Denied,
            _ => Code::Missing,
        };
        assert!(
            matches!(error, Error::Package { code, .. } if code == expected),
            "{fault}: {error}"
        );
    }
    Ok(())
}
