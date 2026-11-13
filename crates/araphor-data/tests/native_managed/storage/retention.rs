#![cfg(feature = "test-fixtures")]

use super::source::{identity, request};
use super::StorageFixture as Fixture;
use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisExtractLimits,
    AnalysisReadModeV1, AnalysisResultCommitV1, AnalysisStore, AnalysisTableRead,
    AnalysisTableRequests, AnalysisWitnessV1, ContextSensitivityV1, EvidenceRecord,
    EvidenceRetentionOwner, ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1,
    ValidatedEvidenceBatchV1,
};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const RAW: &[u8] = b"\0data/ref/evidence/";
const SEGMENT: &[u8] = b"\0data/ref/batch/";

fn retained(
    store: &AnalysisStore,
    ids: &[String],
    witnesses: &[AnalysisWitnessV1],
    contexts: &[AnalysisContextRefV1],
) -> TestResult {
    let requests = AnalysisTableRequests::new();
    let before = store.meta()?;
    for tenant in [[1; 16], [9; 16]] {
        let mut selection = AnalysisSelectionV1::new(tenant, Vec::new());
        selection.results = ids.to_vec();
        let page = store.read_tables(
            &selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Metadata,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert!(page.tables.is_empty());
        if tenant == [1; 16] {
            assert!(page.extraction.missing_results.is_empty());
            assert_eq!(page.extraction.witnesses, witnesses);
            assert_eq!(
                page.extraction
                    .references
                    .iter()
                    .filter_map(|reference| reference.context())
                    .cloned()
                    .collect::<Vec<_>>(),
                contexts
            );
            assert_eq!(
                page.extraction
                    .references
                    .iter()
                    .filter_map(|reference| reference.result())
                    .map(|reference| reference.result_id.clone())
                    .collect::<BTreeSet<_>>(),
                ids.iter().cloned().collect()
            );
        } else {
            assert_eq!(page.extraction.missing_results, ids);
            assert!(page.extraction.witnesses.is_empty());
            assert!(page.extraction.references.is_empty());
        }
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}

fn pins(store: &AnalysisStore, result: u64) -> TestResult {
    let view = store.view()?;
    let mut cursors = BTreeSet::new();
    let prefix = [RAW, &result.to_be_bytes()].concat();
    let entries = records(&view, &prefix)?;
    assert!(!entries.is_empty());
    for (key, value) in entries {
        assert_eq!(key.len(), RAW.len() + 24);
        assert_eq!(value[0], 0);
        let segment = &key[RAW.len() + 8..RAW.len() + 16];
        let expiry = &key[RAW.len() + 16..];
        assert_eq!(expiry, 100u64.to_be_bytes());
        let ranges: Vec<(u64, u64)> = rmp_serde::from_slice(&value[1..])?;
        assert!(!ranges.is_empty());
        assert!(ranges.windows(2).all(|pair| pair[0].1 + 1 < pair[1].0));
        for (first, last) in ranges {
            assert!(first <= last);
            for cursor in first..=last {
                assert!(cursors.insert(cursor));
            }
        }
        let reverse = [SEGMENT, segment, &result.to_be_bytes(), expiry].concat();
        assert_eq!(view.snapshot().get(reverse)?.as_deref(), Some(expiry));
    }
    assert_eq!(cursors, (1..=8193).collect());
    let prefix = [b"\0data/ref/context/".as_slice(), &result.to_be_bytes()].concat();
    assert_eq!(records(&view, &prefix)?.len(), 257);
    Ok(())
}

#[test]
fn retained_provenance_survives_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let retention = RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(1024 * 1024),
    };
    let store = AnalysisStore::open_with_retention(&root, retention)?;
    let source = identity();
    let frame = Vec::<u8>::try_from(&EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    for first in (1..=8193u64).step_by(araphor_data::EVIDENCE_BATCH_RECORDS) {
        let last = (first + araphor_data::EVIDENCE_BATCH_RECORDS as u64 - 1).min(8193);
        let count = (last - first + 1) as usize;
        store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: last,
                intake_utc_ns: 1,
                framed_records: frame.repeat(count).into(),
                frame_ends: (1..=count).map(|index| index * frame.len()).collect(),
            },
        )?;
    }
    let contexts = (0..257u32)
        .map(|index| AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "context".into(),
                entity_key: index.to_be_bytes().to_vec(),
                lifetime_key: b"lifetime".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        })
        .collect::<Vec<_>>();
    let context_refs = store.commit_contexts(&contexts)?;
    let keys = contexts
        .iter()
        .map(|context| context.key.clone())
        .collect::<Vec<_>>();
    let held = store.view()?;
    let actual = keys
        .iter()
        .map(|key| {
            let (version, revision) = held.context(key)?.ok_or("context absent")?;
            assert_eq!(&version.key, key);
            Ok(AnalysisContextRefV1 {
                key: key.clone(),
                commit_revision: revision,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(actual, context_refs);
    drop(held);
    let witnesses = (1..=8193)
        .map(|cursor| AnalysisWitnessV1 {
            identity: source.clone().into(),
            cursor,
            expires_utc_ns: 100,
        })
        .collect::<Vec<_>>();
    let scope = ProcessorScopeV1 {
        processor_id: "generic-proof".into(),
        method_version: 1,
        identity: source.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    let generic = store.commit_result(&AnalysisResultCommitV1 {
        scope: scope.clone(),
        expected_cursor: 0,
        consumed_cursor: 8193,
        coverage_revision: 0,
        context_revision: context_refs
            .first()
            .ok_or("context absent")?
            .commit_revision,
        result_id: "generic-provenance".into(),
        body: b"result".to_vec(),
        created_utc_ns: 1,
        witnesses: witnesses.clone(),
        context_refs: context_refs.clone(),
    })?;
    let generic = PackageResultRefV1 {
        result_id: "generic-provenance".into(),
        commit_revision: generic.commit_revision,
    };
    let held = store.view()?;
    let before = store.meta()?;
    for _ in 0..65 {
        let actual = held.processor_result(&scope)?.ok_or("generic result")?;
        assert_eq!(actual.result_id, generic.result_id);
        assert_eq!(actual.commit_revision, generic.commit_revision);
        assert_eq!(actual.body, b"result");
    }
    let mut foreign = scope.clone();
    foreign.identity.tenant_id = [9; 16];
    assert!(held.processor_result(&foreign)?.is_none());
    assert_eq!(store.meta()?, before);
    drop(held);
    retained(
        &store,
        std::slice::from_ref(&generic.result_id),
        &witnesses,
        &context_refs,
    )?;
    #[derive(serde::Deserialize)]
    struct Generic {
        request: AnalysisResultCommitV1,
    }
    let mut generic_id = None;
    for (key, bytes) in records(store.view()?.as_ref(), b"\0data/@progress/result/")? {
        if key.len() == b"\0data/@progress/result/".len() + 8 {
            let saved: Generic = rmp_serde::from_slice(&bytes[1..])?;
            assert_eq!(saved.request.witnesses, witnesses);
            assert_eq!(saved.request.context_refs, context_refs);
            generic_id = Some(u64::from_be_bytes(key[key.len() - 8..].try_into()?));
        }
    }
    pins(&store, generic_id.ok_or("generic record")?)?;
    let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    selection.contexts = araphor_data::Selection::Exact(keys);
    selection.results = vec![generic.result_id.clone()];
    let fixture = Fixture::new_scope(
        &store,
        "counter",
        "Retain independent call state.".into(),
        selection,
    )?;
    let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    let requests = AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
    let captured = store
        .read_managed_tables_filtered(
            &fixture.instance.grant.selection.project(&requests)?,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                expected: None,
                instance: fixture.instance.clone(),
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state;
    let mut input = request("retained-provenance");
    input.witness_expiry = 100;
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    #[derive(serde::Deserialize)]
    struct Capture {
        dependencies: Vec<PackageResultRefV1>,
    }
    #[derive(serde::Deserialize)]
    struct Attempt {
        capture: Capture,
    }
    let (_, bytes) = super::terminal::attempt_record(store.view()?.as_ref(), &input.id)?;
    let saved: Attempt = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(saved.capture.dependencies, [generic.clone()]);
    let evaluations = [
        fixture.continued(&input, 10, None)?,
        fixture.continued(&input, 11, None)?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let held = store.view()?;
    let current = fixture.current(&store)?;
    let before = store.meta()?;
    for _ in 0..65 {
        let actual = store.managed_result_at(
            &held,
            &current,
            &receipt.results[&10].result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(actual.result, receipt.results[&10]);
    }
    let mut foreign = current.clone();
    foreign.spec.tenant = [9; 16];
    assert!(store
        .managed_result_at(
            &held,
            &foreign,
            &receipt.results[&10].result_id,
            10,
            &AnalysisReadControl::default()
        )
        .is_err());
    assert_eq!(store.meta()?, before);
    drop(held);
    for reference in receipt
        .results
        .values()
        .chain(std::iter::once(&receipt.selected))
    {
        retained(
            &store,
            std::slice::from_ref(&reference.result_id),
            &witnesses,
            &context_refs,
        )?;
        let (key, _) = super::output::result_record(store.view()?.as_ref(), &reference.result_id)?;
        pins(&store, u64::from_be_bytes(key[7..].try_into()?))?;
    }
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source, 20)?
            .removed_records,
        0
    );
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/evidence/payload/")
        .next()
        .transpose()?
        .is_some());
    assert_eq!(
        store
            .source_status(&source)?
            .ok_or("source absent")?
            .retained_event_count,
        8193
    );
    let removed = store.remove_managed(&fixture.current(&store)?, || Ok(()))?;
    assert!(removed.removed);
    assert!(
        !store
            .managed_result(
                &removed,
                &receipt.results[&10].result_id,
                20,
                &AnalysisReadControl::default()
            )?
            .current
    );
    assert_eq!(
        store.managed_history(
            &removed.grant.selection,
            &removed.spec.id,
            &AnalysisReadControl::default()
        )?,
        [receipt.clone()]
    );
    let cut = store.meta()?.commit_revision;
    drop((attempt, captured, store));
    let store = AnalysisStore::open_with_retention(&root, retention)?;
    retained(
        &store,
        std::slice::from_ref(&receipt.results[&10].result_id),
        &witnesses,
        &context_refs,
    )?;
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source, 21)?
            .removed_records,
        0
    );
    assert_eq!(
        EvidenceRetentionOwner::new(&store)
            .retain(&source, 101)?
            .removed_records,
        8193
    );
    assert_eq!(
        store
            .source_status(&source)?
            .ok_or("source absent")?
            .retained_event_count,
        0
    );
    assert_eq!(
        store
            .read_at(cut)?
            .source_status(&source)?
            .ok_or("historical source")?
            .retained_event_count,
        8193
    );
    assert_eq!(std::fs::read_dir(root.join("segments"))?.count(), 0);
    retained(
        &store,
        &[
            generic.result_id.clone(),
            receipt.results[&10].result_id.clone(),
        ],
        &witnesses,
        &context_refs,
    )?;
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, retention)?;
    retained(
        &store,
        std::slice::from_ref(&receipt.results[&10].result_id),
        &witnesses,
        &context_refs,
    )?;
    assert_eq!(
        store
            .source_status(&source)?
            .ok_or("source absent")?
            .retained_event_count,
        0
    );
    assert_eq!(
        store
            .read_at(cut)?
            .source_status(&source)?
            .ok_or("historical source")?
            .retained_event_count,
        8193
    );
    assert_eq!(
        store.managed_history(
            &removed.grant.selection,
            &removed.spec.id,
            &AnalysisReadControl::default()
        )?,
        [receipt]
    );
    Ok(())
}
