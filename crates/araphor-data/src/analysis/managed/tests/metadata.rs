use super::*;

fn evidence(
    store: &AnalysisStore,
    tenant: [u8; 16],
    ids: &[String],
) -> TestResult<(
    Vec<crate::AnalysisWitnessV1>,
    Vec<crate::AnalysisContextRefV1>,
)> {
    let mut selection = AnalysisSelectionV1::new(tenant, Vec::new());
    selection.results = ids.to_vec();
    let requests = AnalysisTableRequests::new();
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
    assert!(page.extraction.missing_results.is_empty());
    assert_eq!(
        page.extraction
            .references
            .iter()
            .filter_map(|reference| reference.result())
            .map(|reference| reference.result_id.clone())
            .collect::<BTreeSet<_>>(),
        ids.iter().cloned().collect()
    );
    let contexts = page
        .extraction
        .references
        .iter()
        .filter_map(|reference| reference.context())
        .cloned()
        .collect();
    Ok((page.extraction.witnesses, contexts))
}

fn witness_rows(store: &AnalysisStore, name: &str) -> TestResult<Vec<(u64, u64)>> {
    let view = store.view()?;
    let mut id = None;
    for entry in view.snapshot().prefix(b"\0data/X") {
        let (key, bytes) = entry?;
        if key.len() != 15 {
            continue;
        }
        assert_eq!(bytes.first(), Some(&0));
        let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
        if stored.id == name {
            id = Some(key[7..].to_vec());
            break;
        }
    }
    let id = id.ok_or("witness result")?;
    let raw = b"\0data/ref/raw/";
    let prefix = [raw.as_slice(), id.as_slice()].concat();
    let mut rows = Vec::new();
    for entry in view.snapshot().prefix(prefix) {
        let (key, bytes) = entry?;
        assert_eq!(key.len(), raw.len() + 24);
        assert_eq!(bytes.first(), Some(&0));
        let segment = &key[raw.len() + 8..raw.len() + 16];
        let expiry = &key[raw.len() + 16..];
        let deadline = u64::from_be_bytes(expiry.try_into()?);
        let ranges: Vec<(u64, u64)> = rmp_serde::from_slice(&bytes[1..])?;
        assert!(!ranges.is_empty());
        assert!(ranges.windows(2).all(|pair| pair[0].1 + 1 < pair[1].0));
        for (first, last) in ranges {
            assert!(first <= last);
            rows.extend((first..=last).map(|cursor| (cursor, deadline)));
        }
        let reverse = [
            b"\0data/ref/segment/".as_slice(),
            segment,
            id.as_slice(),
            expiry,
        ]
        .concat();
        assert_eq!(view.snapshot().get(reverse)?.as_deref(), Some(expiry));
    }
    rows.sort_unstable();
    Ok(rows)
}

#[test]
fn attempt_witnesses_keep_earliest() -> TestResult {
    for (deadline, reverse) in [(100, false), (300, true)] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let source = crate::analysis::tests::identity();
        let bytes = Vec::<u8>::try_from(&crate::EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        store.accept_validated_batch(
            source.clone(),
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 2,
                intake_utc_ns: 1,
                frame_ends: vec![bytes.len(), bytes.len() * 2],
                framed_records: [bytes.as_slice(), bytes.as_slice()].concat().into(),
            },
        )?;
        let context = crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "witness-fixture".into(),
                entity_key: vec![1],
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: vec![1],
        };
        let context_revision = store.commit_context(&context)?;
        let contexts = vec![crate::AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: context_revision,
        }];
        let scope = crate::ProcessorScopeV1 {
            processor_id: "witness-fixture".into(),
            method_version: 1,
            identity: source.clone(),
        };
        store.register_processor(&scope, crate::ProcessorClassV1::Optional, 1)?;
        let retained = crate::AnalysisResultCommitV1 {
            scope,
            expected_cursor: 0,
            consumed_cursor: 2,
            coverage_revision: 0,
            context_revision,
            result_id: "retained-witnesses".into(),
            body: vec![1],
            created_utc_ns: 5,
            witnesses: (1..=2)
                .map(|cursor| crate::AnalysisWitnessV1 {
                    identity: source.clone().into(),
                    cursor,
                    expires_utc_ns: 200,
                })
                .collect(),
            context_refs: contexts.clone(),
        };
        store.commit_result(&retained)?;
        let mut fixture = Fixture::admit(&store)?;
        let mut spec = fixture.instance.spec.clone();
        let mut grant = fixture.instance.grant.clone();
        spec.id = "witnesses".into();
        grant.selection = AnalysisSelectionV1::tenant(source.tenant_id);
        grant.selection.results = vec![retained.result_id.clone()];
        fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
        let tables = AnalysisTableRequests::from([("events".into(), Some(BTreeSet::new()))]);
        let control = AnalysisReadControl::default();
        let mut captured = store
            .read_managed_tables_filtered(
                &grant.selection.project(&tables)?,
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
                    requests: &tables,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &control,
                None,
            )?
            .state;
        assert_eq!(captured.contract.witnesses.len(), 4);
        assert_eq!(captured.contract.contexts, contexts);
        assert_eq!(
            captured
                .contract
                .witnesses
                .iter()
                .filter(|witness| witness.expires_utc_ns == 0)
                .count(),
            2
        );
        if reverse {
            captured.contract.witnesses.reverse();
        }
        let mut input = request("witness-union");
        input.witness_expiry = deadline;
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let expected = (1..=2)
            .map(|cursor| crate::AnalysisWitnessV1 {
                identity: source.clone().into(),
                cursor,
                expires_utc_ns: deadline.min(200),
            })
            .collect::<Vec<_>>();
        assert_eq!(attempt.0.capture.witnesses, expected);
        assert_eq!(attempt.request(), &input);
        assert!(attempt.0.capture.witnesses.windows(2).all(|pair| {
            (&pair[0].identity, pair[0].cursor) < (&pair[1].identity, pair[1].cursor)
        }));
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        let ids = receipt
            .results
            .values()
            .chain(std::iter::once(&receipt.selected))
            .map(|reference| reference.result_id.clone())
            .collect::<Vec<_>>();
        for id in &ids {
            assert_eq!(
                evidence(&store, source.tenant_id, std::slice::from_ref(id))?,
                (expected.clone(), contexts.clone())
            );
            let physical = witness_rows(&store, id)?;
            assert_eq!(physical, [(1, deadline.min(200)), (2, deadline.min(200))]);
        }
        let saved = store
            .managed_attempt(source.tenant_id, "witnesses", &input.id, &control)?
            .ok_or("committed witness attempt")?;
        let original = ManagedCodec::encode(&saved.0)?;
        let before = store.meta()?;
        let retried = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        assert_eq!(retried.receipt(), Some(&receipt));
        assert_eq!(ManagedCodec::encode(&retried.0)?, original);
        assert_eq!(store.meta()?, before);
        let mut changed = input.clone();
        changed.witness_expiry += 1;
        assert!(matches!(
            store.register_managed_attempt(&captured, &changed, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?, before);
        drop((retried, saved, attempt, captured, store));
        let store = AnalysisStore::open(&root)?;
        assert_eq!(
            store.managed_history(&grant.selection, "witnesses", &control)?,
            std::slice::from_ref(&receipt)
        );
        let reopened = store
            .managed_attempt(source.tenant_id, "witnesses", &input.id, &control)?
            .ok_or("reopened witness attempt")?;
        assert_eq!(ManagedCodec::encode(&reopened.0)?, original);
        for id in &ids {
            assert_eq!(
                evidence(&store, source.tenant_id, std::slice::from_ref(id))?,
                (expected.clone(), contexts.clone())
            );
        }
    }
    Ok(())
}
