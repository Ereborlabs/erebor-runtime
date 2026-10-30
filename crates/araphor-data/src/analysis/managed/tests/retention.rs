use super::*;

#[test]
fn retained_provenance_survives_expiry() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let retention = crate::RetentionLimitsV1 {
        raw_max_age_ns: Some(1),
        raw_max_bytes: Some(1024 * 1024),
    };
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    let source = crate::analysis::tests::identity();
    let frame = Vec::<u8>::try_from(&crate::EvidenceRecord {
        operation: 7,
        ..Default::default()
    })?;
    for first in (1..=8193u64).step_by(crate::EVIDENCE_BATCH_RECORDS) {
        let last = (first + crate::EVIDENCE_BATCH_RECORDS as u64 - 1).min(8193);
        let count = (last - first + 1) as usize;
        store.accept_validated_batch(
            source.clone(),
            crate::ValidatedEvidenceBatchV1 {
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
        .map(|index| crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "context".into(),
                entity_key: index.to_be_bytes().to_vec(),
                lifetime_key: b"lifetime".to_vec(),
                owner_revision: 1,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: b"context".to_vec(),
        })
        .collect::<Vec<_>>();
    let context_refs = store.commit_contexts(&contexts)?;
    let keys = contexts
        .iter()
        .map(|context| context.key.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        store.package_contexts(source.tenant_id, &keys)?,
        context_refs
    );
    let witnesses = (1..=8193)
        .map(|cursor| crate::AnalysisWitnessV1 {
            identity: source.clone().into(),
            cursor,
            expires_utc_ns: 100,
        })
        .collect::<Vec<_>>();
    let scope = crate::ProcessorScopeV1 {
        processor_id: "generic-proof".into(),
        method_version: 1,
        identity: source.clone(),
    };
    store.register_processor(&scope, crate::ProcessorClassV1::Optional, 1)?;
    let generic = store.commit_result(&crate::AnalysisResultCommitV1 {
        scope,
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
    let generic = crate::analysis::PackageResultRefV1 {
        result_id: "generic-provenance".into(),
        commit_revision: generic.commit_revision,
    };
    let mut ids = vec![generic.result_id.clone(); 65];
    assert_eq!(
        store.package_result_refs(source.tenant_id, &ids)?,
        vec![generic.clone(); 65]
    );
    assert_eq!(
        store.package_evidence(source.tenant_id, &ids)?,
        (witnesses.clone(), context_refs.clone())
    );
    assert!(store.package_result_refs([9; 16], &ids).is_err());
    assert_eq!(
        store.package_evidence([9; 16], &ids)?,
        (Vec::new(), Vec::new())
    );
    let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    selection.contexts = crate::Selection::Exact(keys);
    selection.results = vec![generic.result_id.clone()];
    let fixture = Fixture::admit_scope(&store, false, selection)?;
    let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
    let requests = AnalysisTableRequests::from([("events".into(), Some(BTreeSet::from([cursor])))]);
    let captured = store
        .read_managed_tables(
            &fixture.instance.grant.selection,
            &ManagedRead {
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
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?
        .state;
    assert_eq!(captured.contract.dependencies, vec![generic.clone()]);
    let mut input = request("retained-provenance");
    input.witness_expiry = 100;
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    ids.fill(receipt.results[&10].result_id.clone());
    assert_eq!(
        store.package_result_refs(source.tenant_id, &ids)?,
        vec![receipt.results[&10].clone(); 65]
    );
    assert_eq!(
        store.package_evidence(source.tenant_id, &ids)?,
        (witnesses.clone(), context_refs.clone())
    );
    assert!(store.package_result_refs([9; 16], &ids).is_err());
    assert_eq!(
        store.package_evidence([9; 16], &ids)?,
        (Vec::new(), Vec::new())
    );
    for reference in receipt
        .results
        .values()
        .chain(std::iter::once(&receipt.selected))
    {
        let counts = store.read_snapshot(|reader| {
            reader.query_row(
                "SELECT (SELECT count(*) FROM evidence_refs WHERE ref_id = ?), (SELECT count(*) FROM context_refs WHERE ref_id = ?), (SELECT count(*) FROM evidence_refs WHERE ref_id = ? AND expires_utc_ns = 100)",
                params![reference.result_id, reference.result_id, reference.result_id],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?, row.get::<_, u64>(2)?)),
            ).context(crate::AnalysisDatabaseSnafu { operation: "read retained reference counts" })
        })?;
        assert_eq!(counts, (8193, 257, 8193));
        assert_eq!(
            store.package_evidence(source.tenant_id, std::slice::from_ref(&reference.result_id))?,
            (witnesses.clone(), context_refs.clone())
        );
    }
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 20)?
            .removed_records,
        0
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
        vec![receipt.clone()]
    );
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    assert_eq!(
        store.package_evidence(source.tenant_id, &ids)?,
        (witnesses.clone(), context_refs.clone())
    );
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
            .retain(&source, 21)?
            .removed_records,
        0
    );
    assert_eq!(
        crate::EvidenceRetentionOwner::new(&store)
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
    let combined = [
        generic.result_id.clone(),
        receipt.results[&10].result_id.clone(),
    ];
    assert_eq!(
        store.package_evidence(source.tenant_id, &combined)?,
        (witnesses.clone(), context_refs.clone())
    );
    drop(store);
    let store = AnalysisStore::open_with_limits(&root, retention, Default::default())?;
    assert_eq!(
        store.package_evidence(source.tenant_id, &ids)?,
        (witnesses, context_refs)
    );
    assert_eq!(
        store.managed_history(
            &removed.grant.selection,
            &removed.spec.id,
            &AnalysisReadControl::default()
        )?,
        vec![receipt]
    );
    Ok(())
}
