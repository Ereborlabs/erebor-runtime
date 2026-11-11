use super::*;

#[test]
fn context_owner_filter_precedes_key_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let tenant = [1; 16];
    let context = |owner: &str, entity: u8| AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: owner.into(),
            entity_key: vec![entity],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![entity],
    };
    let unrelated = context("a-unrelated", 1);
    let unrelated_second = context("a-unrelated", 3);
    let policy = context("z-policy", 2);
    store.commit_context(&unrelated)?;
    store.commit_context(&unrelated_second)?;
    store.commit_context(&policy)?;
    let owners = BTreeSet::from(["z-policy".to_owned()]);
    let control = AnalysisReadControl::default();
    let columns =
        BTreeSet::from([AnalysisStore::table_schemas()["context_versions"].index_of("owner_id")?]);
    let requests = AnalysisTableRequests::from([("context_versions".into(), Some(columns))]);
    let mut exact = AnalysisSelectionV1::new(tenant, Vec::new());
    exact.contexts = Selection::Exact(vec![unrelated.key.clone(), policy.key.clone()]);
    for (scope, limits) in [
        (
            AnalysisSelectionV1::tenant(tenant),
            AnalysisExtractLimits {
                keys: Some(1),
                ..Default::default()
            },
        ),
        (exact, AnalysisExtractLimits::default()),
    ] {
        let page = store.read_tables_filtered(
            &scope.project(&requests)?,
            &scope,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 0,
            },
            limits,
            &control,
            Some(&owners),
        )?;
        assert_eq!(
            page.extraction
                .references
                .iter()
                .filter_map(|reference| reference.context())
                .map(|reference| &reference.key)
                .collect::<Vec<_>>(),
            [&policy.key]
        );
        let rows = &page.tables["context_versions"];
        assert_eq!(rows.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        let names = rows[0]
            .column_by_name("owner_id")
            .ok_or("owner_id is absent")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::StringArray>()
            .ok_or("owner_id is not text")?;
        assert_eq!(names.value(0), "z-policy");
    }
    Ok(())
}

#[test]
fn analysis_exact_builtin_selection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    store.enable_notification_owner()?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let key = AnalysisContextKeyV1 {
        tenant_id: [1; 16],
        owner_id: crate::NOTIFICATION_STATE_OWNER.into(),
        entity_key: vec![1],
        lifetime_key: vec![2],
        owner_revision: 1,
    };
    let mut exact = AnalysisSelectionV1::new([1; 16], Vec::new());
    exact.select_profiles(Selection::Exact(vec!["profile:exact".into()]))?;
    exact.select_graphs(Selection::Exact(vec!["graph:exact".into()]), None)?;
    exact.select_notifications(Selection::Exact(vec![key.clone()]))?;
    let requests = AnalysisTableRequests::from([
        ("behaviors".into(), None),
        ("graph_manifest".into(), None),
        ("notifications".into(), None),
    ]);
    let before = store.meta()?;
    for expanded in [false, true] {
        let mut scope = exact.clone();
        if expanded {
            scope.sources = Selection::All;
        }
        let mut selected = scope.project(&requests)?;
        let projected = selected.clone();
        let mut output =
            AnalysisExtractionV1::new(before.clone(), AnalysisExtractLimits::default());
        output.charge(selected.allocation_bytes())?;
        let bytes = output.input_bytes;
        let view = store.view()?;
        store.select_sources(&view, &mut selected, &mut output, &control)?;
        store.select_profiles(&view, &mut selected, &mut output, &control)?;
        store.select_graphs(&view, &mut selected, &mut output, &control)?;
        assert_eq!(selected.profiles(), &["profile:exact"]);
        assert_eq!(selected.graphs(), &["graph:exact"]);
        assert_eq!(selected.notification_keys(), std::slice::from_ref(&key));
        assert!(output.input_bytes >= selected.allocation_bytes());
        if !expanded {
            assert_eq!(selected, projected);
            assert_eq!(output.input_bytes, bytes);
        }
    }
    let relations = exact.source_revisions(7);
    for expected in ["context_versions", "analysis_results", "graph_findings"] {
        assert!(relations
            .iter()
            .any(|(name, revision)| name == expected && *revision == 7));
    }
    store.release_notification_owner();
    for mut selection in [AnalysisSelectionV1::new([1; 16], Vec::new()), exact] {
        let profiles = selection.profiles().to_vec();
        let graphs = selection.graphs().to_vec();
        let obligations = selection.notification_keys().to_vec();
        let mut output =
            AnalysisExtractionV1::new(before.clone(), AnalysisExtractLimits::default());
        let view = store.view()?;
        store.select_profiles(&view, &mut selection, &mut output, &control)?;
        store.select_graphs(&view, &mut selection, &mut output, &control)?;
        assert_eq!(selection.profiles(), profiles);
        assert_eq!(selection.graphs(), graphs);
        assert_eq!(selection.notification_keys(), obligations);
        assert_eq!(output.input_bytes, 0);
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn analysis_extract_selection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let identity = identity(1);
    for (cursor, received) in [(1, 10), (2, 30), (3, 20)] {
        store.accept_validated_batch(identity.clone(), batch(cursor, 1, received)?)?;
    }
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..identity.clone()
    };
    store.accept_validated_batch(foreign.clone(), batch(1, 1, 20)?)?;
    let before = store.meta()?;
    let mut selection = AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]);
    selection.received_from = Bound::Included(20);
    selection.received_until = Bound::Excluded(30);
    let fields = [(
        "events",
        &["tenant_id", "source_cursor", "received_utc_ns", "cpu_id"][..],
    )];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(page.extraction.meta, before);
    assert!(page.exhausted);
    assert_eq!(
        page.extraction.scanned_bytes,
        store
            .raw
            .lock()
            .map_err(|_| "raw lock poisoned")?
            .index
            .entries
            .values()
            .filter(|entry| entry.identity == identity && entry.commit.intake == 20)
            .map(|entry| entry.frame_bytes)
            .sum::<usize>()
    );
    assert_eq!(unsigned(&page, "events", "source_cursor")?, vec![3]);
    assert_eq!(unsigned(&page, "events", "received_utc_ns")?, vec![20]);
    assert_eq!(
        binary(&page, "events", "tenant_id")?,
        vec![identity.tenant_id.to_vec()]
    );
    let mut cpus = Vec::new();
    for batch in &page.tables["events"] {
        let values = batch
            .column_by_name("cpu_id")
            .ok_or("CPU column absent")?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or("CPU column is not UInt32")?;
        cpus.extend_from_slice(values.values());
    }
    assert_eq!(cpus, vec![0]);
    assert_eq!(page.extraction.projected_bytes, (5 + 16) + 9 + 9 + 5);
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 3);
    assert_eq!(store.meta()?, before);
    for (from, until) in [
        (Bound::Excluded(u64::MAX), Bound::Unbounded),
        (Bound::Unbounded, Bound::Excluded(0)),
        (Bound::Included(31), Bound::Included(30)),
    ] {
        selection.received_from = from;
        selection.received_until = until;
        let empty = read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(row_count(&empty, "events"), 0);
        assert_eq!(empty.extraction.scanned_bytes, 0);
    }
    selection.sources = Selection::Exact(Vec::new());
    let empty = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(row_count(&empty, "events"), 0);
    selection.sources = Selection::Exact(vec![foreign]);
    assert!(read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default()
    )
    .is_err());
    selection.sources = Selection::Exact(vec![identity.clone(), identity]);
    assert!(read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default()
    )
    .is_err());
    assert!(store.maintenance.try_write().is_ok());
    Ok(())
}

#[test]
fn extraction_keys_disabled_default() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = Selection::Exact(
        (0..=KEY_LIMIT)
            .map(|revision| AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision as u64,
            })
            .collect(),
    );
    assert!(selection.valid());
    let control = AnalysisReadControl::default();
    let fields = [("context_versions", &["body"][..])];
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Metadata,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(page.extraction.missing_contexts.len(), KEY_LIMIT + 1);
    assert_eq!(page.extraction.scanned_bytes, 0);
    assert!(page.exhausted);
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Metadata,
            AnalysisExtractLimits {
                keys: Some(KEY_LIMIT),
                ..Default::default()
            },
            &control,
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    Ok(())
}

#[test]
fn analysis_tenant_key_limits() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = identity(1);
    store.accept_validated_batch(first.clone(), batch(1, 1, 10)?)?;
    let mut selection = AnalysisSelectionV1::tenant(first.tenant_id);
    selection.contexts = Selection::Exact(
        (0..KEY_LIMIT - 1)
            .map(|revision| AnalysisContextKeyV1 {
                tenant_id: first.tenant_id,
                owner_id: "policy".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision as u64,
            })
            .collect(),
    );
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let fields = [
        ("events", &["source_cursor"][..]),
        ("context_versions", &["body"][..]),
    ];
    let limits = AnalysisExtractLimits {
        keys: Some(KEY_LIMIT),
        ..Default::default()
    };
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Metadata,
        limits,
        &control,
    )?;
    assert_eq!(page.extraction.sources.len(), 1);
    assert_eq!(page.extraction.missing_contexts.len(), KEY_LIMIT - 1);
    assert_eq!(page.extraction.scanned_bytes, 0);
    assert!(page.exhausted);
    let next = EvidenceIntakeIdentityV1 {
        source_id: [4; 16],
        ..first.clone()
    };
    store.accept_validated_batch(next, batch(1, 1, 20)?)?;
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Metadata,
            limits,
            &control
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    let page = read(
        &store,
        &selection,
        &fields,
        AnalysisReadModeV1::Metadata,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(page.extraction.sources.len(), 2);
    assert_eq!(page.extraction.missing_contexts.len(), KEY_LIMIT - 1);
    assert_eq!(page.extraction.scanned_bytes, 0);
    assert!(page.exhausted);
    let selection = AnalysisSelectionV1::tenant(first.tenant_id);
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits {
                input_bytes: size_of::<AnalysisSelectionV1>() - 1,
                ..Default::default()
            },
            &control
        ),
        Err(crate::Error::AnalysisInputTooLarge { .. })
    ));
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        read(
            &store,
            &selection,
            &fields,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &cancelled
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    let mut invalid = selection.clone();
    invalid.sources = Selection::Exact(vec![first.clone(), first.clone()]);
    assert!(!invalid.valid());
    let mut invalid = selection.clone();
    invalid.nodes = vec![first.node_id.clone(), first.node_id];
    assert!(!invalid.valid());
    let mut invalid = selection;
    invalid.nodes.push(String::new());
    assert!(!invalid.valid());
    Ok(())
}
