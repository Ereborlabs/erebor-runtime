use super::*;

#[test]
fn source_reads_release_views() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store =
        AnalysisStore::open_with_retention(directory.path().join("store"), Default::default())?;
    SourceFixture::append(&store, 1, 3)?;
    let mut context = araphor_data::AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "source-cut".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: b"{}".to_vec(),
    };
    store.commit_context(&context)?;
    let fixture = SourceFixture {
        fixture: SourceFixture::admit(&store, AnalysisSelectionV1::tenant([1; 16]))?,
        execution: Arc::default(),
        requests: BTreeMap::from([
            ("events".into(), Some(SourceFixture::columns("events")?)),
            (
                "context_versions".into(),
                Some(SourceFixture::columns("context_versions")?),
            ),
        ]),
    };
    let first = fixture.read(
        &store,
        ManagedSourceRead::Initial,
        &AnalysisReadControl::default(),
    )?;
    let receipt = fixture.publish(&store, &first.state, "source-view")?;
    let instance = fixture.fixture.current(&store)?;
    let (reference, call, _) = store.managed_reference(
        &instance,
        &receipt.selected.result_id,
        10,
        &AnalysisReadControl::default(),
    )?;
    assert!(call.is_none());
    SourceFixture::append(&store, 4, 2)?;
    context.key.owner_revision = 2;
    store.commit_context(&context)?;
    let meta = store.meta()?;
    for case in 0..3 {
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        assert_eq!(
            store.context_head([1; 16], "source-cut", &[1], &[2])?,
            Some(context.clone())
        );
        let current = store.read_tables(
            &instance.grant.selection,
            AnalysisTableRead {
                requests: &fixture.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            current.tables["events"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            5
        );
        assert_eq!(
            current.tables["context_versions"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        let scope = instance
            .spec
            .destination
            .selection(&instance.grant.selection)?
            .project(&fixture.requests)?;
        let read = || AnalysisTableRead {
            requests: &fixture.requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: reference.request().time_utc_ns,
        };
        match case {
            0 => {
                let old = store.read_managed_reference(
                    &scope,
                    &reference,
                    read(),
                    AnalysisExtractLimits::default(),
                    &AnalysisReadControl::default(),
                    None,
                )?;
                let source = old.state.source().ok_or("historical source")?;
                assert_eq!(
                    source
                        .datasets()
                        .iter()
                        .map(sdk::Dataset::rows)
                        .collect::<Vec<_>>(),
                    [1, 3]
                );
                assert_eq!(
                    source.proof().ok_or("historical proof")?.as_ref(),
                    &receipt.selected
                );
            }
            1 => assert!(store
                .read_managed_reference(
                    &scope,
                    &reference,
                    read(),
                    AnalysisExtractLimits {
                        scan_bytes: 1,
                        ..Default::default()
                    },
                    &AnalysisReadControl::default(),
                    None,
                )
                .is_err()),
            _ => {
                let control = Arc::new(AnalysisReadControl::default());
                let cancelled = Arc::clone(&control);
                control.on_read_step(move || cancelled.cancel())?;
                assert!(matches!(
                    store.read_managed_reference(
                        &scope,
                        &reference,
                        read(),
                        AnalysisExtractLimits::default(),
                        &control,
                        None,
                    ),
                    Err(araphor_data::Error::AnalysisReadCancelled { .. })
                ));
            }
        }
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        assert_eq!(
            store.context_head([1; 16], "source-cut", &[1], &[2])?,
            Some(context.clone())
        );
        let current = store.read_tables(
            &instance.grant.selection,
            AnalysisTableRead {
                requests: &fixture.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            current.tables["events"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            5
        );
        assert_eq!(
            current.tables["context_versions"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        assert_eq!(store.meta()?, meta);
    }
    Ok(())
}

#[test]
fn source_references_project_context() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_retention(
        directory.path().join("store"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            raw_max_bytes: None,
        },
    )?;
    SourceFixture::append(&store, 1, 3)?;
    let mut context = araphor_data::AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "projection".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: b"first".to_vec(),
    };
    let first_context = store.commit_context(&context)?;
    let mut columns = SourceFixture::columns("context_versions")?;
    columns
        .insert(araphor_data::AnalysisStore::table_schemas()["context_versions"].index_of("body")?);
    let fixture = SourceFixture {
        fixture: SourceFixture::admit(&store, AnalysisSelectionV1::tenant([1; 16]))?,
        execution: Arc::default(),
        requests: BTreeMap::from([
            ("events".into(), Some(SourceFixture::columns("events")?)),
            ("context_versions".into(), Some(columns.clone())),
        ]),
    };
    let owners = BTreeSet::from(["projection".into(), "unused".into()]);
    let control = AnalysisReadControl::default();
    let initial =
        fixture.read_owners(&store, ManagedSourceRead::Initial, &control, Some(&owners))?;
    let parent_receipt = fixture.publish(&store, &initial.state, "project-parent")?;
    let parent_ref = SourceFixture::reference(&initial.state, &parent_receipt)?;
    let current = fixture.fixture.current(&store)?;
    let (parent, call, _) =
        store.managed_reference(&current, &parent_receipt.selected.result_id, 10, &control)?;
    assert!(call.is_none());
    SourceFixture::append(&store, 4, 2)?;
    context.key.owner_revision = 2;
    context.body = b"second".to_vec();
    let second_context = store.commit_context(&context)?;
    let next = fixture.read_owners(
        &store,
        ManagedSourceRead::Changes(parent_ref.clone()),
        &control,
        Some(&owners),
    )?;
    let frame = next.state.source().ok_or("before source frame")?;
    frame.check_before(&parent)?;
    assert!(initial
        .state
        .source()
        .ok_or("initial source frame")?
        .check_before(&parent)
        .is_err());
    let (parent_key, parent_bytes) =
        super::super::terminal::attempt_record(store.view()?.as_ref(), "project-parent")?;
    for fault in 0..9 {
        let mut saved: Value = rmp_serde::from_slice(&parent_bytes[1..])?;
        match fault {
            0 => {
                let Value::String(name) = field(&mut saved, &["receipt", "selected", "result_id"])?
                else {
                    return Err("selected name".into());
                };
                name.push_str("-foreign");
            }
            1 => {
                *field(&mut saved, &["capture", "revision"])? =
                    Value::U64(parent.captured_revision() + 1)
            }
            2 => {
                let mut tenant = [1u8; 16];
                tenant[0] ^= 1;
                *field(&mut saved, &["capture", "tenant"])? = serde_value::to_value(tenant)?;
            }
            3 => {
                let Value::String(name) = field(&mut saved, &["capture", "instance"])? else {
                    return Err("instance name".into());
                };
                name.push_str("-foreign");
            }
            4 => {
                *field(&mut saved, &["capture", "generation"])? =
                    Value::U64(parent.instance().generation + 1)
            }
            5 => match field(&mut saved, &["capture", "store"])? {
                Value::Bytes(bytes) => bytes.fill(0),
                Value::Seq(bytes) => bytes.iter_mut().for_each(|byte| *byte = Value::U8(0)),
                Value::String(value) => *value = uuid::Uuid::nil().to_string(),
                _ => return Err("store identity".into()),
            },
            6 => {
                *field(&mut saved, &["capture", "schema"])? =
                    Value::U32(parent.source_meta().schema_version + 1)
            }
            7 => *field(&mut saved, &["capture", "recovery"])? = Value::U64(0),
            _ => *field(&mut saved, &["capture", "recovery"])? = Value::U64(u64::MAX),
        }
        let mut transaction = store.write()?;
        transaction.native().insert(&parent_key, framed(&saved)?);
        transaction.commit([])?;
        let loaded = store.managed_attempt([1; 16], "counter", "project-parent", &control);
        match fault {
            2 | 3 => assert!(
                matches!(
                    loaded,
                    Err(araphor_data::Error::Package {
                        code: Code::Invalid,
                        field: "managed attempt key",
                        ..
                    })
                ),
                "before fault {fault}: {loaded:?}"
            ),
            4 => assert!(
                matches!(
                    loaded,
                    Err(araphor_data::Error::Package {
                        code: Code::Missing,
                        field: "managed version",
                        ..
                    })
                ),
                "before fault {fault}: {loaded:?}"
            ),
            _ => {
                let loaded = loaded?.ok_or("changed parent")?;
                assert!(
                    matches!(
                        frame.check_before(&loaded),
                        Err(araphor_data::Error::Package {
                            code: Code::Conflict,
                            field: "managed before owner",
                            ..
                        })
                    ),
                    "before fault {fault}"
                );
            }
        }
        let mut transaction = store.write()?;
        transaction.native().insert(&parent_key, &parent_bytes);
        transaction.commit([])?;
        frame.check_before(&parent)?;
    }
    let child_receipt = fixture.publish(&store, &next.state, "project-child")?;
    let current = fixture.fixture.current(&store)?;
    let (child, call, _) =
        store.managed_reference(&current, &child_receipt.selected.result_id, 10, &control)?;
    assert!(call.is_none());
    for receipt in [&parent_receipt, &child_receipt] {
        assert!(witnesses(&store, &receipt.selected)?.is_empty());
    }
    let (child_key, child_bytes) =
        super::super::terminal::attempt_record(store.view()?.as_ref(), "project-child")?;
    let original = [
        (parent_key.clone(), parent_bytes.clone()),
        (child_key.clone(), child_bytes.clone()),
    ];
    let removed =
        araphor_data::EvidenceRetentionOwner::new(&store).retain(&identity(), u64::MAX)?;
    assert_eq!(removed.removed_records, 5);
    let before = store.meta()?;
    let requests = BTreeMap::from([("context_versions".into(), Some(columns))]);
    let selection = current
        .spec
        .destination
        .selection(&current.grant.selection)?
        .project(&requests)?;
    let selected = BTreeSet::from(["projection".into()]);
    let old = store.read_managed_reference(
        &selection,
        &parent,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: parent.request().time_utc_ns,
        },
        AnalysisExtractLimits::default(),
        &control,
        Some(&selected),
    )?;
    let changed = store.read_managed_reference(
        &selection,
        &child,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Changes(parent_ref.position),
            now: child.request().time_utc_ns,
        },
        AnalysisExtractLimits::default(),
        &control,
        Some(&selected),
    )?;
    for (page, reference, version, revision, body) in [
        (&old, &parent, 1, first_context, b"first".as_slice()),
        (&changed, &child, 2, second_context, b"second".as_slice()),
    ] {
        assert_eq!(page.page.extraction.meta, reference.source_meta());
        assert!(page.page.extraction.sources.is_empty());
        assert!(!page.page.tables.contains_key("events"));
        let frame = page.state.source().ok_or("projected native source")?;
        assert_eq!(
            frame.position().commit_revision,
            reference.captured_revision()
        );
        assert_eq!(frame.position().ordinal, u32::MAX);
        assert_eq!(frame.selection(), &selection);
        assert_eq!(frame.projection(), &requests);
        assert_eq!(frame.datasets().len(), 1);
        let data = &frame.datasets()[0];
        assert_eq!(data.name, "context_versions");
        assert_eq!(data.rows(), 1);
        let batch = &data.batches[0];
        let owner = batch
            .column_by_name("owner_revision")
            .ok_or("context owner revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("context owner revision type")?;
        let committed = batch
            .column_by_name("commit_revision")
            .ok_or("context commit revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("context commit revision type")?;
        let value = batch
            .column_by_name("body")
            .ok_or("context body")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::BinaryArray>()
            .ok_or("context body type")?;
        assert_eq!(owner.value(0), version);
        assert_eq!(committed.value(0), revision);
        assert_eq!(value.value(0), body);
    }
    let old = old.state.source().ok_or("parent projected source")?;
    assert_eq!(old.read(), &ManagedSourceRead::Initial);
    assert_eq!(old.proof().map(Arc::as_ref), Some(&parent_receipt.selected));
    let changed = changed.state.source().ok_or("child projected source")?;
    assert_eq!(
        changed.read(),
        &ManagedSourceRead::Changes(parent_ref.clone())
    );
    assert_eq!(
        changed.proof().map(Arc::as_ref),
        Some(&child_receipt.selected)
    );
    let scope = current
        .spec
        .destination
        .selection(&current.grant.selection)?
        .project(&fixture.requests)?;
    let read = |mode, now| AnalysisTableRead {
        requests: &fixture.requests,
        event_ranges: None,
        mode,
        now,
    };
    let complete_error = store
        .read_managed_reference(
            &scope,
            &parent,
            read(AnalysisReadModeV1::Complete, parent.request().time_utc_ns),
            AnalysisExtractLimits::default(),
            &control,
            Some(&owners),
        )
        .err();
    assert!(
        matches!(
            &complete_error,
            Some(araphor_data::Error::RetainedRangeExpired { .. })
        ),
        "{complete_error:?}"
    );
    let changes_error = store
        .read_managed_reference(
            &scope,
            &child,
            read(
                AnalysisReadModeV1::Changes(parent_ref.position),
                child.request().time_utc_ns,
            ),
            AnalysisExtractLimits::default(),
            &control,
            Some(&owners),
        )
        .err();
    assert!(
        matches!(
            &changes_error,
            Some(araphor_data::Error::AnalysisReplayExpired { .. })
        ),
        "{changes_error:?}"
    );
    for (key, bytes) in original {
        assert_eq!(
            store.view()?.snapshot().get(key)?.as_deref(),
            Some(bytes.as_slice())
        );
    }
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.fixture.current(&store)?, current);
    Ok(())
}
