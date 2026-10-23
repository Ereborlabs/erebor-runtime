use super::*;
use crate::PackageErrorCodeV1 as Code;

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
        let tables = AnalysisTableRequests::from([("events".into(), None)]);
        let control = AnalysisReadControl::default();
        let mut captured = store
            .read_managed_tables(
                &grant.selection,
                &ManagedRead {
                    expected: None,
                    instance: fixture.instance.clone(),
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &tables,
                    event_ranges: None,
                    inputs: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &control,
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
                store.package_evidence(source.tenant_id, std::slice::from_ref(id))?,
                (expected.clone(), contexts.clone())
            );
            let physical = store.read_snapshot(|reader| {
                let mut statement = reader
                    .prepare("SELECT durable_cursor, expires_utc_ns FROM evidence_refs WHERE ref_id = ? ORDER BY durable_cursor")
                    .context(crate::AnalysisDatabaseSnafu { operation: "prepare exact witness test" })?;
                let rows = statement.query_map(params![id], |row| {
                    Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
                }).context(crate::AnalysisDatabaseSnafu { operation: "read exact witness test" })?;
                rows.collect::<duckdb::Result<Vec<_>>>()
                    .context(crate::AnalysisDatabaseSnafu { operation: "decode exact witness test" })
            })?;
            assert_eq!(physical, [(1, deadline.min(200)), (2, deadline.min(200))]);
        }
        let saved = store
            .managed_attempt(source.tenant_id, "witnesses", &input.id, &control)?
            .ok_or("committed witness attempt")?;
        let original = serde_json::to_vec(&saved.0)?;
        let before = store.meta()?;
        let retried = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        assert_eq!(retried.receipt(), Some(&receipt));
        assert_eq!(serde_json::to_vec(&retried.0)?, original);
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
        assert_eq!(serde_json::to_vec(&reopened.0)?, original);
        for id in &ids {
            assert_eq!(
                store.package_evidence(source.tenant_id, std::slice::from_ref(id))?,
                (expected.clone(), contexts.clone())
            );
        }
    }
    Ok(())
}

#[test]
fn metadata_skips_prior_ipc() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let mut fixture = Fixture::admit(&store)?;
    let mut spec = fixture.instance.spec.clone();
    let mut grant = fixture.instance.grant.clone();
    spec.id = "metadata".into();
    grant.selection.contexts = crate::Selection::All;
    grant.selection.select_profiles(crate::Selection::All)?;
    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "metadata-fixture".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    let changed = store.commit_context(&context)?;
    let requests = AnalysisTableRequests::new();
    let page = store.read_managed_tables(
        &fixture.instance.grant.selection,
        &ManagedRead {
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
    )?;
    assert!(page.page.tables.is_empty());
    assert_eq!(page.page.extraction.references.len(), 1);
    let reference = page.page.extraction.references[0]
        .context()
        .ok_or("captured context")?;
    assert_eq!(reference.key, context.key);
    assert_eq!(reference.commit_revision, changed);
    let captured = page.state;
    let mut input = request("metadata");
    input.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: vec![1],
        next_change: None,
    });
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let selected = ManagedRead {
        expected: None,
        instance: fixture.current(&store)?,
        rebuild: false,
        completed: Some(receipt.commit_revision),
    };
    let mut selection = selected.instance.grant.selection.clone();
    selection.select_profiles(crate::Selection::Exact(Vec::new()))?;
    let tables = AnalysisTableRequests::from([("context_versions".into(), None)]);
    let before = store.meta()?;
    let stale = ManagedRead {
        expected: None,
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: Some(0),
    };
    assert!(matches!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &stale,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    let metadata = store.managed_dependency_revision(
        &selection,
        &tables,
        &selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(metadata, (before.clone(), changed));
    assert!(metadata.1 <= captured.revision());
    assert!(receipt.commit_revision > captured.revision());
    assert!(matches!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &selected,
            AnalysisExtractLimits {
                keys: Some(0),
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    let dependent = store.managed_dependency_revision(
        &selected.instance.grant.selection,
        &tables,
        &selected,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(dependent, (before.clone(), changed));
    {
        let mut writer = store.writer()?;
        let count = writer.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = ? WHERE role = 'checkpoint'",
            params![vec![0_u8, 1, 2, 3]],
        )?;
        assert_eq!(count, 2);
    }
    assert_eq!(
        store.managed_dependency_revision(
            &selection,
            &tables,
            &selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?,
        metadata
    );
    assert!(store
        .read_managed_tables(
            &selection,
            &selected,
            AnalysisTableRead {
                requests: &tables,
                event_ranges: None,
                inputs: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn metadata_fences_managed_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let tables = AnalysisTableRequests::new();
    let control = AnalysisReadControl::default();
    let mut selected = ManagedRead {
        expected: None,
        instance: fixture.instance.clone(),
        rebuild: false,
        completed: Some(0),
    };
    let read = |selected: &ManagedRead| {
        store.managed_dependency_revision(
            &selected.instance.grant.selection,
            &tables,
            selected,
            AnalysisExtractLimits::default(),
            &control,
        )
    };
    assert_eq!(read(&selected)?.1, 0);
    let active = store.set_managed_running(
        [1; 16],
        "counter",
        selected.instance.lifecycle,
        true,
        || Ok(()),
    )?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture generation",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.instance = active;
    let captured = fixture.capture(&store, false)?;
    let attempt =
        store.register_managed_attempt(&captured, &request("metadata-pending"), || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        read(&selected),
        Err(crate::Error::Package {
            code: Code::Conflict,
            field: "managed capture completion",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    selected.completed = Some(terminal.revision);
    assert_eq!(read(&selected)?.1, 0);
    let mut foreign = selected.instance.grant.selection.clone();
    foreign.tenant_id = [2; 16];
    assert!(matches!(
        store.managed_dependency_revision(
            &foreign,
            &tables,
            &selected,
            AnalysisExtractLimits::default(),
            &control
        ),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "managed capture scope",
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    Ok(())
}
