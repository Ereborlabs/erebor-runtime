use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type SourceState = (u32, u64, u64, u64, u64);

fn report(source: &EvidenceIntakeIdentityV1, revision: u64) -> ValidatedCoverageV1 {
    ValidatedCoverageV1 {
        identity: source.clone(),
        cpu_id: 1,
        revision,
        encoded_report: revision.to_be_bytes().to_vec(),
    }
}

fn position(revision: u64) -> StorePositionV1 {
    StorePositionV1 {
        commit_revision: revision,
        ordinal: u32::MAX,
    }
}

fn source_state(
    store: &AnalysisStore,
    source: &EvidenceIntakeIdentityV1,
    revision: u64,
) -> TestResult<Option<SourceState>> {
    Ok(store.read_snapshot(|reader| {
        reader.query_row(
            "SELECT cpu_id, contiguous_cursor, coverage_revision, retained_floor, commit_revision
             FROM source_versions WHERE stream_key = ? AND commit_revision <= ?
             ORDER BY commit_revision DESC LIMIT 1",
            params![source.key(), revision],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read test source history" })
    })?)
}

#[test]
fn source_receipts_keep_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    let source = crate::analysis::tests::identity();
    let registration = store.register_processor(
        &crate::ProcessorScopeV1 {
            processor_id: "source-history".into(),
            method_version: 1,
            identity: source.clone(),
        },
        crate::ProcessorClassV1::Optional,
        1,
    )?;
    assert!(registration > 0);
    assert_eq!(source_state(&store, &source, registration)?, None);
    store.accept_validated_coverage(report(&source, 7))?;
    let coverage = store.meta()?.commit_revision;
    assert!(coverage > registration);
    assert_eq!(source_state(&store, &source, registration)?, None);
    assert_eq!(
        source_state(&store, &source, coverage)?,
        Some((1, 0, 7, 0, coverage))
    );
    store.accept_validated_batch(
        source.clone(),
        crate::ValidatedEvidenceBatchV1 {
            cpu_id: 1,
            first_cursor: 1,
            last_cursor: 2,
            intake_utc_ns: 100,
            framed_records: b"ab".to_vec().into(),
            frame_ends: vec![1, 2],
        },
    )?;
    let accepted = store.meta()?.commit_revision;
    assert_eq!(
        source_state(&store, &source, accepted)?,
        Some((1, 2, 7, 0, accepted))
    );
    store.accept_validated_coverage(report(&source, 9))?;
    let updated = store.meta()?.commit_revision;
    assert_eq!(
        source_state(&store, &source, updated)?,
        Some((1, 2, 9, 0, updated))
    );
    store.accept_validated_coverage(report(&source, 9))?;
    assert_eq!(store.meta()?.commit_revision, updated);
    store.checkpoint()?;
    let expired = EvidenceRetentionOwner::new(&store).retain(&source, 201)?;
    assert_eq!(expired.removed_records, 2);
    assert_eq!(expired.retained_floor, 2);
    assert!(expired.commit_revision > updated);
    assert_eq!(
        source_state(&store, &source, expired.commit_revision)?,
        Some((1, 2, 9, 2, expired.commit_revision))
    );
    assert_eq!(
        source_state(&store, &source, coverage)?,
        Some((1, 0, 7, 0, coverage))
    );
    assert_eq!(
        source_state(&store, &source, accepted)?,
        Some((1, 2, 7, 0, accepted))
    );
    assert_eq!(
        source_state(&store, &source, updated)?,
        Some((1, 2, 9, 0, updated))
    );
    assert!(matches!(
        store.read_page(&source, 1),
        Err(crate::Error::RetainedRangeExpired { .. })
    ));
    drop(store);
    let reopened = AnalysisStore::open_with_limits(&root, limits, Default::default())?;
    assert_eq!(source_state(&reopened, &source, registration)?, None);
    assert_eq!(
        source_state(&reopened, &source, coverage)?,
        Some((1, 0, 7, 0, coverage))
    );
    assert_eq!(
        source_state(&reopened, &source, accepted)?,
        Some((1, 2, 7, 0, accepted))
    );
    assert_eq!(
        source_state(&reopened, &source, updated)?,
        Some((1, 2, 9, 0, updated))
    );
    let receipt = reopened
        .source_receipt(&source)?
        .ok_or("reopened source receipt")?;
    assert_eq!(
        (
            receipt.cpu_id,
            receipt.contiguous_cursor,
            receipt.coverage_revision,
            receipt.retained_floor
        ),
        (1, 2, 9, 2)
    );
    let versions = reopened.read_snapshot(|reader| {
        reader
            .query_row(
                "SELECT count(*) FROM source_versions WHERE stream_key = ?",
                params![source.key()],
                |row| row.get::<_, u64>(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "count test source history",
            })
    })?;
    assert_eq!(versions, 4);
    Ok(())
}

#[test]
fn source_history_rejects_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let source = crate::analysis::tests::identity();
    store.accept_validated_coverage(report(&source, 7))?;
    let first = store.meta()?.commit_revision;
    store.accept_validated_coverage(report(&source, 9))?;
    let mut writer = store.writer()?;
    AnalysisStore::validate_state(writer.get()?, &root)?;
    for mutation in [
        "UPDATE source_versions SET identity_json = '{}' WHERE commit_revision = ?",
        "UPDATE source_versions SET tenant_id = X'00' WHERE commit_revision = ?",
        "UPDATE source_versions SET cpu_id = 2 WHERE commit_revision = ?",
        "UPDATE source_versions SET contiguous_cursor = 1 WHERE commit_revision = ?",
        "UPDATE source_versions SET retained_floor = 1 WHERE commit_revision = ?",
        "UPDATE source_versions SET coverage_revision = 8 WHERE commit_revision = ?",
        "UPDATE source_versions SET commit_revision = 0 WHERE commit_revision = ?",
        "UPDATE source_versions SET commit_revision = 99 WHERE commit_revision = ?",
        "DELETE FROM source_versions WHERE commit_revision = ?",
    ] {
        let transaction = writer.get_mut()?.transaction()?;
        assert_eq!(
            transaction.execute(mutation, params![first])?,
            1,
            "{mutation}"
        );
        assert!(
            AnalysisStore::validate_state(&transaction, &root).is_err(),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    AnalysisStore::validate_state(writer.get()?, &root)?;
    Ok(())
}

#[test]
fn source_schema_requires_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let valid = Connection::open_in_memory()?;
    valid.execute_batch(AnalysisStore::SOURCE_SCHEMA)?;
    AnalysisStore::validate_source_schema(&valid, directory.path())?;
    for schema in [
        AnalysisStore::SOURCE_SCHEMA.replace("commit_revision DESC", "commit_revision ASC"),
        AnalysisStore::SOURCE_SCHEMA.replace(",\n    PRIMARY KEY (stream_key, commit_revision)", ""),
        AnalysisStore::SOURCE_SCHEMA.replace("cpu_id UINTEGER NOT NULL", "cpu_id UINTEGER"),
    ] {
        assert_ne!(schema, AnalysisStore::SOURCE_SCHEMA);
        let invalid = Connection::open_in_memory()?;
        invalid.execute_batch(&schema)?;
        assert!(AnalysisStore::validate_source_schema(&invalid, directory.path()).is_err());
    }
    Ok(())
}

#[test]
fn coverage_changes_keep_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = Arc::new(AnalysisStore::open(&root)?);
    let source = crate::analysis::tests::identity();
    let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    for revision in 1..=16 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let after = position(store.meta()?.commit_revision);
    for revision in 17..=22 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&store);
    let arrival = source.clone();
    *control.snapshot_step.lock().map_err(|_| "snapshot hook")? = Some(Box::new(move || {
        writer.accept_validated_coverage(report(&arrival, 23))?;
        Ok(())
    }));
    let first = store.coverage_changes(&selection, after, &control)?;
    assert_eq!(first.meta, before);
    assert_eq!(
        first
            .reports
            .iter()
            .map(|report| report.reference.revision)
            .collect::<Vec<_>>(),
        (17..=22).collect::<Vec<_>>()
    );
    for changed in &first.reports {
        assert_eq!(changed.reference.source, source);
        assert!(changed.reference.position > after);
        assert!(changed.reference.position.commit_revision <= before.commit_revision);
        assert_eq!(
            changed.encoded_report,
            changed.reference.revision.to_be_bytes()
        );
        assert_eq!(
            store.coverage_report(
                &selection,
                &changed.reference,
                &AnalysisReadControl::default()
            )?,
            *changed
        );
    }
    let next = store.coverage_changes(
        &selection,
        position(first.meta.commit_revision),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(next.reports.len(), 1);
    assert_eq!(next.reports[0].reference.revision, 23);
    let current = store.meta()?;
    store.accept_validated_coverage(report(&source, 23))?;
    assert_eq!(store.meta()?, current);
    assert!(store
        .coverage_changes(
            &selection,
            position(current.commit_revision),
            &AnalysisReadControl::default()
        )?
        .reports
        .is_empty());
    let reference = first.reports[0].reference.clone();
    let bytes = rmp_serde::to_vec_named(&reference)?;
    assert_eq!(
        rmp_serde::from_slice::<CoverageReportRef>(&bytes)?,
        reference
    );
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(
        reopened.coverage_changes(
            &selection,
            position(first.meta.commit_revision),
            &AnalysisReadControl::default()
        )?,
        next
    );
    assert_eq!(
        reopened.coverage_report(&selection, &reference, &AnalysisReadControl::default())?,
        first.reports[0]
    );
    let backup = root.join("backups/saved");
    reopened.backup(&backup)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(
        restored.coverage_report(&selection, &reference, &AnalysisReadControl::default())?,
        first.reports[0]
    );
    assert_eq!(
        restored
            .coverage_changes(
                &selection,
                position(first.meta.commit_revision),
                &AnalysisReadControl::default()
            )?
            .reports,
        next.reports
    );
    Ok(())
}

#[test]
fn coverage_changes_apply_scope() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let alpha = crate::analysis::tests::identity();
    let beta = EvidenceIntakeIdentityV1 {
        node_id: "node-b".into(),
        source_epoch: 2,
        ..alpha.clone()
    };
    let foreign = EvidenceIntakeIdentityV1 {
        tenant_id: [2; 16],
        ..alpha.clone()
    };
    for source in [&alpha, &beta, &foreign] {
        store.accept_validated_coverage(report(source, 1))?;
    }
    for source in [&beta, &foreign] {
        assert_eq!(
            store.writer()?.get_mut()?.execute(
                "UPDATE coverage SET report=? WHERE stream_key=?",
                params![Vec::<u8>::new(), source.key()]
            )?,
            1
        );
    }
    let mut selection = AnalysisSelectionV1::new(alpha.tenant_id, vec![alpha.clone()]);
    let selected =
        store.coverage_changes(&selection, position(0), &AnalysisReadControl::default())?;
    assert_eq!(selected.reports.len(), 1);
    assert_eq!(selected.reports[0].reference.source, alpha);
    let denied = AnalysisSelectionV1::new(alpha.tenant_id, vec![beta.clone()]);
    assert!(store
        .coverage_report(
            &denied,
            &selected.reports[0].reference,
            &AnalysisReadControl::default()
        )
        .is_err());
    selection.sources = Selection::Exact(Vec::new());
    assert!(store
        .coverage_changes(&selection, position(0), &AnalysisReadControl::default())?
        .reports
        .is_empty());
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE coverage SET report=? WHERE stream_key=?",
            params![report(&beta, 1).encoded_report, beta.key()]
        )?,
        1
    );
    selection.sources = Selection::All;
    let all = store.coverage_changes(&selection, position(0), &AnalysisReadControl::default())?;
    assert_eq!(
        all.reports
            .iter()
            .map(|report| &report.reference.source)
            .collect::<Vec<_>>(),
        [&alpha, &beta]
    );
    selection.nodes = vec![beta.node_id.clone()];
    let filtered =
        store.coverage_changes(&selection, position(0), &AnalysisReadControl::default())?;
    assert_eq!(filtered.reports, all.reports[1..]);
    Ok(())
}

#[test]
fn coverage_changes_reject_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let source = crate::analysis::tests::identity();
    let selection = AnalysisSelectionV1::tenant(source.tenant_id);
    store.accept_validated_coverage(report(&source, 1))?;
    let changed =
        store.coverage_changes(&selection, position(0), &AnalysisReadControl::default())?;
    let reference = &changed.reports[0].reference;
    for case in 0..4 {
        let mut invalid = reference.clone();
        match case {
            0 => invalid.source.node_id = "another-node".into(),
            1 => invalid.revision += 1,
            2 => invalid.position.ordinal += 1,
            _ => invalid.position.commit_revision += 1,
        }
        assert!(store
            .coverage_report(&selection, &invalid, &AnalysisReadControl::default())
            .is_err());
    }
    let before = store.meta()?;
    for (sql, parameters) in [
        (
            "UPDATE coverage SET report=? WHERE commit_revision=?",
            vec![
                duckdb::types::Value::Blob(Vec::new()),
                duckdb::types::Value::UBigInt(before.commit_revision),
            ],
        ),
        (
            "UPDATE coverage SET report=?,revision=0 WHERE commit_revision=?",
            vec![
                duckdb::types::Value::Blob(report(&source, 1).encoded_report),
                duckdb::types::Value::UBigInt(before.commit_revision),
            ],
        ),
        (
            "UPDATE coverage SET report=?,revision=1,ordinal=1 WHERE commit_revision=?",
            vec![
                duckdb::types::Value::Blob(report(&source, 1).encoded_report),
                duckdb::types::Value::UBigInt(before.commit_revision),
            ],
        ),
    ] {
        assert_eq!(
            store
                .writer()?
                .get_mut()?
                .execute(sql, duckdb::params_from_iter(parameters))?,
            1
        );
        assert!(store
            .coverage_changes(&selection, position(0), &AnalysisReadControl::default())
            .is_err());
    }
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE coverage SET revision=?,ordinal=0,commit_revision=? WHERE stream_key=?",
            params![1u64, before.commit_revision + 1, source.key()]
        )?,
        1
    );
    assert!(store
        .coverage_changes(&selection, position(0), &AnalysisReadControl::default())
        .is_err());
    let mut future = reference.clone();
    future.position.commit_revision += 1;
    assert!(store
        .coverage_report(&selection, &future, &AnalysisReadControl::default())
        .is_err());
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE coverage SET commit_revision=? WHERE stream_key=?",
            params![before.commit_revision, source.key()]
        )?,
        1
    );
    assert_eq!(
        store.coverage_changes(&selection, position(0), &AnalysisReadControl::default())?,
        changed
    );
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn coverage_changes_keep_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let source = crate::analysis::tests::identity();
    let selection = AnalysisSelectionV1::tenant(source.tenant_id);
    for revision in 1..=3 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let before = store.meta()?;
    let receipt = store.source_receipt(&source)?;
    let control = Arc::new(AnalysisReadControl::default());
    let cancel = Arc::clone(&control);
    control.on_read_step(move || cancel.cancel())?;
    assert!(store
        .coverage_changes(&selection, position(0), &control)
        .is_err());
    for after in [
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        position(before.commit_revision + 1),
    ] {
        assert!(store
            .coverage_changes(&selection, after, &AnalysisReadControl::default())
            .is_err());
    }
    assert_eq!(store.meta()?, before);
    assert_eq!(store.source_receipt(&source)?, receipt);
    assert_eq!(
        store
            .coverage_changes(&selection, position(0), &AnalysisReadControl::default())?
            .reports
            .len(),
        3
    );
    Ok(())
}

#[test]
fn coverage_changes_use_index() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let source = crate::analysis::tests::identity();
    for revision in 1..=16 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let after = store.meta()?.commit_revision;
    for revision in 17..=22 {
        store.accept_validated_coverage(report(&source, revision))?;
    }
    let changes = store.coverage_changes(
        &AnalysisSelectionV1::tenant(source.tenant_id),
        position(after),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(changes.reports.len(), 6);
    store.read_snapshot(|reader| {
        assert_index(reader, AnalysisStore::COVERAGE_CHANGES_SQL, params![after])?;
        for report in &changes.reports {
            assert_index(
                reader,
                AnalysisStore::COVERAGE_REPORT_SQL,
                params![report.reference.position.commit_revision],
            )?;
        }
        Ok(())
    })?;
    let error = store
        .writer()?
        .get_mut()?
        .execute(
            "INSERT INTO coverage SELECT stream_key,tenant_id,revision+1000,report,commit_revision,ordinal FROM coverage WHERE commit_revision=?",
            params![changes.reports[0].reference.position.commit_revision],
        )
        .err()
        .ok_or("the coverage commit was duplicated")?;
    assert!(error.to_string().contains("commit_revision"));
    Ok(())
}

fn assert_index(reader: &Connection, sql: &str, parameters: &[&dyn duckdb::ToSql]) -> Result<()> {
    let plan = reader
        .prepare(&format!("EXPLAIN ANALYZE {sql}"))
        .and_then(|mut statement| statement.query_row(parameters, |row| row.get::<_, String>(1)))
        .context(AnalysisDatabaseSnafu {
            operation: "inspect coverage change access path",
        })?;
    assert!(plan.contains("Index Scan"), "{plan}");
    Ok(())
}
