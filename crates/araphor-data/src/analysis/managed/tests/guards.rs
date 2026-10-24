use super::*;

#[derive(Debug, PartialEq)]
struct GuardCut {
    meta: crate::AnalysisStoreMetaV1,
    instance: ManagedInstance,
    prior: Vec<(u64, u64, String)>,
    heads: Vec<(u64, u64, Option<String>)>,
    attempts: Vec<(String, Vec<u8>, u64)>,
    history: Vec<ManagedReceipt>,
    arrow: Vec<(String, String, u64, Vec<u8>)>,
    counts: [u64; 9],
}

impl GuardCut {
    fn read(store: &AnalysisStore, fixture: &Fixture) -> TestResult<Self> {
        let captured = fixture.capture(store, false)?;
        let prior = [10, 11]
            .into_iter()
            .filter_map(|call| {
                captured
                    .prior(call)
                    .map(|prior| (call, prior.revision, prior.result.clone()))
            })
            .collect();
        let (heads, attempts, arrow, counts) = store.read_snapshot(|reader| {
            let mut statement = reader.prepare(
                "SELECT call_id, state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? ORDER BY call_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed guard heads" })?;
            let rows = statement.query_map(params![[1u8; 16].as_slice(), fixture.instance.spec.id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            }).context(crate::AnalysisDatabaseSnafu { operation: "read managed guard heads" })?;
            let heads = rows.collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode managed guard heads" })?;
            let mut statement = reader.prepare(
                "SELECT attempt_id, contract, completed FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? ORDER BY attempt_id",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed guard attempts" })?;
            let rows = statement.query_map(params![[1u8; 16].as_slice(), fixture.instance.spec.id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            }).context(crate::AnalysisDatabaseSnafu { operation: "read managed guard attempts" })?;
            let attempts = rows.collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode managed guard attempts" })?;
            let mut statement = reader.prepare(
                "SELECT result_id, role, slot, ipc FROM managed_arrow ORDER BY result_id, role, slot",
            ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed guard payloads" })?;
            let rows = statement.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            }).context(crate::AnalysisDatabaseSnafu { operation: "read managed guard payloads" })?;
            let arrow = rows.collect::<duckdb::Result<Vec<_>>>()
                .context(crate::AnalysisDatabaseSnafu { operation: "decode managed guard payloads" })?;
            let counts = reader.query_row(
                "SELECT (SELECT count(*) FROM managed_versions), (SELECT count(*) FROM managed_instances), (SELECT count(*) FROM managed_calls), (SELECT count(*) FROM managed_attempts), (SELECT count(*) FROM analysis_results), (SELECT count(*) FROM managed_arrow), (SELECT count(*) FROM managed_edges), (SELECT count(*) FROM evidence_refs), (SELECT count(*) FROM context_refs)",
                [],
                |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?]),
            ).context(crate::AnalysisDatabaseSnafu { operation: "count managed guard rows" })?;
            Ok((heads, attempts, arrow, counts))
        })?;
        Ok(Self {
            meta: store.meta()?,
            instance: captured.instance().clone(),
            prior,
            heads,
            attempts,
            history: store.managed_history(
                &captured.instance().grant.selection,
                &captured.instance().spec.id,
                &AnalysisReadControl::default(),
            )?,
            arrow,
            counts,
        })
    }
}

#[test]
fn capture_checks_store_identity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("source");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let foreign = AnalysisStore::open(directory.path().join("foreign"))?;
    let other = Fixture::admit(&foreign)?;
    let mut receipts = Vec::new();
    for (store, fixture) in [(&store, &fixture), (&foreign, &other)] {
        let captured = fixture.capture(store, false)?;
        let input = request("seed");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        receipts.push(fixture.publish(
            store,
            &attempt,
            &[
                fixture.evaluation(&input, 10, Some(&captured))?,
                fixture.evaluation(&input, 11, Some(&captured))?,
            ],
            &[fixture.output(12)?, fixture.output(13)?],
        )?);
    }
    assert_eq!(receipts[0], receipts[1]);
    let captured = fixture.capture(&store, false)?;
    let original = GuardCut::read(&store, &fixture)?;
    let separate = GuardCut::read(&foreign, &other)?;
    assert_ne!(original.meta.store_uuid, separate.meta.store_uuid);
    assert_eq!(original.meta.schema_version, separate.meta.schema_version);
    assert_eq!(original.meta.recovery_epoch, separate.meta.recovery_epoch);
    assert_eq!(original.meta.commit_revision, separate.meta.commit_revision);
    assert_eq!(original.instance, separate.instance);
    assert_eq!(original.prior.len(), 2);
    assert_eq!(original.prior, separate.prior);
    assert_eq!(original.heads, separate.heads);
    assert_eq!(original.history, separate.history);
    assert_eq!(original.arrow, separate.arrow);
    assert_eq!(original.counts, separate.counts);
    let rejected = request("foreign-capture");
    assert!(matches!(
        foreign.register_managed_attempt(&captured, &rejected, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&foreign, &other)?, separate);
    assert_eq!(GuardCut::read(&store, &fixture)?, original);

    let input = request("pending");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(22)?, fixture.output(23)?];
    let pending = GuardCut::read(&store, &fixture)?;
    let backup = root.join("backups/identity");
    let manifest = store.backup(&backup)?;
    assert_eq!(GuardCut::read(&store, &fixture)?, pending);
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    let before = GuardCut::read(&restored, &fixture)?;
    assert_eq!(before.meta.store_uuid, pending.meta.store_uuid);
    assert_eq!(before.meta.schema_version, pending.meta.schema_version);
    assert_eq!(before.meta.commit_revision, pending.meta.commit_revision);
    assert_eq!(before.meta.recovery_epoch, manifest.recovery_epoch + 1);
    assert_eq!(manifest.recovery_epoch, pending.meta.recovery_epoch);
    assert_eq!(before.instance, pending.instance);
    assert_eq!(before.prior, pending.prior);
    assert_eq!(before.heads, pending.heads);
    assert_eq!(before.attempts, pending.attempts);
    assert_eq!(before.history, pending.history);
    assert_eq!(before.arrow, pending.arrow);
    assert_eq!(before.counts, pending.counts);
    let copied = restored
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored pending attempt")?;
    assert_eq!(copied.request(), attempt.request());
    assert_eq!(copied.instance(), attempt.instance());
    assert!(copied.receipt().is_none());
    assert!(copied.terminal().is_none());
    let rejected = request("stale-restore");
    assert!(restored
        .managed_attempt(
            [1; 16],
            "counter",
            &rejected.id,
            &AnalysisReadControl::default(),
        )?
        .is_none());
    assert!(matches!(
        restored.register_managed_attempt(&captured, &rejected, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);
    let error = fixture
        .publish(&restored, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("source live attempt published after restore")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);
    assert_eq!(GuardCut::read(&store, &fixture)?, pending);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    assert_eq!(fixture.current(&store)?.progress, receipt.commit_revision);
    assert_eq!(GuardCut::read(&restored, &fixture)?, before);

    let fresh = fixture.capture(&restored, false)?;
    let input = request("after-restore");
    let attempt = restored.register_managed_attempt(&fresh, &input, || Ok(()))?;
    let receipt = fixture.publish(
        &restored,
        &attempt,
        &[
            fixture.evaluation(&input, 10, Some(&fresh))?,
            fixture.evaluation(&input, 11, Some(&fresh))?,
        ],
        &[fixture.output(32)?, fixture.output(33)?],
    )?;
    assert_eq!(
        fixture.current(&restored)?.progress,
        receipt.commit_revision
    );
    assert_eq!(
        restored.managed_history(
            &fixture.instance.grant.selection,
            "counter",
            &AnalysisReadControl::default(),
        )?,
        vec![receipts.remove(0), receipt]
    );
    assert!(restored
        .managed_attempt(
            [1; 16],
            "counter",
            "pending",
            &AnalysisReadControl::default(),
        )?
        .ok_or("preserved restored pending attempt")?
        .receipt()
        .is_none());
    Ok(())
}
