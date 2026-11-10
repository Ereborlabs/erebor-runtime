use super::*;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisExtractLimits, AnalysisReadModeV1,
    AnalysisTableRead, AnalysisTableRequests, ContextSensitivityV1, EvidenceIntakeIdentityV1,
    EvidenceRecord, ManagedExit, ManagedFrontier, ManagedGraphOperation, ManagedPage, ManagedRead,
    ManagedRequest, ManagedSourceRead, PackageReadinessV1, ValidatedEvidenceBatchV1,
};

fn identity() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

pub(super) fn append(store: &NativeStore, cursor: u64) -> araphor_data::Result<()> {
    let framed_records = Vec::<u8>::try_from(&EvidenceRecord {
        task_cookie: cursor,
        observed_boottime_ns: cursor,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        identity(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: 100,
            frame_ends: vec![framed_records.len()],
            framed_records: framed_records.into(),
        },
    )?;
    Ok(())
}

pub(super) fn context(revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "native-context".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![3, 4],
    }
}

pub(super) fn capture(
    store: &NativeStore,
    instance: &ManagedInstance,
    follow: bool,
) -> araphor_data::Result<ManagedPage> {
    capture_completed(store, instance, follow, 0)
}

fn capture_completed(
    store: &NativeStore,
    instance: &ManagedInstance,
    follow: bool,
    completed: u64,
) -> araphor_data::Result<ManagedPage> {
    let selection = instance
        .spec
        .destination
        .selection(&instance.grant.selection)?;
    let requests: AnalysisTableRequests = ["events", "context_versions"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect();
    let selection = selection.project(&requests)?;
    store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            instance: instance.clone(),
            expected: None,
            rebuild: false,
            follow,
            source: Some(ManagedSourceRead::Initial),
            completed: Some(completed),
            execution: None,
        },
        AnalysisTableRead {
            requests: &requests,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

pub(super) fn request(id: &str, frontier: bool) -> ManagedRequest {
    ManagedRequest {
        id: id.into(),
        time_utc_ns: 1000,
        seed: None,
        rebuild: false,
        witness_expiry: 2000,
        frontier: frontier.then(|| ManagedFrontier {
            cursor: vec![1, 2, 3],
            next_change: None,
            pending: false,
        }),
    }
}

fn fixture(store: &NativeStore, id: &str) -> araphor_data::Result<ManagedInstance> {
    let mut fixture = Fixture::new(store, [1; 16], id, true)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let instance = fixture.admit(store)?;
    store.set_managed_running([1; 16], id, instance.lifecycle, true, || Ok(()))
}

#[test]
fn real_capture_claim_terminal_and_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = fixture(&store, "real")?;
    for cursor in 1..=3 {
        append(&store, cursor)?;
    }
    store.commit_contexts(&[context(1)])?;
    let captured = capture(&store, &instance, false)?;
    assert_eq!(
        captured.page.tables["events"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        3
    );
    assert_eq!(
        captured.page.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    let frame = captured.state.source().ok_or("source frame")?;
    for data in frame.datasets() {
        assert_eq!(&data.batches, &captured.page.tables[&data.name]);
    }
    assert_eq!(
        frame.position().commit_revision,
        captured.page.extraction.meta.commit_revision
    );
    let revision = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    let req = request("attempt", false);
    assert!(store
        .register_managed_attempt(&captured.state, &req, || Err(Code::Denied.error("guard")))
        .is_err());
    assert_eq!(store.view()?.revision(), revision);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let attempt = store.register_managed_attempt(&captured.state, &req, || Ok(()))?;
    assert_eq!(attempt.captured_revision(), revision);
    captured.state.check_current(&attempt)?;
    assert!(matches!(
        store.register_managed_attempt(&captured.state, &req, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let pending = store.view()?;
    let loaded = store
        .managed_attempt([1; 16], "real", "attempt", &AnalysisReadControl::default())?
        .ok_or("attempt")?;
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let before = store.view()?.revision();
    assert!(store
        .finish_managed(&attempt, ManagedExit::Cancelled, || Err(
            Code::Denied.error("guard")
        ))
        .is_err());
    assert_eq!(store.view()?.revision(), before);
    let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    assert!(terminal.revision > before);
    assert!(pending
        .managed_attempt([1; 16], "real", "attempt", &AnalysisReadControl::default())?
        .ok_or("pending")?
        .terminal()
        .is_none());
    let revision = store.view()?.revision();
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert_eq!(store.view()?.revision(), revision);
    let retried = store.register_managed_attempt(&captured.state, &req, || Ok(()))?;
    assert_eq!(retried.terminal(), Some(&terminal));
    drop(pending);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_attempt([1; 16], "real", "attempt", &AnalysisReadControl::default())?
            .ok_or("terminal")?
            .terminal(),
        Some(&terminal)
    );
    assert_eq!(
        store
            .managed_resume([1; 16], "real", &AnalysisReadControl::default())?
            .completed,
        terminal.revision
    );
    assert_eq!(
        store
            .view()?
            .managed_instance([1; 16], "real", &AnalysisReadControl::default())?
            .ok_or("instance")?
            .progress,
        0
    );
    Ok(())
}

#[test]
fn non_frontier_attempts_can_coexist() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let instance = fixture(&store, "parallel")?;
    append(&store, 1)?;
    let captured = capture(&store, &instance, false)?;
    let first =
        store.register_managed_attempt(&captured.state, &request("first", false), || Ok(()))?;
    let second =
        store.register_managed_attempt(&captured.state, &request("second", false), || Ok(()))?;
    assert!(matches!(
        store.register_managed_attempt(&captured.state, &request("frontier", true), || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    store.finish_managed(&first, ManagedExit::Cancelled, || Ok(()))?;
    let last = store.finish_managed(&second, ManagedExit::Cancelled, || Ok(()))?;
    let resume = store.managed_resume([1; 16], "parallel", &AnalysisReadControl::default())?;
    assert_eq!(resume.completed, last.revision);
    assert_eq!(resume.instance.progress, 0);
    Ok(())
}

#[test]
fn recovery_checks_historical_completion() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let instance = fixture(&store, "completed")?;
    append(&store, 1)?;
    let captured = capture(&store, &instance, false)?;
    let first =
        store.register_managed_attempt(&captured.state, &request("first", false), || Ok(()))?;
    let first = store.finish_managed(&first, ManagedExit::Cancelled, || Ok(()))?;
    let captured = capture_completed(&store, &instance, false, first.revision)?;
    let second =
        store.register_managed_attempt(&captured.state, &request("second", false), || Ok(()))?;
    let third =
        store.register_managed_attempt(&captured.state, &request("third", false), || Ok(()))?;
    store.finish_managed(&second, ManagedExit::Cancelled, || Ok(()))?;
    let third = store.finish_managed(&third, ManagedExit::Cancelled, || Ok(()))?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_resume([1; 16], "completed", &AnalysisReadControl::default())?
            .completed,
        third.revision
    );
    Ok(())
}

#[test]
fn restart_settles_only_frontiers_in_one_commit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let first = fixture(&store, "first")?;
    let second = fixture(&store, "second")?;
    append(&store, 1)?;
    let captured = capture(&store, &first, false)?;
    store.register_managed_attempt(&captured.state, &request("frontier", true), || Ok(()))?;
    store.register_managed_attempt(&captured.state, &request("manual", false), || Ok(()))?;
    let captured = capture(&store, &second, false)?;
    store.register_managed_attempt(&captured.state, &request("frontier", true), || Ok(()))?;
    let before = store.view()?.revision();
    drop(store);
    let store = NativeStore::open(&directory.path().join("store"))?;
    assert_eq!(store.view()?.revision(), before + 1);
    let control = AnalysisReadControl::default();
    let first = store
        .managed_attempt([1; 16], "first", "frontier", &control)?
        .ok_or("first")?;
    let second = store
        .managed_attempt([1; 16], "second", "frontier", &control)?
        .ok_or("second")?;
    assert_eq!(
        first.terminal().ok_or("first terminal")?.revision,
        second.terminal().ok_or("second terminal")?.revision
    );
    assert_eq!(
        first.terminal().ok_or("first terminal")?.exit,
        ManagedExit::Cancelled
    );
    assert!(store
        .managed_attempt([1; 16], "first", "manual", &control)?
        .ok_or("manual")?
        .terminal()
        .is_none());
    assert!(matches!(
        store.managed_resume([1; 16], "first", &control),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert_eq!(
        store
            .managed_resume([1; 16], "second", &control)?
            .instance
            .progress,
        0
    );
    let revision = store.view()?.revision();
    drop(store);
    let store = NativeStore::open(&directory.path().join("store"))?;
    assert_eq!(store.view()?.revision(), revision);
    Ok(())
}

#[test]
fn failure_frontier_resume_and_denied_suspension() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let instance = fixture(&store, "failed")?;
    append(&store, 1)?;
    let captured = capture(&store, &instance, false)?;
    let req = request("failed", true);
    let attempt = store.register_managed_attempt(&captured.state, &req, || Ok(()))?;
    let terminal = store.finish_managed(&attempt, ManagedExit::Failed(Code::Limit), || Ok(()))?;
    let resume = store.managed_resume([1; 16], "failed", &AnalysisReadControl::default())?;
    assert_eq!(resume.completed, terminal.revision);
    assert_eq!(resume.frontier, req.frontier);
    assert!(matches!(
        store
            .managed_status(
                &AnalysisSelectionV1::tenant([1; 16]),
                "failed",
                &AnalysisReadControl::default()
            )?
            .readiness,
        PackageReadinessV1::Failed {
            code: Code::Limit,
            ..
        }
    ));
    assert!(matches!(
        store.register_managed_attempt(&captured.state, &request("stale", false), || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    let instance = fixture(&store, "denied")?;
    let captured = capture(&store, &instance, false)?;
    let attempt =
        store.register_managed_attempt(&captured.state, &request("denied", true), || Ok(()))?;
    let terminal = store.finish_managed(&attempt, ManagedExit::Failed(Code::Denied), || Ok(()))?;
    assert!(terminal.suspended);
    let resume = store.managed_resume([1; 16], "denied", &AnalysisReadControl::default())?;
    assert!(!resume.instance.running);
    assert_eq!(resume.instance.lifecycle, terminal.revision);
    assert!(resume.frontier.is_none());
    drop(store);
    let store = NativeStore::open(&directory.path().join("store"))?;
    assert!(matches!(
        store
            .managed_status(
                &AnalysisSelectionV1::tenant([1; 16]),
                "denied",
                &AnalysisReadControl::default()
            )?
            .readiness,
        PackageReadinessV1::Failed {
            code: Code::Denied,
            ..
        }
    ));
    Ok(())
}

#[test]
fn freshness_uses_actual_sources_and_graph_follow_keeps_its_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let instance = fixture(&store, "stale")?;
    append(&store, 1)?;
    let captured = capture(&store, &instance, false)?;
    append(&store, 2)?;
    assert!(matches!(
        store.register_managed_attempt(&captured.state, &request("raw-stale", false), || Ok(())),
        Err(Error::AnalysisSourceChanged { .. })
    ));
    let captured = capture(&store, &instance, false)?;
    store.commit_contexts(&[context(1)])?;
    assert!(matches!(
        store.register_managed_attempt(
            &captured.state,
            &request("context-stale", false),
            || Ok(())
        ),
        Err(Error::AnalysisSourceChanged { .. })
    ));
    let mut fixture = Fixture::new(&store, [1; 16], "follow", true)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    fixture.spec.destination = ManagedDestination::Graph {
        source: identity(),
        events_sql: fixture.spec.definition.sql.clone(),
        control_sql: fixture.spec.definition.sql.clone(),
        calls: std::collections::BTreeSet::from([10]),
        operation: ManagedGraphOperation::Evaluate,
    };
    let instance = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], "follow", instance.lifecycle, true, || Ok(()))?;
    let captured = capture(&store, &instance, true)?;
    let cut = captured.page.extraction.meta.commit_revision;
    append(&store, 3)?;
    let attempt =
        store.register_managed_attempt(&captured.state, &request("follow", true), || Ok(()))?;
    assert_eq!(attempt.captured_revision(), cut);
    assert!(store.view()?.revision() > cut);
    let other = store
        .view()?
        .managed_instance([1; 16], "stale", &AnalysisReadControl::default())?
        .ok_or("instance")?;
    let captured = capture(&store, &other, false)?;
    store.stop_managed(&instance, || Ok(()))?;
    let other_attempt = store.register_managed_attempt(
        &captured.state,
        &request("unrelated-lifecycle", false),
        || Ok(()),
    )?;
    let captured = capture(&store, &other, false)?;
    store.stop_managed(&other, || Ok(()))?;
    assert!(matches!(
        store.register_managed_attempt(&captured.state, &request("stale-lifecycle", false), || Ok(
            ()
        )),
        Err(Error::AnalysisConflict { .. })
    ));
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    store.finish_managed(&other_attempt, ManagedExit::Cancelled, || Ok(()))?;
    Ok(())
}

#[test]
fn recovery_rejects_missing_attempt_indexes_and_old_format() -> TestResult {
    for prefix in [b"\0data/p".as_slice(), b"\0data/o", b"\0data/E"] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let instance = fixture(&store, "corrupt")?;
        append(&store, 1)?;
        let captured = capture(&store, &instance, false)?;
        let attempt =
            store
                .register_managed_attempt(&captured.state, &request("corrupt", false), || Ok(()))?;
        if prefix != b"\0data/p" {
            store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
        }
        let (key, _) = store
            .view()?
            .snapshot()
            .prefix(prefix)
            .next()
            .ok_or("index")??;
        let mut tx = store.write()?;
        tx.native().remove(key);
        tx.commit([])?;
        drop(store);
        assert!(NativeStore::open(&directory.path().join("store")).is_err());
    }
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let mut tx = store.write()?;
    tx.native().insert(b"\0data/format", 2u64.to_be_bytes());
    assert!(tx.commit([]).is_err());
    drop(store);
    assert!(NativeStore::open(&directory.path().join("store")).is_err());
    Ok(())
}

pub(super) fn field<'a>(
    value: &'a mut serde_value::Value,
    names: &[&str],
) -> Result<&'a mut serde_value::Value, Box<dyn std::error::Error>> {
    let mut current = value;
    for name in names {
        let serde_value::Value::Map(map) = current else {
            return Err("record map".into());
        };
        current = map
            .get_mut(&serde_value::Value::String((*name).into()))
            .ok_or("record field")?;
    }
    Ok(current)
}

#[test]
fn recovery_rejects_invalid_captured_contracts() -> TestResult {
    for changed in [
        "scope",
        "grant",
        "version",
        "lifecycle",
        "running",
        "sources",
        "contexts",
        "witnesses",
        "progress",
        "completed",
    ] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let instance = fixture(&store, "corrupt")?;
        append(&store, 1)?;
        store.commit_contexts(&[context(1)])?;
        let captured = capture(&store, &instance, false)?;
        store.register_managed_attempt(&captured.state, &request("corrupt", false), || Ok(()))?;
        let (key, bytes) = store
            .view()?
            .snapshot()
            .prefix(b"\0data/a")
            .next()
            .ok_or("attempt")??;
        assert_eq!(bytes[0], 0);
        use serde_value::Value;
        let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
        let capture = field(&mut record, &["capture"])?;
        *field(capture, &["contexts"])? = serde_value::to_value(
            captured
                .page
                .extraction
                .references
                .iter()
                .filter_map(|reference| reference.context())
                .collect::<Vec<_>>(),
        )?;
        *field(capture, &["witnesses"])? =
            serde_value::to_value(&captured.page.extraction.witnesses)?;
        match changed {
            "scope" => {
                let Value::Seq(tenant) = field(capture, &["grant", "selection", "tenant_id"])?
                else {
                    return Err("tenant".into());
                };
                tenant[0] = Value::U8(2);
            }
            "grant" => *field(capture, &["grant", "revision"])? = Value::U64(999),
            "version" => *field(capture, &["expected_generation"])? = Value::U64(0),
            "lifecycle" => *field(capture, &["lifecycle"])? = Value::U64(0),
            "running" => *field(capture, &["running"])? = Value::Bool(false),
            "sources" | "contexts" | "witnesses" => {
                let Value::Seq(values) = field(capture, &[changed])? else {
                    return Err("references".into());
                };
                values.push(values.first().ok_or("reference")?.clone());
            }
            "progress" => {
                *field(capture, &["progress"])? = Value::U64(1);
                *field(capture, &["completed"])? = Value::U64(1);
            }
            "completed" => *field(capture, &["completed"])? = Value::U64(1),
            _ => unreachable!(),
        }
        let mut tx = store.write()?;
        tx.native()
            .insert(key, [vec![0], rmp_serde::to_vec(&record)?].concat());
        tx.commit([])?;
        drop(store);
        assert!(
            NativeStore::open(&directory.path().join("store")).is_err(),
            "{changed}"
        );
    }
    Ok(())
}

#[test]
fn recovery_requires_saved_failure() -> TestResult {
    for code in [Code::Limit, Code::Denied] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let instance = fixture(&store, "failure")?;
        append(&store, 1)?;
        let captured = capture(&store, &instance, false)?;
        let attempt = store.register_managed_attempt(
            &captured.state,
            &request("failure", true),
            || Ok(()),
        )?;
        store.finish_managed(&attempt, ManagedExit::Failed(code), || Ok(()))?;
        let (key, _) = store
            .view()?
            .snapshot()
            .prefix(b"\0data/Y")
            .next()
            .ok_or("failure")??;
        let mut tx = store.write()?;
        tx.native().remove(key);
        tx.commit([])?;
        drop(store);
        assert!(
            NativeStore::open(&directory.path().join("store")).is_err(),
            "{code:?}"
        );
    }
    Ok(())
}
