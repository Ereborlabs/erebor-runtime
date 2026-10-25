use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn terminal_keeps_successful_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let mut first = request("complete");
    first.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: vec![1, 2, 3],
        next_change: Some(99),
    });
    let captured = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&captured, &first, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&first, 10, Some(&captured))?,
        fixture.evaluation(&first, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let prior = fixture.capture(&store, false)?;
    let failed = request("failed");
    let attempt = store.register_managed_attempt(&prior, &failed, || Ok(()))?;
    let before = store.meta()?;
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let exit = ManagedExit::Failed(Code::Invalid);
    let terminal = store.finish_managed(&attempt, exit, || Ok(()))?;
    assert!(terminal.revision > before.commit_revision);
    assert_eq!(terminal.instance, "counter");
    assert_eq!(terminal.attempt, failed.id);
    assert_eq!(terminal.exit, exit);
    assert!(!terminal.suspended);
    let ManagedResume {
        instance: current,
        frontier,
        ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(frontier, receipt.frontier);
    let after = fixture.capture(&store, false)?;
    for call in [10, 11] {
        let before = prior.prior(call).ok_or("prior call")?;
        let after = after.prior(call).ok_or("retained call")?;
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.result, before.result);
        let before = before.checkpoint.as_ref().ok_or("prior checkpoint")?;
        let after = after.checkpoint.as_ref().ok_or("retained checkpoint")?;
        assert_eq!(after.version, before.version);
        assert_eq!(after.datasets.len(), before.datasets.len());
        for (after, before) in after.datasets.iter().zip(&before.datasets) {
            assert_eq!(after.name, before.name);
            assert_eq!(after.batches, before.batches);
        }
    }
    assert!(store
        .managed_selected(
            [1; 16],
            "counter",
            &failed.id,
            &AnalysisReadControl::default()
        )?
        .is_none());
    let meta = store.meta()?;
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&attempt, exit, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert_eq!(store.meta()?, meta);
    assert!(matches!(
        store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(
        matches!(store.register_managed_attempt(&prior, &failed, || Ok(()))?.terminal(), Some(saved) if saved == &terminal)
    );
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs)
        .is_err());
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let saved = store
        .managed_attempt(
            [1; 16],
            "counter",
            &failed.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved terminal")?;
    assert_eq!(saved.terminal(), Some(&terminal));
    assert!(saved.receipt().is_none());
    let before = store.meta()?;
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&saved, exit, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert_eq!(store.finish_managed(&attempt, exit, || Ok(()))?, terminal);
    assert!(store
        .finish_managed(
            &saved,
            exit,
            || Err(Code::Denied.error("historical caller"))
        )
        .is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(
        store
            .managed_resume([1; 16], "counter", &AnalysisReadControl::default())?
            .frontier,
        receipt.frontier
    );
    assert!(store
        .managed_selected(
            [1; 16],
            "counter",
            &first.id,
            &AnalysisReadControl::default()
        )?
        .is_some());
    Ok(())
}

#[test]
fn unknown_claim_cannot_finish() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = request("pending");
    let original = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt")?;
    let before = store.meta()?;
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert_eq!(store.meta()?, before);
    let diagnostic = AnalysisReadControl::default();
    diagnostic.cancel()?;
    assert!(store
        .finish_managed(&original, ManagedExit::Cancelled, || diagnostic.check())
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    let terminal = store.finish_managed(&original, ManagedExit::Cancelled, || Ok(()))?;
    assert!(!terminal.suspended);
    let ManagedResume {
        instance: current,
        frontier,
        ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current.progress, 0);
    assert_eq!(frontier, None);
    assert_eq!(current.lifecycle, fixture.instance.lifecycle);
    assert!(!current.running);
    let captured = fixture.capture(&store, false)?;
    let input = request("recovered-pending");
    let original = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let before = store.meta()?;
    assert!(original
        .2
        .as_ref()
        .ok_or("live claim owner")?
        .has_changed()
        .is_ok());
    drop(store);
    assert!(original
        .2
        .as_ref()
        .ok_or("closed claim owner")?
        .has_changed()
        .is_err());
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, before);
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let error = fixture
        .publish(&store, &original, &evaluations, &outputs)
        .err()
        .ok_or("old live claim published after reopen")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert!(matches!(
        store.finish_managed(&original, ManagedExit::Cancelled, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    let loaded = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("recovered pending")?;
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert!(loaded.terminal().is_none());
    assert!(store
        .managed_resume([1; 16], "counter", &AnalysisReadControl::default())
        .is_err());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[test]
fn denied_exit_fences_lifecycle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store, false)?;
    let stale = store.register_managed_attempt(&captured, &request("stale"), || Ok(()))?;
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    let mut notices = store.subscribe_activations();
    let terminal = store.finish_managed(&stale, ManagedExit::Failed(Code::Denied), || Ok(()))?;
    assert!(!terminal.suspended);
    assert!(!notices.has_changed()?);
    let ManagedResume {
        instance: current, ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(current, restarted);
    let captured = fixture.capture(&store, false)?;
    let attempt = store.register_managed_attempt(&captured, &request("denied"), || Ok(()))?;
    let before = store.meta()?;
    assert!(store
        .finish_managed(&attempt, ManagedExit::Failed(Code::Denied), || Err(
            Code::Denied.error("diagnostic authority")
        ))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(!notices.has_changed()?);
    let terminal = store.finish_managed(&attempt, ManagedExit::Failed(Code::Denied), || Ok(()))?;
    assert!(terminal.suspended);
    assert!(notices.has_changed()?);
    assert_eq!(*notices.borrow_and_update(), terminal.revision);
    let ManagedResume {
        instance: current, ..
    } = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert!(!current.running);
    assert_eq!(current.lifecycle, terminal.revision);
    assert_eq!(current.generation, fixture.instance.generation);
    assert_eq!(current.progress, 0);
    assert!(store
        .active_managed(&AnalysisReadControl::default())?
        .1
        .is_empty());
    Ok(())
}

#[test]
fn recovery_checks_terminal_contract() -> TestResult {
    for fault in 0..5 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let capture = fixture.capture(&store, false)?;
        let attempt = store.register_managed_attempt(&capture, &request("corrupt"), || Ok(()))?;
        let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
        let mut saved = attempt.0.clone();
        saved.terminal = Some(terminal.clone());
        match fault {
            0 => saved.terminal.as_mut().ok_or("terminal")?.attempt = "different".into(),
            1 => saved.terminal.as_mut().ok_or("terminal")?.revision = saved.registered,
            2 => saved.terminal.as_mut().ok_or("terminal")?.suspended = true,
            3 => {
                saved.receipt = Some(ManagedReceipt {
                    frontier: None,
                    instance: "counter".into(),
                    attempt: "corrupt".into(),
                    commit_revision: terminal.revision,
                    selected: crate::analysis::PackageResultRefV1 {
                        result_id: "forged".into(),
                        commit_revision: terminal.revision,
                    },
                    results: BTreeMap::new(),
                })
            }
            _ => {}
        }
        let completed = if fault == 4 {
            terminal.revision - 1
        } else {
            terminal.revision
        };
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE managed_attempts SET contract = ?, completed = ?",
            params![serde_json::to_vec(&saved)?, completed],
        )?;
        drop(writer);
        drop(store);
        assert!(
            AnalysisStore::open(&root).is_err(),
            "terminal fault {fault}"
        );
    }
    Ok(())
}

fn native_request(id: &str) -> ManagedRequest {
    ManagedRequest {
        frontier: Some(ManagedFrontier {
            pending: false,
            cursor: id.as_bytes().to_vec(),
            next_change: Some(30),
        }),
        ..request(id)
    }
}

type TerminalRow = (Vec<u8>, String, String, Vec<u8>, u64);

fn terminal_rows(reader: &duckdb::Connection) -> crate::Result<Vec<TerminalRow>> {
    let mut statement = reader
        .prepare(
            "SELECT tenant_id, instance_id, attempt_id, contract, completed
         FROM managed_attempts ORDER BY tenant_id, instance_id, attempt_id",
        )
        .context(crate::AnalysisDatabaseSnafu {
            operation: "prepare startup terminal inventory",
        })?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .context(crate::AnalysisDatabaseSnafu {
            operation: "read startup terminal inventory",
        })?;
    rows.collect::<duckdb::Result<Vec<_>>>()
        .context(crate::AnalysisDatabaseSnafu {
            operation: "decode startup terminal inventory",
        })
}

#[test]
fn live_recovery_keeps_claim() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let captured = fixture.capture(&store, false)?;
    let input = native_request("live-recovery");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let before = store.meta()?;
    let lifecycle = store.subscribe_activations();
    store.recover()?;
    assert_eq!(store.meta()?, before);
    assert!(!lifecycle.has_changed()?);
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .ok_or("live recovered intent")?
            .terminal(),
        None
    );
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
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
    assert_eq!(receipt.commit_revision, before.commit_revision + 1);
    assert_eq!(receipt.results.len(), 2);
    assert_eq!(receipt.frontier, input.frontier);
    assert_eq!(
        store
            .managed_resume([1; 16], "counter", &AnalysisReadControl::default())?
            .frontier,
        receipt.frontier
    );
    assert!(!lifecycle.has_changed()?);
    Ok(())
}

#[test]
fn startup_keeps_committed_state() -> TestResult {
    for stopped in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
        let captured = fixture.capture(&store, false)?;
        let input = native_request("committed");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        if !stopped {
            let captured = fixture.capture(&store, false)?;
            let failed =
                store.register_managed_attempt(&captured, &request("known-failure"), || Ok(()))?;
            store.finish_managed(&failed, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
        }
        let captured = fixture.capture(&store, false)?;
        let interrupted = native_request("interrupted");
        let pending = store.register_managed_attempt(&captured, &interrupted, || Ok(()))?;
        if stopped {
            store.set_managed_running(
                [1; 16],
                "counter",
                captured.instance().lifecycle,
                false,
                || Ok(()),
            )?;
        }
        let current = fixture.current(&store)?;
        let failure: Option<Vec<u8>> = store.read_snapshot(|reader| {
            reader
                .query_row("SELECT failure FROM managed_instances", [], |row| {
                    row.get(0)
                })
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "read startup failure fence",
                })
        })?;
        let prior = fixture.capture(&store, false)?;
        let frozen = receipt
            .results
            .values()
            .chain(std::iter::once(&receipt.selected))
            .map(|reference| store.frozen_result(&reference.result_id))
            .collect::<crate::Result<Vec<_>>>()?;
        let rows: (u64, u64) = store.read_snapshot(|reader| reader.query_row("SELECT (SELECT count(*) FROM analysis_results), (SELECT count(*) FROM managed_arrow)", [], |row| Ok((row.get(0)?, row.get(1)?))).context(crate::AnalysisDatabaseSnafu { operation: "read startup output fence" }))?;
        let before = store.meta()?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        let mut expected = before.clone();
        expected.commit_revision += 1;
        assert_eq!(store.meta()?, expected);
        assert_eq!(fixture.current(&store)?, current);
        let loaded = store
            .managed_attempt(
                [1; 16],
                "counter",
                &interrupted.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("settled interrupted output")?;
        assert_eq!(loaded.request(), &interrupted);
        assert_eq!(loaded.instance(), pending.instance());
        assert!(loaded.receipt().is_none());
        let terminal = loaded.terminal().ok_or("startup cancellation")?;
        assert_eq!(terminal.exit, ManagedExit::Cancelled);
        assert!(!terminal.suspended);
        assert_eq!(terminal.revision, expected.commit_revision);
        let resume = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
        assert_eq!(resume.instance, current);
        assert_eq!(resume.frontier, receipt.frontier);
        assert_eq!(resume.completed, terminal.revision);
        let status = store.managed_status(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(status.instance, current);
        assert_eq!(status.status_progress, receipt.commit_revision);
        if stopped {
            assert!(matches!(
                status.readiness,
                crate::PackageReadinessV1::Inactive
            ));
        } else {
            assert!(matches!(
                status.readiness,
                crate::PackageReadinessV1::Failed {
                    code: Code::Invalid,
                    ..
                }
            ));
        }
        let retained_failure: Option<Vec<u8>> = store.read_snapshot(|reader| {
            reader
                .query_row("SELECT failure FROM managed_instances", [], |row| {
                    row.get(0)
                })
                .context(crate::AnalysisDatabaseSnafu {
                    operation: "read recovered failure fence",
                })
        })?;
        assert_eq!(retained_failure, failure);
        assert_eq!(
            store.managed_history(
                &current.grant.selection,
                "counter",
                &AnalysisReadControl::default()
            )?,
            std::slice::from_ref(&receipt)
        );
        assert_eq!(
            receipt
                .results
                .values()
                .chain(std::iter::once(&receipt.selected))
                .map(|reference| store.frozen_result(&reference.result_id))
                .collect::<crate::Result<Vec<_>>>()?,
            frozen
        );
        let after = fixture.capture(&store, false)?;
        for call in [10, 11] {
            let before = prior.prior(call).ok_or("committed call before startup")?;
            let after = after.prior(call).ok_or("committed call after startup")?;
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.result, before.result);
            let before = before
                .checkpoint
                .as_ref()
                .ok_or("committed checkpoint before startup")?;
            let after = after
                .checkpoint
                .as_ref()
                .ok_or("committed checkpoint after startup")?;
            assert_eq!(after.version, before.version);
            assert_eq!(after.datasets.len(), before.datasets.len());
            for (actual, expected) in after.datasets.iter().zip(&before.datasets) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.batches, expected.batches);
            }
            let result = store.managed_result(
                &current,
                &receipt.results[&call].result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(
                sdk::wire::Output::encode_model(&result.output, &fixture.model)?,
                sdk::wire::Output::encode_model(&outputs[(call - 10) as usize], &fixture.model)?
            );
            let evaluation = store.managed_evaluation(
                &current,
                &receipt.results[&call].result_id,
                &AnalysisReadControl::default(),
            )?;
            let original = &evaluations[(call - 10) as usize];
            assert_eq!(evaluation.context, original.context);
            assert_eq!(evaluation.parameters, original.parameters);
            assert_eq!(evaluation.inputs.len(), original.inputs.len());
            for (actual, expected) in evaluation.inputs.iter().zip(&original.inputs) {
                assert_eq!(actual.data.name, expected.data.name);
                assert_eq!(actual.data.batches, expected.data.batches);
                assert_eq!(actual.revision, expected.revision);
                assert_eq!(actual.coverage, expected.coverage);
            }
        }
        let retained_rows: (u64, u64) = store.read_snapshot(|reader| reader.query_row("SELECT (SELECT count(*) FROM analysis_results), (SELECT count(*) FROM managed_arrow)", [], |row| Ok((row.get(0)?, row.get(1)?))).context(crate::AnalysisDatabaseSnafu { operation: "read recovered output fence" }))?;
        assert_eq!(retained_rows, rows);
        store.verify_state()?;
        drop(store);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?, expected);
        assert_eq!(fixture.current(&store)?, current);
    }
    Ok(())
}

#[test]
fn startup_cancels_promoted_attempts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let current =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let spec = version::target(&store, &current, "Retain simultaneous candidate intents.")?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let captured = version::capture(&store, &current, &target, false)?;
    let inputs = [
        native_request("candidate-a"),
        native_request("candidate-b"),
        native_request("candidate-commit"),
    ];
    let attempts = inputs
        .iter()
        .map(|input| store.register_managed_attempt(&captured, input, || Ok(())))
        .collect::<crate::Result<Vec<_>>>()?;
    let evaluations = [
        fixture.evaluation(&inputs[2], 10, Some(&captured))?,
        fixture.evaluation(&inputs[2], 11, Some(&captured))?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempts[2],
        &evaluations,
        &[fixture.output(12)?, fixture.output(103)?],
    )?;
    let current = fixture.current(&store)?;
    assert_eq!(current.generation, target.generation);
    assert_ne!(
        current.generation,
        attempts[0].0.capture.expected_generation
    );
    assert!(current.running);
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let frozen = receipt
        .results
        .values()
        .chain(std::iter::once(&receipt.selected))
        .map(|reference| store.frozen_result(&reference.result_id))
        .collect::<crate::Result<Vec<_>>>()?;
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let mut expected = before.clone();
    expected.commit_revision += 2;
    assert_eq!(store.meta()?, expected);
    assert_eq!(fixture.current(&store)?, current);
    let mut revisions = BTreeSet::new();
    for (input, original) in inputs.iter().zip(&attempts).take(2) {
        let loaded = store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("settled promoted intent")?;
        let terminal = loaded.terminal().ok_or("promoted intent cancellation")?;
        assert_eq!(terminal.exit, ManagedExit::Cancelled);
        assert!(!terminal.suspended);
        assert!(loaded.receipt().is_none());
        assert!(revisions.insert(terminal.revision));
        let mut unchanged = original.0.clone();
        unchanged.terminal = Some(terminal.clone());
        assert_eq!(
            serde_json::to_vec(&loaded.0)?,
            serde_json::to_vec(&unchanged)?
        );
        assert_eq!(
            store.finish_managed(original, ManagedExit::Cancelled, || Ok(()))?,
            *terminal
        );
    }
    assert_eq!(
        revisions,
        BTreeSet::from([before.commit_revision + 1, before.commit_revision + 2])
    );
    let resume = store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(resume.instance, current);
    assert_eq!(resume.frontier, receipt.frontier);
    assert_eq!(resume.completed, expected.commit_revision);
    let status = store.managed_status(
        &current.grant.selection,
        "counter",
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(status.instance, current);
    assert_eq!(status.status_progress, receipt.commit_revision);
    assert!(matches!(status.readiness, crate::PackageReadinessV1::Ready));
    assert_eq!(
        store.managed_history(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(
        receipt
            .results
            .values()
            .chain(std::iter::once(&receipt.selected))
            .map(|reference| store.frozen_result(&reference.result_id))
            .collect::<crate::Result<Vec<_>>>()?,
        frozen
    );
    assert_eq!(
        *store.subscribe_revision().borrow(),
        expected.commit_revision
    );
    store.verify_state()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, expected);
    assert_eq!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        resume
    );
    Ok(())
}

#[test]
fn startup_filters_generations() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let old_capture = fixture.capture(&store, false)?;
    let current = fixture.current(&store)?;
    let spec = version::target(&store, &current, "Promote one genuine target.")?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let capture = version::capture(&store, &current, &target, false)?;
    let commit = native_request("promote");
    let promoted = store.register_managed_attempt(&capture, &commit, || Ok(()))?;
    let old_input = native_request("old-native");
    let old = store.register_managed_attempt(&old_capture, &old_input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&commit, 10, Some(&capture))?,
        fixture.evaluation(&commit, 11, Some(&capture))?,
    ];
    let receipt = fixture.publish(
        &store,
        &promoted,
        &evaluations,
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let current = fixture.current(&store)?;
    let spec = version::target(&store, &current, "Keep this target prospective.")?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let capture = version::capture(&store, &current, &target, false)?;
    let prospective =
        store.register_managed_attempt(&capture, &native_request("prospective"), || Ok(()))?;
    let capture = fixture.capture(&store, false)?;
    let native =
        store.register_managed_attempt(&capture, &native_request("current-native"), || Ok(()))?;
    let unknown =
        store.register_managed_attempt(&capture, &request("current-unknown"), || Ok(()))?;
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    let mut expected = before.clone();
    expected.commit_revision += 1;
    assert_eq!(store.meta()?, expected);
    assert_eq!(fixture.current(&store)?, current);
    let settled = store
        .managed_attempt(
            [1; 16],
            "counter",
            &native.request().id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("settled current generation")?;
    assert_eq!(
        settled.terminal().ok_or("current cancellation")?.exit,
        ManagedExit::Cancelled
    );
    assert_eq!(
        settled.terminal().ok_or("current cancellation")?.revision,
        expected.commit_revision
    );
    for original in [&old, &prospective, &unknown] {
        let loaded = store
            .managed_attempt(
                [1; 16],
                "counter",
                &original.request().id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("preserved unknown intent")?;
        assert_eq!(
            serde_json::to_vec(&loaded.0)?,
            serde_json::to_vec(&original.0)?
        );
        assert!(loaded.terminal().is_none());
        assert!(loaded.receipt().is_none());
        assert!(matches!(
            store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
            Err(crate::Error::Package {
                code: Code::Incomplete,
                ..
            })
        ));
        assert!(matches!(
            store.finish_managed(original, ManagedExit::Cancelled, || Ok(())),
            Err(crate::Error::AnalysisConflict { .. })
        ));
    }
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &AnalysisReadControl::default()),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert!(matches!(
        store.prepare_managed_version(&current, &spec, || Ok(())),
        Err(crate::Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert_eq!(
        store.managed_history(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        [receipt]
    );
    assert_eq!(store.meta()?, expected);
    store.verify_state()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, expected);
    assert_eq!(fixture.current(&store)?, current);
    Ok(())
}

#[test]
fn startup_quota_is_atomic() -> TestResult {
    for limited in [0, 1, 2] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let fixture = Fixture::admit(&store)?;
        let image = store
            .package_image(
                [1; 16],
                "managed-fixture",
                Some("r1"),
                &AnalysisReadControl::default(),
            )?
            .ok_or("shared fixture image")?;
        store.install_package_image([2; 16], &image, || Ok(()))?;
        let mut spec = fixture.instance.spec.clone();
        spec.tenant = [2; 16];
        store.admit_definition([2; 16], &spec.definition, || Ok(()))?;
        let mut grant = fixture.instance.grant.clone();
        grant.selection.tenant_id = [2; 16];
        let peer = store.admit_managed(&spec, &grant, || Ok(()))?;
        for (index, instance) in [&fixture.instance, &peer].into_iter().enumerate() {
            let capture = version::capture(&store, instance, instance, false)?;
            let id = if index + 1 == limited {
                "q".repeat(1024)
            } else {
                format!("tenant-{index}")
            };
            store.register_managed_attempt(&capture, &native_request(&id), || Ok(()))?;
        }
        let before = store.meta()?;
        let contracts = store.read_snapshot(terminal_rows)?;
        let changed: u64 = store.read_snapshot(|reader| reader.query_row("SELECT last_changed_revision FROM relation_revisions WHERE relation_name = 'managed_attempts'", [], |row| row.get(0)).context(crate::AnalysisDatabaseSnafu { operation: "read startup relation fence" }))?;
        let usage = store.read_snapshot(|reader| {
            AnalysisStore::logical_usage(reader, if limited == 2 { [2; 16] } else { [1; 16] })
        })?;
        let cap = if limited == 0 { usage.0 } else { usage.1 } + 1;
        let limits = crate::StorageLimitsV1 {
            logical_max_bytes: (limited == 0).then_some(cap),
            tenant_max_bytes: (limited != 0).then_some(cap),
            ..Default::default()
        };
        drop(store);
        let error = AnalysisStore::open_with_limits(&root, Default::default(), limits)
            .err()
            .ok_or("startup bypassed logical quota")?;
        assert!(
            matches!(error, crate::Error::StorageCapacity { resource, .. } if resource == if limited == 0 { "global logical bytes" } else { "tenant logical bytes" })
        );
        let reader = AnalysisStore::open_native(
            &root.join("analysis.duckdb"),
            Default::default(),
            duckdb::AccessMode::ReadOnly,
        )?;
        assert_eq!(
            AnalysisStore::read_meta_from(&reader, &root.join("analysis.duckdb"))?,
            before
        );
        assert_eq!(terminal_rows(&reader)?, contracts);
        assert_eq!(reader.query_row("SELECT last_changed_revision FROM relation_revisions WHERE relation_name = 'managed_attempts'", [], |row| row.get::<_, u64>(0))?, changed);
        assert_eq!(
            AnalysisStore::logical_usage(&reader, if limited == 2 { [2; 16] } else { [1; 16] })?,
            usage
        );
        drop(reader);
        let store = AnalysisStore::open(&root)?;
        assert_eq!(store.meta()?.commit_revision, before.commit_revision + 2);
        assert_eq!(fixture.current(&store)?, fixture.instance);
        assert_eq!(
            store.managed_instance([2; 16], "counter", &AnalysisReadControl::default())?,
            Some(peer)
        );
        let after = store.read_snapshot(|reader| {
            AnalysisStore::logical_usage(reader, if limited == 2 { [2; 16] } else { [1; 16] })
        })?;
        assert!(if limited == 0 {
            after.0 > cap
        } else {
            after.1 > cap
        });
        if limited != 0 {
            let other = store.read_snapshot(|reader| {
                AnalysisStore::logical_usage(reader, if limited == 2 { [1; 16] } else { [2; 16] })
            })?;
            assert!(other.1 <= cap);
        }
        for (_, _, _, bytes, completed) in store.read_snapshot(terminal_rows)? {
            let attempt: model::Attempt = serde_json::from_slice(&bytes)?;
            assert_eq!(
                attempt.terminal.ok_or("quota retry cancellation")?.exit,
                ManagedExit::Cancelled
            );
            assert!(completed > before.commit_revision);
        }
        store.verify_state()?;
    }
    Ok(())
}

#[test]
fn startup_restores_native_intent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("source");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
        Ok(())
    })?;
    let captured = fixture.capture(&store, false)?;
    let input = native_request("before-backup");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let current = fixture.current(&store)?;
    let capture = fixture.capture(&store, false)?;
    let pending_input = native_request("live-through-backup");
    let pending = store.register_managed_attempt(&capture, &pending_input, || Ok(()))?;
    let pending_evaluations = [
        fixture.evaluation(&pending_input, 10, Some(&capture))?,
        fixture.evaluation(&pending_input, 11, Some(&capture))?,
    ];
    let frozen = receipt
        .results
        .values()
        .chain(std::iter::once(&receipt.selected))
        .map(|reference| store.frozen_result(&reference.result_id))
        .collect::<crate::Result<Vec<_>>>()?;
    let contracts = store.read_snapshot(terminal_rows)?;
    let before = store.meta()?;
    let changed: u64 = store.read_snapshot(|reader| reader.query_row("SELECT last_changed_revision FROM relation_revisions WHERE relation_name = 'managed_attempts'", [], |row| row.get(0)).context(crate::AnalysisDatabaseSnafu { operation: "read restore terminal fence" }))?;
    let usage = store.read_snapshot(|reader| AnalysisStore::logical_usage(reader, [1; 16]))?;
    let backup = root.join("backups/native-pending");
    let manifest = store.backup(&backup)?;
    assert_eq!(manifest.commit_revision, before.commit_revision);
    assert_eq!(manifest.recovery_epoch, before.recovery_epoch);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.read_snapshot(terminal_rows)?, contracts);
    assert!(pending
        .2
        .as_ref()
        .ok_or("source live backup claim")?
        .has_changed()
        .is_ok());

    let limited = directory.path().join("limited");
    let error = AnalysisStore::restore_with_limits(
        &backup,
        &limited,
        crate::StorageLimitsV1 {
            logical_max_bytes: Some(usage.0 + 1),
            ..Default::default()
        },
    )
    .err()
    .ok_or("restored settlement bypassed quota")?;
    assert!(matches!(
        error,
        crate::Error::StorageCapacity {
            resource: "global logical bytes",
            ..
        }
    ));
    assert!(limited.join("restore.pending").is_file());
    assert!(matches!(
        AnalysisStore::open(&limited),
        Err(crate::Error::AnalysisState { .. })
    ));
    let reader = AnalysisStore::open_native(
        &limited.join("analysis.duckdb"),
        Default::default(),
        duckdb::AccessMode::ReadOnly,
    )?;
    let failed = AnalysisStore::read_meta_from(&reader, &limited.join("analysis.duckdb"))?;
    let mut epoch = before.clone();
    epoch.recovery_epoch += 1;
    assert_eq!(failed, epoch);
    assert_eq!(terminal_rows(&reader)?, contracts);
    assert_eq!(reader.query_row("SELECT last_changed_revision FROM relation_revisions WHERE relation_name = 'managed_attempts'", [], |row| row.get::<_, u64>(0))?, changed);
    assert_eq!(AnalysisStore::logical_usage(&reader, [1; 16])?, usage);
    drop(reader);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.read_snapshot(terminal_rows)?, contracts);

    let target = directory.path().join("restored");
    let restored = AnalysisStore::restore(&backup, &target)?;
    let mut expected = epoch;
    expected.commit_revision += 1;
    assert_eq!(restored.meta()?, expected);
    assert!(!target.join("restore.pending").exists());
    assert_eq!(fixture.current(&restored)?, current);
    let recovered = restored
        .managed_attempt(
            [1; 16],
            "counter",
            &pending_input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored native intent")?;
    let terminal = recovered.terminal().ok_or("restored native cancellation")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    assert!(!terminal.suspended);
    assert_eq!(terminal.revision, expected.commit_revision);
    assert!(recovered.receipt().is_none());
    let mut retained = pending.0.clone();
    retained.terminal = Some(terminal.clone());
    assert_eq!(
        serde_json::to_vec(&recovered.0)?,
        serde_json::to_vec(&retained)?
    );
    let resumed = restored.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?;
    assert_eq!(resumed.instance, current);
    assert_eq!(resumed.frontier, receipt.frontier);
    assert_eq!(resumed.completed, terminal.revision);
    assert_eq!(
        restored.managed_history(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(
        receipt
            .results
            .values()
            .chain(std::iter::once(&receipt.selected))
            .map(|reference| restored.frozen_result(&reference.result_id))
            .collect::<crate::Result<Vec<_>>>()?,
        frozen
    );
    for (index, reference) in receipt.results.values().enumerate() {
        let result = restored.managed_result(
            &current,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(
            sdk::wire::Output::encode_model(&result.output, &fixture.model)?,
            sdk::wire::Output::encode_model(&outputs[index], &fixture.model)?
        );
        let evaluation = restored.managed_evaluation(
            &current,
            &reference.result_id,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(evaluation.context, evaluations[index].context);
        assert_eq!(evaluation.parameters, evaluations[index].parameters);
        assert_eq!(evaluation.inputs.len(), evaluations[index].inputs.len());
        for (actual, original) in evaluation.inputs.iter().zip(&evaluations[index].inputs) {
            assert_eq!(actual.data.name, original.data.name);
            assert_eq!(actual.data.batches, original.data.batches);
            assert_eq!(actual.revision, original.revision);
            assert_eq!(actual.coverage, original.coverage);
        }
    }
    let selected = restored
        .managed_selected(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored selected state")?;
    assert_eq!(selected.commit_revision, receipt.commit_revision);
    assert_eq!(selected.data.batches, outputs[0].datasets[0].batches);
    let error = fixture
        .publish(&restored, &pending, &pending_evaluations, &outputs)
        .err()
        .ok_or("foreign source claim published into restore")?;
    assert!(matches!(
        error.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(restored.meta()?, expected);
    assert_eq!(store.meta()?, before);
    assert_eq!(store.read_snapshot(terminal_rows)?, contracts);
    assert_eq!(fixture.current(&store)?, current);
    let source_pending = store
        .managed_attempt(
            [1; 16],
            "counter",
            &pending_input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("original source intent")?;
    assert_eq!(
        serde_json::to_vec(&source_pending.0)?,
        serde_json::to_vec(&pending.0)?
    );
    assert!(source_pending.terminal().is_none());
    let published = fixture.publish(
        &store,
        &pending,
        &pending_evaluations,
        &[fixture.output(22)?, fixture.output(33)?],
    )?;
    assert_eq!(published.commit_revision, before.commit_revision + 1);
    assert_eq!(published.results.len(), 2);
    assert_eq!(
        store
            .managed_resume([1; 16], "counter", &AnalysisReadControl::default())?
            .frontier,
        published.frontier
    );
    assert_eq!(restored.meta()?, expected);
    assert_eq!(fixture.current(&restored)?, current);
    assert_eq!(
        restored.managed_history(
            &current.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        std::slice::from_ref(&receipt)
    );
    restored.verify_state()?;
    store.verify_state()?;
    drop(restored);
    let restored = AnalysisStore::open(&target)?;
    assert_eq!(restored.meta()?, expected);
    assert_eq!(fixture.current(&restored)?, current);
    assert_eq!(
        restored.managed_resume([1; 16], "counter", &AnalysisReadControl::default())?,
        resumed
    );
    assert_eq!(
        receipt
            .results
            .values()
            .chain(std::iter::once(&receipt.selected))
            .map(|reference| restored.frozen_result(&reference.result_id))
            .collect::<crate::Result<Vec<_>>>()?,
        frozen
    );
    Ok(())
}
