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
