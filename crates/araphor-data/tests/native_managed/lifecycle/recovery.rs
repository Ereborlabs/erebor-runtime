use super::*;

#[test]
fn version_retry_preserves_mappings() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = Fixture::new(&store, [1; 16], "graph-version", true)?;
    let current = fixture.admit(&store)?;
    let mut spec = current.spec.clone();
    spec.manifest
        .calls
        .insert(11, spec.manifest.calls[&10].clone());
    let candidate = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    assert_ne!(candidate.generation, current.generation);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.prepare_managed_version(&current, &spec, || Ok(()))?,
        candidate
    );
    let view = store.view()?;
    let graph = view
        .managed_graph([1; 16], "graph-version", &AnalysisReadControl::default())?
        .ok_or("mapping")?;
    assert_eq!(graph.writers.len(), 2);
    let (key, _) = view
        .snapshot()
        .prefix(b"\0data/G")
        .next()
        .ok_or("mapping")??;
    let mut tx = store.write()?;
    tx.native().remove(key);
    tx.commit([])?;
    let cursor = store.database().inner().journal_head()?;
    assert!(store
        .prepare_managed_version(&current, &spec, || Ok(()))
        .is_err());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    drop((view, store));
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[test]
fn pending_work_allows_stop() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = fixture(&store, "pending-stop")?;
    let admitted = fixture.admit(&store)?;
    let running =
        store.set_managed_running([1; 16], "pending-stop", admitted.lifecycle, true, || Ok(()))?;
    let page = capture(&store, &running, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("stopped", false),
        || Ok(()),
    )?;
    let stopped = store.stop_managed(&running, || Ok(()))?;
    assert!(matches!(
        store.renew_managed(&stopped, &stopped.grant, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    let running =
        store.set_managed_running([1; 16], "pending-stop", stopped.lifecycle, true, || Ok(()))?;
    let page = capture(&store, &running, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("suspended", false),
        || Ok(()),
    )?;
    let suspended = store.suspend_managed(&running, || Ok(()))?;
    assert!(!suspended.running);
    assert!(matches!(
        store.remove_managed(&suspended, || Ok(())),
        Err(Error::AnalysisBusy { .. })
    ));
    store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
    drop((page, attempt, store));
    let store = NativeStore::open(&root)?;
    let running = store.set_managed_running(
        [1; 16],
        "pending-stop",
        suspended.lifecycle,
        true,
        || Ok(()),
    )?;
    let page = capture(&store, &running, None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("failed", false),
        || Ok(()),
    )?;
    store.finish_managed(&attempt, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    let removed = store.remove_managed(&running, || Ok(()))?;
    drop((page, attempt, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.managed_instance([1; 16], "pending-stop", &AnalysisReadControl::default())?,
        Some(removed)
    );
    Ok(())
}

#[test]
fn recovery_checks_current_heads() -> TestResult {
    for change in ["head", "progress"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = fixture(&store, "heads")?;
        let current = fixture.admit(&store)?;
        let page = capture(&store, &current, None)?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request("first", false),
            || Ok(()),
        )?;
        let first = publish(&store, &attempt, false)?;
        let current = store
            .managed_instance([1; 16], "heads", &AnalysisReadControl::default())?
            .ok_or("instance")?;
        let old = store.view()?;
        let page = capture(&store, &current, None)?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request("second", false),
            || Ok(()),
        )?;
        publish(&store, &attempt, false)?;
        let mut tx = store.write()?;
        if change == "head" {
            let (key, bytes) = old
                .snapshot()
                .prefix(b"\0data/Q")
                .next()
                .ok_or("old head")??;
            tx.native().insert(key, bytes);
        } else {
            let (key, bytes) = store
                .view()?
                .snapshot()
                .prefix(b"\0data/J")
                .next()
                .ok_or("instance")??;
            let (tenant, id, grant, generation, _, running, removed, lifecycle): (
                [u8; 16],
                String,
                PackageGrantV1,
                u64,
                u64,
                bool,
                bool,
                u64,
            ) = rmp_serde::from_slice(&bytes[1..])?;
            tx.native().insert(
                key,
                [
                    vec![0],
                    rmp_serde::to_vec(&(
                        tenant,
                        id,
                        grant,
                        generation,
                        first.commit_revision,
                        running,
                        removed,
                        lifecycle,
                    ))?,
                ]
                .concat(),
            );
        }
        tx.commit([])?;
        drop((old, page, attempt, store));
        assert!(NativeStore::open(&root).is_err(), "accepted stale {change}");
    }
    Ok(())
}
