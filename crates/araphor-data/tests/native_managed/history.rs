use super::*;

#[test]
fn generations_keep_delayed_capture() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = Fixture::new(&store, [1; 16], "history", false)?;
    let admitted = fixture.admit(&store)?;
    let active =
        store.set_managed_running([1; 16], "history", admitted.lifecycle, true, || Ok(()))?;
    let captured = attempts::capture(&store, &active, false)?;
    let cut = captured.page.extraction.meta.commit_revision;
    let state = captured.state;
    drop(captured.page);
    for value in [1, 2] {
        let mut tx = store.write()?;
        tx.native().insert(b"history-preamble", [value]);
        tx.commit([])?;
    }
    store.checkpoint()?;
    let bytes = store
        .view()?
        .snapshot()
        .get(b"\0data/history-policy")?
        .ok_or("history policy")?;
    let id = fjall::RetentionId::from_bytes(bytes.as_ref().try_into()?);
    let policy = store
        .database()
        .history()?
        .into_iter()
        .find(|policy| policy.id == id)
        .ok_or("owned policy")?;
    let view = store.view()?;
    let (_, header) = view
        .snapshot()
        .prefix(b"\0data/@package/")
        .next()
        .ok_or("retained package")??;
    let (_, _, installed, _): (
        serde::de::IgnoredAny,
        serde::de::IgnoredAny,
        u64,
        serde::de::IgnoredAny,
    ) = rmp_serde::from_slice(&header[1..])?;
    assert_eq!(
        policy.first,
        store.read_at(installed)?.snapshot().revision()
    );
    assert!(policy.first <= store.read_at(admitted.generation)?.snapshot().revision());
    drop(view);
    let request = attempts::request("delayed", false);
    let attempt = store.register_managed_attempt(&state, &request, || Ok(()))?;
    assert_eq!(attempt.captured_revision(), cut);
    store.finish_managed(&attempt, araphor_data::ManagedExit::Cancelled, || Ok(()))?;
    let current = store
        .managed_instance([1; 16], "history", &AnalysisReadControl::default())?
        .ok_or("active instance")?;
    let stopped = store.stop_managed(&current, || Ok(()))?;
    let removed = store.remove_managed(&stopped, || Ok(()))?;
    store.checkpoint()?;
    assert_eq!(
        store.read_at(cut)?.managed_instance(
            [1; 16],
            "history",
            &AnalysisReadControl::default()
        )?,
        Some(active.clone())
    );
    let recreated = store.recreate_managed(&removed, &fixture.spec, &fixture.grant, || Ok(()))?;
    assert!(recreated.generation > admitted.generation);
    store.checkpoint()?;
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((state, attempt, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.read_at(cut)?.managed_instance(
            [1; 16],
            "history",
            &AnalysisReadControl::default()
        )?,
        Some(active)
    );
    assert_eq!(
        store.view()?.managed_version(
            [1; 16],
            "history",
            admitted.generation,
            &AnalysisReadControl::default()
        )?,
        fixture.spec
    );
    Ok(())
}
