use super::*;

#[test]
fn ordinary_watch_keeps_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut tx = store.write()?;
    tx.native().insert(b"history-point", [1]);
    tx.commit([])?;
    let first = store.view()?;
    let watch = store.subscribe_inputs_at(
        &first,
        &AnalysisSelectionV1::tenant([1; 16]),
        &requests("events"),
        None,
        &AnalysisReadControl::default(),
        &Budget,
    )?;
    let revision = first.revision();
    drop(first);
    let mut tx = store.write()?;
    let middle = tx.revision();
    tx.native().insert(b"history-point", [2]);
    tx.commit([])?;
    let mut tx = store.write()?;
    tx.native().insert(b"history-point", [3]);
    tx.commit([])?;
    store.checkpoint()?;
    assert_eq!(
        store
            .read_at(middle)?
            .snapshot()
            .get(b"history-point")?
            .as_deref(),
        Some([2].as_slice())
    );
    let previous = store.read_at(revision)?;
    assert!(matches!(
        store.subscribe_inputs_at(
            &previous,
            &AnalysisSelectionV1::tenant([1; 16]),
            &requests("events"),
            None,
            &AnalysisReadControl::default(),
            &Budget,
        ),
        Err(araphor_data::Error::AnalysisInputExpired { .. })
    ));
    drop(previous);
    assert_eq!(
        watch.position(),
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0
        }
    );
    drop(watch);
    store.checkpoint()?;
    assert!(matches!(
        store.read_at(middle),
        Err(araphor_data::Error::NativeStorage {
            source: fjall::Error::HistoryUnavailable(_, _),
            ..
        })
    ));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert!(store.read_at(middle).is_err());
    Ok(())
}
