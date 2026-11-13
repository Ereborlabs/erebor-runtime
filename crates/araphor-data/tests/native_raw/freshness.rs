use super::*;

fn head(store: &NativeStore, name: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let key = [b"\0data/relation/".as_slice(), name.as_bytes()].concat();
    let value = store.view()?.snapshot().get(key)?.ok_or("relation head")?;
    Ok(u64::from_be_bytes(value.as_ref().try_into()?))
}

#[test]
fn coverage_first_binding_survives_raw_tail_recovery() -> TestResult {
    for metadata in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("store"))?;
        let source = identity();
        store.accept_validated_coverage(coverage(&source, 1))?;
        let binding = store.view()?.revision();
        assert_eq!(head(&store, "source_bindings")?, binding);
        let native = store.database().inner().journal_head()?;
        store.accept_validated_batch(source.clone(), batch(1))?;
        let event = store.view()?.revision();
        assert_ne!(store.database().inner().journal_head()?, native);
        if metadata {
            let mut tx = store.write()?;
            tx.native().insert(b"ordinary", [1u8]);
            tx.commit([])?;
        }
        drop(store);
        let store = NativeStore::open(&directory.path().join("store"))?;
        let mut tx = store.write()?;
        tx.native().insert(b"continued", [1u8]);
        tx.commit([])?;
        assert_eq!(head(&store, "source_bindings")?, binding);
        assert_eq!(head(&store, "events")?, event);
    }
    Ok(())
}

#[test]
fn new_raw_tail_sources_advance_the_recovered_binding_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("store"))?;
    let first = identity();
    store.accept_validated_coverage(coverage(&first, 1))?;
    store.accept_validated_batch(first, batch(1))?;
    let mut second = identity();
    second.source_id = [4; 16];
    store.accept_validated_batch(second, batch(1))?;
    let binding = store.view()?.revision();
    drop(store);
    let store = NativeStore::open(&directory.path().join("store"))?;
    let mut tx = store.write()?;
    tx.native().insert(b"continued", [1u8]);
    tx.commit([])?;
    assert_eq!(head(&store, "source_bindings")?, binding);
    assert_eq!(head(&store, "events")?, binding);
    Ok(())
}
