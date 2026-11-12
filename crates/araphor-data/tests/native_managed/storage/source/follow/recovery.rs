use super::*;

#[test]
fn graph_origin_rejects_rebinding() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = FollowFixture::new(&store, true)?;
    let page = fixture.read(&store, true)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &FollowFixture::input(),
        || Ok(()),
    )?);
    let receipt = fixture.publish(&store, &attempt)?;
    FollowFixture::check_results(&fixture.source.fixture, &store, &receipt)?;
    let control = AnalysisReadControl::default();
    let view = store.view()?;
    let source = records(&view, b"\0data/@source/")?;
    let mapping = view
        .managed_graph([1; 16], "graph-prefix", &control)?
        .ok_or("Graph mapping")?;
    let key = [
        b"\0data/O".as_slice(),
        &mapping.writers[&13].to_be_bytes(),
        &receipt.commit_revision.to_be_bytes(),
    ]
    .concat();
    let bytes = view.snapshot().get(&key)?.ok_or("Graph origin")?.to_vec();
    #[derive(serde::Deserialize)]
    struct Origin {
        call: u64,
    }
    let original: Origin = rmp_serde::from_slice(&bytes[1..])?;
    assert_eq!(original.call, 13);
    let mut changed: Value = rmp_serde::from_slice(&bytes[1..])?;
    *field(&mut changed, &["call"])? = serde_value::to_value(10u64)?;
    let mut write = store.write()?;
    write
        .native()
        .insert(&key, [vec![0], rmp_serde::to_vec(&changed)?].concat());
    write.commit([])?;
    drop((page, attempt, view));
    let FollowFixture {
        source: retained, ..
    } = fixture;
    let SourceFixture {
        fixture, execution, ..
    } = retained;
    drop(execution);
    drop(store);
    let error = NativeStore::open(&root)
        .err()
        .ok_or("rebound Graph origin accepted")?;
    assert!(
        matches!(
            error,
            Error::Package {
                code: Code::Invalid,
                field: "managed Graph layer owner",
                ..
            }
        ),
        "{error:?}"
    );
    super::super::repair(&root, &key, &bytes)?;
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .view()?
            .snapshot()
            .get(&key)?
            .ok_or("repaired origin")?
            .as_ref(),
        bytes
    );
    assert_eq!(records(store.view()?.as_ref(), b"\0data/@source/")?, source);
    assert_eq!(
        store.graph_source([1; 16], &receipt.selected.result_id)?,
        Some(identity())
    );
    let saved = store
        .managed_attempt([1; 16], "graph-prefix", "graph-prefix", &control)?
        .ok_or("repaired attempt")?;
    assert_eq!(saved.receipt(), Some(&receipt));
    let current = fixture.current(&store)?;
    let result = store.managed_result(&current, &receipt.selected.result_id, 10, &control)?;
    assert_eq!(result.result, receipt.selected);
    assert_eq!(result.receipt, receipt);
    FollowFixture::check_results(&fixture, &store, &receipt)?;
    Ok(())
}
