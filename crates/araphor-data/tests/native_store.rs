

use araphor_data::analysis::native::NativeStore;
use araphor_data::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, Error};
use fjall::SingleWriterTxDatabase;
use std::sync::Arc;

const HEAD: &[u8] = b"\0data/head";

fn cut(revision: u64) -> Vec<u8> {
    [b"\0data/cut/".as_slice(), &revision.to_be_bytes()].concat()
}

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn context(revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "native-test".into(),
            entity_key: vec![2],
            lifetime_key: vec![3],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![revision as u8],
    }
}

#[test]
fn context_retry_history_and_rollback() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let initial = store.view()?;
    assert_eq!(initial.revision(), 0);
    assert_eq!(store.read_at(0)?.revision(), 0);
    let mut aborted = store.write()?;
    aborted.context(&context(1), Some(0))?;
    aborted.rollback();
    assert_eq!(store.view()?.revision(), 0);
    assert!(store.write()?.commit([])?.is_none());
    assert!(NativeStore::open(&root).is_err());
    let first = context(1);
    let mut tx = store.write()?;
    let reference = tx.context(&first, Some(0))?;
    let first_revision = reference.commit_revision;
    assert_eq!(first_revision, 1);
    assert_eq!(reference.commit_revision, tx.revision());
    let receipt = tx.commit([])?.ok_or("empty context commit")?;
    assert!(initial.context(&first.key)?.is_none());
    let before = store.view()?;
    assert_eq!(
        before.context(&first.key)?,
        Some((first.clone(), reference.commit_revision))
    );
    assert_eq!(before.context_head(&first.key)?, Some(reference.clone()));
    let mut retry = store.write()?;
    assert_eq!(retry.context(&first, Some(0))?, reference);
    assert!(retry.commit([])?.is_none());
    assert_eq!(store.view()?.revision(), before.revision());
    assert_eq!(
        store.database().inner().journal_head()?,
        Some(receipt.cursor)
    );
    let mut different = first.clone();
    different.body.push(9);
    assert!(matches!(
        store.write()?.context(&different, None),
        Err(Error::AnalysisConflict { .. })
    ));
    let second = context(2);
    let mut aborted = store.write()?;
    aborted.context(&second, Some(1))?;
    aborted.native().insert(b"result", b"rolled back");
    aborted.native().insert(b"progress", b"rolled back");
    aborted.rollback();
    assert!(store.view()?.context(&second.key)?.is_none());
    assert!(store.view()?.snapshot().get(b"result")?.is_none());
    assert!(store.view()?.snapshot().get(b"progress")?.is_none());
    let mut tx = store.write()?;
    assert!(matches!(
        tx.context(&second, Some(0)),
        Err(Error::AnalysisConflict { .. })
    ));
    tx.rollback();
    let mut tx = store.write()?;
    tx.context(&second, Some(1))?;
    tx.commit([])?.ok_or("empty second commit")?;
    assert_eq!(before.context_head(&first.key)?, Some(reference));
    assert_eq!(
        store
            .read_at(before.revision())?
            .context(&first.key)?
            .map(|row| row.0),
        Some(first.clone())
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    let uuid = store.view()?.store_uuid();
    drop(before);
    drop(initial);
    drop(store);
    let reopened = NativeStore::open(&root)?;
    assert_eq!(reopened.view()?.store_uuid(), uuid);
    assert_eq!(
        reopened
            .read_at(first_revision)?
            .context(&first.key)?
            .map(|row| row.0),
        Some(first)
    );
    assert_eq!(
        reopened.view()?.context(&second.key)?.map(|row| row.0),
        Some(second)
    );
    Ok(())
}

#[test]
fn graph_context_progress_share_one_batch() -> TestResult {
    use araphor_graph::{
        native::{Declaration, Graph},
        EntityKind, Relation,
    };
    use araphor_analysis_sdk::Schema;
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("data"))?;
    let graph = Graph::new(11)?;
    let declaration = Declaration {
        relation: 31,
        shape: Relation {
            kind: EntityKind::Node,
            properties: Schema::empty(),
        },
        endpoints: None,
    };
    let mut feed = store
        .database()
        .inner()
        .journal_feed(store.database().inner().journal_head()?)?;
    let mut aborted = store.write()?;
    graph.install(aborted.native(), &[21], std::slice::from_ref(&declaration))?;
    aborted.context(&context(1), Some(0))?;
    aborted.native().insert(b"progress", b"10");
    aborted.rollback();
    assert!(feed.next_batch()?.is_none());
    let mut tx = store.write()?;
    graph.install(tx.native(), &[21], &[declaration])?;
    tx.context(&context(1), Some(0))?;
    tx.native().insert(b"progress", b"10");
    tx.native().insert(b"reference", b"source-10");
    let revision = tx.revision();
    let receipt = tx
        .commit([b"layer-cut".to_vec()])?
        .ok_or("empty joint commit")?;
    let batch = feed.next_batch()?.ok_or("joint batch absent")?;
    assert_eq!(batch.cursor, receipt.cursor);
    assert_eq!(batch.revision(), receipt.revision);
    assert!(feed.next_batch()?.is_none());
    assert!(batch
        .items
        .iter()
        .any(|item| item.key.starts_with(b"\0graph/f")));
    assert!(batch
        .items
        .iter()
        .any(|item| item.key.starts_with(b"\0data/C")));
    for key in [
        HEAD,
        b"progress",
        b"reference",
        b"layer-cut",
        &cut(revision),
    ] {
        assert!(batch.items.iter().any(|item| item.key.as_ref() == key));
    }
    let view = store.view()?;
    assert_eq!(view.revision(), revision);
    assert_eq!(
        view.snapshot().get(b"layer-cut")?.as_deref(),
        Some(receipt.revision.to_bytes().as_slice())
    );
    assert_eq!(
        view.snapshot().get(cut(revision))?.as_deref(),
        Some(receipt.revision.to_bytes().as_slice())
    );
    assert_eq!(
        store
            .read_at(revision)?
            .snapshot()
            .get(b"progress")?
            .as_deref(),
        Some(b"10".as_slice())
    );
    Ok(())
}

#[test]
fn readers_do_not_wait_for_writer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&dir.path().join("data"))?);
    let initial = store.view()?;
    let mut tx = store.write()?;
    tx.native().insert(b"value", b"next");
    let (send, receive) = std::sync::mpsc::channel();
    let reader = Arc::clone(&store);
    let handle = std::thread::spawn(move || send.send(reader.view()).unwrap());
    let captured = receive.recv_timeout(std::time::Duration::from_secs(5));
    tx.commit([])?;
    handle.join().map_err(|_| "reader panicked")?;
    let captured = captured??;
    assert_eq!(captured.revision(), initial.revision());
    assert!(captured.snapshot().get(b"value")?.is_none());
    assert_eq!(
        store.view()?.snapshot().get(b"value")?.as_deref(),
        Some(b"next".as_slice())
    );
    Ok(())
}

#[test]
fn long_context_keys_and_invalid_stamps() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut first = context(1);
    first.key.entity_key = vec![0xfe; 140_000];
    first.key.lifetime_key = vec![0xfd; 80_000];
    let mut tx = store.write()?;
    tx.context(&first, Some(0))?;
    tx.commit([])?;
    assert_eq!(
        store.view()?.context(&first.key)?.map(|row| row.0),
        Some(first.clone())
    );
    let mut second = first.clone();
    second.key.entity_key[70_000] = 1;
    let mut tx = store.write()?;
    tx.context(&second, Some(0))?;
    tx.commit([])?;
    assert_eq!(
        store.view()?.context(&second.key)?.map(|row| row.0),
        Some(second)
    );
    for row in store.view()?.snapshot().iter() {
        assert!(row?.0.len() <= u16::MAX as usize);
    }
    let count = store.view()?.snapshot().prefix(b"\0data/key/").count();
    let mut invalid = context(1);
    invalid.key.entity_key = vec![9];
    let mut tx = store.write()?;
    assert!(matches!(
        tx.context(&invalid, Some(1)),
        Err(Error::AnalysisConflict { .. })
    ));
    tx.native().insert(b"other", b"committed");
    tx.commit([])?;
    assert_eq!(
        store.view()?.snapshot().prefix(b"\0data/key/").count(),
        count
    );
    let revision = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    let mut tx = store.write()?;
    tx.native().insert(b"lost", b"absent");
    assert!(tx
        .commit([b"duplicate".to_vec(), b"duplicate".to_vec()])
        .is_err());
    assert!(store.view().is_err());
    assert!(store.write().is_err());
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), revision);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.view()?.snapshot().get(b"lost")?.is_none());
    assert!(store.write()?.commit([])?.is_none());
    Ok(())
}

#[test]
fn prior_native_format_is_rejected() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.view()?.snapshot().get(b"\0data/format")?.as_deref(),
        Some(10u64.to_be_bytes().as_slice())
    );
    let mut tx = store.branch().write_tx()?;
    tx.insert(b"\0data/format", 9u64.to_be_bytes());
    tx.commit_stamped([cut(0)])?;
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::NativeState {
            field: "format version",
            ..
        })
    ));
    Ok(())
}

#[test]
fn initialization_and_cut_recovery() -> TestResult {
    use std::os::unix::fs::DirBuilderExt as _;
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let db = SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    db.create_branch("data")?;
    drop(db);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), 0);
    assert_eq!(store.database().history()?.len(), 1);
    let initial_cut = store
        .view()?
        .snapshot()
        .get(cut(0))?
        .ok_or("initial cut absent")?;
    let mut tx = store.write()?;
    tx.context(&context(1), Some(0))?;
    tx.commit([])?;
    let mut tx = store.write()?;
    tx.native().insert(cut(1), initial_cut);
    tx.commit([])?;
    assert!(matches!(
        store.read_at(1),
        Err(Error::NativeState {
            field: "cut index revision",
            ..
        })
    ));
    // Catalogue commits can advance the native publication after the last Data write.
    let replacement = store
        .branch()
        .retain_history(store.view()?.snapshot().revision()..)?;
    let revision = store.view()?.revision();
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.revision(), revision);
    assert!(store.read_at(1).is_err());
    for policy in store.database().history()? {
        if policy.id != replacement {
            store.database().release_history(policy.id)?;
        }
    }
    assert_eq!(store.database().history()?.len(), 1);
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::NativeState {
            field: "required history protection",
            ..
        })
    ));
    Ok(())
}
