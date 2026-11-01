use super::*;

use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};
use sdk::arrow_array::{BinaryArray, StringArray};

type ContextRow = (String, u64, u64, Vec<u8>);

impl Journal {
    fn context(owner: &str, revision: u64) -> AnalysisContextVersionV1 {
        AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: owner.into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: revision.to_be_bytes().to_vec(),
        }
    }

    fn select_contexts(&mut self) {
        self.requests.insert(
            "context_versions".into(),
            Some(
                (0..AnalysisStore::table_schemas()["context_versions"]
                    .fields()
                    .len())
                    .collect(),
            ),
        );
    }

    fn context_rows(page: &AnalysisPositionPageV1) -> TestResult<Vec<ContextRow>> {
        let mut rows = Vec::new();
        for batch in page.tables.get("context_versions").into_iter().flatten() {
            let owners = batch
                .column_by_name("owner_id")
                .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                .ok_or("context owner absent")?;
            let versions = batch
                .column_by_name("owner_revision")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or("context version absent")?;
            let revisions = batch
                .column_by_name("commit_revision")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or("context commit absent")?;
            let bodies = batch
                .column_by_name("body")
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or("context body absent")?;
            for row in 0..batch.num_rows() {
                rows.push((
                    owners.value(row).into(),
                    versions.value(row),
                    revisions.value(row),
                    bodies.value(row).into(),
                ));
            }
        }
        Ok(rows)
    }
}

#[test]
fn context_changes_keep_cut() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = Arc::new(AnalysisStore::open(&root)?);
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    journal.select_contexts();
    store.commit_context(&Journal::context("delta-context", 1))?;
    let seed = Journal::frontier(&store)?;
    let mut future = Journal::context("delta-context", 2);
    future.valid_from_utc_ns = Some(100);
    future.valid_until_utc_ns = Some(200);
    let mut expired = Journal::context("delta-context", 3);
    expired.valid_from_utc_ns = Some(1);
    expired.valid_until_utc_ns = Some(2);
    let references = store.commit_contexts(&[future, expired])?;
    assert_eq!(references[0].commit_revision, references[1].commit_revision);
    let before = store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&store);
    *control.snapshot_step.lock().map_err(|_| "snapshot hook")? = Some(Box::new(move || {
        writer.commit_context(&Journal::context("delta-context", 4))?;
        Ok(())
    }));
    let first = journal.read(&store, seed, &control)?;
    assert!(Journal::rows(&first.page)?.is_empty());
    assert_eq!(first.page.extraction.meta, before);
    assert_eq!(
        Journal::context_rows(&first.page)?,
        [2u64, 3].map(|version| (
            "delta-context".into(),
            version,
            before.commit_revision,
            version.to_be_bytes().to_vec()
        ))
    );
    let delivered = first
        .page
        .extraction
        .references
        .iter()
        .filter_map(|reference| reference.context().cloned())
        .collect::<Vec<_>>();
    assert_eq!(delivered, references);
    assert_eq!(first.state.contract.contexts, references);
    let next = journal.read(
        &store,
        first.page.scanned_through,
        &AnalysisReadControl::default(),
    )?;
    let rows = Journal::context_rows(&next.page)?;
    assert_eq!(rows.iter().map(|row| row.1).collect::<Vec<_>>(), [4]);
    let before = store.meta()?;
    assert_eq!(
        store.commit_context(&Journal::context("delta-context", 4))?,
        before.commit_revision
    );
    assert_eq!(store.meta()?, before);
    let empty = journal.read(
        &store,
        next.page.scanned_through,
        &AnalysisReadControl::default(),
    )?;
    assert!(Journal::context_rows(&empty.page)?.is_empty());
    assert!(empty.page.extraction.references.is_empty());
    assert_eq!(store.meta()?, before);
    let instance = journal.fixture.current(&store)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let replay = journal.read(
        &reopened,
        first.page.scanned_through,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(Journal::context_rows(&replay.page)?, rows);
    assert_eq!(replay.state.contract.contexts, next.state.contract.contexts);
    assert_eq!(journal.fixture.current(&reopened)?, instance);
    Ok(())
}

#[test]
fn context_changes_apply_scope() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    journal.select_contexts();
    let seed = Journal::frontier(&store)?;
    let alpha = Journal::context("alpha", 1);
    let beta = Journal::context("beta", 1);
    let mut foreign = Journal::context("foreign", 1);
    foreign.key.tenant_id = [2; 16];
    store.commit_contexts(&[alpha.clone(), beta.clone(), foreign])?;
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET body=? WHERE owner_id=?",
            params![Vec::<u8>::new(), "foreign"]
        )?,
        1
    );
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET body=? WHERE owner_id=?",
            params![Vec::<u8>::new(), "beta"]
        )?,
        1
    );
    journal.owners = Some(BTreeSet::from(["alpha".into()]));
    let alpha_only = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&alpha_only.page)?
            .iter()
            .map(|row| row.0.as_str())
            .collect::<Vec<_>>(),
        ["alpha"]
    );
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET body=? WHERE owner_id=?",
            params![beta.body, "beta"]
        )?,
        1
    );
    journal.selection.contexts = crate::Selection::Exact(vec![alpha.key, beta.key.clone()]);
    let intersection = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&intersection.page)?,
        Journal::context_rows(&alpha_only.page)?
    );
    journal.owners = Some(BTreeSet::new());
    assert!(Journal::context_rows(
        &journal
            .read(&store, seed, &AnalysisReadControl::default())?
            .page
    )?
    .is_empty());
    journal.owners = None;
    journal.selection.contexts = crate::Selection::Exact(vec![beta.key]);
    let beta_only = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&beta_only.page)?
            .iter()
            .map(|row| row.0.as_str())
            .collect::<Vec<_>>(),
        ["beta"]
    );
    journal.selection.contexts = crate::Selection::Exact(vec![Journal::context("absent", 99).key]);
    assert!(Journal::context_rows(
        &journal
            .read(&store, seed, &AnalysisReadControl::default())?
            .page
    )?
    .is_empty());
    journal.selection.contexts = crate::Selection::Exact(Vec::new());
    assert!(Journal::context_rows(
        &journal
            .read(&store, seed, &AnalysisReadControl::default())?
            .page
    )?
    .is_empty());
    journal.selection.contexts = crate::Selection::All;
    let all = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&all.page)?
            .iter()
            .map(|row| row.0.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );
    let ordinary = store.read_tables_filtered(
        &journal.selection,
        AnalysisTableRead {
            requests: &journal.requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Changes(seed),
            now: 10,
        },
        journal.limits,
        &AnalysisReadControl::default(),
        None,
    )?;
    assert_eq!(
        Journal::context_rows(&ordinary)?,
        Journal::context_rows(&all.page)?
    );
    Ok(())
}

#[test]
fn context_changes_exact_keys() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    journal.select_contexts();
    let seed = Journal::frontier(&store)?;
    let contexts = (1..=6)
        .map(|version| Journal::context("exact-context", version))
        .collect::<Vec<_>>();
    let references = store.commit_contexts(&contexts)?;
    journal.selection.contexts = crate::Selection::Exact(
        contexts
            .into_iter()
            .rev()
            .map(|context| context.key)
            .collect(),
    );
    let changes = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&changes.page)?
            .iter()
            .map(|row| row.1)
            .collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
    assert_eq!(changes.state.contract.contexts, references);
    Ok(())
}

#[test]
fn context_changes_reject_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    journal.select_contexts();
    let seed = Journal::frontier(&store)?;
    let context = Journal::context("corrupt-context", 1);
    let revision = store.commit_context(&context)?;
    let key = crate::analysis::context::version_key(&context.key)?;
    let instance = journal.fixture.current(&store)?;
    let before = store.meta()?;
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET version_key=? WHERE version_key=?",
            params![b"wrong".as_slice(), key]
        )?,
        1
    );
    assert!(journal
        .read(&store, seed, &AnalysisReadControl::default())
        .is_err());
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET version_key=?,commit_revision=? WHERE owner_id=?",
            params![key, revision + 1, context.key.owner_id]
        )?,
        1
    );
    assert!(journal
        .read(&store, seed, &AnalysisReadControl::default())
        .is_err());
    let mut qualified = context.key.clone();
    qualified.owner_id = "native-package-v1".into();
    let qualified_key = crate::analysis::context::version_key(&qualified)?;
    assert_eq!(store.writer()?.get_mut()?.execute("UPDATE context_versions SET version_key=?,owner_id=?,commit_revision=? WHERE version_key=?", params![qualified_key, qualified.owner_id, revision, key])?, 1);
    assert!(journal
        .read(&store, seed, &AnalysisReadControl::default())
        .is_err());
    assert_eq!(
        store.writer()?.get_mut()?.execute(
            "UPDATE context_versions SET version_key=?,owner_id=? WHERE version_key=?",
            params![key, context.key.owner_id, qualified_key]
        )?,
        1
    );
    let recovered = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(Journal::context_rows(&recovered.page)?.len(), 1);
    assert_eq!(store.meta()?, before);
    assert_eq!(journal.fixture.current(&store)?, instance);
    Ok(())
}

#[test]
fn context_changes_keep_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    Journal::append(&store, 1, 1)?;
    let mut journal = Journal::new(&store)?;
    journal.select_contexts();
    let seed = Journal::frontier(&store)?;
    store.commit_contexts(
        &(1..=3)
            .map(|version| Journal::context("retry-context", version))
            .collect::<Vec<_>>(),
    )?;
    let before = store.meta()?;
    let instance = journal.fixture.current(&store)?;
    journal.selection.binding_ids.push([9; 16]);
    journal.limits.keys = Some(4);
    assert!(matches!(
        journal.read_as(
            &store,
            &journal.request(&store)?,
            seed,
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input keys",
            ..
        })
    ));
    journal.selection.binding_ids.clear();
    journal.limits.keys = Some(2);
    assert!(journal
        .read(&store, seed, &AnalysisReadControl::default())
        .is_err());
    journal.limits.keys = None;
    let control = Arc::new(AnalysisReadControl::default());
    let cancel = Arc::clone(&control);
    control.on_read_step(move || cancel.cancel())?;
    assert!(journal.read(&store, seed, &control).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(journal.fixture.current(&store)?, instance);
    let retry = journal.read(&store, seed, &AnalysisReadControl::default())?;
    assert_eq!(
        Journal::context_rows(&retry.page)?
            .iter()
            .map(|row| row.1)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert!(retry.state.prior(10).is_none());
    Ok(())
}

#[test]
fn context_changes_release_copies() -> TestResult {
    let read = |length, input_bytes| -> TestResult<AnalysisPositionPageV1> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        Journal::append(&store, 1, 1)?;
        let mut journal = Journal::new(&store)?;
        journal.requests.insert(
            "context_versions".into(),
            Some(BTreeSet::from([AnalysisStore::table_schemas()
                ["context_versions"]
                .index_of("owner_revision")?])),
        );
        journal.limits.input_bytes = input_bytes;
        let seed = Journal::frontier(&store)?;
        let contexts = (1..=6)
            .map(|version| {
                let mut context = Journal::context("sized-context", version);
                context.body = vec![42; length];
                context
            })
            .collect::<Vec<_>>();
        store.commit_contexts(&contexts)?;
        Ok(journal
            .read(&store, seed, &AnalysisReadControl::default())?
            .page)
    };
    let baseline = read(1, usize::MAX)?;
    let length = 4096;
    let larger = read(length, baseline.extraction.input_bytes + length * 2)?;
    assert_eq!(
        larger.extraction.input_bytes,
        baseline.extraction.input_bytes
    );
    assert_eq!(larger.extraction.scanned_bytes, length * 6);
    assert_eq!(
        larger.tables["context_versions"]
            .iter()
            .flat_map(|batch| {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .into_iter()
                    .flat_map(|column| column.values().iter().copied())
            })
            .collect::<Vec<_>>(),
        (1..=6).collect::<Vec<_>>()
    );
    Ok(())
}
