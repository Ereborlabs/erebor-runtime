use super::*;
use araphor_data::{
    analysis::native::{ManagedCommit, ManagedReturn},
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    InputSubscription, ManagedAttempt, ManagedPage, ManagedRead, StorePositionV1,
};
use serde::Deserialize;

#[derive(Debug, Deserialize, PartialEq)]
struct Cut {
    revision: u64,
    native: (u64, u64, u64),
    raw: Option<(u64, u64, u64)>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Consumer {
    generation: u64,
    version: u64,
    cut: Cut,
    completed_through: StorePositionV1,
}

fn saved(store: &NativeStore) -> Result<Consumer, Box<dyn std::error::Error>> {
    let view = store.view()?;
    let value = view
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .ok_or("consumer")??
        .1;
    assert_eq!(value[0], 0);
    Ok(rmp_serde::from_slice(&value[1..])?)
}

fn instance(store: &NativeStore) -> araphor_data::Result<ManagedInstance> {
    let mut fixture = Fixture::new(store, [1; 16], "durable-input", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let admitted = fixture.admit(store)?;
    store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
        Ok(())
    })
}

fn requests() -> AnalysisTableRequests {
    ["events", "context_versions"]
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
        .collect()
}

fn subscribe(
    store: &Arc<NativeStore>,
    instance: &ManagedInstance,
) -> araphor_data::Result<InputSubscription> {
    store.subscribe_managed_inputs(
        instance,
        &instance.grant.selection,
        &requests(),
        None,
        &AnalysisReadControl::default(),
        &super::graph::Budget,
    )
}

fn capture(
    store: &NativeStore,
    instance: &ManagedInstance,
    inputs: &InputSubscription,
    mode: AnalysisReadModeV1,
) -> araphor_data::Result<ManagedPage> {
    let requests = requests();
    let selection = instance.grant.selection.project(&requests)?;
    store.read_managed_subscribed(
        inputs,
        &selection,
        &ManagedRead {
            instance: instance.clone(),
            expected: None,
            rebuild: false,
            follow: false,
            source: None,
            completed: None,
            execution: None,
        },
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode,
            now: 1000,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

fn publish(
    store: &NativeStore,
    attempt: &ManagedAttempt,
    completed: bool,
    reject: bool,
) -> Result<araphor_data::ManagedReceipt, Box<dyn std::error::Error>> {
    let evaluation = super::publication::evaluation(attempt);
    let schema = attempt.instance().spec.manifest.selected_schema.clone();
    let model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("rows", schema)]);
    let output = super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let control = AnalysisReadControl::default();
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt,
        completed,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &attempt.instance().spec.manifest.selected_schema,
    };
    Ok(store.commit_managed(store.prepare_managed(&input)?, || {
        if reject {
            Err(Code::Denied.error("guard"))
        } else {
            Ok(())
        }
    })?)
}

#[tokio::test]
async fn initial_capture_atomic_ack_and_restart_replay() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let initial = instance(&store)?;
    super::attempts::append(&store, 1)?;
    let mut inputs = subscribe(&store, &initial)?;
    assert!(inputs.needs_initial());
    let first = saved(&store)?;
    let page = capture(&store, &initial, &inputs, AnalysisReadModeV1::Complete)?;
    assert_eq!(
        page.page.tables["events"]
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    let captured = page.page.extraction.meta.commit_revision;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("initial", true),
        || Ok(()),
    )?;
    let before = store.view()?.revision();
    assert!(publish(&store, &attempt, true, true).is_err());
    assert_eq!(store.view()?.revision(), before);
    assert_eq!(saved(&store)?.completed_through, first.completed_through);
    let receipt = publish(&store, &attempt, true, false)?;
    let committed = saved(&store)?;
    assert_eq!(
        committed.completed_through,
        StorePositionV1 {
            commit_revision: captured,
            ordinal: u32::MAX
        }
    );
    assert_eq!(committed.cut.revision, before);
    assert!(captured < receipt.commit_revision);
    store.checkpoint_inputs()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), inputs.changed())
            .await
            .is_err()
    );
    assert!(!inputs.needs_initial());
    super::attempts::append(&store, 2)?;
    let second = store.view()?.revision();
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop((page, attempt, inputs, store));
    let store = Arc::new(NativeStore::open(&root)?);
    let current = store
        .managed_resume([1; 16], "durable-input", &AnalysisReadControl::default())?
        .instance;
    let mut inputs = subscribe(&store, &current)?;
    assert!(!inputs.needs_initial());
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(2), inputs.changed())
            .await??
            .commit_revision,
        second
    );
    let page = capture(
        &store,
        &current,
        &inputs,
        AnalysisReadModeV1::Changes(committed.completed_through),
    )?;
    assert_eq!(
        page.page.tables["events"]
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("resumed", true),
        || Ok(()),
    )?;
    publish(&store, &attempt, true, false)?;
    store.checkpoint_inputs()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), inputs.changed())
            .await
            .is_err()
    );
    assert_eq!(
        saved(&store)?.completed_through.commit_revision,
        page.page.extraction.meta.commit_revision
    );
    Ok(())
}

#[tokio::test]
async fn filtered_checkpoints_stop_before_matches_and_do_not_loop() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let instance = instance(&store)?;
    let mut inputs = subscribe(&store, &instance)?;
    let first = saved(&store)?;
    let before = store.view()?.revision();
    let retry = subscribe(&store, &instance)?;
    assert_eq!(store.view()?.revision(), before);
    assert_eq!(saved(&store)?, first);
    let mut interest = requests();
    interest.remove("context_versions");
    assert!(store
        .subscribe_managed_inputs(
            &instance,
            &instance.grant.selection,
            &interest,
            None,
            &AnalysisReadControl::default(),
            &super::graph::Budget
        )
        .is_err());
    let mut foreign = super::attempts::context(1);
    foreign.key.tenant_id = [9; 16];
    store.commit_contexts(&[foreign])?;
    let filtered = store.view()?.revision();
    store.checkpoint_inputs()?;
    assert_eq!(saved(&store)?.cut.revision, filtered);
    assert_eq!(saved(&store)?.completed_through.commit_revision, 0);
    assert!(inputs.needs_initial());
    let checkpoint = store.view()?.revision();
    for _ in 0..3 {
        store.checkpoint_inputs()?;
    }
    assert_eq!(store.view()?.revision(), checkpoint);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), inputs.changed())
            .await
            .is_err()
    );
    super::attempts::append(&store, 1)?;
    let matched = store.view()?.revision();
    store.commit_contexts(&[super::attempts::context(1)])?;
    store.checkpoint_inputs()?;
    assert!(saved(&store)?.cut.revision < matched);
    assert!(inputs.changed().await?.commit_revision >= matched);
    drop(retry);
    Ok(())
}

#[test]
fn incomplete_and_metadata_publications_do_not_acknowledge_rows() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let mut instance = instance(&store)?;
    super::attempts::append(&store, 1)?;
    let inputs = subscribe(&store, &instance)?;
    let first = saved(&store)?;
    for (name, mode, complete) in [
        ("metadata", AnalysisReadModeV1::Metadata, true),
        ("incomplete", AnalysisReadModeV1::Complete, false),
    ] {
        let page = capture(&store, &instance, &inputs, mode)?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::attempts::request(name, true),
            || Ok(()),
        )?;
        publish(&store, &attempt, complete, false)?;
        assert_eq!(saved(&store)?.completed_through, first.completed_through);
        instance = store
            .view()?
            .managed_instance([1; 16], "durable-input", &AnalysisReadControl::default())?
            .ok_or("instance")?;
    }
    let page = capture(&store, &instance, &inputs, AnalysisReadModeV1::Complete)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("cancelled", false),
        || Ok(()),
    )?;
    store.finish_managed(&attempt, araphor_data::ManagedExit::Cancelled, || Ok(()))?;
    assert_eq!(saved(&store)?.completed_through, first.completed_through);
    drop((inputs, page, attempt, store));
    let store = Arc::new(NativeStore::open(&root)?);
    let instance = store
        .view()?
        .managed_instance([1; 16], "durable-input", &AnalysisReadControl::default())?
        .ok_or("instance")?;
    assert!(subscribe(&store, &instance)?.needs_initial());
    Ok(())
}

#[test]
fn narrowed_and_projected_reads_publish_without_consuming_omitted_inputs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let mut instance = instance(&store)?;
    super::attempts::append(&store, 1)?;
    let inputs = subscribe(&store, &instance)?;
    let page = capture(&store, &instance, &inputs, AnalysisReadModeV1::Complete)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("initial", true),
        || Ok(()),
    )?;
    publish(&store, &attempt, true, false)?;
    let completed = saved(&store)?.completed_through;
    for cursor in 2..=3 {
        super::attempts::append(&store, cursor)?;
    }
    for narrow in [true, false] {
        instance = store
            .view()?
            .managed_instance([1; 16], "durable-input", &AnalysisReadControl::default())?
            .ok_or("instance")?;
        let mut requests = requests();
        if !narrow {
            requests.remove("context_versions");
        }
        let mut selection = instance.grant.selection.project(&requests)?;
        if narrow {
            selection.cursor_from = std::ops::Bound::Included(3);
        }
        let page = store.read_managed_subscribed(
            &inputs,
            &selection,
            &ManagedRead {
                instance: instance.clone(),
                expected: None,
                rebuild: false,
                follow: false,
                source: None,
                completed: None,
                execution: None,
            },
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 1000,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?;
        if narrow {
            assert_eq!(
                page.page.tables["events"]
                    .iter()
                    .map(sdk::RecordBatch::num_rows)
                    .sum::<usize>(),
                1
            );
        }
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::attempts::request(if narrow { "narrow" } else { "projected" }, true),
            || Ok(()),
        )?;
        publish(&store, &attempt, true, false)?;
        assert_eq!(saved(&store)?.completed_through, completed);
    }
    Ok(())
}

#[test]
fn reopen_does_not_checkpoint_checkpoint_records() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let instance = instance(&store)?;
    let inputs = subscribe(&store, &instance)?;
    let mut foreign = super::attempts::context(1);
    foreign.key.tenant_id = [9; 16];
    store.commit_contexts(&[foreign])?;
    store.checkpoint_inputs()?;
    let record = saved(&store)?;
    let checkpoint = store.view()?.revision();
    assert!(record.cut.revision < checkpoint);
    drop((inputs, store));
    let store = Arc::new(NativeStore::open(&root)?);
    for _ in 0..3 {
        store.checkpoint_inputs()?;
    }
    assert_eq!(store.view()?.revision(), checkpoint);
    assert_eq!(saved(&store)?, record);
    assert!(subscribe(&store, &instance)?.needs_initial());
    Ok(())
}

#[test]
fn recovery_rejects_completion_without_successful_capture() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let instance = instance(&store)?;
    super::attempts::append(&store, 1)?;
    let inputs = subscribe(&store, &instance)?;
    let record = saved(&store)?;
    let (key, bytes) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/input/")
        .next()
        .ok_or("consumer")??;
    let mut value: serde_json::Value = rmp_serde::from_slice(&bytes[1..])?;
    value["completed_through"]["commit_revision"] = record.cut.revision.into();
    value["completed_through"]["ordinal"] = u32::MAX.into();
    let mut changed = vec![0];
    changed.extend(rmp_serde::to_vec_named(&value)?);
    let mut tx = store.write()?;
    tx.native().insert(key, changed);
    tx.commit([])?;
    drop((inputs, store));
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[tokio::test]
async fn stop_and_start_preserve_unconsumed_inputs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let instance = instance(&store)?;
    let mut inputs = subscribe(&store, &instance)?;
    let before = saved(&store)?;
    let stopped = store.stop_managed(&instance, || Ok(()))?;
    super::attempts::append(&store, 1)?;
    let raw = store.view()?.revision();
    store.checkpoint_inputs()?;
    assert!(saved(&store)?.cut.revision < raw);
    assert_eq!(inputs.changed().await?.commit_revision, raw);
    let started = store.set_managed_running(
        [1; 16],
        &stopped.spec.id,
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    let retry = subscribe(&store, &started)?;
    assert_eq!(saved(&store)?.version, before.version);
    assert!(retry.needs_initial());
    let page = capture(&store, &started, &retry, AnalysisReadModeV1::Complete)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("started", true),
        || Ok(()),
    )?;
    publish(&store, &attempt, true, false)?;
    assert_eq!(
        saved(&store)?.completed_through.commit_revision,
        page.page.extraction.meta.commit_revision
    );
    assert!(!retry.needs_initial());
    Ok(())
}

#[tokio::test]
async fn graph_publication_acknowledges_its_capture_and_preserves_later_raw_input() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let mut fixture = Fixture::new(&store, [1; 16], "durable-input", true)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let admitted = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    let mut inputs = subscribe(&store, &instance)?;
    super::attempts::append(&store, 1)?;
    let requests = requests();
    let selection = instance.grant.selection.project(&requests)?;
    let control = AnalysisReadControl::default();
    let page = store.read_managed_subscribed(
        &inputs,
        &selection,
        &ManagedRead {
            instance: instance.clone(),
            expected: None,
            rebuild: false,
            follow: true,
            source: None,
            completed: None,
            execution: None,
        },
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let cut = page.page.extraction.meta.commit_revision;
    super::attempts::append(&store, 2)?;
    let later = store.view()?.revision();
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("graph-follow", true),
        || Ok(()),
    )?);
    let descriptor = store
        .view()?
        .package_revision([1; 16], "managed-graph", "1", &control)?
        .ok_or("descriptor")?;
    let descriptor: sdk::Package = serde_json::from_slice(&descriptor.descriptor)?;
    let model = &descriptor.exports[0];
    let graph = araphor_data::analysis::native::ManagedGraphTransaction::new(
        &store,
        Arc::clone(&attempt),
        10,
        model,
        Vec::new(),
        Arc::new(super::graph::Budget),
        &control,
    )?;
    graph.stage(
        &store,
        "task",
        super::graph::node(&graph, b"task-a")?,
        Arc::new(()),
        &control,
    )?;
    let journal = graph.freeze(&store, &control)?;
    let evaluation = super::publication::evaluation(&attempt);
    let output = super::publication::output(model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: Some(&journal),
        retained: None,
    }];
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let before = store.view()?;
    let original = saved(&store)?;
    assert!(store
        .commit_managed(store.prepare_managed(&input)?, || Err(
            Code::Denied.error("guard")
        ))
        .is_err());
    assert_eq!(saved(&store)?, original);
    assert_eq!(store.view()?.revision(), before.revision());
    let receipt = store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
    assert_eq!(saved(&store)?.completed_through.commit_revision, cut);
    assert!(saved(&store)?.cut.revision < later);
    assert!(before
        .snapshot()
        .prefix(b"\0data/graph/publication/")
        .next()
        .is_none());
    assert!(before
        .managed_attempt([1; 16], "durable-input", "graph-follow", &control)?
        .ok_or("pending attempt")?
        .receipt()
        .is_none());
    let published = store.read_at(receipt.commit_revision)?;
    assert!(published
        .managed_graph_publication([1; 16], &receipt.selected, &control)?
        .is_some());
    assert_eq!(
        published
            .managed_instance([1; 16], "durable-input", &control)?
            .ok_or("instance")?
            .progress,
        receipt.commit_revision
    );
    assert_eq!(inputs.changed().await?.commit_revision, later);
    Ok(())
}

#[tokio::test]
async fn completed_capture_discards_an_unobserved_wake() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let instance = instance(&store)?;
    let mut inputs = subscribe(&store, &instance)?;
    super::attempts::append(&store, 1)?;
    let page = capture(&store, &instance, &inputs, AnalysisReadModeV1::Complete)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("initial", true),
        || Ok(()),
    )?;
    assert_ne!(inputs.position().commit_revision, 0);
    publish(&store, &attempt, true, false)?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), inputs.changed())
            .await
            .is_err()
    );
    super::attempts::append(&store, 2)?;
    assert_eq!(
        inputs.changed().await?.commit_revision,
        store.view()?.revision()
    );
    Ok(())
}
