use super::*;
use araphor_data::AnalysisTableRequests;
use serde_value::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn inventory(store: &NativeStore, prefix: &[u8]) -> TestResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    store
        .view()?
        .snapshot()
        .prefix(prefix)
        .map(|entry| {
            let (key, value) = entry?;
            Ok((key.to_vec(), value.to_vec()))
        })
        .collect()
}

fn result_record(store: &NativeStore, name: &str) -> TestResult<(Vec<u8>, Vec<u8>)> {
    #[derive(serde::Deserialize)]
    struct Header {
        id: String,
    }
    for (key, bytes) in inventory(store, b"\0data/X")? {
        assert_eq!(key.len(), 15);
        assert_eq!(bytes.first(), Some(&0));
        let header: Header = rmp_serde::from_slice(&bytes[1..])?;
        if header.id == name {
            return Ok((key, bytes));
        }
    }
    Err("selected result".into())
}

#[test]
fn graph_empty_step_has_no_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume([1; 16], "source", &control)?;
    let page = follow(&store, &resume, &Arc::default())?;
    assert!(page.state.follows_graph());
    let mut input = super::super::attempts::request("empty-follow", true);
    input.frontier.as_mut().ok_or("frontier")?.cursor = vec![1];
    let attempt = store.register_managed_attempt(&page.state, &input, || Ok(()))?;
    let mut selection = instance.grant.selection.clone();
    selection.select_graphs(araphor_data::Selection::All, None)?;
    let requests = AnalysisTableRequests::from([
        ("events".into(), None),
        ("graph_manifest".into(), None),
        ("graph_state".into(), None),
    ]);
    let before = store.view()?;
    let raw = store.source_receipt(&identity())?;
    let source = inventory(&store, b"\0data/@source/")?;
    let graph = inventory(&store, b"\0data/graph/publication/")?;
    let budget = super::super::graph::Budget;
    let inputs =
        store.subscribe_inputs_at(&before, &selection, &requests, None, &control, &budget)?;
    let position = inputs.position();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: Vec::new(),
    };
    let commit = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: input.time_utc_ns,
        returns: &[],
        selected: &selected,
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let (receipt, progress) =
        store.commit_managed_graph(store.prepare_managed(&commit)?, || Ok(()))?;
    assert!(receipt.results.is_empty());
    assert!(receipt.graph.is_none());
    assert!(progress.is_none());
    assert!(store.meta()?.commit_revision > before.revision());
    assert_eq!(store.source_receipt(&identity())?, raw);
    assert_eq!(inventory(&store, b"\0data/@source/")?, source);
    assert_eq!(inventory(&store, b"\0data/graph/publication/")?, graph);
    assert!(store.processor_result(&scope())?.is_none());
    assert!(store.graph_window_headers(&identity(), None)?.is_empty());
    let replay =
        store.subscribe_inputs_at(&before, &selection, &requests, None, &control, &budget)?;
    assert_eq!(inputs.position(), position);
    assert_eq!(replay.position(), position);
    let current = store.managed_resume([1; 16], "source", &control)?.instance;
    assert!(matches!(
        store
            .managed_result(&current, &receipt.selected.result_id, 1000, &control)?
            .kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    let (key, bytes) = result_record(&store, &receipt.selected.result_id)?;
    let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
    *super::super::attempts::field(&mut record, &["body", "Selected", "rows"])? =
        serde_value::to_value(1u64)?;
    let mut write = store.write()?;
    write
        .native()
        .insert(&key, [vec![0], rmp_serde::to_vec(&record)?].concat());
    write.commit([])?;
    assert!(matches!(
        store.managed_result(&current, &receipt.selected.result_id, 1000, &control),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed success destination",
            ..
        })
    ));
    drop((page, attempt, before, inputs, replay));
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed success destination",
            ..
        })
    ));
    let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = database.branch("data")?.ok_or("repair branch")?;
    let mut transaction = branch.write_tx()?;
    let head = transaction.get(b"\0data/head")?.ok_or("repair head")?;
    transaction.insert(&key, &bytes);
    transaction.commit_stamped([[b"\0data/cut/".as_slice(), head.as_ref()].concat()])?;
    drop((branch, database));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        result_record(&store, &receipt.selected.result_id)?,
        (key, bytes)
    );
    assert!(matches!(
        store
            .managed_result(&current, &receipt.selected.result_id, 1000, &control)?
            .kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    assert_eq!(
        store
            .managed_attempt([1; 16], "source", &input.id, &control)?
            .ok_or("repaired receipt")?
            .receipt(),
        Some(&receipt)
    );
    assert_eq!(inventory(&store, b"\0data/@source/")?, source);
    assert_eq!(inventory(&store, b"\0data/graph/publication/")?, graph);
    Ok(())
}
