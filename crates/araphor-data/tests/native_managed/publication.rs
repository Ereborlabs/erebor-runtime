use super::*;
use araphor_data::analysis::native::{
    ManagedCommit, ManagedGraphJournal, ManagedGraphTransaction, ManagedReturn,
};
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    ManagedExit, ManagedPage, ManagedRead, ManagedResume, ManagedSourceRead,
};
use sdk::arrow_array::{UInt64Array, UInt8Array};

#[path = "publication/recovery.rs"]
mod recovery;

pub(super) fn evaluation(attempt: &araphor_data::ManagedAttempt) -> sdk::Evaluation {
    sdk::Evaluation {
        export: "count".into(),
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        previous_outputs: Vec::new(),
        context: sdk::EvaluationContext {
            id: attempt.request().id.clone(),
            time_utc_ns: attempt.request().time_utc_ns as i64,
            seed: attempt.request().seed,
        },
    }
}

pub(super) fn output(model: &sdk::Model) -> Result<sdk::Output, Box<dyn std::error::Error>> {
    let batch = sdk::RecordBatch::try_new(
        Arc::new(model.outputs[0].schema.clone()),
        vec![Arc::new(UInt64Array::from(vec![1]))],
    )?;
    Ok(sdk::Output {
        datasets: vec![sdk::Dataset {
            name: "rows".into(),
            batches: vec![batch],
        }],
        checkpoint: None,
        evidence: Vec::new(),
        reasons: Vec::new(),
    })
}

fn capture(store: &NativeStore, resume: &ManagedResume) -> araphor_data::Result<ManagedPage> {
    let requests: AnalysisTableRequests = ["events", "context_versions"]
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
        .collect();
    let selection = resume
        .instance
        .spec
        .destination
        .selection(&resume.instance.grant.selection)?
        .project(&requests)?;
    let parent = resume
        .source
        .as_ref()
        .ok_or_else(|| Code::Missing.error("test source parent"))?;
    store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            instance: resume.instance.clone(),
            expected: None,
            rebuild: false,
            follow: false,
            completed: Some(resume.completed),
            execution: None,
            source: Some(ManagedSourceRead::Changes(parent.clone())),
        },
        AnalysisTableRead {
            requests: &requests,
            mode: AnalysisReadModeV1::Changes(parent.position),
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

#[test]
fn checkpoint_resumes_from_native_result_after_each_restart() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let mut model = sdk::Model::new(
        "count",
        Vec::new(),
        vec![sdk::Port::new("rows", schema.clone())],
    );
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 1,
        resume_input_changes: false,
        datasets: vec![sdk::Port::new("state", schema.clone())],
    });
    {
        let store = NativeStore::open(&root)?;
        let fixture = Fixture::with_model(&store, [1; 16], "checkpoint", model.clone())?;
        let instance = fixture.admit(&store)?;
        store.set_managed_running([1; 16], &instance.spec.id, instance.lifecycle, true, || {
            Ok(())
        })?;
    }
    let control = AnalysisReadControl::default();
    let mut last = None;
    for step in 0..2 {
        let store = NativeStore::open(&root)?;
        let resume = store.managed_resume([1; 16], "checkpoint", &control)?;
        let page = if step == 0 {
            super::attempts::capture(&store, &resume.instance, false)?
        } else {
            capture(&store, &resume)?
        };
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::attempts::request(&format!("checkpoint-{step}"), true),
            || Ok(()),
        )?;
        let mut evaluation = evaluation(&attempt);
        if let Some(prior) = page.state.prior(10) {
            let (checkpoint, previous) = prior.state(&model, &[], None, false)?;
            assert!(previous.is_empty());
            let checkpoint = checkpoint.ok_or("retained checkpoint")?;
            let values = checkpoint.datasets[0].batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("checkpoint values")?;
            assert_eq!(values.value(0), 71);
            evaluation.checkpoint = Some(checkpoint);
        } else {
            assert_eq!(step, 0);
        }
        let mut output = output(&model)?;
        output.checkpoint = Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![sdk::Dataset {
                name: "state".into(),
                batches: vec![sdk::RecordBatch::try_new(
                    Arc::new(schema.clone()),
                    vec![Arc::new(UInt64Array::from(vec![71 + step]))],
                )?],
            }],
        });
        let returns = [ManagedReturn {
            call: 10,
            evaluation: &evaluation,
            output: &output,
            changes: None,
            graph: None,
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
            selected_schema: &resume.instance.spec.manifest.selected_schema,
        };
        last = Some(store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?);
    }
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_resume([1; 16], "checkpoint", &control)?
            .instance
            .progress,
        last.ok_or("last checkpoint")?.commit_revision
    );
    Ok(())
}

fn journals(
    store: &NativeStore,
    attempt: &Arc<araphor_data::ManagedAttempt>,
    model: &sdk::Model,
    delete: bool,
) -> Result<[Arc<ManagedGraphJournal>; 2], Box<dyn std::error::Error>> {
    let control = AnalysisReadControl::default();
    let producer = ManagedGraphTransaction::new(
        store,
        Arc::clone(attempt),
        10,
        model,
        Vec::new(),
        Arc::new(super::graph::Budget),
        &control,
    )?;
    let mut batch = super::graph::node(&producer, b"task-a")?;
    if delete {
        assert_eq!(super::graph::read_nodes(&producer, store)?.data.rows(), 1);
        let mut columns = batch.columns().to_vec();
        columns[2] = Arc::new(UInt8Array::from(vec![araphor_graph::Write::Remove as u8]));
        batch = sdk::RecordBatch::try_new(batch.schema(), columns)?;
    }
    producer.stage(store, "task", batch, Arc::new(()), &control)?;
    let producer = producer.freeze(store, &control)?;
    let consumer = ManagedGraphTransaction::new(
        store,
        Arc::clone(attempt),
        20,
        model,
        vec![Arc::clone(&producer)],
        Arc::new(super::graph::Budget),
        &control,
    )?;
    assert_eq!(
        super::graph::read_nodes(&consumer, store)?.data.rows(),
        u64::from(!delete)
    );
    Ok([producer, consumer.freeze(store, &control)?])
}

pub(super) fn publish(
    store: &NativeStore,
    attempt: &araphor_data::ManagedAttempt,
    model: &sdk::Model,
    journals: &[Arc<ManagedGraphJournal>; 2],
    reject: bool,
) -> Result<araphor_data::ManagedReceipt, Box<dyn std::error::Error>> {
    let evaluations = [evaluation(attempt), evaluation(attempt)];
    let outputs = [output(model)?, output(model)?];
    let returns = [10, 20]
        .into_iter()
        .enumerate()
        .map(|(i, call)| ManagedReturn {
            call,
            evaluation: &evaluations[i],
            output: &outputs[i],
            changes: None,
            graph: Some(&journals[i]),
            retained: None,
        })
        .collect::<Vec<_>>();
    let budget = super::graph::Budget;
    let control = AnalysisReadControl::default();
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &outputs[1].datasets[0],
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

#[test]
fn graph_results_consumed_progress_and_historical_cuts_commit_together() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let control = AnalysisReadControl::default();
    let (instance, model) = super::graph::fixture(&store)?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", true),
        || Ok(()),
    )?);
    let journals = journals(&store, &attempt, &model, false)?;
    let before = store.view()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(publish(&store, &attempt, &model, &journals, true).is_err());
    assert_eq!(store.view()?.revision(), before.revision());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store
        .view()?
        .snapshot()
        .prefix(b"\0data/X")
        .next()
        .is_none());
    let receipt = publish(&store, &attempt, &model, &journals, false)?;
    assert_eq!(receipt.results.len(), 2);
    let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
    assert_eq!(resume.instance.progress, receipt.commit_revision);
    assert_eq!(resume.completed, receipt.commit_revision);
    assert_eq!(
        resume.frontier.as_ref().map(|frontier| frontier.pending),
        Some(false)
    );
    assert_eq!(
        resume.source.as_ref().map(|source| &source.result),
        Some(&receipt.selected)
    );
    let publication = store
        .view()?
        .managed_graph_publication([1; 16], &receipt.selected, &control)?
        .ok_or("publication")?;
    assert!(publication.previous.is_none());
    assert_eq!(publication.heads.len(), 2);
    assert!(publication
        .heads
        .values()
        .all(|(_, revision)| *revision == receipt.commit_revision));
    let historical = store.read_at(receipt.commit_revision)?;
    let mapping = historical
        .managed_graph([1; 16], &instance.spec.id, &control)?
        .ok_or("Graph")?;
    let graph = araphor_graph::native::Graph::new(mapping.graph)?;
    let old = graph.view(
        historical.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert!(old
        .member(
            mapping.writers[&10],
            mapping.relations["task"].0,
            b"owner",
            b"task-a",
            &|_, _, _| Ok(None)
        )?
        .is_some());
    let next = capture(&store, &resume)?;
    assert_eq!(
        next.state.prior(10).ok_or("prior")?.result,
        receipt.results[&10].result_id
    );
    let failed = store.register_managed_attempt(
        &next.state,
        &super::attempts::request("failed", true),
        || Ok(()),
    )?;
    let terminal = store.finish_managed(&failed, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
    let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
    assert_eq!(resume.instance.progress, receipt.commit_revision);
    assert_eq!(resume.completed, terminal.revision);
    assert_eq!(
        resume.source.as_ref().map(|source| &source.result),
        Some(&receipt.selected)
    );
    let next = capture(&store, &resume)?;
    let second = Arc::new(store.register_managed_attempt(
        &next.state,
        &super::attempts::request("second", true),
        || Ok(()),
    )?);
    assert_eq!(store.managed_parent(&second, &control)?, resume.source);
    let evaluation = evaluation(&second);
    let output = output(&model)?;
    let retained = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: Some(&receipt.results[&10]),
    }];
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &second,
        completed: true,
        now_utc_ns: 1000,
        returns: &retained,
        selected: &output.datasets[0],
        selected_schema: &second.instance().spec.manifest.selected_schema,
    };
    let before_revision = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    assert!(matches!(
        store.prepare_managed(&input),
        Err(Error::Package {
            code: Code::Unsupported,
            ..
        })
    ));
    assert_eq!(store.view()?.revision(), before_revision);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let second_journals = self::journals(&store, &second, &model, true)?;
    let second_receipt = publish(&store, &second, &model, &second_journals, false)?;
    let publication = store
        .view()?
        .managed_graph_publication([1; 16], &second_receipt.selected, &control)?
        .ok_or("second publication")?;
    assert_eq!(publication.previous, Some(receipt.selected.clone()));
    let current = graph.view(
        store.view()?.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert!(current
        .member(
            mapping.writers[&10],
            mapping.relations["task"].0,
            b"owner",
            b"task-a",
            &|_, _, _| Ok(None)
        )?
        .is_none());
    drop(current);
    drop(old);
    drop(historical);
    drop(before);
    drop(journals);
    drop(second_journals);
    drop(attempt);
    drop(second);
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
    assert_eq!(resume.instance.progress, second_receipt.commit_revision);
    assert_eq!(
        resume.source.as_ref().map(|source| &source.result),
        Some(&second_receipt.selected)
    );
    let historical = store.read_at(receipt.commit_revision)?;
    let old = graph.view(
        historical.snapshot().clone(),
        BTreeMap::new(),
        &|_, _, _| Ok(None),
    )?;
    assert!(old
        .member(
            mapping.writers[&10],
            mapping.relations["task"].0,
            b"owner",
            b"task-a",
            &|_, _, _| Ok(None)
        )?
        .is_some());
    assert_eq!(
        historical
            .managed_graph_publication([1; 16], &receipt.selected, &control)?
            .ok_or("retained publication")?
            .reference,
        receipt.selected
    );
    Ok(())
}

#[test]
fn attributed_raw_events_and_contexts_keep_exact_references_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let control = AnalysisReadControl::default();
    let mut fixture = Fixture::new(&store, [1; 16], "attributed", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let admitted = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    super::attempts::append(&store, 1)?;
    super::attempts::append(&store, 2)?;
    let contexts =
        store.commit_contexts(&[super::attempts::context(1), super::attempts::context(2)])?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let frame = page.state.source().ok_or("source frame")?;
    let mut rows = Vec::new();
    for table in ["events", "context_versions"] {
        assert_eq!(
            page.page.tables[table]
                .iter()
                .map(|batch| batch.num_rows())
                .sum::<usize>(),
            2
        );
        let batch = page.page.tables[table]
            .iter()
            .position(|batch| batch.num_rows() != 0)
            .ok_or("source batch")?;
        let selected = Arc::new(
            frame
                .row_handles(table, batch)?
                .select(&[0], Arc::new(()))?,
        );
        frame.record_rows(&selected)?;
        rows.push(selected);
    }
    assert_eq!(rows[0].witnesses()[0].cursor, 1);
    assert_eq!(rows[1].contexts(), &contexts[..1]);
    frame.attribute_rows(10, &rows, Arc::new(()))?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("attributed", true),
        || Ok(()),
    )?;
    let descriptor = store
        .view()?
        .package_revision([1; 16], "managed-count", "1", &control)?
        .ok_or("descriptor")?;
    let descriptor: sdk::Package = serde_json::from_slice(&descriptor.descriptor)?;
    let evaluation = evaluation(&attempt);
    let output = output(&descriptor.exports[0])?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
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
    let receipt = store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
    assert_eq!(
        store.view()?.snapshot().prefix(b"\0data/ref/raw/").count(),
        2
    );
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/ref/context/")
            .count(),
        2
    );
    let raw = store
        .view()?
        .snapshot()
        .prefix(b"\0data/ref/raw/")
        .next()
        .ok_or("raw reference")??
        .0;
    drop(rows);
    drop(page);
    drop(attempt);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_attempt([1; 16], &instance.spec.id, "attributed", &control)?
            .ok_or("saved attempt")?
            .receipt(),
        Some(&receipt)
    );
    assert_eq!(
        store.view()?.snapshot().prefix(b"\0data/ref/raw/").count(),
        2
    );
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/ref/context/")
            .count(),
        2
    );
    let mut tx = store.write()?;
    tx.native().remove(raw);
    tx.commit([])?;
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}
