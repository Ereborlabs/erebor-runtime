use super::*;
use araphor_data::{
    analysis::{
        native::{ManagedCommit, ManagedReturn},
        PackageResultRefV1,
    },
    AnalysisExtractLimits, AnalysisResultCommitV1, DiscoveryCoverageStateV1, DiscoveryCoverageV1,
    DiscoveryRecordIdV1, DiscoveryRecordV1, GraphCommit, GraphFactV1, GraphFactValueV1,
    GraphManifest, GraphReplayInputV1, GraphRevisionV1, ManagedAttempt, ManagedGraphOperation,
    ProcessorClassV1, ProcessorScopeV1,
};
use std::collections::BTreeSet;

#[path = "source/expiry.rs"]
mod expiry;
#[path = "source/inputs.rs"]
mod inputs;
#[path = "source/read.rs"]
mod read;

#[path = "source/fixtures.rs"]
mod fixtures;
pub(super) use fixtures::packet;

#[test]
fn source_empty_gate() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("empty", true),
        || Ok(()),
    )?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![sdk::RecordBatch::new_empty(Arc::new(
            instance.spec.manifest.selected_schema.clone(),
        ))],
    };
    let control = AnalysisReadControl::default();
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &[],
        selected: &selected,
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let (receipt, progress) =
        store.commit_managed_graph(store.prepare_managed(&input)?, None, || Ok(()))?;
    assert!(receipt.graph.is_none());
    assert!(progress.is_none());
    assert!(store.processor_result(&scope())?.is_none());
    assert!(store.graph_window_headers(&identity(), None)?.is_empty());
    drop((page, attempt));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .managed_attempt([1; 16], "source", "empty", &control)?
            .ok_or("saved gate")?
            .receipt(),
        Some(&receipt)
    );
    Ok(())
}

#[test]
fn source_window_winner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let first = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let page = super::attempts::capture(&store, &first, false)?;
    select(&store, &page, &[1], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", true),
        || Ok(()),
    )?;
    let receipt = publish(&store, &attempt, false)?;
    let mut spec = first.spec.clone();
    spec.id = "second".into();
    let second = store.admit_managed(&spec, &first.grant, || Ok(()))?;
    let second = store.set_managed_running([1; 16], "second", second.lifecycle, true, || Ok(()))?;
    let page = super::attempts::capture(&store, &second, false)?;
    select(&store, &page, &[1], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("second", true),
        || Ok(()),
    )?;
    let winner = publish(&store, &attempt, false)?;
    let headers = store.graph_window_headers(&identity(), None)?;
    assert_eq!(headers.len(), 1);
    assert_ne!(winner.selected, receipt.selected);
    assert_eq!(headers[0].0, winner.selected.result_id);
    assert!(store.graph_window_headers(&identity(), Some(1))?.is_empty());
    drop((page, attempt));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.graph_window_headers(&identity(), None)?[0].0,
        winner.selected.result_id
    );
    Ok(())
}
use fixtures::{append, capture, follow, identity, instance, publish, records, scope, select};

#[test]
fn source_publication_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    for cursor in 1..=2 {
        append(&store, cursor)?;
    }
    let page = super::attempts::capture(&store, &instance, false)?;
    select(&store, &page, &[1, 2], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", true),
        || Ok(()),
    )?;
    let before = store.view()?.revision();
    assert!(publish(&store, &attempt, true).is_err());
    assert_eq!(store.view()?.revision(), before);
    assert!(store.processor_result(&scope())?.is_none());
    let first = publish(&store, &attempt, false)?;
    assert_eq!(first.graph, Some(first.selected.clone()));
    let saved = store
        .managed_attempt([1; 16], "source", "first", &AnalysisReadControl::default())?
        .ok_or("saved")?;
    assert_eq!(saved.receipt(), Some(&first));
    assert_eq!(
        store.graph_record_keys(
            &page.state,
            Some(&saved),
            &first.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )?,
        records(&[1, 2])
    );
    let wanted = BTreeSet::from([records(&[1])[0].clone()]);
    let (summary, facts, proofs) = store.graph_frozen_facts(
        &page.state,
        Some(&saved),
        &first.selected,
        &wanted,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(facts.len(), 1);
    assert!(proofs.is_empty());
    assert_eq!(summary.manifest.last_cursor, 2);
    append(&store, 3)?;
    let resume = store.managed_resume([1; 16], "source", &AnalysisReadControl::default())?;
    let next = capture(&store, &resume)?;
    select(&store, &next, &[2, 3], Some(&first.selected))?;
    let mut request = super::attempts::request("second", true);
    request.rebuild = true;
    let second = store.register_managed_attempt(&next.state, &request, || Ok(()))?;
    let receipt = publish(&store, &second, false)?;
    let saved = store
        .managed_attempt([1; 16], "source", "second", &AnalysisReadControl::default())?
        .ok_or("second")?;
    assert_eq!(
        store.graph_record_keys(
            &next.state,
            Some(&saved),
            &receipt.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )?,
        records(&[2, 3])
    );
    assert_eq!(
        store.graph_record_keys(
            &next.state,
            None,
            &first.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )?,
        records(&[1, 2])
    );
    drop((page, next, attempt, second, saved));
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let resume = store.managed_resume([1; 16], "source", &AnalysisReadControl::default())?;
    let page = capture(&store, &resume)?;
    assert_eq!(
        store.graph_record_keys(
            &page.state,
            None,
            &first.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )?,
        records(&[1, 2])
    );
    assert_eq!(
        store.processor_result(&scope())?.ok_or("head")?.result_id,
        receipt.selected.result_id
    );
    Ok(())
}

#[test]
fn source_recovery_damage() -> TestResult {
    for mode in [
        "member-missing",
        "member-extra",
        "member-value",
        "posting-missing",
        "posting-extra",
        "header-missing",
        "head-missing",
        "window-value",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let instance = instance(&store)?;
        store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
        append(&store, 1)?;
        let page = super::attempts::capture(&store, &instance, false)?;
        select(&store, &page, &[1], None)?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::attempts::request("first", true),
            || Ok(()),
        )?;
        publish(&store, &attempt, false)?;
        let prefix: &[u8] = if mode.starts_with("member") {
            b"\0data/@source/member/".as_slice()
        } else if mode.starts_with("posting") {
            b"\0data/@source/fact/"
        } else if mode.starts_with("header") {
            b"\0data/@source/header/"
        } else if mode.starts_with("head") {
            b"\0data/@source/head/"
        } else {
            b"\0data/@source/window/"
        };
        let (key, value) = store
            .view()?
            .snapshot()
            .prefix(prefix)
            .next()
            .ok_or("record")??;
        let mut tx = store.write()?;
        if mode.ends_with("missing") {
            tx.native().remove(key);
        } else if mode.ends_with("extra") {
            let mut key = key.to_vec();
            *key.last_mut().ok_or("last")? += 1;
            tx.native().insert(key, value);
        } else {
            tx.native().insert(key, vec![0]);
        }
        tx.commit([])?;
        drop((page, attempt));
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "accepted {mode}");
    }
    Ok(())
}

#[test]
fn source_append_prefix() -> TestResult {
    use prost::Message as _;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    for cursor in 1..=2 {
        append(&store, cursor)?;
    }
    let source = identity();
    let report = araphor_data::CoverageReport {
        source_id: source.source_id.to_vec(),
        source_epoch: source.source_epoch,
        cpu_id: 0,
        revision: 1,
        intervals: vec![araphor_data::CoverageInterval {
            interval_id: vec![4; 16],
            source_epoch: 1,
            revision: 1,
            state: "CLOSED".into(),
            first_sequence: 1,
            last_sequence: Some(3),
            opening_counters: Some(Default::default()),
            closing_counters: Some(araphor_data::CoverageCounters {
                next_sequence: 4,
                ..Default::default()
            }),
            ..Default::default()
        }],
    };
    store.accept_validated_coverage(araphor_data::ValidatedCoverageV1 {
        identity: source,
        cpu_id: 0,
        revision: 1,
        encoded_report: report.encode_to_vec(),
    })?;
    let control = AnalysisReadControl::default();
    let execution = Arc::new(araphor_data::ManagedExecution::default());
    let resume = store.managed_resume([1; 16], "source", &control)?;
    let page = follow(&store, &resume, &execution)?;
    select(&store, &page, &[1, 2], None)?;
    assert!(page
        .state
        .source()
        .ok_or("frame")?
        .input_selection()?
        .ok_or("selection")?
        .prefix()
        .is_some());
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", true),
        || Ok(()),
    )?;
    let first = publish(&store, &attempt, false)?;
    append(&store, 3)?;
    let resume = store.managed_resume([1; 16], "source", &control)?;
    let next = follow(&store, &resume, &execution)?;
    assert!(next.state.graph_input(&first.selected).is_some());
    select(&store, &next, &[3], Some(&first.selected))?;
    let attempt = store.register_managed_attempt(
        &next.state,
        &super::attempts::request("append", true),
        || Ok(()),
    )?;
    let receipt = publish(&store, &attempt, false)?;
    let saved = store
        .managed_attempt([1; 16], "source", "append", &control)?
        .ok_or("saved")?;
    assert_eq!(
        store.graph_record_keys(
            &next.state,
            Some(&saved),
            &receipt.selected,
            AnalysisExtractLimits::default(),
            &control
        )?,
        records(&[1, 2, 3])
    );
    assert_eq!(store.graph_window_headers(&identity(), None)?.len(), 1);
    assert!(store.graph_window_headers(&identity(), Some(1))?.is_empty());
    drop((page, next, attempt, saved, execution));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.graph_source([1; 16], &receipt.selected.result_id)?,
        Some(identity())
    );
    Ok(())
}

#[test]
fn source_historical_proofs() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    store.commit_contexts(&[super::attempts::context(99)])?;
    let page = super::attempts::capture(&store, &instance, false)?;
    let input = select(&store, &page, &[1], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request("first", true),
        || Ok(()),
    )?;
    let first = publish(&store, &attempt, false)?;
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume([1; 16], "source", &control)?;
    let next = capture(&store, &resume)?;
    let wanted = BTreeSet::from([records(&[1])[0].clone()]);
    let (_, history) = store.graph_frozen_source(
        &next.state,
        None,
        &first.selected,
        &wanted,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(history.contexts().count(), 1);
    assert_eq!(history.proofs().count(), 1);
    let references = history
        .contexts()
        .map(|(_, reference)| (reference.key.clone(), reference.clone()))
        .collect::<BTreeMap<_, _>>();
    let proofs = history
        .proofs()
        .map(|(record, reference)| (record.clone(), reference.clone()))
        .collect::<Vec<_>>();
    let frame = next.state.source().ok_or("source frame")?;
    let batch = next.page.tables["events"]
        .iter()
        .position(|batch| batch.num_rows() > 0)
        .ok_or("events")?;
    let rows = Arc::new(
        frame
            .row_handles("events", batch)?
            .select(&[0], Arc::new(()))?,
    );
    frame.record_rows(&rows)?;
    let derived = frame.seal_derived(&input, &references, &proofs, Some(history), Arc::new(()))?;
    frame.attribute_input(10, &[rows], &[derived.clone()], Arc::new(()))?;
    frame.select_graph_input(
        &next.state,
        None,
        &input,
        &derived,
        Some(&first.selected),
        (1, 1, 2000),
        (false, false, false),
        Arc::new(()),
    )?;
    let mut request = super::attempts::request("history", true);
    request.rebuild = true;
    let attempt = store.register_managed_attempt(&next.state, &request, || Ok(()))?;
    let second = publish(&store, &attempt, false)?;
    let saved = store
        .managed_attempt([1; 16], "source", "history", &control)?
        .ok_or("saved")?;
    let (_, facts, proofs) = store.graph_frozen_facts(
        &next.state,
        Some(&saved),
        &second.selected,
        &wanted,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(facts.len(), 1);
    assert_eq!(proofs.len(), 1);
    drop((page, next, attempt, saved));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.processor_result(&scope())?.ok_or("result")?.result_id,
        second.selected.result_id
    );
    Ok(())
}
