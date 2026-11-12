#![cfg(feature = "test-fixtures")]

use super::super::calls::call_context;
use super::*;
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisStore, AnalysisTableRead,
    AnalysisTableRequests, ManagedPage,
};
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[path = "current/origins.rs"]
mod origins;
#[path = "current/scope.rs"]
mod scope;

struct Saved {
    _directory: tempfile::TempDir,
    store: Arc<AnalysisStore>,
    fixture: Arc<StorageFixture>,
    context: araphor_data::AnalysisContextRefV1,
    receipt: ManagedReceipt,
    requests: AnalysisTableRequests,
}

impl Saved {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(NativeStore::open(directory.path().join("store"))?);
        Self::append(&store, 1)?;
        let context = araphor_data::AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "saved-input".into(),
                entity_key: vec![1],
                lifetime_key: vec![2],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"{}".to_vec(),
        };
        let revision = store.commit_context(&context)?;
        let context = araphor_data::AnalysisContextRefV1 {
            key: context.key,
            commit_revision: revision,
        };
        let fixture = Arc::new(StorageFixture::new_scope(
            &store,
            "counter",
            "Retain independent call state.".into(),
            AnalysisSelectionV1::tenant([1; 16]),
        )?);
        let cursor = AnalysisStore::table_schemas()["events"].index_of("source_cursor")?;
        let requests = AnalysisTableRequests::from([
            ("events".into(), Some(BTreeSet::from([cursor]))),
            ("context_versions".into(), Some(BTreeSet::new())),
            ("traces".into(), Some(BTreeSet::new())),
        ]);
        let capture = store
            .read_managed_tables_filtered(
                &fixture.instance.grant.selection.project(&requests)?,
                &ManagedRead {
                    source: None,
                    execution: None,
                    follow: false,
                    instance: fixture.instance.clone(),
                    expected: None,
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &AnalysisReadControl::default(),
                None,
            )?
            .state;
        let mut input = request("saved-first");
        input.witness_expiry = 100;
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let evaluations = [
            fixture.continued(&input, 10, None)?,
            fixture.continued(&input, 11, None)?,
        ];
        let outputs = [fixture.output(7)?, fixture.output(3)?];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
        Ok(Self {
            _directory: directory,
            store,
            fixture,
            context,
            receipt,
            requests,
        })
    }

    fn append(store: &AnalysisStore, cursor: u64) -> araphor_data::Result<()> {
        let record = araphor_data::EvidenceRecord {
            observed_boottime_ns: cursor,
            ..Default::default()
        };
        let framed = Vec::<u8>::try_from(&record)?;
        store.accept_validated_batch(
            super::super::source::identity(),
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                frame_ends: vec![framed.len()],
                framed_records: framed.into(),
            },
        )?;
        Ok(())
    }

    fn capture_page(&self) -> TestResult<ManagedPage> {
        let instance = self.fixture.current(&self.store)?;
        let mut page = self.store.read_managed_tables_filtered(
            &instance.grant.selection.project(&self.requests)?,
            &ManagedRead {
                source: None,
                execution: None,
                follow: false,
                instance,
                expected: None,
                rebuild: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?;
        for call in [10, 11] {
            if page.state.prior(call).is_some() {
                let evaluation = self.fixture.evaluation(&request("parameters"), call)?;
                page.state.hydrate_prior(
                    call,
                    &self.fixture.model,
                    evaluation.parameters.map(|batch| sdk::Dataset {
                        name: "parameters".into(),
                        batches: vec![batch],
                    }),
                    None,
                )?;
            }
        }
        Ok(page)
    }

    fn capture(&self) -> TestResult<ManagedCapture> {
        Ok(self.capture_page()?.state)
    }

    fn commit_state(&self) -> TestResult<GuardCut> {
        GuardCut::read(&self.store, &self.fixture)
    }
}

#[test]
fn source_change_keeps_commit() -> TestResult {
    let saved = Saved::new()?;
    let control = AnalysisReadControl::default();
    let current = saved.fixture.current(&saved.store)?;
    let reference = &saved.receipt.results[&10];
    let original = saved
        .store
        .managed_result(&current, &reference.result_id, 10, &control)?;
    assert!(original.current);
    let selected = StorageFixture::receipt(
        &saved.store,
        [1; 16],
        &current.spec.id,
        &saved.receipt.attempt,
        &control,
    )?
    .ok_or("saved selected output absent")?;
    let captured = saved.capture()?;
    let input = request("source-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.continued(&input, 10, Some(&captured))?,
        saved.fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    Saved::append(&saved.store, 2)?;
    let before = saved.commit_state()?;
    let stale = request("stale-source-registration");
    assert!(matches!(
        saved
            .store
            .register_managed_attempt(&captured, &stale, || Ok(())),
        Err(araphor_data::Error::AnalysisSourceChanged { .. })
    ));
    assert!(saved
        .store
        .managed_attempt([1; 16], &current.spec.id, &stale.id, &control)?
        .is_none());
    assert_eq!(saved.commit_state()?, before);
    let changed = saved
        .store
        .managed_result(&current, &reference.result_id, 10, &control)?;
    assert!(!changed.current);
    assert_eq!(call_context(&changed)?, call_context(&original)?);
    assert_eq!(changed.result, original.result);
    assert_eq!(changed.source, original.source);
    assert_eq!(changed.prior, original.prior);
    assert_eq!(changed.receipt, original.receipt);
    let retained = StorageFixture::receipt(
        &saved.store,
        [1; 16],
        &current.spec.id,
        &saved.receipt.attempt,
        &control,
    )?
    .ok_or("retained selected output absent")?;
    assert_eq!(retained, selected);
    assert_eq!(before.history, std::slice::from_ref(&saved.receipt));
    let failure = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("stale source publication succeeded")?;
    assert!(matches!(
        failure.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisSourceChanged { .. })
    ));
    assert_eq!(saved.commit_state()?, before);
    Ok(())
}

#[test]
fn trace_revocation_keeps_commit() -> TestResult {
    let saved = Saved::new()?;
    let source = araphor_data::TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let mut intent = araphor_data::TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: [3; 16],
        bindings: vec![araphor_data::TraceBindingV1 {
            binding_id: [9; 16],
            namespace_uid: "namespace-a".into(),
            identity: araphor_data::TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                request_id: [3; 16],
                execution_id: [4; 16],
                source_sha256: source.sha256,
            },
        }],
        source,
        authority: b"accepted".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    };
    intent.accepted_unix_ns = 1;
    let mut trace = saved.store.accept_trace(&intent)?;
    let page = saved.capture_page()?;
    assert_eq!(page.page.extraction.trace_reads(), &[intent.request_id]);
    let captured = page.state;
    let first = request("trace-first");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &first, || Ok(()))?;
    let evaluations = [
        saved.fixture.continued(&first, 10, Some(&captured))?,
        saved.fixture.continued(&first, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    let receipt = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)?;
    let page = saved.capture_page()?;
    assert_eq!(page.page.extraction.trace_reads(), &[intent.request_id]);
    let captured = page.state;
    let input = request("trace-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.continued(&input, 10, Some(&captured))?,
        saved.fixture.continued(&input, 11, Some(&captured))?,
    ];
    trace.cancel_requested = true;
    trace.read_revoked = true;
    saved.store.update_trace(&trace)?;
    let before = saved.commit_state()?;
    assert_eq!(before.instance.progress, receipt.commit_revision);
    assert_eq!(before.history, [saved.receipt.clone(), receipt]);
    let mut checked = false;
    let registration =
        saved
            .store
            .register_managed_attempt(&captured, &request("trace-new"), || {
                checked = true;
                Ok(())
            });
    assert!(
        matches!(
            registration,
            Err(araphor_data::Error::AnalysisSourceChanged { .. })
        ),
        "{registration:?}"
    );
    assert!(!checked);
    assert_eq!(saved.commit_state()?, before);
    let failure = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)
        .err()
        .ok_or("revoked trace publication succeeded")?;
    assert!(matches!(
        failure.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::AnalysisSourceChanged { .. })
    ));
    assert_eq!(saved.commit_state()?, before);
    assert!(saved
        .capture_page()?
        .page
        .extraction
        .trace_reads()
        .is_empty());
    assert_eq!(saved.commit_state()?, before);
    Ok(())
}

#[test]
fn raw_fault_keeps_commit() -> TestResult {
    use std::os::unix::fs::FileExt as _;

    let saved = Saved::new()?;
    let captured = saved.capture()?;
    let input = request("raw-pending");
    let attempt = saved
        .store
        .register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        saved.fixture.continued(&input, 10, Some(&captured))?,
        saved.fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [saved.fixture.output(8)?, saved.fixture.output(4)?];
    let next = request("raw-new");
    let before = saved.commit_state()?;
    let files = std::fs::read_dir(saved._directory.path().join("store").join("segments"))?
        .collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(files.len(), 1);
    let path = files[0].path();
    let bytes = std::fs::read(&path)?;
    let file = std::fs::OpenOptions::new().write(true).open(&path)?;
    file.set_len(0)?;
    let registration = saved
        .store
        .register_managed_attempt(&captured, &next, || Ok(()));
    let publication = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs);
    file.write_all_at(&bytes, 0)?;
    file.sync_all()?;
    assert_eq!(std::fs::read(&path)?, bytes);
    assert!(matches!(
        registration,
        Err(araphor_data::Error::Package {
            code: Code::Incomplete,
            field: "witness segment is truncated",
            ..
        })
    ));
    let failure = publication.err().ok_or("missing raw data published")?;
    assert!(matches!(
        failure.downcast_ref::<araphor_data::Error>(),
        Some(araphor_data::Error::Package {
            code: Code::Incomplete,
            field: "witness segment is truncated",
            ..
        })
    ));
    assert_eq!(saved.commit_state()?, before);
    let restored = saved
        .store
        .register_managed_attempt(&captured, &next, || Ok(()))?;
    assert!(restored.receipt().is_none());
    let receipt = saved
        .fixture
        .publish(&saved.store, &attempt, &evaluations, &outputs)?;
    assert_eq!(
        saved.fixture.current(&saved.store)?.progress,
        receipt.commit_revision
    );
    Ok(())
}

#[test]
fn empty_graph_keeps_capture() -> TestResult {
    for selected in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path().join("store"))?;
        let (_, model, source, observation) =
            super::super::super::domain::fixture_source(&store, true)?;
        let scope = araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        };
        store.register_processor(&scope, araphor_data::ProcessorClassV1::Required, 1)?;
        let store = &store;
        let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
        selection.select_graphs(
            if selected {
                araphor_data::Selection::All
            } else {
                araphor_data::Selection::Exact(Vec::new())
            },
            None,
        )?;
        let fixture = StorageFixture::new_scope(
            store,
            "counter",
            "Retain independent call state.".into(),
            selection.clone(),
        )?;
        let requests = if selected {
            let schema = &araphor_data::AnalysisStore::table_schemas()["graph_manifest"];
            AnalysisTableRequests::from([(
                "graph_manifest".into(),
                Some((0..schema.fields().len()).collect()),
            )])
        } else {
            AnalysisTableRequests::new()
        };
        let control = AnalysisReadControl::default();
        let capture = || -> TestResult<_> {
            let instance = fixture.current(store)?;
            let mut page = store.read_managed_tables_filtered(
                &selection.project(&requests)?,
                &ManagedRead {
                    source: None,
                    execution: None,
                    follow: false,
                    instance,
                    expected: None,
                    rebuild: false,
                    completed: None,
                },
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &control,
                None,
            )?;
            for call in [10, 11] {
                if page.state.prior(call).is_some() {
                    let evaluation = fixture.evaluation(&request("parameters"), call)?;
                    page.state.hydrate_prior(
                        call,
                        &fixture.model,
                        evaluation.parameters.map(|batch| sdk::Dataset {
                            name: "parameters".into(),
                            batches: vec![batch],
                        }),
                        None,
                    )?;
                }
            }
            Ok(page)
        };
        let initial = capture()?;
        assert_eq!(initial.page.next_change, None);
        assert_eq!(
            initial
                .page
                .tables
                .get("graph_manifest")
                .into_iter()
                .flatten()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            0
        );
        let first = request("unchanged-empty");
        let first_attempt = store.register_managed_attempt(&initial.state, &first, || Ok(()))?;
        let seeded = fixture.publish(
            store,
            &first_attempt,
            &[
                fixture.continued(&first, 10, Some(&initial.state))?,
                fixture.continued(&first, 11, Some(&initial.state))?,
            ],
            &[fixture.output(2)?, fixture.output(3)?],
        )?;
        assert_eq!(fixture.current(store)?.progress, seeded.commit_revision);
        let empty = capture()?;
        assert_eq!(empty.page.next_change, None);
        assert_eq!(
            empty
                .page
                .tables
                .get("graph_manifest")
                .into_iter()
                .flatten()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            0
        );
        let pending = request("empty-pending");
        let attempt = store.register_managed_attempt(&empty.state, &pending, || Ok(()))?;
        let evaluations = [
            fixture.continued(&pending, 10, Some(&empty.state))?,
            fixture.continued(&pending, 11, Some(&empty.state))?,
        ];
        let outputs = [fixture.output(8)?, fixture.output(9)?];
        let states = [araphor_analysis_types::GraphStateMember {
            record: None,
            position: None,
            fact: None,
            state: araphor_analysis_types::GraphPackageStateV1::Declared("0".into()),
        }];
        super::super::super::domain::commit_named_expiry(
            store,
            &model,
            &observation,
            0,
            None,
            "domain",
            Some((&states, false)),
        )?;
        let committed = store
            .managed_attempt([1; 16], "domain", "domain-0", &control)?
            .ok_or("Graph attempt")?
            .receipt()
            .ok_or("Graph receipt")?
            .clone();
        if !selected {
            let receipt = fixture.publish(store, &attempt, &evaluations, &outputs)?;
            assert!(receipt.commit_revision > committed.commit_revision);
            assert_eq!(fixture.current(store)?.progress, receipt.commit_revision);
            continue;
        }
        let before = GuardCut::read(store, &fixture)?;
        assert_eq!(before.history, [seeded]);
        let mut checked = false;
        assert!(
            matches!(
                store.register_managed_attempt(&empty.state, &request("empty-stale"), || {
                    checked = true;
                    Ok(())
                }),
                Err(araphor_data::Error::AnalysisSourceChanged { .. })
            ),
            "late Graph did not invalidate empty capture"
        );
        assert!(!checked);
        assert_eq!(GuardCut::read(store, &fixture)?, before);
        let failure = fixture
            .publish(store, &attempt, &evaluations, &outputs)
            .err()
            .ok_or("late Graph accepted stale empty publication")?;
        assert!(matches!(
            failure.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisSourceChanged { .. })
        ));
        assert_eq!(GuardCut::read(store, &fixture)?, before);
        let fresh = capture()?;
        assert_eq!(
            fresh.page.tables["graph_manifest"]
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        assert_eq!(fresh.page.next_change, Some(2000));
        assert!(fresh.page.extraction.references.iter().any(|entry| entry
            .result()
            .is_some_and(|result| result.result_id == committed.selected.result_id
                && result.commit_revision == committed.commit_revision)));
        assert_eq!(GuardCut::read(store, &fixture)?, before);
    }
    Ok(())
}
