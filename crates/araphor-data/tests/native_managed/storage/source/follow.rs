use super::*;
use araphor_data::analysis::native::ManagedGraphTransaction;
use araphor_data::{ManagedFrontier, ManagedGraphOperation, ProcessorClassV1, ProcessorScopeV1};

struct FollowFixture {
    source: SourceFixture,
    graph: Option<sdk::Model>,
}

impl FollowFixture {
    fn new(store: &NativeStore, graph: bool) -> TestResult<Self> {
        let mut source = SourceFixture::new(store)?;
        let mut spec = source.fixture.instance.spec.clone();
        spec.id = "graph-prefix".into();
        spec.destination = ManagedDestination::Graph {
            source: identity(),
            calls: if graph {
                BTreeSet::from([10, 11, 13])
            } else {
                BTreeSet::from([10, 11])
            },
            operation: ManagedGraphOperation::Evaluate,
            events_sql: "SELECT * FROM events".into(),
            control_sql: "SELECT * FROM graph_state".into(),
        };
        let graph = if graph {
            let package = crate::Fixture::new(store, [1; 16], "follow-graph", true)?;
            let call = package.spec.manifest.calls[&10].clone();
            let row = store
                .view()?
                .package_revision(
                    [1; 16],
                    &call.package.package_id,
                    &call.package.revision,
                    &AnalysisReadControl::default(),
                )?
                .ok_or("Graph descriptor")?;
            let descriptor: sdk::Package = serde_json::from_slice(&row.descriptor)?;
            let mut images = spec.definition.images.clone();
            images.push(call.image.clone());
            let sql = format!(
                "WITH unused AS (SELECT * FROM \"managed-graph\".\"1\".count()) {} CROSS JOIN \"managed-graph\".\"1\".count() g",
                spec.definition.sql
            );
            let mut definition = spec.definition.definition.clone();
            definition.program = Program::Sql {
                source: Source::Inline {
                    inline: sql.clone(),
                },
            };
            spec.definition = ResolvedDefinition::new(definition, sql, images)?;
            spec.manifest.definition =
                store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
            spec.manifest.calls.insert(12, call.clone());
            spec.manifest.calls.insert(13, call);
            Some(descriptor.exports[0].clone())
        } else {
            None
        };
        let instance = store.admit_managed(&spec, &source.fixture.instance.grant, || Ok(()))?;
        source.fixture.instance =
            store.set_managed_running([1; 16], &spec.id, instance.lifecycle, true, || Ok(()))?;
        source.requests = ["events", "context_versions"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    Some((0..AnalysisStore::table_schemas()[name].fields().len()).collect()),
                )
            })
            .collect();
        store.register_processor(&Self::scope(), ProcessorClassV1::Required, 1)?;
        crate::source::append(store, 1)?;
        Ok(Self { source, graph })
    }

    fn scope() -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: identity(),
        }
    }

    fn read(&self, store: &NativeStore, follow: bool) -> TestResult<ManagedPage> {
        let instance = self.source.fixture.current(store)?;
        let selection = instance
            .spec
            .destination
            .selection(&instance.grant.selection)?
            .project(&self.source.requests)?;
        let page = store.read_managed_tables_filtered(
            &selection,
            &ManagedRead {
                instance,
                expected: None,
                rebuild: false,
                follow,
                completed: follow.then_some(0),
                source: Some(ManagedSourceRead::Initial),
                execution: Some(Arc::clone(&self.source.execution)),
            },
            AnalysisTableRead {
                requests: &self.source.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?;
        crate::source::select(store, &page, &[1], None)?;
        Ok(page)
    }

    fn input() -> ManagedRequest {
        let mut input = request("graph-prefix");
        input.frontier = Some(ManagedFrontier {
            cursor: vec![1],
            next_change: None,
            pending: false,
        });
        input
    }

    fn append(store: &NativeStore, same_source: bool) -> TestResult {
        if same_source {
            crate::source::append(store, 2)?;
        } else {
            let mut source = identity();
            source.source_id = [93; 16];
            let frame = Vec::<u8>::try_from(&EvidenceRecord {
                observed_boottime_ns: 2,
                ..Default::default()
            })?;
            store.accept_validated_batch(
                source,
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: 1,
                    last_cursor: 1,
                    intake_utc_ns: 2,
                    frame_ends: vec![frame.len()],
                    framed_records: frame.into(),
                },
            )?;
        }
        Ok(())
    }

    fn publish(
        &self,
        store: &NativeStore,
        attempt: &Arc<ManagedAttempt>,
    ) -> TestResult<ManagedReceipt> {
        let fixture = &self.source.fixture;
        let evaluations = [
            fixture.evaluation(attempt.request(), 10)?,
            fixture.evaluation(attempt.request(), 11)?,
        ];
        let outputs = [fixture.output(2)?, fixture.output(3)?];
        let control = AnalysisReadControl::default();
        let graph = self
            .graph
            .as_ref()
            .map(|model| -> TestResult<_> {
                let transaction = ManagedGraphTransaction::new(
                    store,
                    Arc::clone(attempt),
                    13,
                    model,
                    Vec::new(),
                    Arc::new(crate::graph::Budget),
                    &control,
                )?;
                assert_eq!(
                    crate::graph::read_nodes(&transaction, store)?.data.rows(),
                    0
                );
                transaction.stage(
                    store,
                    "task",
                    crate::graph::node(&transaction, b"task-a")?,
                    Arc::new(()),
                    &control,
                )?;
                assert_eq!(
                    crate::graph::read_nodes(&transaction, store)?.data.rows(),
                    1
                );
                Ok((
                    transaction.freeze(store, &control)?,
                    crate::publication::evaluation(attempt),
                    crate::publication::output(model)?,
                ))
            })
            .transpose()?;
        let mut returns = [10, 11]
            .into_iter()
            .enumerate()
            .map(|(index, call)| ManagedReturn {
                call,
                evaluation: &evaluations[index],
                output: &outputs[index],
                changes: None,
                graph: None,
                retained: None,
            })
            .collect::<Vec<_>>();
        if let Some((journal, evaluation, output)) = &graph {
            returns.push(ManagedReturn {
                call: 13,
                evaluation,
                output,
                changes: None,
                graph: Some(journal),
                retained: None,
            });
        }
        let budget = crate::graph::Budget;
        let (receipt, progress) = store.commit_managed_graph(
            store.prepare_managed(&ManagedCommit {
                control: &control,
                budget: &budget,
                attempt,
                completed: true,
                now_utc_ns: 10,
                returns: &returns,
                selected: &outputs[0].datasets[0],
                selected_schema: &fixture.instance.spec.manifest.selected_schema,
            })?,
            || Ok(()),
        )?;
        assert_eq!(receipt.graph.as_ref(), Some(&receipt.selected));
        assert_eq!(
            progress.ok_or("Source progress")?.commit_revision,
            receipt.commit_revision
        );
        Ok(receipt)
    }

    fn check_results(
        fixture: &Fixture,
        store: &NativeStore,
        receipt: &ManagedReceipt,
    ) -> TestResult {
        assert_eq!(
            receipt.results.keys().copied().collect::<Vec<_>>(),
            [10, 11, 13]
        );
        assert!(!receipt.results.contains_key(&12));
        for (call, value) in [(10, 2), (11, 3)] {
            assert_eq!(
                fixture.checkpoint(store, &receipt.results[&call])?.datasets[0].batches,
                fixture
                    .output(value)?
                    .checkpoint
                    .ok_or("checkpoint")?
                    .datasets[0]
                    .batches
            );
        }
        let view = store.view()?;
        let publication = view
            .managed_graph_publication([1; 16], &receipt.selected, &AnalysisReadControl::default())?
            .ok_or("Graph publication")?;
        assert_eq!(publication.reference, receipt.selected);
        let mapping = view
            .managed_graph(
                [1; 16],
                &fixture.instance.spec.id,
                &AnalysisReadControl::default(),
            )?
            .ok_or("Graph mapping")?;
        assert_eq!(publication.graph, mapping.graph);
        assert_eq!(
            publication.heads.keys().copied().collect::<Vec<_>>(),
            [mapping.writers[&13]]
        );
        assert_eq!(
            publication.heads[&mapping.writers[&13]].1,
            receipt.commit_revision
        );
        let graph = araphor_graph::native::Graph::new(mapping.graph)?;
        let graph = graph.view(view.snapshot().clone(), BTreeMap::new(), &|_, _, _| {
            Ok(None)
        })?;
        assert!(graph
            .member(
                mapping.writers[&13],
                mapping.relations["task"].0,
                b"owner",
                b"task-a",
                &|_, _, _| Ok(None)
            )?
            .is_some());
        Ok(())
    }

    fn cut(
        store: &NativeStore,
    ) -> TestResult<(
        araphor_data::AnalysisStoreMetaV1,
        BTreeMap<Vec<u8>, Vec<u8>>,
        Option<fjall::Cursor>,
    )> {
        Ok((
            store.meta()?,
            records(store.view()?.as_ref(), b"")?,
            store.database().inner().journal_head()?,
        ))
    }

    fn saved_follow(store: &NativeStore, id: &str) -> TestResult<bool> {
        #[derive(serde::Deserialize)]
        struct Follow {
            follow: bool,
        }
        #[derive(serde::Deserialize)]
        struct Saved {
            request: ManagedRequest,
            capture: Follow,
        }
        for bytes in records(store.view()?.as_ref(), b"\0data/a")?.values() {
            let saved: Saved = rmp_serde::from_slice(&bytes[1..])?;
            if saved.request.id == id {
                return Ok(saved.capture.follow);
            }
        }
        Err("saved Follow capture".into())
    }
}

#[test]
fn graph_reopen_uses_selected_call_subset() -> TestResult {
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
    drop((page, attempt));
    let FollowFixture { source, .. } = fixture;
    let SourceFixture {
        fixture, execution, ..
    } = source;
    drop(execution);
    drop(store);
    let store = NativeStore::open(&root)?;
    let saved = store
        .managed_attempt(
            [1; 16],
            &fixture.instance.spec.id,
            "graph-prefix",
            &AnalysisReadControl::default(),
        )?
        .ok_or("reopened attempt")?;
    assert_eq!(saved.receipt(), Some(&receipt));
    assert!(FollowFixture::saved_follow(
        &store,
        saved.request().id.as_str()
    )?);
    FollowFixture::check_results(&fixture, &store, &receipt)?;
    Ok(())
}

#[test]
fn graph_follow_retains_prefix() -> TestResult {
    for same_source in [false, true] {
        for before_admission in [false, true] {
            let directory = tempfile::tempdir()?;
            let store = NativeStore::open(directory.path().join("data"))?;
            let fixture = FollowFixture::new(&store, true)?;
            let page = fixture.read(&store, true)?;
            assert!(page.state.follows_graph());
            let captured = page.state.revision();
            let position = page.state.source().ok_or("captured source")?.position();
            if before_admission {
                FollowFixture::append(&store, same_source)?;
            }
            let attempt = Arc::new(store.register_managed_attempt(
                &page.state,
                &FollowFixture::input(),
                || Ok(()),
            )?);
            assert_eq!(attempt.captured_revision(), captured);
            if !before_admission {
                FollowFixture::append(&store, same_source)?;
            }
            let receipt = fixture.publish(&store, &attempt)?;
            assert!(receipt.commit_revision > captured);
            let current = fixture.source.fixture.current(&store)?;
            assert_eq!(current.progress, receipt.commit_revision);
            FollowFixture::check_results(&fixture.source.fixture, &store, &receipt)?;
            assert!(matches!(
                store
                    .managed_result(
                        &current,
                        &receipt.selected.result_id,
                        10,
                        &AnalysisReadControl::default()
                    )?
                    .kind,
                araphor_data::InstanceResultKindV1::Selected
            ));
            let result = store.managed_result(
                &current,
                &receipt.results[&10].result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert!(!result.current);
            assert_eq!(result.result, receipt.results[&10]);
            assert_eq!(result.receipt, receipt);
            assert_eq!(
                receipt.frontier.as_ref(),
                attempt.request().frontier.as_ref()
            );
            let health = store
                .processor_health(&FollowFixture::scope())?
                .ok_or("processor health")?;
            assert_eq!(health.consumed_cursor, 1);
            assert_eq!(health.accepted_cursor, if same_source { 2 } else { 1 });
            let saved = store
                .managed_attempt(
                    [1; 16],
                    &current.spec.id,
                    "graph-prefix",
                    &AnalysisReadControl::default(),
                )?
                .ok_or("saved attempt")?;
            assert!(FollowFixture::saved_follow(
                &store,
                saved.request().id.as_str()
            )?);
            assert_eq!(saved.captured_revision(), captured);
            let parent = store
                .managed_resume([1; 16], &current.spec.id, &AnalysisReadControl::default())?
                .source
                .ok_or("saved source")?;
            assert_eq!(parent.position, position);
            assert_eq!(parent.result, receipt.selected);
        }
    }
    Ok(())
}

#[test]
fn finite_graph_rejects_changes() -> TestResult {
    for same_source in [false, true] {
        for before_admission in [false, true] {
            let directory = tempfile::tempdir()?;
            let store = NativeStore::open(directory.path().join("data"))?;
            let fixture = FollowFixture::new(&store, true)?;
            let page = fixture.read(&store, false)?;
            assert!(!page.state.follows_graph());
            if before_admission {
                FollowFixture::append(&store, same_source)?;
                let before = FollowFixture::cut(&store)?;
                assert!(matches!(
                    store.register_managed_attempt(&page.state, &FollowFixture::input(), || Ok(())),
                    Err(Error::AnalysisSourceChanged { .. })
                ));
                assert_eq!(FollowFixture::cut(&store)?, before);
            } else {
                let attempt = Arc::new(store.register_managed_attempt(
                    &page.state,
                    &FollowFixture::input(),
                    || Ok(()),
                )?);
                FollowFixture::append(&store, same_source)?;
                let before = FollowFixture::cut(&store)?;
                let error = fixture
                    .publish(&store, &attempt)
                    .err()
                    .ok_or("stale finite publication succeeded")?;
                assert!(
                    matches!(
                        error.downcast_ref::<Error>(),
                        Some(Error::AnalysisSourceChanged { .. })
                    ),
                    "{error:?}"
                );
                assert_eq!(FollowFixture::cut(&store)?, before);
            }
            assert!(store.processor_result(&FollowFixture::scope())?.is_none());
        }
    }
    Ok(())
}

#[test]
fn source_metadata_denies_graph() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("data"))?;
    let fixture = FollowFixture::new(&store, false)?;
    let page = fixture.read(&store, true)?;
    let attempt = Arc::new(store.register_managed_attempt(
        &page.state,
        &FollowFixture::input(),
        || Ok(()),
    )?);
    let before = FollowFixture::cut(&store)?;
    assert!(matches!(
        ManagedGraphTransaction::new(
            &store,
            Arc::clone(&attempt),
            10,
            &fixture.source.fixture.model,
            Vec::new(),
            Arc::new(crate::graph::Budget),
            &AnalysisReadControl::default()
        ),
        Err(Error::Package {
            code: Code::Denied,
            field: "Graph invocation capability",
            ..
        })
    ));
    assert_eq!(FollowFixture::cut(&store)?, before);
    let receipt = fixture.publish(&store, &attempt)?;
    assert_eq!(
        receipt.results.keys().copied().collect::<Vec<_>>(),
        [10, 11]
    );
    assert!(store
        .view()?
        .managed_graph_publication([1; 16], &receipt.selected, &AnalysisReadControl::default())?
        .is_none());
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                &fixture.source.fixture.instance.spec.id,
                "graph-prefix",
                &AnalysisReadControl::default()
            )?
            .ok_or("Source attempt")?
            .receipt(),
        Some(&receipt)
    );
    Ok(())
}
