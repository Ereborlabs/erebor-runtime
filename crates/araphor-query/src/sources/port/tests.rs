use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
use datafusion::physical_plan::collect;
use futures_util::FutureExt as _;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Debug, Default)]
struct Values {
    calls: AtomicUsize,
    fail: AtomicBool,
    keyed: bool,
    unshared: bool,
    seen: Mutex<Vec<Vec<u64>>>,
}

impl PortSource for Values {
    fn reusable(&self) -> bool {
        true
    }

    fn snapshot_bound(&self) -> bool {
        !self.unshared
    }

    fn key_columns(&self) -> &[(usize, usize)] {
        if self.keyed {
            &[(0, 0)]
        } else {
            &[]
        }
    }

    fn read<'a>(
        &'a self,
        _image: Option<SourceImage>,
        driver: Vec<sdk::RecordBatch>,
        _header: Vec<sdk::RecordBatch>,
        source: Arc<SourceSnapshot>,
        _context: Arc<TaskContext>,
    ) -> BoxFuture<'a, Result<super::PortRead>> {
        async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if self.fail.swap(false, Ordering::SeqCst) {
                return datafusion::common::exec_err!("fixture source failure");
            }
            let mut seen = driver
                .iter()
                .flat_map(|batch| {
                    batch
                        .column(0)
                        .as_any()
                        .downcast_ref::<sdk::arrow_array::UInt64Array>()
                        .unwrap()
                        .values()
                        .to_vec()
                })
                .collect::<Vec<_>>();
            seen.sort_unstable();
            self.seen.lock().unwrap().push(seen);
            let memory = source.memory().reserve_input(0)?;
            let input = sdk::Input {
                data: sdk::Dataset {
                    name: "values".into(),
                    batches: driver,
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: source
                        .snapshot()?
                        .page
                        .extraction
                        .meta
                        .commit_revision
                        .to_string(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: vec![],
                },
            };
            for batch in &input.data.batches {
                source.memory().retain_input(batch, &memory)?;
            }
            memory.try_resize(input.metadata_bytes())?;
            Ok((input, memory))
        }
        .map(|result| result.map(Into::into))
        .boxed()
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    session: crate::execution::Session,
    control: Arc<AnalysisReadControl>,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let engine = crate::execution::Engine::new(store, Default::default())?;
        let control = Arc::new(AnalysisReadControl::default());
        let session = engine.session(AnalysisSelectionV1::tenant([1; 16]), &control, 1)?;
        Ok(Self {
            _directory: directory,
            session,
            control,
        })
    }

    async fn port(&self, source: Arc<Values>) -> TestResult<SourcePort> {
        let driver = self
            .session
            .engine()
            .prepare("SELECT CAST(7 AS BIGINT UNSIGNED) AS value", vec![])
            .await?
            .0;
        let schema = Arc::new(driver.schema().as_arrow().clone());
        Ok(SourcePort::new(
            &self.session,
            "values".into(),
            schema,
            driver,
            LogicalPlanBuilder::empty(true).build()?,
            source,
        )
        .await?)
    }

    fn context(&self) -> TestResult<(Arc<SourceSnapshot>, SessionState)> {
        Self::capture(&self.session, None, &[], BTreeMap::new())
    }

    fn capture(
        session: &crate::execution::Session,
        managed: Option<araphor_data::ManagedRead>,
        plans: &[Arc<dyn ExecutionPlan>],
        mut requests: araphor_data::AnalysisTableRequests,
    ) -> TestResult<(Arc<SourceSnapshot>, SessionState)> {
        let indexed = managed.is_some();
        let source = SourceSnapshot::new(
            Arc::clone(session.engine().store()),
            session.selection().clone(),
            Default::default(),
            session.control().within(None)?,
            None,
            1,
            Arc::clone(session.memory()),
            managed,
        );
        let mut bounds = SourceSnapshot::requests(&mut requests, plans, None, None)?;
        SourceSnapshot::project_requests(&mut requests, &mut bounds, indexed)?;
        if indexed {
            let mut keys = Vec::new();
            for plan in plans {
                keys.extend(crate::sources::SourceLookup::keys(plan, None)?);
            }
            source.bind_index(crate::sources::SourceIndex::new(
                keys,
                Arc::clone(session.memory()),
            )?)?;
        }
        source.capture(&requests, bounds, super::super::ReadMode::Snapshot)?;
        let mut state = session.state()?;
        state.config_mut().set_extension(Arc::clone(&source));
        state
            .config_mut()
            .set_extension(Arc::clone(session.control()));
        state
            .config_mut()
            .set_extension(session.evaluation_permit()?);
        state
            .config_mut()
            .set_extension(session.call_context(Default::default()));
        Ok((source, state))
    }

    fn append(&self, cursor: u64) -> TestResult {
        use araphor_data::{EvidenceIntakeIdentityV1, EvidenceRecord, ValidatedEvidenceBatchV1};
        let frame = Vec::<u8>::try_from(&EvidenceRecord {
            operation: 7,
            ..Default::default()
        })?;
        self.session.engine().store().accept_validated_batch(
            EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "port-test".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    fn managed(
        &self,
        sql: &str,
        driver: &LogicalPlan,
    ) -> TestResult<araphor_data::ManagedInstance> {
        use araphor_data::{ManagedDestination, ManagedManifest, ManagedSpec, PackageGrantV1};
        use araphor_discovery_definition::{Definition, Program, ResolvedDefinition, Source};
        let store = self.session.engine().store();
        let definition = ResolvedDefinition::new(
            Definition {
                name: "source-binding".into(),
                description: String::new(),
                labels: BTreeMap::new(),
                program: Program::Sql {
                    source: Source::Inline { inline: sql.into() },
                },
            },
            sql.into(),
            vec![],
        )?;
        let revision = store.admit_definition([1; 16], &definition, || Ok(()))?;
        let instance = store.admit_managed(
            &ManagedSpec {
                tenant: [1; 16],
                id: "source-binding".into(),
                definition,
                manifest: ManagedManifest {
                    format: 1,
                    planner: "datafusion-55/source-binding-1".into(),
                    definition: revision,
                    calls: BTreeMap::new(),
                    selected_schema: driver.schema().as_arrow().clone(),
                },
                destination: ManagedDestination::Selected,
            },
            &PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: self.session.selection().clone(),
                expires_utc_ns: None,
                authorization_id: Some("source-binding".into()),
            },
            || Ok(()),
        )?;
        Ok(store.set_managed_running(
            [1; 16],
            &instance.spec.id,
            instance.lifecycle,
            true,
            || Ok(()),
        )?)
    }
}

#[tokio::test]
async fn bindings_share_one_cut() -> TestResult {
    let fixture = Fixture::new()?;
    let values = Arc::new(Values::default());
    let port = fixture.port(Arc::clone(&values)).await?;
    let (source, state) = fixture.context()?;
    let left = port.scan(&state, None, &[], None).await?;
    let right = port.scan(&state, None, &[], None).await?;
    let reads = [
        left.downcast_ref::<PortExec>().unwrap().read,
        right.downcast_ref::<PortExec>().unwrap().read,
    ];
    assert_ne!(reads[0], reads[1]);
    let (a, b) = tokio::try_join!(
        collect(left, state.task_ctx()),
        collect(right, state.task_ctx())
    )?;
    assert_eq!(a, b);
    assert_eq!(values.calls.load(Ordering::SeqCst), 1);
    let a = source
        .captured_input(&SourceOrigin::Port(reads[0]))?
        .ok_or("first binding")?;
    let b = source
        .captured_input(&SourceOrigin::Port(reads[1]))?
        .ok_or("second binding")?;
    assert_eq!(a.revision, b.revision);
    assert_eq!(a.coverage, b.coverage);
    assert!(Arc::ptr_eq(
        a.data.batches[0].column(0),
        b.data.batches[0].column(0)
    ));

    let (_, next) = fixture.context()?;
    collect(port.scan(&next, None, &[], None).await?, next.task_ctx()).await?;
    assert_eq!(values.calls.load(Ordering::SeqCst), 2);
    for image in [SourceImage::Before, SourceImage::After] {
        let imaged = port.imaged(image, &mut BTreeMap::new())?;
        collect(
            imaged.scan(&state, None, &[], None).await?,
            state.task_ctx(),
        )
        .await?;
    }
    assert_eq!(values.calls.load(Ordering::SeqCst), 4);
    for instant in [11, 12] {
        let mut clock = state.clone();
        clock.execution_props_mut().query_execution_start_time =
            Some(chrono::DateTime::from_timestamp_nanos(instant));
        let clocked = port.clocked(&clock);
        collect(
            clocked.scan(&state, None, &[], None).await?,
            state.task_ctx(),
        )
        .await?;
    }
    assert_eq!(values.calls.load(Ordering::SeqCst), 6);
    let before = port.imaged(SourceImage::Before, &mut BTreeMap::new())?;
    let repeated = before.imaged(SourceImage::After, &mut BTreeMap::new())?;
    let plan = repeated.scan(&state, None, &[], None).await?;
    assert!(plan.downcast_ref::<PortExec>().unwrap().binding.is_none());
    Ok(())
}

#[tokio::test]
async fn bindings_check_retry_context() -> TestResult {
    let fixture = Fixture::new()?;
    let values = Arc::new(Values {
        fail: AtomicBool::new(true),
        ..Default::default()
    });
    let port = fixture.port(Arc::clone(&values)).await?;
    let (source, state) = fixture.context()?;
    let first = port.scan(&state, None, &[], None).await?;
    let read = first.downcast_ref::<PortExec>().unwrap().read;
    let error = collect(first, state.task_ctx())
        .await
        .expect_err("source failure");
    assert!(
        matches!(error, DataFusionError::Execution(message) if message == "fixture source failure")
    );
    assert!(source.captured_input(&SourceOrigin::Port(read))?.is_none());
    let second = port.scan(&state, None, &[], None).await?;
    collect(second, state.task_ctx()).await?;
    assert_eq!(values.calls.load(Ordering::SeqCst), 2);
    let (_, other) = fixture.context()?;
    let key = (port.slot, None, None);
    assert!(source
        .bind_shared(
            key,
            None,
            123,
            Arc::clone(&port.schema),
            &other.task_ctx(),
            async {
                panic!("foreign context must not run the source");
            }
        )
        .await
        .is_err());
    fixture.control.cancel()?;
    assert!(source
        .bind_shared(
            key,
            None,
            124,
            Arc::clone(&port.schema),
            &state.task_ctx(),
            async {
                panic!("cancelled context must not run the source");
            }
        )
        .await
        .is_err());
    assert_eq!(values.calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn keyed_ports_keep_reads() -> TestResult {
    use araphor_data::{ManagedRead, ManagedSourceRead};
    use datafusion::logical_expr::JoinType;
    use datafusion::physical_expr::expressions::Column;
    use datafusion::physical_plan::joins::{HashJoinExecBuilder, PartitionMode};

    let fixture = Fixture::new()?;
    for cursor in 1..=2 {
        fixture.append(cursor)?;
    }
    let sql = "SELECT source_cursor AS value FROM events";
    let (driver, requests) = fixture.session.engine().prepare(sql, vec![]).await?;
    let instance = fixture.managed(sql, &driver)?;
    let values = Arc::new(Values {
        keyed: true,
        ..Default::default()
    });
    let port = SourcePort::new(
        &fixture.session,
        "values".into(),
        Arc::new(driver.schema().as_arrow().clone()),
        SourceImage::After.plan(&driver)?,
        LogicalPlanBuilder::empty(true).build()?,
        values.clone(),
    )
    .await?;
    let state = fixture.session.state()?;
    let full = port.scan(&state, None, &[], None).await?;
    assert!(full.downcast_ref::<PortExec>().unwrap().binding.is_some());
    let mut plans = vec![Arc::clone(&full)];
    for (key, predicate) in [(1, ""), (2, ""), (3, ""), (0, "WHERE false")] {
        let (logical, _) = fixture
            .session
            .engine()
            .prepare(
                &format!("SELECT CAST({key} AS BIGINT UNSIGNED) AS value {predicate}"),
                vec![],
            )
            .await?;
        let left = state.create_physical_plan(&logical).await?;
        let right = port.scan(&state, None, &[], None).await?;
        let column = Arc::new(Column::new("value", 0)) as Arc<dyn PhysicalExpr>;
        let join = HashJoinExecBuilder::new(
            left,
            right,
            vec![(Arc::clone(&column), column)],
            JoinType::Inner,
        )
        .with_partition_mode(PartitionMode::CollectLeft)
        .build_exec()?;
        let plan = crate::sources::SourceLookup.optimize(join, state.config_options())?;
        let mut producers = 0;
        let mut readers = 0;
        PortExec::apply(&plan, &mut |node| {
            if node.is::<crate::sources::keys::KeyBuildExec>() {
                producers += 1;
            }
            if let Some(source) = SourceData::from_plan(node.as_ref()) {
                readers += usize::from(source.key.is_some());
            }
            if let Some(port) = node.downcast_ref::<PortExec>() {
                assert!(port.binding.is_none());
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        assert_eq!((producers, readers), (1, 1));
        plans.push(plan);
    }
    let (source, context) = Fixture::capture(
        &fixture.session,
        Some(ManagedRead {
            instance,
            execution: None,
            expected: None,
            rebuild: false,
            follow: true,
            source: Some(ManagedSourceRead::Initial),
            completed: None,
        }),
        &plans,
        requests,
    )?;
    assert!(source.source_view()?.is_some());
    let rows = collect(full, context.task_ctx()).await?;
    assert_eq!(
        rows.iter().map(sdk::RecordBatch::num_rows).sum::<usize>(),
        2
    );
    collect(
        port.scan(&context, None, &[], None).await?,
        context.task_ctx(),
    )
    .await?;
    assert_eq!(values.calls.load(Ordering::SeqCst), 1);
    for (index, (plan, expected)) in plans
        .into_iter()
        .skip(1)
        .zip([vec![1], vec![2], vec![], vec![]])
        .enumerate()
    {
        let result = collect(plan, context.task_ctx()).await?;
        let actual = result
            .iter()
            .flat_map(|batch| {
                batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        assert_eq!(values.calls.load(Ordering::SeqCst), (index + 2).min(4));
    }
    assert_eq!(values.calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        *values.seen.lock().unwrap(),
        [vec![1, 2], vec![1], vec![2], vec![]]
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_stops_binding_waiters() -> TestResult {
    let fixture = Fixture::new()?;
    let port = fixture.port(Arc::new(Values::default())).await?;
    let (source, state) = fixture.context()?;
    let context = state.task_ctx();
    let key = (port.slot, None, None);
    let (started, ready) = tokio::sync::oneshot::channel();
    let first = source.bind_shared(key, None, 101, Arc::clone(&port.schema), &context, async {
        let _ = started.send(());
        std::future::pending::<Result<()>>().await
    });
    tokio::pin!(first);
    tokio::select! {
        result = &mut first => return Err(format!("source completed before cancellation: {result:?}").into()),
        result = ready => result?,
    }
    let second = source.bind_shared(key, None, 102, Arc::clone(&port.schema), &context, async {
        panic!("a cancelled waiter must not initialize the source");
    });
    tokio::pin!(second);
    assert!(futures_util::poll!(&mut second).is_pending());
    fixture.control.cancel()?;
    let (a, b) = tokio::join!(first, second);
    assert!(a.is_err());
    assert!(b.is_err());
    assert!(source.captured_input(&SourceOrigin::Port(101))?.is_none());
    assert!(source.captured_input(&SourceOrigin::Port(102))?.is_none());
    Ok(())
}

#[tokio::test]
async fn native_reset_isolates_cuts() -> TestResult {
    use araphor_data::{ManagedRead, ManagedSourceRead};
    use datafusion::datasource::{provider_as_source, view::ViewTable};
    use datafusion::logical_expr::JoinType;
    use datafusion::physical_expr::expressions::Column;
    use datafusion::physical_plan::execution_plan::reset_plan_states;
    use datafusion::physical_plan::joins::{HashJoinExecBuilder, PartitionMode};

    let fixture = Fixture::new()?;
    fixture.append(1)?;
    let sql = "SELECT source_cursor AS value FROM events";
    let (driver, requests) = fixture.session.engine().prepare(sql, vec![]).await?;
    let instance = fixture.managed(sql, &driver)?;
    let values = Arc::new(Values {
        keyed: true,
        ..Default::default()
    });
    let port = SourcePort::new(
        &fixture.session,
        "values".into(),
        Arc::new(driver.schema().as_arrow().clone()),
        SourceImage::After.plan(&driver)?,
        LogicalPlanBuilder::empty(true).build()?,
        values.clone(),
    )
    .await?;
    let mut state = fixture.session.state()?;
    *state.config_mut() = state
        .config()
        .clone()
        .set_bool("datafusion.optimizer.enable_dynamic_filter_pushdown", false);
    let right = port.scan(&state, None, &[], None).await?;
    let read = right.downcast_ref::<PortExec>().unwrap().read;
    let admitted = LogicalPlanBuilder::scan(
        "before.units",
        provider_as_source(Arc::new(ViewTable::new(driver.clone(), None))),
        None,
    )?
    .build()?;
    assert!(crate::definition::physical::PackageExec::before_reusable(
        &admitted, &driver, &right, &state
    )?);
    let native = right.downcast_ref::<PortExec>().unwrap();
    let scalar = Arc::new(
        datafusion::physical_plan::scalar_subquery::ScalarSubqueryExec::new(
            Arc::clone(&native.inputs[0]),
            vec![],
            datafusion::logical_expr::physical_planning_context::ScalarSubqueryResults::new(0),
        ),
    );
    let hidden = native.replace_inputs([scalar, Arc::clone(&native.inputs[1])])?;
    assert!(!crate::definition::physical::PackageExec::before_reusable(
        &admitted, &driver, &hidden, &state
    )?);
    let mut dynamic = state.clone();
    *dynamic.config_mut() = dynamic.config().clone().set_bool(
        "datafusion.optimizer.enable_join_dynamic_filter_pushdown",
        true,
    );
    assert!(!crate::definition::physical::PackageExec::before_reusable(
        &admitted, &driver, &right, &dynamic
    )?);

    let schema = right.schema();
    let keys = SourceProvider::identity()?;
    let left = SourceProvider::port(keys, Arc::clone(&schema))
        .scan(&state, None, &[], None)
        .await?;
    let column = Arc::new(Column::new("value", 0)) as Arc<dyn PhysicalExpr>;
    let join = HashJoinExecBuilder::new(
        left,
        right,
        vec![(Arc::clone(&column), column)],
        JoinType::Inner,
    )
    .with_partition_mode(PartitionMode::CollectLeft)
    .build_exec()?;
    let shared = crate::sources::SourceLookup.optimize(join, state.config_options())?;
    let mut probe = None;
    PortExec::apply(&shared, &mut |node| {
        if node.is::<PortExec>() {
            probe = Some(Arc::clone(node));
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    let probe = probe.ok_or("reset source probe")?;
    let managed = || {
        Some(ManagedRead {
            instance: instance.clone(),
            execution: None,
            expected: None,
            rebuild: false,
            follow: true,
            source: Some(ManagedSourceRead::Initial),
            completed: None,
        })
    };
    let plans = [Arc::clone(&shared)];
    let (a, state_a) = Fixture::capture(&fixture.session, managed(), &plans, requests.clone())?;
    fixture.append(2)?;
    let control_b = Arc::new(AnalysisReadControl::default());
    let session_b =
        fixture
            .session
            .engine()
            .session(fixture.session.selection().clone(), &control_b, 1)?;
    let (b, state_b) = Fixture::capture(&session_b, managed(), &plans, requests)?;
    let cut_a = a.snapshot()?.page.extraction.meta.commit_revision;
    let cut_b = b.snapshot()?.page.extraction.meta.commit_revision;
    assert!(cut_a < cut_b);
    for (source, key) in [(&a, 1), (&b, 2)] {
        let batch = sdk::RecordBatch::try_new(
            Arc::clone(&schema),
            vec![Arc::new(sdk::arrow_array::UInt64Array::from(vec![key]))],
        )?;
        source.bind_port(keys, Arc::clone(&schema), vec![batch], None)?;
    }
    let first = reset_plan_states(Arc::clone(&shared))?;
    let second = reset_plan_states(Arc::clone(&shared))?;
    let (rows_a, rows_b) = tokio::try_join!(
        collect(first, state_a.task_ctx()),
        collect(second, state_b.task_ctx())
    )?;
    for (rows, expected) in [(&rows_a, 1), (&rows_b, 2)] {
        let values = rows
            .iter()
            .flat_map(|batch| {
                batch
                    .column(1)
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect::<Vec<_>>();
        assert_eq!(values, [expected]);
    }
    for (source, cut, expected) in [(&a, cut_a, 1), (&b, cut_b, 2)] {
        let input = source
            .captured_input(&SourceOrigin::Port(read))?
            .ok_or("reset source binding")?;
        assert_eq!(input.revision.id, cut.to_string());
        assert_eq!(
            input.coverage,
            sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: vec![]
            }
        );
        assert_eq!(input.data.rows(), 1);
        assert_eq!(
            input
                .data
                .batches
                .iter()
                .flat_map(|batch| batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::UInt64Array>()
                    .unwrap()
                    .values()
                    .to_vec())
                .collect::<Vec<_>>(),
            [expected]
        );
    }
    assert_eq!(values.calls.load(Ordering::SeqCst), 2);
    let mut seen = values.seen.lock().unwrap().clone();
    seen.sort();
    assert_eq!(seen, [vec![1], vec![2]]);
    fixture.control.cancel()?;
    assert!(
        collect(reset_plan_states(Arc::clone(&probe))?, state_a.task_ctx())
            .await
            .is_err()
    );
    let rows = collect(reset_plan_states(probe)?, state_b.task_ctx()).await?;
    let expected = rows_b
        .iter()
        .map(|batch| batch.project(&[1]))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(rows, expected);
    Ok(())
}

#[tokio::test]
async fn ports_require_binding_contract() -> TestResult {
    let fixture = Fixture::new()?;
    let values = Arc::new(Values {
        unshared: true,
        ..Default::default()
    });
    let port = fixture.port(Arc::clone(&values)).await?;
    let (_, state) = fixture.context()?;
    let first = port.scan(&state, None, &[], None).await?;
    let second = port.scan(&state, None, &[], None).await?;
    assert!(first.downcast_ref::<PortExec>().unwrap().binding.is_none());
    tokio::try_join!(
        collect(first, state.task_ctx()),
        collect(second, state.task_ctx())
    )?;
    assert_eq!(values.calls.load(Ordering::SeqCst), 2);
    Ok(())
}
