use super::*;

mod arrivals;
use crate::{GraphOwner, GraphProgram, InstanceHost};
use araphor_data::{ManagedGraphOperation, ProcessorScopeV1};

struct Running {
    stop: watch::Sender<bool>,
    feed: tokio::task::JoinHandle<crate::Result<()>>,
    host: tokio::task::JoinHandle<crate::Result<()>>,
}

impl Running {
    fn start(owner: Arc<GraphOwner>, host: Arc<InstanceHost>) -> Self {
        let (stop, receiver) = watch::channel(false);
        let host = tokio::spawn(host.serve(receiver.clone(), u64::MAX));
        let feed = tokio::spawn(owner.run(receiver));
        Self { stop, feed, host }
    }

    async fn stop(self) -> TestResult {
        self.stop.send_replace(true);
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            self.feed.await??;
            self.host.await??;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await??;
        Ok(())
    }
}

async fn program(fixture: &Fixture) -> TestResult<GraphProgram> {
    let publication = fixture.prepare("").await?;
    let program = GraphProgram {
        grant: publication.grant.clone(),
        definition: publication.prepared.resolved().clone(),
        events_sql: "SELECT * FROM events".into(),
    };
    let expiry = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&fixture.control),
        )
        .await?;
    for definition in [&program.definition, &expiry] {
        fixture.authority.commit_many(
            &[(&program.grant, PackageActionV1::Install, None)],
            &mut || {
                fixture.query.store().admit_definition(
                    fixture.source.tenant_id,
                    definition,
                    || {
                        program.grant.remaining()?;
                        fixture.control.check()
                    },
                )?;
                Ok(())
            },
        )?;
    }
    for operation in [
        ManagedGraphOperation::Evaluate,
        ManagedGraphOperation::Expire,
    ] {
        assert!(fixture
            .query
            .store()
            .managed_instance(
                fixture.source.tenant_id,
                &operation.instance_id(&fixture.source),
                &fixture.control,
            )?
            .is_none());
    }
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    Ok(program)
}

pub(super) fn append(
    query: &Arc<Engine>,
    source: &EvidenceIntakeIdentityV1,
    record: &araphor_data::DiscoveryRecordV1,
    cursor: u64,
) -> TestResult {
    query.store().accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: cursor,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    Ok(())
}

fn scope(source: &EvidenceIntakeIdentityV1) -> ProcessorScopeV1 {
    ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    }
}

pub(super) async fn observe(
    query: &Arc<Engine>,
    ready: impl FnMut() -> TestResult<bool>,
) -> TestResult {
    observe_for(query, std::time::Duration::from_secs(30), ready).await
}

pub(super) async fn observe_for(
    query: &Arc<Engine>,
    timeout: std::time::Duration,
    mut ready: impl FnMut() -> TestResult<bool>,
) -> TestResult {
    let mut notices = query.store().subscribe_revision();
    tokio::time::timeout(timeout, async {
        loop {
            notices.borrow_and_update();
            let observed = match ready() {
                Err(error)
                    if matches!(
                        error.downcast_ref::<araphor_data::Error>(),
                        Some(araphor_data::Error::Package {
                            code: Code::Incomplete,
                            field: "managed pending attempt",
                            ..
                        })
                    ) =>
                {
                    false
                }
                result => result?,
            };
            if observed {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
            notices.changed().await?;
        }
    })
    .await??;
    Ok(())
}

fn complete(
    query: &Arc<Engine>,
    control: &AnalysisReadControl,
    source: &EvidenceIntakeIdentityV1,
    cursor: u64,
) -> TestResult<bool> {
    if !query
        .store()
        .processor_health(&scope(source))?
        .is_some_and(|health| health.consumed_cursor == cursor)
    {
        return Ok(false);
    }
    for operation in [
        ManagedGraphOperation::Evaluate,
        ManagedGraphOperation::Expire,
    ] {
        if !query
            .store()
            .managed_instance(source.tenant_id, &operation.instance_id(source), control)?
            .is_some_and(|instance| instance.running && instance.progress > 0)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[tokio::test]
async fn feed_advances_sources() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        records,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority,
            vec![program],
            &control,
        )
        .await?,
    );
    let second = EvidenceIntakeIdentityV1 {
        source_id: [61; 16],
        ..source.clone()
    };
    append(&query, &second, &records[0], 1)?;
    assert!(query.store().processor_health(&scope(&second))?.is_some());
    assert!(query.store().processor_result(&scope(&second))?.is_none());
    let running = Running::start(Arc::clone(&owner), host);
    observe(&query, || {
        Ok(complete(&query, &control, &source, 3)? && complete(&query, &control, &second, 1)?)
    })
    .await?;
    let first = query
        .store()
        .processor_result(&scope(&source))?
        .ok_or("first Graph head")?;
    let other = query
        .store()
        .processor_result(&scope(&second))?
        .ok_or("second Graph head")?;
    assert_ne!(first.result_id, other.result_id);
    let old = query
        .store()
        .graph_result(source.tenant_id, &first.result_id)?;
    append(&query, &source, &records[0], 4)?;
    observe(&query, || {
        Ok(query
            .store()
            .processor_health(&scope(&source))?
            .is_some_and(|health| health.consumed_cursor == 4))
    })
    .await?;
    assert_eq!(
        query.store().processor_result(&scope(&second))?,
        Some(other)
    );
    assert_eq!(
        query
            .store()
            .graph_result(source.tenant_id, &first.result_id)?,
        old
    );
    running.stop().await?;
    drop(owner);
    assert!(!query.store().graph_enabled());
    let lease = query.store().lease_managed()?;
    drop(lease);
    assert_eq!(query.memory().input_reserved(), 0);
    Ok(())
}

#[tokio::test]
async fn feed_keeps_explicit_stop() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        records,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority.clone(),
            vec![program.clone()],
            &control,
        )
        .await?,
    );
    let running = Running::start(Arc::clone(&owner), Arc::clone(&host));
    observe(&query, || complete(&query, &control, &source, 3)).await?;
    let id = ManagedGraphOperation::Evaluate.instance_id(&source);
    let crate::instance::Restored::Present(job) =
        host.restore(source.tenant_id, &id, &control).await?
    else {
        return Err("Graph job".into());
    };
    let stopped = host
        .stop(Arc::clone(&job), job.admitted().lifecycle, &control)
        .await?;
    assert!(!stopped.admitted().running);
    let saved = query.store().processor_result(&scope(&source))?;
    running.stop().await?;
    drop(stopped);
    drop(job);
    drop(owner);
    drop(host);
    append(&query, &source, &records[0], 4)?;
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts);
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority,
            vec![program],
            &control,
        )
        .await?,
    );
    let second = EvidenceIntakeIdentityV1 {
        source_id: [62; 16],
        ..source.clone()
    };
    append(&query, &second, &records[0], 1)?;
    let running = Running::start(Arc::clone(&owner), host);
    observe(&query, || complete(&query, &control, &second, 1)).await?;
    assert!(
        !query
            .store()
            .managed_instance(source.tenant_id, &id, &control)?
            .ok_or("retained stopped Graph job")?
            .running
    );
    assert_eq!(query.store().processor_result(&scope(&source))?, saved);
    assert_eq!(
        query
            .store()
            .processor_health(&scope(&source))?
            .ok_or("stopped Graph progress")?
            .consumed_cursor,
        3
    );
    running.stop().await?;
    drop(owner);
    Ok(())
}

#[tokio::test]
async fn feed_stops_retired_sources() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority.clone(),
            vec![program.clone()],
            &control,
        )
        .await?,
    );
    let running = Running::start(Arc::clone(&owner), host);
    observe(&query, || complete(&query, &control, &source, 3)).await?;
    running.stop().await?;
    drop(owner);
    query
        .store()
        .retire_required(&araphor_data::ProcessorRetirementV1 {
            scope: scope(&source),
            change_id: "graph-feed-downtime".into(),
            reason: "Stop this required processor.".into(),
            expected_cursor: 3,
            cutoff_cursor: 3,
        })?;
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts);
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority,
            vec![program],
            &control,
        )
        .await?,
    );
    let running = Running::start(Arc::clone(&owner), host);
    observe(&query, || {
        for operation in [
            ManagedGraphOperation::Evaluate,
            ManagedGraphOperation::Expire,
        ] {
            if query
                .store()
                .managed_instance(source.tenant_id, &operation.instance_id(&source), &control)?
                .ok_or("retired Graph job")?
                .running
            {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await?;
    assert_eq!(
        query
            .store()
            .processor_health(&scope(&source))?
            .ok_or("retired Graph source")?
            .state,
        araphor_data::ProcessorStateV1::Retired
    );
    running.stop().await?;
    drop(owner);
    Ok(())
}

struct ProgramAuthority {
    denied: AtomicBool,
    inner: Arc<Authority>,
}

impl PackageAuthorization for ProgramAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if grant.principal == "denied Graph feed" && self.denied.load(Ordering::SeqCst) {
            return Err(Code::Denied.error("Graph program fixture authority"));
        }
        self.inner.check(grant, action)
    }

    fn admit(&self, grant: &PackageGrantV1, bundle: &PackageBundle) -> araphor_data::Result<()> {
        self.check(grant, PackageActionV1::Run)?;
        self.inner.admit(grant, bundle)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.check(grant, action)?;
        self.inner.commit(grant, action, bundle, operation)
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        for (grant, action, _) in grants {
            self.check(grant, *action)?;
        }
        self.inner.commit_many(grants, operation)
    }

    fn changes(&self) -> watch::Receiver<u64> {
        self.inner.changes()
    }
}

#[tokio::test]
async fn denied_feed_keeps_sibling() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let mut first = program(&fixture).await?;
    first.grant.principal = "denied Graph feed".into();
    first.grant.selection.nodes = vec![fixture.source.node_id.clone()];
    let second = EvidenceIntakeIdentityV1 {
        node_id: format!("{}-sibling", fixture.source.node_id),
        source_id: [63; 16],
        ..fixture.source.clone()
    };
    let mut other = first.clone();
    other.grant.principal = "healthy Graph feed".into();
    other.grant.selection.nodes = vec![second.node_id.clone()];
    let Fixture {
        query,
        control,
        source,
        records,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let authority = Arc::new(ProgramAuthority {
        denied: AtomicBool::new(false),
        inner: authority,
    });
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts);
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority.clone(),
            vec![first, other],
            &control,
        )
        .await?,
    );
    append(&query, &second, &records[0], 1)?;
    let running = Running::start(Arc::clone(&owner), host);
    observe(&query, || {
        Ok(complete(&query, &control, &source, 3)? && complete(&query, &control, &second, 1)?)
    })
    .await?;
    let retained = query.store().processor_result(&scope(&source))?;
    let (entry, joined) = tokio::sync::oneshot::channel();
    *owner
        .joined
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(entry);
    authority.denied.store(true, Ordering::SeqCst);
    authority
        .inner
        .changes
        .send_modify(|revision| *revision += 1);
    let future_denied = EvidenceIntakeIdentityV1 {
        source_id: [64; 16],
        ..source.clone()
    };
    let future_allowed = EvidenceIntakeIdentityV1 {
        source_id: [65; 16],
        ..second.clone()
    };
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(30), joined).await??,
        0
    );
    observe(&query, || {
        let id = ManagedGraphOperation::Evaluate.instance_id(&source);
        let status = query.store().managed_status(
            &AnalysisSelectionV1::tenant(source.tenant_id),
            &id,
            &control,
        )?;
        Ok(matches!(
            status.readiness,
            araphor_data::PackageReadinessV1::Failed {
                code: Code::Denied,
                ..
            }
        ))
    })
    .await?;
    append(&query, &future_denied, &records[0], 1)?;
    append(&query, &future_allowed, &records[0], 1)?;
    observe(&query, || complete(&query, &control, &future_allowed, 1)).await?;
    assert!(query
        .store()
        .processor_health(&scope(&future_denied))?
        .is_none());
    assert!(query
        .store()
        .managed_instance(
            source.tenant_id,
            &ManagedGraphOperation::Evaluate.instance_id(&future_denied),
            &control
        )?
        .is_none());
    assert!(query.store().processor_health(&scope(&source))?.is_some());
    assert_eq!(query.store().processor_result(&scope(&source))?, retained);
    assert!(query.store().processor_health(&scope(&second))?.is_some());
    running.stop().await?;
    drop(owner);
    assert!(!query.store().graph_enabled());
    Ok(())
}

#[tokio::test]
async fn feed_rejects_stale_grants() -> TestResult {
    for operation in [
        ManagedGraphOperation::Evaluate,
        ManagedGraphOperation::Expire,
    ] {
        let fixture = Fixture::target(Target::Sql)?;
        let mut configured = program(&fixture).await?;
        let retained = configured.grant.clone();
        configured.grant.principal.push_str("-replacement");
        let id = operation.instance_id(&fixture.source);
        let existing = match operation {
            ManagedGraphOperation::Evaluate => {
                GraphPublication::admit(
                    Arc::clone(&fixture.query),
                    fixture.authority.clone(),
                    fixture.facts.clone(),
                    retained.clone(),
                    id.clone(),
                    fixture.source.clone(),
                    configured.events_sql.clone(),
                    configured.definition.clone(),
                    &fixture.control,
                )
                .await?
            }
            ManagedGraphOperation::Expire => {
                GraphPublication::admit_expiry(
                    Arc::clone(&fixture.query),
                    fixture.authority.clone(),
                    retained.clone(),
                    id.clone(),
                    fixture.source.clone(),
                    &fixture.control,
                )
                .await?
            }
        };
        let old = existing.admitted().clone();
        let Fixture {
            query,
            control,
            source,
            facts,
            authority,
            _directory,
            _graph,
            ..
        } = fixture;
        drop(_graph);
        let host =
            InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
        let owner = Arc::new(
            GraphOwner::new(
                Arc::clone(&query),
                host,
                authority,
                vec![configured],
                &control,
            )
            .await?,
        );
        let (_stop, stopped) = watch::channel(false);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            Arc::clone(&owner).run(stopped),
        )
        .await?
        .err()
        .ok_or("stale Graph grant accepted")?;
        assert!(
            format!("{error:?}").contains("Graph member grant"),
            "{operation:?}: {error:?}"
        );
        assert_eq!(
            query
                .store()
                .managed_instance(source.tenant_id, &id, &control)?,
            Some(old)
        );
        assert!(query.store().processor_result(&scope(&source))?.is_none());
        assert_eq!(facts.calls.load(Ordering::SeqCst), 0);
        drop(existing);
        drop(owner);
        assert!(!query.store().graph_enabled());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn aborted_admission_keeps_owner() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            host,
            authority.clone(),
            vec![program],
            &control,
        )
        .await?,
    );
    let before = query.store().meta()?;
    let weak = Arc::downgrade(&owner);
    let (entered, observed) = tokio::sync::oneshot::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    *authority.gate.lock().map_err(|_| "Graph admission gate")? = Some((entered, waiting));
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(owner.run(stopped));
    tokio::time::timeout(std::time::Duration::from_secs(90), observed).await??;
    worker.abort();
    assert!(worker
        .await
        .err()
        .ok_or("Graph caller not aborted")?
        .is_cancelled());
    assert!(query.store().graph_enabled());
    assert!(weak.upgrade().is_some());
    assert!(!stop.is_closed());
    assert!(query
        .store()
        .lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])
        .is_err());
    assert_eq!(query.store().meta()?, before);
    release.send(())?;
    tokio::time::timeout(std::time::Duration::from_secs(30), stop.closed()).await?;
    assert!(weak.upgrade().is_none());
    assert!(!query.store().graph_enabled());
    assert_eq!(query.store().meta()?, before);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 0);
    for operation in [
        ManagedGraphOperation::Evaluate,
        ManagedGraphOperation::Expire,
    ] {
        assert!(query
            .store()
            .managed_instance(source.tenant_id, &operation.instance_id(&source), &control)?
            .is_none());
    }
    assert!(query.store().processor_result(&scope(&source))?.is_none());
    assert_eq!(query.memory().input_reserved(), 0);
    drop(query.reserve_stream(source.tenant_id)?);
    drop(query.reserve_evaluation(source.tenant_id)?);
    drop(
        query
            .store()
            .lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?,
    );
    Ok(())
}

#[tokio::test]
async fn feed_preserves_removed_job() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        records,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority.clone(),
            vec![program.clone()],
            &control,
        )
        .await?,
    );
    let running = Running::start(Arc::clone(&owner), Arc::clone(&host));
    observe(&query, || complete(&query, &control, &source, 3)).await?;
    let id = ManagedGraphOperation::Evaluate.instance_id(&source);
    let crate::instance::Restored::Present(job) =
        host.restore(source.tenant_id, &id, &control).await?
    else {
        return Err("Graph job before removal".into());
    };
    let removed = host
        .remove(
            program.grant.clone(),
            id.clone(),
            job.admitted().lifecycle,
            &control,
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    let saved = query.store().processor_result(&scope(&source))?;
    let history = query
        .store()
        .managed_history(&program.grant.selection, &id, &control)?;
    let snapshot = query.store().graph_snapshot(&source)?;
    let facts_before = facts.calls.load(Ordering::SeqCst);
    running.stop().await?;
    drop(job);
    drop(owner);
    drop(host);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority,
            vec![program.clone()],
            &control,
        )
        .await?,
    );
    append(&query, &source, &records[0], 4)?;
    let second = EvidenceIntakeIdentityV1 {
        source_id: [64; 16],
        ..source.clone()
    };
    append(&query, &second, &records[0], 1)?;
    let running = Running::start(Arc::clone(&owner), Arc::clone(&host));
    observe(&query, || complete(&query, &control, &second, 1)).await?;
    let crate::instance::Restored::Removed(restored) =
        host.restore(source.tenant_id, &id, &control).await?
    else {
        return Err("Graph removal was not retained".into());
    };
    assert_eq!(restored.as_ref(), &removed);
    assert_eq!(
        query
            .store()
            .managed_instance(source.tenant_id, &id, &control)?,
        Some(removed)
    );
    assert_eq!(
        query
            .store()
            .managed_history(&program.grant.selection, &id, &control)?,
        history
    );
    assert_eq!(query.store().processor_result(&scope(&source))?, saved);
    assert_eq!(query.store().graph_snapshot(&source)?, snapshot);
    assert_eq!(
        query
            .store()
            .processor_health(&scope(&source))?
            .ok_or("removed Graph progress")?
            .consumed_cursor,
        3
    );
    assert_eq!(facts.calls.load(Ordering::SeqCst), facts_before + 1);
    running.stop().await?;
    drop(owner);
    drop(host);
    assert!(!query.store().graph_enabled());
    drop(query.store().lease_managed()?);
    Ok(())
}

#[tokio::test]
async fn failed_feed_recovers_source() -> TestResult {
    use crate::graph::tests::fixture::{activation, policy, record, wire};
    erebor_telemetry::init_test_logging();
    let records = (1..=257)
        .map(|cursor| {
            record(
                cursor,
                &wire(
                    cursor,
                    erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
                    2,
                    2,
                    [20; 16],
                ),
            )
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let mut fixture = Fixture::with_records(Target::Wasm, records)?;
    fixture.serial_guests()?;
    fixture.coverage(1, Some("HEALTHY"))?;
    let program = program(&fixture).await?;
    let Fixture {
        query,
        control,
        source,
        records,
        facts,
        authority,
        _directory,
        _graph,
        ..
    } = fixture;
    drop(_graph);
    let host = InstanceHost::with_graph_facts(Arc::clone(&query), authority.clone(), facts.clone());
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(&query),
            Arc::clone(&host),
            authority,
            vec![program.clone()],
            &control,
        )
        .await?,
    );
    let sibling = EvidenceIntakeIdentityV1 {
        source_id: [93; 16],
        ..source.clone()
    };
    append(&query, &sibling, &records[0], 1)?;
    let began = std::time::Instant::now();
    let before = query.store().meta()?.commit_revision;
    let (entry_sender, observed) = std::sync::mpsc::channel();
    query.guest_entry(entry_sender.clone(), None)?;
    let running = Running::start(Arc::clone(&owner), Arc::clone(&host));
    let result = async {
        let observed = tokio::task::spawn_blocking(move || {
            observed.recv_timeout(std::time::Duration::from_secs(90))?;
            Ok::<_, std::sync::mpsc::RecvTimeoutError>(observed)
        })
        .await??;
        let entry = began.elapsed();
        observe(&query, || {
            Ok(complete(&query, &control, &source, 257)?
                && complete(&query, &control, &sibling, 1)?)
        })
        .await
        .map_err(|error| {
                format!(
                    "Initial Graph sources: {error}; elapsed={:?}; first_capture={:?}; revision={before}->{:?}; expiry_steps={:?}; facts={}; evaluation={:?}; expiry={:?}; sibling={:?}",
                    began.elapsed(),
                    facts.first.lock().unwrap_or_else(|error| error.into_inner())
                        .map(|first| first.saturating_duration_since(began)),
                    query.store().meta().map(|meta| meta.commit_revision),
                    query.store().managed_history(&program.grant.selection,
                        &ManagedGraphOperation::Expire.instance_id(&source), &control)
                        .map(|history| history.len()),
                    facts.calls.load(Ordering::SeqCst),
                    query.store().managed_status(&program.grant.selection,
                        &ManagedGraphOperation::Evaluate.instance_id(&source), &control)
                        .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                    query.store().managed_status(&program.grant.selection,
                        &ManagedGraphOperation::Expire.instance_id(&source), &control)
                        .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                    query.store().managed_status(&program.grant.selection,
                        &ManagedGraphOperation::Evaluate.instance_id(&sibling), &control)
                        .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                )
        })?;
        eprintln!("Initial Graph readiness: entry={entry:?}; ready={:?}", began.elapsed());
        let original = query
            .store()
            .processor_result(&scope(&source))?
            .ok_or("Original Graph result")?;
        let original_graph = query
            .store()
            .graph_result(source.tenant_id, &original.result_id)?
            .ok_or("Original Graph body")?;
        let finding = original_graph
            .findings
            .iter()
            .find(|finding| finding.evidence[0].durable_cursor == 1)
            .ok_or("Original Graph finding")?
            .clone();
        let id = ManagedGraphOperation::Evaluate.instance_id(&source);
        let prior = query
            .store()
            .managed_history(&program.grant.selection, &id, &control)?;
        let prior = prior
            .last()
            .ok_or("Original managed Graph receipt")?
            .clone();
        *facts
            .failed
            .lock()
            .map_err(|_| "Graph source failure flag")? = Some(source.clone());
        query.store().commit_context(&AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "Graph recovery signal".into(),
                entity_key: vec![1],
                lifetime_key: source.key(),
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"Graph provider failure".to_vec(),
        })?;
        observe(&query, || {
            Ok(matches!(
                query
                    .store()
                    .managed_status(&program.grant.selection, &id, &control,)?
                    .readiness,
                araphor_data::PackageReadinessV1::Failed {
                    code: Code::Invalid,
                    ..
                }
            ))
        })
        .await
        .map_err(|error| format!("Graph failure status: {error}"))?;
        assert_eq!(
            query
                .store()
                .processor_health(&scope(&source))?
                .ok_or("Failed Graph progress")?
                .consumed_cursor,
            257
        );
        assert_eq!(
            query.store().processor_result(&scope(&source))?,
            Some(original.clone())
        );
        append(&query, &sibling, &records[0], 2)?;
        observe(&query, || complete(&query, &control, &sibling, 2))
            .await
            .map_err(|error| format!("Sibling Graph progress: {error}"))?;
        assert!(matches!(
            query
                .store()
                .managed_status(&program.grant.selection, &id, &control)?
                .readiness,
            araphor_data::PackageReadinessV1::Failed {
                code: Code::Invalid,
                ..
            }
        ));
        let recovery_facts = facts.calls.load(Ordering::SeqCst);
        *facts
            .failed
            .lock()
            .map_err(|_| "Graph source recovery flag")? = None;
        query.store().commit_context(&AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "Graph recovery signal".into(),
                entity_key: vec![1],
                lifetime_key: source.key(),
                owner_revision: 2,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"Graph provider recovered".to_vec(),
        })?;
        observe(&query, || {
            let status =
                query
                    .store()
                    .managed_status(&program.grant.selection, &id, &control)?;
            Ok(status.instance.progress > prior.commit_revision
                && matches!(status.readiness, araphor_data::PackageReadinessV1::Ready))
        })
        .await
        .map_err(|error| {
            format!(
                "Same-frontier Graph recovery: {error}; facts={recovery_facts}->{}; revision={:?}; source={:?}; evaluation={:?}; expiry={:?}; history={:?}; expiry_history={:?}",
                facts.calls.load(Ordering::SeqCst),
                query.store().meta().map(|meta| meta.commit_revision),
                query.store().processor_health(&scope(&source)),
                query.store().managed_status(&program.grant.selection, &id, &control)
                    .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                query.store().managed_status(&program.grant.selection,
                    &ManagedGraphOperation::Expire.instance_id(&source), &control)
                    .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                query.store().managed_history(&program.grant.selection, &id, &control)
                    .map(|history| (history.len(), history.last().map(|receipt| receipt.commit_revision))),
                query.store().managed_history(&program.grant.selection,
                    &ManagedGraphOperation::Expire.instance_id(&source), &control)
                    .map(|history| (history.len(), history.last().map(|receipt| receipt.commit_revision))),
            )
        })?;
        assert!(facts.calls.load(Ordering::SeqCst) > recovery_facts);
        let after = query
            .store()
            .managed_history(&program.grant.selection, &id, &control)?;
        let recovered = after.last().ok_or("Recovered managed Graph receipt")?;
        assert_ne!(recovered.results, prior.results);
        assert_eq!(
            query
                .store()
                .processor_health(&scope(&source))?
                .ok_or("Recovered Graph progress")?
                .consumed_cursor,
            257
        );
        assert_eq!(
            query.store().processor_result(&scope(&source))?,
            Some(original.clone())
        );
        assert_eq!(
            query
                .store()
                .graph_result(source.tenant_id, &original.result_id)?,
            Some(original_graph.clone())
        );
        assert_eq!(
            query
                .store()
                .processor_health(&scope(&sibling))?
                .ok_or("Sibling Graph progress")?
                .consumed_cursor,
            2
        );
        *facts
            .failed
            .lock()
            .map_err(|_| "Graph evidence failure flag")? = Some(source.clone());
        query.store().commit_context(&AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "Graph recovery signal".into(),
                entity_key: vec![1],
                lifetime_key: source.key(),
                owner_revision: 3,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"Graph evidence recovery failure".to_vec(),
        })?;
        observe(&query, || {
            Ok(matches!(
                query
                    .store()
                    .managed_status(&program.grant.selection, &id, &control)?
                    .readiness,
                araphor_data::PackageReadinessV1::Failed {
                    code: Code::Invalid,
                    ..
                }
            ))
        })
        .await
        .map_err(|error| format!("Second Graph failure status: {error}"))?;
        let evidence = record(
            258,
            &wire(
                258,
                erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect,
                2,
                2,
                [20; 16],
            ),
        )?;
        append(&query, &source, &evidence, 258)?;
        append(&query, &sibling, &records[0], 3)?;
        observe(&query, || complete(&query, &control, &sibling, 3))
            .await
            .map_err(|error| format!("Sibling Graph cursor3: {error}"))?;
        assert_eq!(
            query
                .store()
                .processor_health(&scope(&source))?
                .ok_or("Blocked Graph evidence progress")?
                .consumed_cursor,
            257
        );
        facts
            .supplied
            .lock()
            .map_err(|_| "Graph evidence facts")?
            .extend([policy(&records[0], 1)?, activation(&records[0])?]);
        query.guest_entry(entry_sender, None)?;
        *facts
            .failed
            .lock()
            .map_err(|_| "Graph evidence repair flag")? = None;
        let repair_facts = facts.calls.load(Ordering::SeqCst);
        let repair_revision = query.store().meta()?.commit_revision;
        let repair_began = std::time::Instant::now();
        query.store().commit_context(&AnalysisContextVersionV1 {
            key: araphor_data::AnalysisContextKeyV1 {
                tenant_id: source.tenant_id,
                owner_id: "Graph recovery signal".into(),
                entity_key: vec![1],
                lifetime_key: source.key(),
                owner_revision: 4,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: araphor_data::ContextSensitivityV1::Tenant,
            body: b"Graph evidence repaired".to_vec(),
        })?;
        observe(&query, || {
            Ok(complete(&query, &control, &source, 258)?
                && matches!(
                    query
                        .store()
                        .managed_status(&program.grant.selection, &id, &control)?
                        .readiness,
                    araphor_data::PackageReadinessV1::Ready
                ))
        })
        .await
        .map_err(|error| {
            format!(
                "Repaired Graph cursor258: {error}; elapsed={:?}; guest_entries={}; guest_capacity={:?}; facts={repair_facts}->{}; revision={repair_revision}->{:?}; source={:?}; evaluation={:?}; expiry={:?}; history={:?}",
                repair_began.elapsed(),
                observed.try_iter().count(),
                futures_util::FutureExt::now_or_never(
                    query.wait_package_capacity("component evaluations", 1)),
                facts.calls.load(Ordering::SeqCst),
                query.store().meta().map(|meta| meta.commit_revision),
                query.store().processor_health(&scope(&source)),
                query.store().managed_status(&program.grant.selection, &id, &control)
                    .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                query.store().managed_status(&program.grant.selection,
                    &ManagedGraphOperation::Expire.instance_id(&source), &control)
                    .map(|status| (status.readiness, status.instance.progress, status.instance.running)),
                query.store().managed_history(&program.grant.selection, &id, &control)
                    .map(|history| (history.len(), history.last().map(|receipt| receipt.commit_revision))),
            )
        })?;
        let health = query
            .store()
            .processor_health(&scope(&source))?
            .ok_or("Repaired Graph health")?;
        assert_eq!(health.state, araphor_data::ProcessorStateV1::Current);
        assert!(!health.incomplete);
        let current = query.store().graph_findings(
            source.tenant_id,
            None,
            Some(&finding.finding_id),
            usize::MAX,
            usize::MAX,
        )?;
        let (revised, _) = current.into_iter().next().ok_or("Revised Graph finding")?;
        assert_ne!(revised, original.result_id);
        assert!(!query.store().graph_result(source.tenant_id, &revised)?
            .ok_or("Revised Graph result")?.input_manifest.context.is_empty());
        assert_eq!(
            query
                .store()
                .graph_result(source.tenant_id, &original.result_id)?,
            Some(original_graph)
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    running
        .stop()
        .await
        .map_err(|error| format!("Graph recovery shutdown: {error}; body={result:?}"))?;
    drop(owner);
    drop(host);
    assert_eq!(query.memory().input_reserved(), 0);
    result?;
    Ok(())
}
