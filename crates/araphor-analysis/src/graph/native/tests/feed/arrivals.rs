use super::*;
use crate::graph::tests::fixture::{record, wire};
use erebor_interceptor_abi::{
    EffectObservationReasonV1, EffectPhysicalResultV1, KernelEffectFamilyV1,
    KernelEffectOperationV1,
};

#[tokio::test]
async fn sources_arrive_during_execution() -> TestResult {
    erebor_telemetry::init_test_logging();
    let records = (1..=257)
        .map(|cursor| {
            let mut event = wire(
                cursor,
                EffectPhysicalResultV1::UnknownAfterPreEffect,
                KernelEffectFamilyV1::File as u32,
                KernelEffectOperationV1::OpenRead as u32,
                [20; 16],
            );
            event.reason = EffectObservationReasonV1::ApplicationDefaultAllow as u32;
            event.task_cookie = 8;
            let context = event.decision_context.as_mut().ok_or_else(|| {
                araphor_data::PackageErrorCodeV1::Incomplete.error("fixture background context")
            })?;
            context.process_instance_id = vec![18; 16];
            context.entry_instance_id = vec![19; 16];
            record(cursor, &event)
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let fixture = Fixture::with_records(Target::Wasm, records)?;
    let program = program(&fixture).await?;
    drop(fixture._graph);
    let query = &fixture.query;
    let control = &fixture.control;
    let host = InstanceHost::with_graph_facts(
        Arc::clone(query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let owner = Arc::new(
        GraphOwner::new(
            Arc::clone(query),
            Arc::clone(&host),
            fixture.authority.clone(),
            vec![program],
            control,
        )
        .await?,
    );
    let second = EvidenceIntakeIdentityV1 {
        source_id: [93; 16],
        ..fixture.source.clone()
    };
    let third = EvidenceIntakeIdentityV1 {
        source_id: [94; 16],
        ..fixture.source.clone()
    };
    let (entered, observed) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    query.guest_entry(entered, Some(waiting))?;
    let running = Running::start(Arc::clone(&owner), host);
    let tested = async {
        tokio::task::spawn_blocking(move || {
            observed.recv_timeout(std::time::Duration::from_secs(90))
        })
        .await??;
        assert!(query
            .store()
            .processor_result(&scope(&fixture.source))?
            .is_none());
        let denied = record(
            1,
            &wire(
                1,
                EffectPhysicalResultV1::DeniedBeforeEffect,
                KernelEffectFamilyV1::File as u32,
                KernelEffectOperationV1::OpenRead as u32,
                [20; 16],
            ),
        )?;
        let mut allowed = denied.decode()?;
        allowed.reason = EffectObservationReasonV1::ApplicationDefaultAllow as u32;
        allowed.decision = EffectPhysicalResultV1::UnknownAfterPreEffect as u32;
        allowed.configured_errno = 0;
        allowed.kernel_result = 0;
        let allowed = record(1, &allowed)?;
        for (source, record) in [(&second, &denied), (&third, &allowed)] {
            append(query, source, record, 1)?;
            assert_eq!(
                query
                    .store()
                    .processor_health(&scope(source))?
                    .ok_or("accepted source health")?
                    .accepted_cursor,
                1
            );
        }
        release.send(())?;
        let completed = observe_for(query, std::time::Duration::from_secs(90), || {
            for (source, cursor) in [(&fixture.source, 257), (&second, 1), (&third, 1)] {
                if !complete(query, control, source, cursor)?
                    || !query.store().processor_health(&scope(source))?.is_some_and(|health| {
                        health.state == araphor_data::ProcessorStateV1::Current
                    })
                {
                    return Ok(false);
                }
                let head = query.store().processor_result(&scope(source))?.ok_or("ready Graph head")?;
                let expiry = query.store().managed_resume(source.tenant_id, &ManagedGraphOperation::Expire.instance_id(source), control)?;
                let Some(frontier) = expiry.frontier else { return Ok(false); };
                let now: u64 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos().try_into()?;
                if araphor_query::follow::Cursor::decode(&frontier.cursor)?.read_revision() < head.commit_revision
                    || !frontier.next_change.is_some_and(|deadline| deadline > now) {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await;
        if completed.is_err() {
            let diagnosis = control.within(std::time::Duration::from_secs(5)).map(|read| {
                [&fixture.source, &second, &third].map(|source| {
                    let selection = AnalysisSelectionV1::tenant(source.tenant_id);
                    let status = [ManagedGraphOperation::Evaluate, ManagedGraphOperation::Expire].map(|operation| {
                        let id = operation.instance_id(source);
                        let status = query.store().managed_status(&selection, &id, &read).map(|status| {
                            (status.readiness, status.instance.progress, status.instance.running)
                        });
                        let resume = query.store().managed_resume(source.tenant_id, &id, &read).map(|resume| {
                            let revision = resume.frontier.as_ref().map(|frontier| {
                                araphor_query::follow::Cursor::decode(&frontier.cursor).map(|cursor| cursor.read_revision())
                            });
                            (resume.completed, resume.instance.progress, revision)
                        });
                        (id, format!("{status:?}"), format!("{resume:?}"))
                    });
                    let health = query.store().processor_health(&scope(source));
                    let head = query.store().processor_result(&scope(source)).map(|head| head.map(|head| (head.result_id, head.commit_revision)));
                    serde_json::json!({"source": source, "health": format!("{health:?}"), "head": format!("{head:?}"), "instances": status})
                })
            });
            eprintln!("controlled source state={diagnosis:?}");
        }
        completed?;
        let mut ids = std::collections::BTreeSet::new();
        for (source, cursor) in [(&fixture.source, 257), (&second, 1), (&third, 1)] {
            let head = query
                .store()
                .processor_result(&scope(source))?
                .ok_or("completed Graph head")?;
            let graph = query
                .store()
                .graph_result(source.tenant_id, &head.result_id)?
                .ok_or("completed Graph body")?;
            assert_eq!(&graph.scope.identity, source);
            assert_eq!(graph.last_cursor, cursor);
            assert!(ids.insert(head.result_id));
        }
        assert_eq!(ids.len(), 3);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    drop(release);
    let stopped = running.stop().await;
    tested?;
    stopped?;
    drop(owner);
    assert!(!query.store().graph_enabled());
    assert_eq!(query.memory().input_reserved(), 0);
    Ok(())
}
