use super::*;

#[tokio::test]
async fn managed_versions_rebuild_graph() -> TestResult {
    let mut fixture = Fixture::target(Target::Wasm)?;
    fixture.serial_guests()?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let first = publication.prepared.resolved().clone();
    for (bundle, _) in publication.prepared.images() {
        let mut next = bundle.clone();
        next.root.revision = "2".into();
        for artifact in &mut next.artifacts {
            artifact.descriptor.revision = "2".into();
        }
        fixture
            .authority
            .commit_many(&[(&grant, PackageActionV1::Install, None)], &mut || {
                fixture.query.store().install_package_image(
                    fixture.source.tenant_id,
                    &next,
                    || fixture.control.check(),
                )?;
                Ok(())
            })?;
    }
    let sql = araphor_data::FindingV1::PACKAGES
        .iter()
        .map(|id| format!(
            "SELECT * FROM \"{id}\".\"2\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
        ))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let next = fixture.prepare_sql("*", "", sql).await?;
    let next = next.prepared.resolved().clone();
    assert_ne!(first.images, next.images);
    let destination = araphor_data::ManagedDestination::Graph {
        source: fixture.source.clone(),
        events_sql: "SELECT * FROM events".into(),
        calls: Default::default(),
        operation: araphor_data::ManagedGraphOperation::Evaluate,
    };
    let before = fixture.query.store().meta()?;
    let (_, prepared, first_destination, first_owner) = GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        Some(fixture.facts.clone()),
        &grant,
        first.clone(),
        destination,
        &fixture.control,
    )
    .await?;
    let first_owner = first_owner.ok_or("first Graph projection")?;
    let mut target = first_destination.clone();
    if let araphor_data::ManagedDestination::Graph { calls, .. } = &mut target {
        calls.insert(u64::MAX);
    }
    let (_, next_prepared, next_destination, next_owner) = GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        Some(fixture.facts.clone()),
        &grant,
        next.clone(),
        target,
        &fixture.control,
    )
    .await?;
    let next_owner = next_owner.ok_or("next Graph projection")?;
    assert!(!Arc::ptr_eq(&first_owner, &next_owner));
    assert!(!Arc::ptr_eq(
        &first_owner.projection,
        &next_owner.projection
    ));
    assert_eq!(prepared.resolved(), &first);
    assert_eq!(next_prepared.resolved(), &next);
    assert!(first_owner
        .calls
        .values()
        .all(|call| call.package().revision == "1"));
    assert!(next_owner
        .calls
        .values()
        .all(|call| call.package().revision == "2"));
    let araphor_data::ManagedDestination::Graph { calls, .. } = &next_destination else {
        return Err("target Graph destination".into());
    };
    assert_eq!(calls, &next_owner.calls.keys().copied().collect());
    assert!(!calls.contains(&u64::MAX));
    let (_, rolled, rolled_destination, rolled_owner) = GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        Some(fixture.facts.clone()),
        &grant,
        first.clone(),
        first_destination.clone(),
        &fixture.control,
    )
    .await?;
    let rolled_owner = rolled_owner.ok_or("rollback Graph projection")?;
    assert_eq!(rolled.resolved(), &first);
    assert_eq!(rolled_destination, first_destination);
    assert!(!Arc::ptr_eq(
        &first_owner.projection,
        &rolled_owner.projection
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
    fixture.admit_definition(&grant, &first)?;
    fixture.admit_definition(&grant, &next)?;
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "running-graph-version".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        first.clone(),
        &fixture.control,
    )
    .await?;
    let generation = job.admitted().generation;
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(Arc::clone(&host).serve(stopped, u64::MAX));
    let began = std::time::Instant::now();
    let running = host
        .start(Arc::clone(&job), job.admitted().lifecycle, &fixture.control)
        .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let result = async {
        super::super::feed::observe(&fixture.query, || {
            Ok(fixture
                .query
                .store()
                .processor_health(&scope)?
                .is_some_and(|health| health.consumed_cursor == 3))
        })
        .await
        .map_err(|error| {
            format!(
                "Initial Graph version: {error}; elapsed={:?}; first_capture={:?}; facts={}",
                began.elapsed(),
                fixture
                    .facts
                    .first
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .map(|first| first.saturating_duration_since(began)),
                fixture.facts.calls.load(Ordering::SeqCst)
            )
        })?;
        let original = fixture
            .query
            .store()
            .processor_result(&scope)?
            .ok_or("Initial Graph version")?;
        let original_graph = fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &original.result_id)?
            .ok_or("Initial Graph version body")?;
        assert!(original_graph
            .packages
            .iter()
            .all(|package| package.package_version == 1
                && package.replay_contract_id == format!("{}/v1", package.package_id)));
        let (updated, entries) = Fixture::observe_guests(
            Arc::clone(&fixture.query),
            host.update(
                Arc::clone(&running),
                running.admitted().lifecycle,
                next.clone(),
                true,
                u64::MAX,
                &fixture.control,
            ),
        )
        .await
        .map_err(|error| {
            format!(
                "Graph version Update: {error}; elapsed={:?}",
                began.elapsed()
            )
        })?;
        assert!(updated.admitted().running);
        assert_ne!(updated.admitted().generation, generation);
        assert_eq!(updated.admitted().grant, grant);
        assert_eq!(updated.admitted().spec.definition, next);
        assert!(entries >= 3);
        let (updated_id, updated_graph, updated_revision) = fixture
            .retained_heads()?
            .into_iter()
            .find(|(_, graph, _)| graph.first_cursor == original_graph.first_cursor)
            .ok_or("Updated Graph window head")?;
        assert_ne!(updated_id, original.result_id);
        assert!(updated_revision > original.commit_revision);
        assert_eq!(
            fixture.query.store().processor_result(&scope)?,
            Some(original.clone())
        );
        assert!(updated_graph
            .packages
            .iter()
            .all(|package| package.package_version == 1
                && package.replay_contract_id == format!("{}/v2", package.package_id)));
        let (_, entries) = Fixture::observe_guests(Arc::clone(&fixture.query), async {
            super::super::feed::append(&fixture.query, &fixture.source, &fixture.records[0], 4)?;
            super::super::feed::observe(&fixture.query, || {
                Ok(fixture
                    .query
                    .store()
                    .processor_health(&scope)?
                    .is_some_and(|health| health.consumed_cursor == 4))
            })
            .await
            .map_err(|error| {
                format!(
                    "Graph version2 append: {error}; elapsed={:?}",
                    began.elapsed()
                )
            })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?;
        let current = fixture
            .query
            .store()
            .processor_result(&scope)?
            .ok_or("Updated Graph append")?;
        let appended = fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &current.result_id)?
            .ok_or("Updated Graph append body")?;
        assert_eq!(appended.last_cursor, 4);
        assert!(appended
            .packages
            .iter()
            .all(|package| package.package_version == 1
                && package.replay_contract_id == format!("{}/v2", package.package_id)));
        assert!(entries >= 3);
        let history = fixture.query.store().managed_history(
            &grant.selection,
            "running-graph-version",
            &fixture.control,
        )?;
        let last = history
            .iter()
            .find(|receipt| receipt.commit_revision == current.commit_revision)
            .ok_or("Updated Graph receipt")?;
        assert_eq!(last.commit_revision, current.commit_revision);
        for reference in last.results.values() {
            let araphor_data::ManagedOutput::Call { result, .. } =
                fixture.query.store().managed_output(
                    updated.admitted(),
                    &reference.result_id,
                    request("inspect")?.time_utc_ns,
                    &fixture.control,
                )?
            else {
                return Err("Graph version returned a selected output".into());
            };
            assert_eq!(result.package.revision, "2");
            assert_eq!(result.context.target, "wasm");
        }
        let before = fixture.query.store().meta()?;
        assert!(running
            .run(request("stale-version")?, &fixture.control)
            .await
            .is_err());
        assert_eq!(fixture.query.store().meta()?, before);
        let (rolled, entries) = Fixture::observe_guests(
            Arc::clone(&fixture.query),
            host.rollback(
                Arc::clone(&updated),
                updated.admitted().lifecycle,
                generation,
                true,
                u64::MAX,
                &fixture.control,
            ),
        )
        .await
        .map_err(|error| {
            format!(
                "Graph version Rollback: {error}; elapsed={:?}",
                began.elapsed()
            )
        })?;
        assert!(rolled.admitted().running);
        assert_eq!(rolled.admitted().grant, grant);
        assert_eq!(rolled.admitted().spec.definition, first);
        assert!(entries >= 3);
        let (_, entries) = Fixture::observe_guests(Arc::clone(&fixture.query), async {
            super::super::feed::append(&fixture.query, &fixture.source, &fixture.records[0], 5)?;
            super::super::feed::observe(&fixture.query, || {
                Ok(fixture
                    .query
                    .store()
                    .processor_health(&scope)?
                    .is_some_and(|health| health.consumed_cursor == 5))
            })
            .await
            .map_err(|error| {
                format!(
                    "Graph version1 append: {error}; elapsed={:?}",
                    began.elapsed()
                )
            })?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await?;
        let current = fixture
            .query
            .store()
            .processor_result(&scope)?
            .ok_or("Rolled Graph append")?;
        let graph = fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &current.result_id)?
            .ok_or("Rolled Graph append body")?;
        assert_eq!(graph.last_cursor, 5);
        assert!(graph
            .packages
            .iter()
            .all(|package| package.package_version == 1
                && package.replay_contract_id == format!("{}/v1", package.package_id)));
        assert!(entries >= 3);
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &original.result_id)?,
            Some(original_graph)
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &updated_id)?,
            Some(updated_graph)
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &current.result_id)?,
            Some(graph)
        );
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    stop.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(30), worker).await???;
    result?;
    Ok(())
}

#[tokio::test]
async fn expiry_needs_no_facts() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&fixture.control),
        )
        .await?;
    let destination = araphor_data::ManagedDestination::Graph {
        source: fixture.source.clone(),
        events_sql: String::new(),
        calls: Default::default(),
        operation: araphor_data::ManagedGraphOperation::Expire,
    };
    let before = fixture.query.store().meta()?;
    let (_, prepared, actual, owner) = GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        &grant,
        definition.clone(),
        destination.clone(),
        &fixture.control,
    )
    .await?;
    assert_eq!(prepared.resolved(), &definition);
    assert_eq!(actual, destination);
    assert!(owner.is_none());
    let mut forged = destination.clone();
    if let araphor_data::ManagedDestination::Graph { events_sql, .. } = &mut forged {
        *events_sql = "SELECT * FROM events".into();
    }
    assert!(GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        &grant,
        definition.clone(),
        forged,
        &fixture.control,
    )
    .await
    .is_err());
    let mut forged = destination;
    if let araphor_data::ManagedDestination::Graph { calls, .. } = &mut forged {
        calls.insert(1);
    }
    assert!(GraphPublication::prepare_managed(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        None,
        &grant,
        definition,
        forged,
        &fixture.control,
    )
    .await
    .is_err());
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
