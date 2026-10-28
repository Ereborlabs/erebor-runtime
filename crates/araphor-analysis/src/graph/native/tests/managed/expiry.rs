use super::*;

#[tokio::test]
async fn expiry_allows_new_input() -> TestResult {
    let mut fixture = Fixture::target(Target::Wasm)?;
    fixture.serial_guests()?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let evaluation = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "expired-graph-input".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let input = request("initial")?;
    let first = evaluation.run(input.clone(), &fixture.control).await?;
    assert_eq!(first.results.len(), 3);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let original = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Graph before expiry")?;
    let retained = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &original.result_id)?
        .ok_or("Graph expiry input")?;
    let body = fixture
        .query
        .store()
        .read_result(fixture.source.tenant_id, &original.result_id)?
        .ok_or("Graph input bytes")?;
    let (witnesses, references) = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.result_id),
    )?;
    let contexts = references
        .iter()
        .map(|reference| {
            fixture
                .query
                .store()
                .context_version(&reference.key)?
                .ok_or_else(|| Code::Invalid.error("Graph input context"))
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let calls = fixture.facts.calls.load(Ordering::SeqCst);
    let receiver = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            &evaluation.admitted().spec.id,
            &fixture.control,
        )?
        .ok_or("Graph input instance")?;
    let source = fixture
        .query
        .store()
        .source_receipt(&fixture.source)?
        .ok_or("Graph input source")?;
    let raw = fixture.query.store().read_page(&fixture.source, 1)?.records;
    assert_eq!(raw.len(), 3);
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(araphor_data::GRAPH_WITNESS_TTL_NS),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    let donor = Fixture::stored(Target::Wasm, fixture.records.clone(), directory, store)?;
    assert_eq!(donor.source, fixture.source);
    assert_eq!(
        donor.query.store().read_page(&donor.source, 1)?.records,
        raw
    );
    assert_eq!(
        donor.query.store().source_receipt(&donor.source)?,
        Some(source.clone())
    );
    let before = donor.query.store().meta()?;
    let sources = grant.selection.source_revisions(before.commit_revision);
    let seeded = donor.query.store().commit_graph_snapshot(
        araphor_data::AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 3,
            coverage_revision: source.coverage_revision,
            context_revision: 0,
            result_id: original.result_id.clone(),
            body: Vec::new(),
            created_utc_ns: input.time_utc_ns,
            witnesses: witnesses.clone(),
            context_refs: Vec::new(),
        },
        araphor_data::analysis::CanonicalGraph::bounded(
            retained.clone(),
            donor.query.limits().output_bytes,
        )?,
        &contexts,
        &[],
        &sources,
        true,
        || {
            donor.control.check()?;
            donor.authority.check(&grant, PackageActionV1::Run)
        },
    )?;
    assert_eq!(seeded.consumed_cursor, 3);
    assert_eq!(seeded.commit_revision, before.commit_revision + 1);
    assert_eq!(
        donor
            .query
            .store()
            .graph_result(donor.source.tenant_id, &original.result_id)?,
        Some(retained.clone())
    );
    assert_eq!(
        donor
            .query
            .store()
            .read_result(donor.source.tenant_id, &original.result_id)?,
        Some(body.clone())
    );
    let donor_refs = references
        .iter()
        .map(|reference| AnalysisContextRefV1 {
            key: reference.key.clone(),
            commit_revision: seeded.commit_revision,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        donor.query.store().package_evidence(
            donor.source.tenant_id,
            std::slice::from_ref(&original.result_id)
        )?,
        (witnesses.clone(), donor_refs.clone())
    );
    for context in &contexts {
        assert_eq!(
            donor.query.store().context_version(&context.key)?,
            Some(context.clone())
        );
    }
    let removed = araphor_data::EvidenceRetentionOwner::new(donor.query.store()).retain(
        &donor.source,
        retained
            .witness_deadline_utc_ns
            .checked_add(1)
            .ok_or("expiry retention time")?,
    )?;
    assert_eq!(removed.removed_records, 3);
    assert_eq!(removed.retained_floor, retained.last_cursor);
    let definition = donor
        .query
        .admit_definition(
            donor.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&donor.control),
        )
        .await?;
    donor.admit_definition(&grant, &definition)?;
    let expiry = GraphPublication::admit_expiry(
        Arc::clone(&donor.query),
        donor.authority.clone(),
        grant.clone(),
        "expired-graph-head".into(),
        donor.source.clone(),
        &donor.control,
    )
    .await?;
    assert!(expiry.graph_owner().is_none());
    let (entry, entered) = std::sync::mpsc::channel();
    donor.query.guest_entry(entry.clone(), None)?;
    fixture.query.guest_entry(entry, None)?;
    let current = request("due-head")?;
    assert!(current.time_utc_ns < retained.witness_deadline_utc_ns);
    let delivered = {
        let control = AnalysisReadControl::default();
        let work = expiry.run(current.clone(), &control);
        tokio::pin!(work);
        match tokio::time::timeout(std::time::Duration::from_secs(30), &mut work).await {
            Ok(receipt) => receipt?,
            Err(error) => {
                let cancelled = control.cancel();
                let joined = work.await;
                return Err(format!(
                    "Graph expiry completion: {error}; cancel={cancelled:?}; joined={joined:?}"
                )
                .into());
            }
        }
    };
    assert!(delivered.results.is_empty());
    let (expired_id, _, revision) = donor
        .query
        .store()
        .graph_window_headers(&donor.source, None)?
        .into_iter()
        .find(|(_, graph, _)| graph.first_cursor == retained.first_cursor)
        .ok_or("Donor expired Graph head")?;
    assert_eq!(revision, delivered.commit_revision);
    assert_ne!(expired_id, original.result_id);
    let expected = Graph::expire(
        &retained,
        &original.result_id,
        retained.context_notice_revision,
    )?;
    let generated = donor
        .query
        .store()
        .graph_result(donor.source.tenant_id, &expired_id)?
        .ok_or("Donor expired Graph")?;
    assert_eq!(generated, expected);
    let expired_body = donor
        .query
        .store()
        .read_result(donor.source.tenant_id, &expired_id)?
        .ok_or("Donor expired Graph bytes")?;
    assert_eq!(
        donor
            .query
            .store()
            .package_evidence(donor.source.tenant_id, std::slice::from_ref(&expired_id))?,
        (Vec::new(), donor_refs)
    );
    assert_eq!(
        fixture.query.store().read_page(&fixture.source, 1)?.records,
        raw
    );
    assert_eq!(
        fixture.query.store().source_receipt(&fixture.source)?,
        Some(source.clone())
    );
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    let before = fixture.query.store().meta()?;
    let sources = grant.selection.source_revisions(before.commit_revision);
    let expired = fixture.query.store().commit_graph_snapshot(
        araphor_data::AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 3,
            consumed_cursor: 3,
            coverage_revision: source.coverage_revision,
            context_revision: 0,
            result_id: expired_id.clone(),
            body: Vec::new(),
            created_utc_ns: current.time_utc_ns,
            witnesses: Vec::new(),
            context_refs: Vec::new(),
        },
        araphor_data::analysis::CanonicalGraph::bounded(
            generated,
            fixture.query.limits().output_bytes,
        )?,
        &[],
        &references,
        &sources,
        false,
        || {
            fixture.control.check()?;
            fixture.authority.check(&grant, PackageActionV1::Run)
        },
    )?;
    assert_eq!(expired.consumed_cursor, 3);
    assert_eq!(expired.commit_revision, before.commit_revision + 1);
    assert_eq!(
        fixture.query.store().managed_instance(
            fixture.source.tenant_id,
            &receiver.spec.id,
            &fixture.control
        )?,
        Some(receiver)
    );
    assert_eq!(
        fixture.query.store().read_page(&fixture.source, 1)?.records,
        raw
    );
    assert_eq!(
        fixture.query.store().source_receipt(&fixture.source)?,
        Some(source)
    );
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph expiry progress")?
            .consumed_cursor,
        3
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &original.result_id)?,
        Some(retained.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &original.result_id)?,
        Some(body)
    );
    assert_eq!(
        fixture.query.store().package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&original.result_id)
        )?,
        (witnesses, references.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &expired_id)?,
        Some(expired_body)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&expired_id))?,
        (Vec::new(), references)
    );
    let (_, _, revision) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(id, _, _)| id == &expired_id)
        .ok_or("Expired Graph head")?;
    assert_eq!(revision, expired.commit_revision);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &expired_id)?,
        Some(expected.clone())
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), calls);
    assert_eq!(donor.facts.calls.load(Ordering::SeqCst), 0);
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    assert!(evaluation
        .run(request("expired-only")?, &fixture.control)
        .await?
        .results
        .is_empty());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        fixture.query.store().read_page(&fixture.source, 1)?.records,
        raw
    );
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let record = &fixture.records[0];
    fixture.query.store().accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: request("append-time")?.time_utc_ns,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let (next, entries) = Fixture::observe_guests(
        Arc::clone(&fixture.query),
        evaluation.run(request("after-expiry")?, &fixture.control),
    )
    .await?;
    assert_eq!(next.results.len(), 3);
    assert_eq!(entries, 3);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts + 1);
    let current = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Graph after expiry")?;
    let graph = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &current.result_id)?
        .ok_or("New Graph after expiry")?;
    assert_eq!((graph.first_cursor, graph.last_cursor), (4, 4));
    assert_eq!(graph.input_manifest.evidence.len(), 1);
    assert_eq!(graph.input_manifest.evidence[0].durable_cursor, 4);
    assert!(graph.witness_deadline_utc_ns > retained.witness_deadline_utc_ns);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph progress")?
            .consumed_cursor,
        4
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &original.result_id)?,
        Some(retained)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &expired_id)?,
        Some(expected)
    );
    Ok(())
}

#[tokio::test]
async fn managed_expiry_is_atomic() -> TestResult {
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let records = manifest.records.into_iter().take(3).collect::<Vec<_>>();
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(araphor_data::GRAPH_WITNESS_TTL_NS),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    let fixture = Fixture::stored(Target::Wasm, records, directory, store)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let evaluation = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "managed-retention-input".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let mut evaluation_request = request("retained-input")?;
    evaluation_request.witness_expiry = evaluation_request
        .time_utc_ns
        .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
        .ok_or("Graph witness deadline")?;
    let witness_expiry = evaluation_request.witness_expiry;
    let evaluated = evaluation.run(evaluation_request, &fixture.control).await?;
    assert_eq!(evaluated.results.len(), 3);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let original_head = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("managed retention Graph head")?;
    let original_id = original_head.result_id;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &original_id)?
        .ok_or("managed retention Graph")?;
    let (_, original_refs) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&original_id))?;
    assert_eq!(
        original_refs
            .iter()
            .filter(|reference| reference.key.owner_id == "native-package-v1")
            .count(),
        3
    );
    let retained = araphor_data::EvidenceRetentionOwner::new(fixture.query.store()).retain(
        &fixture.source,
        original
            .witness_deadline_utc_ns
            .max(witness_expiry)
            .checked_add(1)
            .ok_or("retention time")?,
    )?;
    assert_eq!(retained.removed_records, 3);
    assert_eq!(retained.retained_floor, original.last_cursor);
    assert_eq!(
        fixture
            .query
            .store()
            .source_receipt(&fixture.source)?
            .ok_or("retained source receipt")?
            .retained_floor,
        original.last_cursor
    );
    let definition = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&fixture.control),
        )
        .await?;
    fixture.admit_definition(&grant, &definition)?;
    let instance = GraphPublication::admit_expiry(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant,
        "managed-reclaimed-expiry".into(),
        fixture.source.clone(),
        &fixture.control,
    )
    .await?;
    assert!(!instance.admitted().running);
    let (entries, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entries, None)?;
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    let before = fixture.query.store().meta()?.commit_revision;
    let receipt = instance.run(request("due-head")?, &fixture.control).await?;
    assert!(receipt.commit_revision > before);
    assert!(receipt.results.is_empty());
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let (expired_id, _, expired_revision) = heads
        .iter()
        .find(|(_, graph, _)| graph.first_cursor == original.first_cursor)
        .ok_or("managed expired Graph head")?;
    assert_ne!(expired_id, &original_id);
    assert_eq!(*expired_revision, receipt.commit_revision);
    let expected = Graph::expire(&original, &original_id, original.context_notice_revision)?;
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, expired_id)?,
        Some(expected.clone())
    );
    let (witnesses, references) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(expired_id))?;
    assert!(witnesses.is_empty());
    assert_eq!(references, original_refs);
    let (witnesses, _) = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&receipt.selected.result_id),
    )?;
    assert!(witnesses.is_empty());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .managed_attempt(
                fixture.source.tenant_id,
                "managed-reclaimed-expiry",
                "due-head",
                &fixture.control,
            )?
            .ok_or("managed reclaimed expiry attempt")?
            .receipt(),
        Some(&receipt)
    );
    let saved = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "managed-reclaimed-expiry",
            &fixture.control,
        )?
        .ok_or("managed reclaimed expiry instance")?;
    assert_eq!(saved.progress, receipt.commit_revision);
    assert_eq!(
        fixture.query.store().managed_history(
            &saved.grant.selection,
            &saved.spec.id,
            &fixture.control,
        )?,
        [receipt]
    );
    let expired_id = expired_id.clone();
    let source = fixture.source.clone();
    drop(evaluation);
    drop(instance);
    let Fixture {
        query,
        _directory,
        _graph: graph_lease,
        ..
    } = fixture;
    drop(graph_lease);
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let query = Engine::new(store, Default::default())?;
    let authority = Arc::new(Authority {
        changes: watch::channel(0).0,
        allowed: AtomicBool::new(true),
        trusted: AtomicBool::new(true),
        gate: Mutex::default(),
    });
    let control = AnalysisReadControl::default();
    let host = crate::InstanceHost::new(Arc::clone(&query), authority);
    let restored = host
        .admit_current(
            &saved,
            None,
            &Arc::new(control.within(None)?),
            query.memory().scope(),
        )
        .await?;
    let (entries, entered) = std::sync::mpsc::channel();
    query.guest_entry(entries, None)?;
    let before = query
        .store()
        .graph_window_headers(&source, None)?
        .into_iter()
        .map(|(id, graph, revision)| (id, graph.first_cursor, revision))
        .collect::<Vec<_>>();
    let pointer = query.store().processor_result(&scope)?;
    let metadata = query.store().meta()?;
    let current = query
        .store()
        .managed_instance(source.tenant_id, &saved.spec.id, &control)?
        .ok_or("Reopened expiry instance")?;
    let history =
        query
            .store()
            .managed_history(&current.grant.selection, &current.spec.id, &control)?;
    let snapshots = || -> TestResult<GraphHistory> {
        let mut inventory = Vec::new();
        let mut after = None;
        loop {
            let page = query.store().graph_snapshots(
                source.tenant_id,
                Some(&source),
                after.as_deref(),
                false,
            )?;
            if page.is_empty() {
                break;
            }
            for (id, graph, revision) in page {
                after = Some(id.clone());
                let body = query
                    .store()
                    .read_result(source.tenant_id, &id)?
                    .ok_or("Reopened Graph history body")?;
                inventory.push((
                    id.clone(),
                    graph,
                    revision,
                    Some(body),
                    query
                        .store()
                        .package_evidence(source.tenant_id, std::slice::from_ref(&id))?,
                ));
            }
        }
        Ok(inventory)
    };
    let inventory = snapshots()?;
    let resumed = restored.run(request("already-expired")?, &control).await?;
    assert!(resumed.results.is_empty());
    assert_eq!(
        query
            .store()
            .graph_window_headers(&source, None)?
            .into_iter()
            .map(|(id, graph, revision)| (id, graph.first_cursor, revision))
            .collect::<Vec<_>>(),
        before
    );
    assert_eq!(
        query.store().graph_result(source.tenant_id, &expired_id)?,
        Some(expected)
    );
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(query.store().processor_result(&scope)?, pointer);
    assert_eq!(snapshots()?, inventory);
    assert_eq!(resumed.commit_revision, metadata.commit_revision + 2);
    let mut expected_meta = metadata;
    expected_meta.commit_revision = resumed.commit_revision;
    assert_eq!(query.store().meta()?, expected_meta);
    let mut expected_instance = current;
    expected_instance.progress = resumed.commit_revision;
    assert_eq!(
        query
            .store()
            .managed_instance(source.tenant_id, &saved.spec.id, &control)?,
        Some(expected_instance)
    );
    let mut expected_history = history;
    expected_history.push(resumed);
    assert_eq!(
        query
            .store()
            .managed_history(&saved.grant.selection, &saved.spec.id, &control)?,
        expected_history
    );
    Ok(())
}

#[tokio::test]
async fn expiry_query_clock() -> TestResult {
    use futures_util::StreamExt as _;

    let fixture = Fixture::target(Target::Wasm)?;
    let prepared = fixture.prepare("").await?;
    let grant = prepared.grant.clone();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(prepared);
    let evaluation = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "query-clock-expiry-input".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let seeded = evaluation.run(request("seed")?, &fixture.control).await?;
    assert_eq!(seeded.results.len(), 3);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let original = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Query clock Graph head")?;
    let previous = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &original.result_id)?
        .ok_or("Query clock Graph body")?;
    let references = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.result_id),
    )?;
    let session = fixture.query.session(
        AnalysisSelectionV1::tenant(fixture.source.tenant_id),
        &AnalysisReadControl::default(),
        0,
    )?;
    let definition = session
        .prepare_definition(&GraphPublication::expiry_program())
        .await?;
    assert_eq!(
        definition.resolved().definition,
        GraphPublication::expiry_program()
    );
    let clock = super::super::expiry::Clock::new(previous.witness_deadline_utc_ns - 1);
    let sources = definition.sources().clone();
    let mut stream = araphor_query::follow::Subscription::new(
        session,
        Arc::new(definition.plan),
        sources,
        b"native-expiry-clock",
        None,
        clock.clone(),
        true,
    )?;
    let (entry, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    let before = fixture.query.store().meta()?;
    let early = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("Query expiry initial update")??;
    assert_eq!(early.evaluated_utc_ns, previous.witness_deadline_utc_ns - 1);
    assert_eq!(
        early.snapshot.next_change,
        Some(previous.witness_deadline_utc_ns)
    );
    assert_eq!(
        early
            .batches
            .iter()
            .flatten()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        0
    );
    assert!(early.calls.is_empty());
    assert_eq!(fixture.query.store().meta()?, before);
    clock.advance(previous.witness_deadline_utc_ns);
    let due = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("Query expiry due update")??;
    assert_eq!(due.evaluated_utc_ns, previous.witness_deadline_utc_ns);
    assert_eq!(due.snapshot.next_change, None);
    assert!(due.calls.is_empty());
    let batches = due.batches.as_ref().ok_or("Query expiry due rows")?;
    assert_eq!(
        batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    let batch = batches
        .iter()
        .find(|batch| batch.num_rows() != 0)
        .ok_or("Query expiry selected head")?;
    let id = batch
        .column_by_name("graph_result_id")
        .and_then(|array| {
            array
                .as_any()
                .downcast_ref::<sdk::arrow_array::StringArray>()
        })
        .ok_or("Query expiry head ID")?;
    let revision = batch
        .column_by_name("commit_revision")
        .and_then(|array| {
            array
                .as_any()
                .downcast_ref::<sdk::arrow_array::UInt64Array>()
        })
        .ok_or("Query expiry head revision")?;
    let snapshot = batch
        .column_by_name("snapshot")
        .and_then(|array| {
            array
                .as_any()
                .downcast_ref::<sdk::arrow_array::BinaryArray>()
        })
        .ok_or("Query expiry snapshot")?;
    let contexts = batch
        .column_by_name("context_refs")
        .and_then(|array| {
            array
                .as_any()
                .downcast_ref::<sdk::arrow_array::BinaryArray>()
        })
        .ok_or("Query expiry context references")?;
    assert_eq!(id.value(0), original.result_id);
    assert_eq!(revision.value(0), original.commit_revision);
    assert_eq!(
        serde_json::from_slice::<araphor_data::GraphSnapshotV1>(snapshot.value(0))?,
        previous
    );
    let mut contexts = serde_json::from_slice::<Vec<AnalysisContextRefV1>>(contexts.value(0))?;
    contexts.sort_by(|left, right| left.key.cmp(&right.key));
    assert_eq!(contexts, references.1);
    assert_eq!(fixture.query.store().meta()?, before);
    clock.advance(previous.witness_deadline_utc_ns + 1);
    let idle = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("Query expiry clock update")??;
    assert!(idle.batches.is_none());
    assert_eq!(idle.evaluated_utc_ns, previous.witness_deadline_utc_ns);
    assert_eq!(idle.snapshot.next_change, None);
    assert!(idle.calls.is_empty());
    assert!(futures_util::poll!(stream.next()).is_pending());
    stream.cancel_and_join().await?;
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &original.result_id)?,
        Some(previous.clone())
    );
    assert_eq!(
        fixture.query.store().package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&original.result_id),
        )?,
        references
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    Ok(())
}

#[tokio::test]
async fn managed_expiry_subscription_recovers() -> TestResult {
    use futures_util::StreamExt as _;

    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let records = manifest.records.into_iter().take(3).collect::<Vec<_>>();
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open_with_limits(
        directory.path().join("data"),
        araphor_data::RetentionLimitsV1 {
            raw_max_age_ns: Some(araphor_data::GRAPH_WITNESS_TTL_NS),
            raw_max_bytes: None,
        },
        Default::default(),
    )?);
    let fixture = Fixture::stored(Target::Wasm, records, directory, store)?;
    let prepared = fixture.prepare("").await?;
    let grant = prepared.grant.clone();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(prepared);
    let evaluation = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "subscription-expiry-input".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let mut seed = request("seed")?;
    seed.witness_expiry = seed
        .time_utc_ns
        .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
        .ok_or("Graph expiry seed deadline")?;
    let retain_at = seed.witness_expiry;
    let evaluated = evaluation.run(seed, &fixture.control).await?;
    assert_eq!(evaluated.results.len(), 3);
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let original = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Managed subscription Graph head")?;
    let previous = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &original.result_id)?
        .ok_or("Managed subscription Graph body")?;
    let original_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    assert_eq!(original_heads.len(), 1);
    let (_, references) = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.result_id),
    )?;
    assert_eq!(
        references
            .iter()
            .filter(|reference| reference.key.owner_id == "native-package-v1")
            .count(),
        3
    );
    let consumed = fixture
        .query
        .store()
        .processor_health(&scope)?
        .ok_or("Graph progress before expiry")?
        .consumed_cursor;
    assert_eq!(consumed, 3);
    let definition = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&fixture.control),
        )
        .await?;
    fixture.admit_definition(&grant, &definition)?;
    let instance = GraphPublication::admit_expiry(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant,
        "subscription-expiry".into(),
        fixture.source.clone(),
        &fixture.control,
    )
    .await?;
    assert!(instance.admitted().spec.manifest.calls.is_empty());
    assert!(instance.admitted().spec.definition.images.is_empty());
    let (entries, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entries, None)?;
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    let host = crate::InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    let running = host
        .start(
            Arc::clone(&instance),
            instance.admitted().lifecycle,
            &fixture.control,
        )
        .await?;
    let early = request("before-due")?;
    assert!(early.time_utc_ns < previous.witness_deadline_utc_ns);
    let early = running.run(early, &fixture.control).await?;
    assert!(early.results.is_empty());
    assert!(
        !early
            .frontier
            .as_ref()
            .ok_or("Early native frontier")?
            .pending
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        original_heads
    );
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    let retained = fixture.query.memory().input_reserved();
    let mut stream = running.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        running.admitted().lifecycle,
    )?;
    let before = fixture.query.store().meta()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        original_heads
    );
    let removed = araphor_data::EvidenceRetentionOwner::new(fixture.query.store()).retain(
        &fixture.source,
        previous
            .witness_deadline_utc_ns
            .max(retain_at)
            .checked_add(1)
            .ok_or("Managed subscription retention time")?,
    )?;
    assert_eq!(removed.removed_records, 3);
    assert_eq!(removed.retained_floor, previous.last_cursor);
    let retained_revision = fixture.query.store().meta()?.commit_revision;
    let receipt = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("Managed expiry subscription ended")??;
    assert!(receipt.commit_revision > retained_revision);
    assert!(receipt.results.is_empty());
    assert!(
        !receipt
            .frontier
            .as_ref()
            .ok_or("Expiry native frontier")?
            .pending
    );
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    assert_eq!(heads.len(), 1);
    let (expired_id, header, revision) = heads.first().ok_or("Expired native Graph head")?;
    assert_ne!(expired_id, &original.result_id);
    assert_eq!(*revision, receipt.commit_revision);
    assert!(header.retained_input_expired());
    let expected = Graph::expire(
        &previous,
        &original.result_id,
        previous.context_notice_revision,
    )?;
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, expired_id)?,
        Some(expected.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &original.result_id)?,
        Some(previous.clone())
    );
    let (witnesses, contexts) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(expired_id))?;
    assert!(witnesses.is_empty());
    assert_eq!(contexts, references);
    let (witnesses, _) = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&receipt.selected.result_id),
    )?;
    assert!(witnesses.is_empty());
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph progress after expiry")?
            .consumed_cursor,
        consumed
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .managed_attempt(
                fixture.source.tenant_id,
                "subscription-expiry",
                &receipt.attempt,
                &fixture.control,
            )?
            .ok_or("Delivered native expiry attempt")?
            .receipt(),
        Some(&receipt)
    );
    let resume = fixture.query.store().managed_resume(
        fixture.source.tenant_id,
        "subscription-expiry",
        &fixture.control,
    )?;
    assert_eq!(resume.frontier, receipt.frontier);
    assert_eq!(resume.instance.progress, receipt.commit_revision);
    assert_eq!(resume.completed, receipt.commit_revision);
    assert_eq!(
        fixture.query.store().managed_history(
            &resume.instance.grant.selection,
            "subscription-expiry",
            &fixture.control,
        )?,
        [early.clone(), receipt.clone()]
    );
    let idle = fixture.query.store().meta()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?, idle);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        heads
    );
    assert_eq!(stream.cancel_and_join(&fixture.control).await?, None);
    assert_eq!(fixture.query.memory().input_reserved(), retained);
    let after = running.run(request("after")?, &fixture.control).await?;
    assert!(after.results.is_empty());
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        heads
    );
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(original.clone())
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let saved = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "subscription-expiry",
            &fixture.control,
        )?
        .ok_or("Saved native expiry instance")?;
    let frontier = after.frontier.clone().ok_or("Saved expiry frontier")?;
    assert!(!frontier.pending);
    assert_eq!(saved.progress, after.commit_revision);
    let before_reopen = fixture.query.store().meta()?;
    let expired_id = expired_id.clone();
    drop((running, instance, evaluation, host));
    let Fixture {
        query,
        source,
        authority,
        control,
        _directory,
        _graph: graph_lease,
        ..
    } = fixture;
    drop(graph_lease);
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let query = Engine::new(store, Default::default())?;
    let facts = Arc::new(Facts::default());
    let host = crate::InstanceHost::with_graph_facts(Arc::clone(&query), authority, facts.clone());
    let crate::instance::Restored::Present(restored) = host
        .restore(source.tenant_id, "subscription-expiry", &control)
        .await?
    else {
        return Err("Restored native expiry instance".into());
    };
    assert_eq!(restored.admitted(), &saved);
    assert_eq!(query.store().meta()?, before_reopen);
    let resumed =
        query
            .store()
            .managed_resume(source.tenant_id, "subscription-expiry", &control)?;
    assert_eq!(resumed.frontier, Some(frontier));
    assert_eq!(resumed.instance.progress, after.commit_revision);
    assert_eq!(resumed.completed, after.commit_revision);
    assert_eq!(
        query
            .store()
            .managed_history(&saved.grant.selection, "subscription-expiry", &control)?,
        [early, receipt, after]
    );
    let (entries, entered) = std::sync::mpsc::channel();
    query.guest_entry(entries, None)?;
    let retained = query.memory().input_reserved();
    let mut stream = restored.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        restored.admitted().lifecycle,
    )?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(query.store().meta()?, before_reopen);
    assert_eq!(query.store().graph_window_headers(&source, None)?, heads);
    assert_eq!(
        query.store().graph_result(source.tenant_id, &expired_id)?,
        Some(expected)
    );
    assert_eq!(
        query
            .store()
            .graph_result(source.tenant_id, &original.result_id)?,
        Some(previous)
    );
    assert_eq!(query.store().processor_result(&scope)?, Some(original));
    assert_eq!(
        query
            .store()
            .processor_health(&scope)?
            .ok_or("Recovered Graph progress")?
            .consumed_cursor,
        consumed
    );
    let (witnesses, contexts) = query
        .store()
        .package_evidence(source.tenant_id, std::slice::from_ref(&expired_id))?;
    assert!(witnesses.is_empty());
    assert_eq!(contexts, references);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(stream.cancel_and_join(&control).await?, None);
    assert_eq!(query.memory().input_reserved(), retained);
    Ok(())
}
