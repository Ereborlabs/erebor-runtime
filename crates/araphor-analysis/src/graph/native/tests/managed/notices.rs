use super::*;
use futures_util::StreamExt as _;

impl Fixture {
    async fn graph_definition(
        &self,
    ) -> TestResult<(
        PackageGrantV1,
        araphor_discovery_definition::ResolvedDefinition,
    )> {
        let prepared = self.prepare("").await?;
        let grant = prepared.grant.clone();
        let definition = prepared.prepared.resolved().clone();
        self.admit_definition(&grant, &definition)?;
        Ok((grant, definition))
    }

    async fn managed_graph(
        &self,
        grant: &PackageGrantV1,
        definition: &araphor_discovery_definition::ResolvedDefinition,
        id: &str,
        sql: &str,
    ) -> TestResult<Arc<crate::Instance>> {
        Ok(GraphPublication::admit(
            Arc::clone(&self.query),
            self.authority.clone(),
            self.facts.clone(),
            grant.clone(),
            id.into(),
            self.source.clone(),
            sql.into(),
            definition.clone(),
            &self.control,
        )
        .await?)
    }

    pub(super) fn retained_heads(
        &self,
    ) -> TestResult<Vec<(String, araphor_data::GraphSnapshotV1, u64)>> {
        self.query
            .store()
            .graph_window_headers(&self.source, None)?
            .into_iter()
            .map(|(id, header, revision)| {
                let graph = self
                    .query
                    .store()
                    .graph_result(self.source.tenant_id, &id)?
                    .ok_or("retained Graph body")?;
                assert_eq!(graph.first_cursor, header.first_cursor);
                assert_eq!(graph.last_cursor, header.last_cursor);
                Ok((id, graph, revision))
            })
            .collect()
    }

    fn graph_scope(&self) -> araphor_data::ProcessorScopeV1 {
        araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: self.source.clone(),
        }
    }

    fn signal_notice(&self, revision: u64) -> TestResult<u64> {
        Ok(self
            .query
            .store()
            .commit_context(&AnalysisContextVersionV1 {
                key: araphor_data::AnalysisContextKeyV1 {
                    tenant_id: self.source.tenant_id,
                    owner_id: "Graph notice signal".into(),
                    entity_key: vec![1],
                    lifetime_key: self.source.key(),
                    owner_revision: revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: araphor_data::ContextSensitivityV1::Tenant,
                body: b"unchanged Graph facts".to_vec(),
            })?)
    }

    async fn running_graph(&self, job: Arc<crate::Instance>) -> TestResult<Arc<crate::Instance>> {
        let host = crate::InstanceHost::with_graph_facts(
            Arc::clone(&self.query),
            self.authority.clone(),
            self.facts.clone(),
        );
        Ok(host
            .start(Arc::clone(&job), job.admitted().lifecycle, &self.control)
            .await?)
    }
}

async fn next_receipt(
    stream: &mut crate::instance::Subscription,
) -> TestResult<araphor_data::ManagedReceipt> {
    Ok(
        tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await?
            .ok_or("managed Graph subscription ended")??,
    )
}

#[tokio::test]
async fn unchanged_notice_reuses_calls() -> TestResult {
    use crate::graph::tests::fixture::{record, wire};
    const CAPACITY: usize = 64 * 1024 * 1024;
    let records = (1..=3)
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
    fixture.query = Engine::new(
        Arc::clone(fixture.query.store()),
        araphor_query::execution::Limits {
            input_capacity: Some(CAPACITY),
            output_capacity: Some(CAPACITY),
            output_bytes: 4 * 1024 * 1024,
            ..Default::default()
        },
    )?;
    fixture.serial_guests()?;
    let memory = Arc::clone(fixture.query.memory());
    assert_eq!(memory.input_reserved(), 0);
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "unchanged-notice",
            "SELECT * FROM events",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let first = next_receipt(&mut stream)
        .await
        .map_err(|error| format!("Initial Graph receipt: {error}"))?;
    assert_eq!(first.results.len(), 3);
    let head = fixture
        .query
        .store()
        .processor_result(&fixture.graph_scope())?
        .ok_or("Graph notice head")?;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &head.result_id)?
        .ok_or("Graph notice body")?;
    let references = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&head.result_id),
    )?;
    let (entry, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    let signal = fixture.signal_notice(1)?;
    let reused = next_receipt(&mut stream)
        .await
        .map_err(|error| format!("Unchanged Graph receipt: {error}"))?;
    assert!(reused.commit_revision > signal);
    assert!(
        !reused
            .frontier
            .as_ref()
            .ok_or("Unchanged Graph frontier")?
            .pending
    );
    assert_eq!(reused.results, first.results);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_result(&fixture.graph_scope())?,
        Some(head.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &head.result_id)?,
        Some(original.clone())
    );
    assert_eq!(
        fixture.query.store().package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&head.result_id)
        )?,
        references
    );
    let coverage = fixture
        .query
        .store()
        .source_receipt(&fixture.source)?
        .ok_or("Graph notice coverage")?
        .coverage_revision;
    assert_eq!(
        fixture.query.store().graph_notice(
            &fixture.graph_scope(),
            &head.result_id,
            head.commit_revision
        )?,
        Some((reused.commit_revision, coverage))
    );
    let saved = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "unchanged-notice",
            &fixture.control,
        )?
        .ok_or("Graph notice instance")?;
    let history = fixture.query.store().managed_history(
        &saved.grant.selection,
        &saved.spec.id,
        &fixture.control,
    )?;
    assert_eq!(history, [first.clone(), reused.clone()]);
    assert!(matches!(
        fixture.query.store().managed_query_output(
            &saved.grant.selection,
            &saved.spec.id,
            None,
            request("inspect")?.time_utc_ns,
            &fixture.control,
        )?,
        araphor_data::ManagedOutput::Selected { .. }
    ));
    for reference in reused.results.values() {
        let araphor_data::ManagedOutput::Call { result, .. } =
            fixture.query.store().managed_output(
                &saved,
                &reference.result_id,
                request("inspect-call")?.time_utc_ns,
                &fixture.control,
            )?
        else {
            return Err("Retained Graph call returned selected output".into());
        };
        assert!(result.current);
        assert_eq!(result.commit_revision, reference.commit_revision);
    }
    let idle = fixture.query.store().meta()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?, idle);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    assert!(original.input_manifest.coverage.is_empty());
    let body = fixture
        .query
        .store()
        .read_result(fixture.source.tenant_id, &head.result_id)?;
    for (revision, interval) in [(1, 8), (2, 9)] {
        let (_, entries) = Fixture::observe_guests(Arc::clone(&fixture.query), async {
            super::super::gates::report(
                &fixture,
                revision,
                &[([interval; 16], revision, "HEALTHY")],
            )?;
            next_receipt(&mut stream).await
        })
        .await?;
        assert_eq!(entries, 3);
        assert_eq!(
            fixture
                .query
                .store()
                .graph_notice(
                    &fixture.graph_scope(),
                    &head.result_id,
                    head.commit_revision,
                )?
                .ok_or("Fallback Graph notice")?
                .1,
            revision,
        );
        assert_eq!(
            fixture
                .query
                .store()
                .processor_result(&fixture.graph_scope())?,
            Some(head.clone()),
        );
        assert_eq!(
            fixture
                .query
                .store()
                .read_result(fixture.source.tenant_id, &head.result_id)?,
            body,
        );
    }
    let mut artifacts = Vec::new();
    for call in saved.spec.manifest.calls.values() {
        artifacts.push(
            fixture
                .query
                .store()
                .package_revision(
                    fixture.source.tenant_id,
                    &call.package.package_id,
                    &call.package.revision,
                )?
                .ok_or("Original Graph artifact")?,
        );
    }
    fixture.query.store().fault_write(
        "UPDATE package_revisions SET artifact = 'invalid'::BLOB",
        &[],
    )?;
    let error = fixture
        .prepare("")
        .await
        .err()
        .ok_or("Cold corrupted Graph image admitted")?;
    assert!(
        matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::Query {
                source: araphor_query::Error::Data {
                    source: araphor_data::Error::AnalysisContract {
                        source: sdk::Error::Io { path, .. }, ..
                    },
                },
            }) if path.as_path() == std::path::Path::new("<OCI archive>")
        ),
        "{error:?}",
    );
    for artifact in artifacts {
        fixture.query.store().fault_write(
            "UPDATE package_revisions SET artifact = ? WHERE tenant_id = ? AND package_id = ? AND revision = ?",
            &[&artifact.artifact, &artifact.tenant_id.as_slice(), &artifact.package_id, &artifact.revision],
        )?;
    }
    let fact = araphor_data::GraphFactV1 {
        record_id: fixture.records[0].id.clone(),
        value: araphor_data::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: false,
            reviewed_policy_revision: "reviewed-source".into(),
        },
    };
    let fact = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: fixture.source.tenant_id,
            owner_id: "Graph changed fact".into(),
            entity_key: vec![1],
            lifetime_key: fixture.source.key(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&fact)?,
    };
    let (_, entries) = Fixture::observe_guests(Arc::clone(&fixture.query), async {
        fixture
            .facts
            .supplied
            .lock()
            .map_err(|_| "Changed Graph fact")?
            .push(fact.clone());
        fixture.query.store().commit_context(&fact)?;
        next_receipt(&mut stream).await
    })
    .await?;
    assert_eq!(entries, 3);
    let (changed, replacement, changed_revision) = fixture
        .retained_heads()?
        .into_iter()
        .find(|(_, graph, _)| graph.input_manifest.context.contains(&fact.key))
        .ok_or("Changed Graph window")?;
    assert_ne!(changed, head.result_id);
    assert_eq!(
        replacement.previous_result_id.as_ref(),
        Some(&head.result_id)
    );
    assert_ne!(replacement.input_manifest, original.input_manifest);
    assert_eq!(
        replacement.witness_deadline_utc_ns,
        original.witness_deadline_utc_ns
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &head.result_id)?,
        body
    );
    stream.cancel_and_join(&fixture.control).await?;
    let (forced, entries) = Fixture::observe_guests(
        Arc::clone(&fixture.query),
        job.run(request("forced")?, &fixture.control),
    )
    .await?;
    assert_ne!(forced.results, first.results);
    assert_eq!(entries, 3);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &head.result_id)?,
        Some(original)
    );
    let notice =
        fixture
            .query
            .store()
            .graph_notice(&fixture.graph_scope(), &changed, changed_revision)?;
    let mut denied = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let (entry, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        || Err(Code::Denied.error("Graph reused commit authority")),
    )?;
    fixture.signal_notice(2)?;
    assert!(next_receipt(&mut denied).await.is_err());
    let terminal = denied
        .cancel_and_join(&fixture.control)
        .await?
        .ok_or("Denied Graph retained attempt")?;
    assert_eq!(
        terminal.exit,
        araphor_data::ManagedExit::Failed(Code::Denied)
    );
    assert!(terminal.suspended);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let status = fixture.query.store().managed_status(
        &grant.selection,
        "unchanged-notice",
        &fixture.control,
    )?;
    assert!(!status.instance.running);
    assert_eq!(status.instance.progress, forced.commit_revision);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Denied,
            ..
        }
    ));
    assert_eq!(
        fixture
            .query
            .store()
            .graph_notice(&fixture.graph_scope(), &changed, changed_revision,)?,
        notice
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &changed,)?,
        Some(replacement)
    );
    drop(job);
    assert_eq!(memory.input_reserved(), 0);
    drop(memory.reserve_input(CAPACITY)?);
    drop(memory.reserve_output(CAPACITY)?);
    Ok(())
}

#[tokio::test]
async fn managed_drains_prefixes() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "prefix-notices",
            "SELECT events.* FROM events CROSS JOIN graph_state
             WHERE source_cursor = consumed_cursor + 1",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let scope = fixture.graph_scope();
    let coverage = fixture
        .query
        .store()
        .source_receipt(&fixture.source)?
        .ok_or("Graph source receipt")?
        .coverage_revision;
    let mut heads = Vec::new();
    for cursor in 1..=3 {
        let receipt = next_receipt(&mut stream).await?;
        assert_eq!(receipt.results.len(), 3);
        let result = fixture
            .query
            .store()
            .processor_result(&scope)?
            .ok_or("managed prefix head")?;
        let graph = fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &result.result_id)?
            .ok_or("managed prefix snapshot")?;
        assert_eq!(graph.first_cursor, cursor);
        assert_eq!(graph.last_cursor, cursor);
        assert_eq!(graph.input_manifest.evidence.len(), 1);
        assert_eq!(graph.input_manifest.evidence[0].durable_cursor, cursor);
        assert_eq!(graph.input_positions.len(), 1);
        assert_eq!(graph.packages.len(), 3);
        assert_eq!(result.commit_revision, receipt.commit_revision);
        assert_eq!(
            fixture.query.store().graph_notice(
                &scope,
                &result.result_id,
                result.commit_revision,
            )?,
            Some((receipt.commit_revision, coverage))
        );
        let health = fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("managed prefix progress")?;
        assert_eq!(health.consumed_cursor, cursor);
        assert_eq!(health.accepted_cursor, 3);
        heads.push((result, graph));
    }
    let before = fixture.query.store().meta()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 3);
    for (result, graph) in heads {
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &result.result_id)?,
            Some(graph)
        );
    }
    stream.cancel_and_join(&fixture.control).await?;
    Ok(())
}

#[tokio::test]
async fn managed_notice_is_atomic() -> TestResult {
    retained_notices(&[(1, 1), (2, 2), (3, 3)]).await
}

#[tokio::test]
async fn managed_overlap_drains_heads() -> TestResult {
    retained_notices(&[(1, 3), (2, 3)]).await
}

async fn retained_notices(cuts: &[(u64, u64)]) -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let scope = fixture.graph_scope();
    let coverage = fixture
        .query
        .store()
        .source_receipt(&fixture.source)?
        .ok_or("Graph source receipt")?
        .coverage_revision;
    let mut heads = Vec::new();
    for &(first, last) in cuts {
        let job = fixture
            .managed_graph(
                &grant,
                &definition,
                &format!("notice-seed-{first}"),
                &format!("SELECT * FROM events WHERE source_cursor BETWEEN {first} AND {last}"),
            )
            .await?;
        let receipt = job.run(request("seed")?, &fixture.control).await?;
        assert_eq!(receipt.results.len(), 3);
        let (id, graph, revision) = fixture
            .retained_heads()?
            .into_iter()
            .find(|(_, graph, _)| graph.first_cursor == first)
            .ok_or("retained notice snapshot")?;
        assert_eq!((graph.first_cursor, graph.last_cursor), (first, last));
        assert_eq!(revision, receipt.commit_revision);
        heads.push((id, graph, revision));
    }
    let current = fixture.query.store().processor_result(&scope)?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "retained-notices",
            "WITH changes AS (
                SELECT COALESCE(MAX(commit_revision), 0) AS revision
                FROM context_versions WHERE owner_id = 'Graph notice signal'
             ), heads AS (
                SELECT first_cursor, last_cursor, notice_context_revision
                FROM graph_manifest
                QUALIFY ROW_NUMBER() OVER (
                    PARTITION BY tenant_id, source_key, first_cursor
                    ORDER BY commit_revision DESC) = 1
             ), work AS (
                SELECT first_cursor, last_cursor FROM heads CROSS JOIN changes
                WHERE notice_context_revision < revision
                ORDER BY first_cursor LIMIT 1
             ) SELECT events.* FROM events JOIN work
               ON source_cursor BETWEEN first_cursor AND last_cursor",
        )
        .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let idle = next_receipt(&mut stream).await?;
    assert!(idle.results.is_empty());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), cuts.len());
    let signal = fixture.signal_notice(1)?;
    let mut stamped = Vec::new();
    for (index, _) in heads.iter().enumerate() {
        let receipt = next_receipt(&mut stream).await?;
        assert_eq!(receipt.results.len(), 3);
        assert!(receipt.commit_revision > signal);
        stamped.push(receipt.commit_revision);
        for (position, (id, retained, revision)) in heads.iter().enumerate() {
            assert_eq!(
                fixture.query.store().graph_notice(&scope, id, *revision,)?,
                Some((
                    if position <= index {
                        stamped[position]
                    } else {
                        *revision
                    },
                    coverage,
                ))
            );
            assert_eq!(
                fixture
                    .query
                    .store()
                    .graph_result(fixture.source.tenant_id, id)?,
                Some(retained.clone())
            );
        }
    }
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), cuts.len() * 2);
    assert_eq!(fixture.query.store().processor_result(&scope)?, current);
    let drained = next_receipt(&mut stream).await?;
    assert!(drained.results.is_empty());
    assert!(drained.commit_revision > *stamped.last().ok_or("last Graph notice")?);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), cuts.len() * 2);
    let before = fixture.query.store().meta()?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), stream.next())
            .await
            .is_err()
    );
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), cuts.len() * 2);
    let authority = fixture.authority.clone();
    fixture.query.store().set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        move || {
            authority.set(false);
            Err(Code::Denied.error("Graph notice final guard"))
        },
    )?;
    fixture.signal_notice(2)?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
            .await?
            .ok_or("notice denial ended without an error")?
            .is_err()
    );
    for (index, (id, graph, revision)) in heads.iter().enumerate() {
        assert_eq!(
            fixture.query.store().graph_notice(&scope, id, *revision,)?,
            Some((stamped[index], coverage))
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, id)?,
            Some(graph.clone())
        );
    }
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("retained notice progress")?
            .consumed_cursor,
        3
    );
    assert!(fixture
        .authority
        .check(&job.admitted().grant, PackageActionV1::Run)
        .is_err());
    stream.cancel_and_join(&fixture.control).await?;
    Ok(())
}

#[tokio::test]
async fn manifest_tracks_exact_source() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    let (plan, sources) = fixture
        .query
        .prepare(
            "SELECT graph_result_id, first_cursor, notice_context_revision FROM graph_manifest",
            Vec::new(),
        )
        .await?;
    let control = AnalysisReadControl::default();
    let session = fixture.query.session(
        AnalysisSelectionV1::new(fixture.source.tenant_id, vec![fixture.source.clone()]),
        &control,
        request("manifest-time")?.time_utc_ns,
    )?;
    let mut stream = session.subscribe(plan, sources, b"exact Graph manifest", true)?;
    let initial = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("initial Graph manifest")??;
    assert_eq!(
        initial
            .batches
            .iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    let (id, first) = publication.refresh("graph:manifest-first".into()).await?;
    let changed = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("first Graph manifest")??;
    assert!(changed.batches.is_some());
    assert_eq!(
        changed
            .batches
            .iter()
            .flatten()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    assert!(changed.cursor.read_revision() >= first.commit_revision);
    assert!(changed
        .snapshot
        .results()
        .any(|result| result.result_id == id));
    let other = EvidenceIntakeIdentityV1 {
        source_id: [201; 16],
        ..fixture.source.clone()
    };
    assert_ne!(other, fixture.source);
    for record in &fixture.records {
        fixture.query.store().accept_validated_batch(
            other.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                intake_utc_ns: record.id.durable_cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    let instance = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "other-source-manifest".into(),
        other,
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let receipt = instance
        .run(request("other-head")?, &fixture.control)
        .await?;
    let unrelated = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await?
        .ok_or("unrelated Graph manifest metadata")??;
    assert!(unrelated.batches.is_none());
    assert_eq!(unrelated.cursor, changed.cursor);
    assert_eq!(unrelated.evaluated_utc_ns, changed.evaluated_utc_ns);
    assert!(unrelated.snapshot.page.extraction.meta.commit_revision >= receipt.commit_revision);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn managed_expiry_drains_heads() -> TestResult {
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
    let fixture = Fixture::stored(Target::Sql, records, directory, store)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let mut retain_at = 0;
    for cursor in 1..=3 {
        let job = fixture
            .managed_graph(
                &grant,
                &definition,
                &format!("expiry-seed-{cursor}"),
                &format!("SELECT * FROM events WHERE source_cursor = {cursor}"),
            )
            .await?;
        let mut input = request("seed")?;
        input.witness_expiry = input
            .time_utc_ns
            .checked_add(araphor_data::GRAPH_WITNESS_TTL_NS)
            .ok_or("Managed expiry input deadline")?;
        retain_at = retain_at.max(input.witness_expiry);
        let receipt = job.run(input, &fixture.control).await?;
        assert_eq!(receipt.results.len(), 3);
    }
    let originals = fixture.retained_heads()?;
    assert_eq!(originals.len(), 3);
    let mut references = BTreeMap::new();
    for (id, graph, _) in &originals {
        retain_at = retain_at.max(graph.witness_deadline_utc_ns);
        let (_, context) = fixture
            .query
            .store()
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(id))?;
        assert_eq!(
            context
                .iter()
                .filter(|reference| reference.key.owner_id == "native-package-v1")
                .count(),
            3
        );
        references.insert(graph.first_cursor, context);
    }
    let retained = araphor_data::EvidenceRetentionOwner::new(fixture.query.store()).retain(
        &fixture.source,
        retain_at.checked_add(1).ok_or("expiry retention time")?,
    )?;
    assert_eq!(retained.removed_records, 3);
    assert_eq!(retained.retained_floor, 3);
    let definition = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            GraphPublication::expiry_program(),
            Arc::clone(&fixture.control),
        )
        .await?;
    fixture.admit_definition(&grant, &definition)?;
    let job = GraphPublication::admit_expiry(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant,
        "multi-head-expiry".into(),
        fixture.source.clone(),
        &fixture.control,
    )
    .await?;
    let job = fixture.running_graph(job).await?;
    let mut stream = job.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        job.admitted().lifecycle,
    )?;
    let (entries, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entries, None)?;
    let facts = fixture.facts.calls.load(Ordering::SeqCst);
    let current = fixture
        .query
        .store()
        .processor_result(&fixture.graph_scope())?;
    let mut receipts = Vec::new();
    for expired in 1..=3 {
        let receipt = next_receipt(&mut stream).await?;
        assert!(receipt.results.is_empty());
        if let Some(previous) = receipts.last() {
            assert!(receipt.commit_revision > *previous);
        }
        receipts.push(receipt.commit_revision);
        let heads = fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?;
        assert_eq!(heads.len(), 3);
        let due = heads
            .iter()
            .filter(|(_, graph, _)| !graph.retained_input_expired())
            .count();
        assert_eq!(due, 3 - expired);
        for (id, graph, revision) in heads {
            let (original_id, original, original_revision) = originals
                .iter()
                .find(|(_, original, _)| original.first_cursor == graph.first_cursor)
                .ok_or("exact expired window")?;
            if graph.retained_input_expired() {
                assert_ne!(&id, original_id);
                assert!(receipts.contains(&revision));
                let expected =
                    Graph::expire(original, original_id, original.context_notice_revision)?;
                assert_eq!(
                    fixture
                        .query
                        .store()
                        .graph_result(fixture.source.tenant_id, &id)?,
                    Some(expected)
                );
                let (witnesses, contexts) = fixture
                    .query
                    .store()
                    .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?;
                assert!(witnesses.is_empty());
                assert_eq!(Some(&contexts), references.get(&graph.first_cursor));
            } else {
                assert_eq!(&id, original_id);
                assert_eq!(revision, *original_revision);
            }
            assert_eq!(
                fixture
                    .query
                    .store()
                    .graph_result(fixture.source.tenant_id, original_id)?,
                Some(original.clone())
            );
        }
    }
    assert_eq!(
        fixture
            .query
            .store()
            .processor_result(&fixture.graph_scope())?,
        current
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    let before = fixture.query.store().meta()?;
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
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
        heads
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), facts);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    stream.cancel_and_join(&fixture.control).await?;
    Ok(())
}
