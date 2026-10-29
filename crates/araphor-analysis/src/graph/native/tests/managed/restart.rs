use super::*;
use futures_util::StreamExt as _;

#[tokio::test]
async fn graph_restart_keeps_frontier() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "graph-restart".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let first = job
        .run(request("before-restart")?, &fixture.control)
        .await?;
    let frontier = first.frontier.clone().ok_or("Graph native frontier")?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let graph = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Graph head before restart")?;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &graph.result_id)?;
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let running = host
        .start(Arc::clone(&job), job.admitted().lifecycle, &fixture.control)
        .await?;
    let saved = running.admitted().clone();
    for image in &saved.spec.definition.images {
        assert!(fixture.query.store().uninstall_package_image(
            fixture.source.tenant_id,
            image,
            || Ok(())
        )?);
    }
    let unchanged = fixture.query.store().meta()?;
    assert!(fixture.prepare("").await.is_err());
    assert_eq!(fixture.query.store().meta()?, unchanged);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let before = fixture.query.store().meta()?;
    let record = fixture.records.last().ok_or("Graph record")?.clone();
    let Fixture {
        query,
        control,
        source,
        facts,
        authority,
        _directory,
        _graph: graph_lease,
        ..
    } = fixture;
    drop(running);
    drop(job);
    drop(host);
    drop(graph_lease);
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let query = Engine::new(store, Default::default())?;
    let host = crate::InstanceHost::with_graph_facts(Arc::clone(&query), authority, facts.clone());
    let crate::instance::Restored::Present(restored) = host
        .restore(source.tenant_id, "graph-restart", &control)
        .await?
    else {
        return Err("restored Graph job".into());
    };
    assert_eq!(restored.admitted(), &saved);
    assert_eq!(query.store().meta()?, before);
    let resumed = query
        .store()
        .managed_resume(source.tenant_id, "graph-restart", &control)?;
    assert_eq!(resumed.frontier, Some(frontier));
    assert_eq!(resumed.instance.progress, first.commit_revision);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 1);
    let retained = query.memory().input_reserved();
    let mut stream = restored.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        restored.admitted().lifecycle,
    )?;
    let mut next = Box::pin(stream.next());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), next.as_mut())
            .await
            .is_err()
    );
    assert_eq!(query.store().meta()?, before);
    assert_eq!(query.store().processor_result(&scope)?, Some(graph.clone()));
    assert_eq!(facts.calls.load(Ordering::SeqCst), 1);
    query.store().accept_validated_batch(
        source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.into(),
        },
    )?;
    let second = tokio::time::timeout(std::time::Duration::from_secs(30), next)
        .await?
        .ok_or("Graph change after restart")??;
    assert_ne!(second.attempt, first.attempt);
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(second.results.len(), 3);
    assert_eq!(facts.calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph progress")?
            .consumed_cursor,
        4
    );
    assert_eq!(
        query
            .store()
            .managed_attempt(source.tenant_id, "graph-restart", &first.attempt, &control)?
            .ok_or("retained Graph attempt")?
            .receipt(),
        Some(&first)
    );
    assert_eq!(
        query
            .store()
            .graph_result(source.tenant_id, &graph.result_id)?,
        original
    );
    assert_eq!(stream.cancel_and_join(&control).await?, None);
    assert_eq!(query.memory().input_reserved(), retained);
    Ok(())
}

#[tokio::test]
async fn graph_call_progress_flush_failure_rolls_back() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "graph-progress-flush".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let first = job
        .run(request("progress-first")?, &fixture.control)
        .await?;
    let store = fixture.query.store();
    let scope = fixture.graph_scope();
    let head = store
        .processor_result(&scope)?
        .ok_or("first Graph result")?;
    let graph = store
        .graph_result(fixture.source.tenant_id, &head.result_id)?
        .ok_or("first Graph snapshot")?;
    let record = fixture.records.last().ok_or("Graph record")?.clone();
    store.accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.into(),
        },
    )?;
    let retained = store.retained_counts(fixture.source.tenant_id)?;
    let table = "CREATE TABLE graph_call_progress (
        scope_id UBIGINT NOT NULL, evidence_id UBIGINT NOT NULL,
        digest BLOB NOT NULL CHECK (octet_length(digest) = 32),
        state VARCHAR, valid_from UBIGINT NOT NULL, valid_to UBIGINT,
        PRIMARY KEY (scope_id, evidence_id, valid_from),
        CHECK (valid_to IS NULL OR valid_to > valid_from)";
    store.fault_write(
        &format!(
            "CREATE TABLE graph_call_progress_saved AS SELECT * FROM graph_call_progress;
             DROP TABLE graph_call_progress;
             {table}, CHECK (valid_from <= {}));
             INSERT INTO graph_call_progress SELECT * FROM graph_call_progress_saved;",
            first.commit_revision
        ),
        &[],
    )?;
    let second = request("progress-second")?;
    let failed = job
        .run(second, &fixture.control)
        .await
        .err()
        .ok_or("Graph call progress flush unexpectedly succeeded")?;
    assert!(
        format!("{failed:?}").contains("flush Graph call progress"),
        "{failed:?}"
    );
    assert_eq!(store.retained_counts(fixture.source.tenant_id)?, retained);
    assert_eq!(store.processor_result(&scope)?, Some(head.clone()));
    assert_eq!(
        store
            .managed_resume(
                fixture.source.tenant_id,
                "graph-progress-flush",
                &fixture.control
            )?
            .instance
            .progress,
        first.commit_revision
    );
    assert_eq!(
        store.graph_result(fixture.source.tenant_id, &head.result_id)?,
        Some(graph)
    );
    store.verify_state()?;
    store.fault_write(
        &format!(
            "DROP TABLE graph_call_progress;
             {table});
             INSERT INTO graph_call_progress SELECT * FROM graph_call_progress_saved;
             DROP TABLE graph_call_progress_saved;"
        ),
        &[],
    )?;
    let retried = job
        .run(request("progress-retry")?, &fixture.control)
        .await?;
    assert_eq!(retried.results.len(), 3);
    assert!(retried.commit_revision > first.commit_revision);
    assert_eq!(
        store
            .processor_health(&scope)?
            .ok_or("Graph progress")?
            .consumed_cursor,
        4
    );
    store.verify_state()?;
    Ok(())
}

#[tokio::test]
async fn retained_noncontinuing_graph_call_uses_native_prior() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let artifact = PackageArtifactV1 {
        descriptor: araphor_detector_example::BurstDetector::package(),
        implementations: vec![PackageImplementationV1::Wasm {
            exports: vec!["detect".into()],
            artifact: araphor_analysis_builtins::components::DETECTOR.to_vec(),
        }],
        fixtures: Vec::new(),
    };
    fixture.query.store().install_package_image(
        fixture.source.tenant_id,
        &PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?,
        || Ok(()),
    )?;
    let calls = araphor_data::FindingV1::PACKAGES
        .iter()
        .map(|id| {
            format!(
                "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => \
                (SELECT * FROM records), facts => (SELECT * FROM facts), \
                manifest => (SELECT * FROM manifest))"
            )
        })
        .chain(std::iter::once(
            "SELECT * FROM \"example-burst\".\"1\".detect('subjects', \
                records => (SELECT * FROM records), facts => (SELECT * FROM facts), \
                manifest => (SELECT * FROM manifest), threshold => 2)"
                .into(),
        ))
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let prepared = fixture.prepare_sql("*", "", calls).await?;
    let grant = prepared.grant.clone();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(prepared);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "retained-burst".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let first = job.run(request("burst-first")?, &fixture.control).await?;
    assert_eq!(first.results.len(), 4);
    let burst = job
        .admitted()
        .spec
        .manifest
        .calls
        .iter()
        .find(|(_, call)| call.package.package_id == "example-burst")
        .map(|(id, _)| *id)
        .ok_or("example Graph call")?;
    let scope = fixture.graph_scope();
    let head = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("first burst Graph")?;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &head.result_id)?
        .ok_or("first burst snapshot")?;
    assert!(original
        .findings
        .iter()
        .any(|finding| finding.package_id == "example-burst"));
    let second = job.run(request("burst-second")?, &fixture.control).await?;
    assert_eq!(second.results.len(), first.results.len());
    let fresh = second.results.get(&burst).ok_or("fresh example call")?;
    assert_ne!(Some(fresh), first.results.get(&burst));
    assert_eq!(
        fixture.query.store().processor_result(&scope)?,
        Some(head.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &head.result_id,)?,
        Some(original.clone())
    );
    drop(job);
    let Fixture {
        query,
        control,
        source,
        _graph,
        _directory,
        ..
    } = fixture;
    drop(_graph);
    drop(query);
    let reopened = AnalysisStore::open(_directory.path().join("data"))?;
    assert_eq!(reopened.processor_result(&scope)?, Some(head.clone()));
    assert_eq!(
        reopened.graph_result(source.tenant_id, &head.result_id,)?,
        Some(original)
    );
    let resumed = reopened.managed_resume(source.tenant_id, "retained-burst", &control)?;
    let saved = reopened.managed_evaluation(&resumed.instance, &fresh.result_id, &control)?;
    assert_eq!(saved.export, "detect");
    Ok(())
}

#[tokio::test]
async fn graph_call_reopen_rejects_corruption() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "graph-call-recovery".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let first = job
        .run(request("graph-call-first")?, &fixture.control)
        .await?;
    assert_eq!(first.results.len(), 3);
    let record = fixture
        .records
        .last()
        .ok_or("Graph recovery record")?
        .clone();
    fixture.query.store().accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.into(),
        },
    )?;
    let second = job
        .run(request("graph-call-second")?, &fixture.control)
        .await?;
    assert_eq!(second.results.len(), 3);
    let store = fixture.query.store();
    let backup = fixture._directory.path().join("data/backups/graph-call");
    store.backup(&backup)?;
    for (name, sql) in [
        ("scope pin", "UPDATE graph_call_scopes SET image_digest = 'wrong' WHERE scope_id = (SELECT min(scope_id) FROM graph_call_scopes)"),
        ("membership count", "UPDATE graph_call_versions SET subject_count = subject_count + 1 WHERE result_id = (SELECT min(result_id) FROM graph_call_versions)"),
        ("anchor", "UPDATE graph_call_subjects SET anchor_fact = X'00' WHERE rowid = (SELECT min(rowid) FROM graph_call_subjects)"),
        ("orphan", "INSERT INTO graph_call_progress SELECT (SELECT max(scope_id) + 1 FROM graph_call_scopes), evidence_id, digest, state, valid_from, valid_to FROM graph_call_progress LIMIT 1"),
        ("overlap", "INSERT INTO graph_call_subjects SELECT m.scope_id, m.subject_id, m.anchor_record_id, m.anchor_fact, (SELECT max(v.commit_revision) FROM graph_call_versions v WHERE v.scope_id = m.scope_id), NULL FROM graph_call_subjects m WHERE m.valid_to IS NULL AND m.valid_from < (SELECT max(v.commit_revision) FROM graph_call_versions v WHERE v.scope_id = m.scope_id) LIMIT 1"),
        ("base", "UPDATE graph_call_versions SET base_result_id = NULL WHERE base_result_id IS NOT NULL"),
    ] {
        let root = fixture._directory.path().join(format!("graph-call-{name}"));
        let restored = AnalysisStore::restore(&backup, &root)?;
        restored.fault_write(sql, &[])?;
        drop(restored);
        assert!(AnalysisStore::open(&root).is_err(), "{name}");
    }
    Ok(())
}

fn graph_cut(
    store: &AnalysisStore,
    source: &EvidenceIntakeIdentityV1,
) -> araphor_data::Result<serde_json::Value> {
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    let head = store.processor_result(&scope)?;
    let health = store.processor_health(&scope)?;
    let mut windows = Vec::new();
    for (id, header, revision) in store.graph_window_headers(source, None)? {
        let evidence = store.package_evidence(source.tenant_id, std::slice::from_ref(&id))?;
        let contexts = evidence
            .1
            .iter()
            .map(|reference| {
                store
                    .context_version(&reference.key)?
                    .ok_or_else(|| Code::Missing.error("retained Graph context"))
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        windows.push(serde_json::json!({
            "id": id,
            "header": header,
            "revision": revision,
            "graph": store.graph_result(source.tenant_id, &id)?,
            "body": store.read_result(source.tenant_id, &id)?,
            "frozen": store.frozen_result(&id)?,
            "evidence": evidence,
            "contexts": contexts,
            "reference": store.package_result_refs(source.tenant_id, &[id])?,
        }));
    }
    Ok(serde_json::json!({
        "head": head.map(|head| (head.result_id, head.commit_revision, head.body)),
        "health": health.map(|health| (
            health.state, health.accepted_cursor, health.consumed_cursor,
            health.resume_floor, health.cursor_lag, health.incomplete,
        )),
        "snapshot": store.graph_snapshot(source)?,
        "windows": windows,
    }))
}

fn retained_calls(
    store: &AnalysisStore,
    instance: &araphor_data::ManagedInstance,
    receipt: &araphor_data::ManagedReceipt,
    now: u64,
    control: &AnalysisReadControl,
) -> araphor_data::Result<serde_json::Value> {
    use snafu::ResultExt as _;

    let mut calls = Vec::new();
    for (call, reference) in &receipt.results {
        let declaration = &instance.spec.manifest.calls[call];
        let descriptor = store
            .package_revision(
                instance.spec.tenant,
                &declaration.package.package_id,
                &declaration.package.revision,
            )?
            .ok_or_else(|| Code::Missing.error("retained Graph descriptor"))?
            .decode_artifact()?
            .descriptor;
        let evaluation = store.managed_evaluation(instance, &reference.result_id, control)?;
        let checked = descriptor
            .check_evaluation(&evaluation)
            .context(araphor_data::AnalysisContractSnafu)?;
        let input = checked
            .encode()
            .context(araphor_data::AnalysisContractSnafu)?;
        let result = store.managed_result(instance, &reference.result_id, now, control)?;
        let output = sdk::wire::Output::encode_checked(&checked, &result.output)
            .context(araphor_data::AnalysisContractSnafu)?;
        calls.push(serde_json::json!({
            "call": call,
            "reference": reference,
            "frozen": store.frozen_result(&reference.result_id)?,
            "evaluation": (
                input.export_name, input.inputs, input.parameters,
                input.context, input.checkpoint, input.previous_outputs,
            ),
            "context": result.context,
            "output": output,
            "revision": result.commit_revision,
            "evidence": store.package_evidence(
                instance.spec.tenant, std::slice::from_ref(&reference.result_id),
            )?,
        }));
    }
    Ok(serde_json::Value::Array(calls))
}

fn managed_cut(
    store: &AnalysisStore,
    source: &EvidenceIntakeIdentityV1,
    id: &str,
    attempt: Option<&str>,
    now: u64,
) -> araphor_data::Result<serde_json::Value> {
    let control = AnalysisReadControl::default();
    let meta = store.meta()?;
    let instance = store
        .managed_instance(source.tenant_id, id, &control)?
        .ok_or_else(|| Code::Missing.error("Graph crash instance"))?;
    let history = store.managed_history(&instance.grant.selection, id, &control)?;
    let mut outputs = Vec::new();
    for receipt in &history {
        let selected = store
            .managed_selected(source.tenant_id, id, &receipt.attempt, &control)?
            .ok_or_else(|| Code::Missing.error("Graph crash selected output"))?;
        let araphor_data::ManagedOutput::Selected { packet, .. } =
            store.managed_output(&instance, &receipt.selected.result_id, now, &control)?
        else {
            return Err(Code::Invalid.error("Graph crash selected kind"));
        };
        outputs.push(serde_json::json!({
            "receipt": receipt,
            "selected": packet,
            "selected_revision": selected.commit_revision,
            "frozen": store.frozen_result(&receipt.selected.result_id)?,
            "evidence": store.package_evidence(
                source.tenant_id, std::slice::from_ref(&receipt.selected.result_id),
            )?,
            "calls": retained_calls(store, &instance, receipt, now, &control)?,
        }));
    }
    let pending = attempt
        .map(|attempt| {
            store
                .managed_attempt(source.tenant_id, id, attempt, &control)?
                .map(|attempt| {
                    serde_json::json!((
                        attempt.request(),
                        attempt.instance(),
                        attempt.receipt(),
                        attempt.terminal(),
                    ))
                })
                .ok_or_else(|| Code::Missing.error("Graph crash attempt"))
        })
        .transpose()?;
    let (_, active) = store.active_managed(&control)?;
    Ok(serde_json::json!({
        "meta": (
            meta.store_uuid.to_string(), meta.schema_version,
            meta.recovery_epoch, meta.commit_revision,
        ),
        "instance": instance,
        "active": active.into_iter().map(|member| (
            member.tenant, member.id, member.generation, member.lifecycle,
        )).collect::<Vec<_>>(),
        "attempt": pending,
        "history": history,
        "outputs": outputs,
        "graph": graph_cut(store, source)?,
        "retained": store.retained_counts(source.tenant_id)?,
        "witnesses": store.witness_usage(source.tenant_id, now)?,
    }))
}

fn write_cut(path: &std::path::Path, cut: &serde_json::Value) -> araphor_data::Result<()> {
    let bytes = serde_json::to_vec(cut).map_err(|source| araphor_data::Error::PackageEncoding {
        source,
        location: snafu::location!(),
    })?;
    std::fs::write(path, bytes).map_err(|source| araphor_data::Error::Io {
        source,
        path: path.to_owned(),
        location: snafu::location!(),
    })
}

#[tokio::test]
async fn managed_rechecks_keep_heads() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(
            &grant,
            &definition,
            "historical-graph",
            "SELECT * FROM events",
        )
        .await?;
    let first_input = request("first")?;
    let first = job.run(first_input.clone(), &fixture.control).await?;
    assert_eq!(first.results.len(), 3);
    let domain = graph_cut(fixture.query.store(), &fixture.source)?;
    let calls = retained_calls(
        fixture.query.store(),
        job.admitted(),
        &first,
        first_input.time_utc_ns,
        &fixture.control,
    )?;
    let scope = fixture.graph_scope();
    let head = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("original Graph head")?;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &head.result_id)?;
    let body = fixture.query.store().frozen_result(&head.result_id)?;
    let evidence = fixture.query.store().package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&head.result_id),
    )?;
    let second = job.run(request("same")?, &fixture.control).await?;
    assert!(second.commit_revision > first.commit_revision);
    assert_eq!(second.results.len(), 3);
    assert_eq!(graph_cut(fixture.query.store(), &fixture.source)?, domain);
    assert_eq!(
        retained_calls(
            fixture.query.store(),
            job.admitted(),
            &first,
            first_input.time_utc_ns,
            &fixture.control,
        )?,
        calls
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "historical-graph",
            &fixture.control,
        )?,
        [first.clone(), second.clone()]
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 2);
    drop(job);
    let Fixture {
        query,
        control,
        source,
        facts,
        authority,
        records,
        _graph,
        _directory,
        ..
    } = fixture;
    drop(_graph);
    drop(query);
    let store = Arc::new(AnalysisStore::open(_directory.path().join("data"))?);
    let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
    let query = Engine::new(store, Default::default())?;
    let host = crate::InstanceHost::with_graph_facts(Arc::clone(&query), authority, facts.clone());
    let crate::instance::Restored::Present(job) = host
        .restore(source.tenant_id, "historical-graph", &control)
        .await?
    else {
        return Err("historical Graph restore".into());
    };
    assert_eq!(graph_cut(query.store(), &source)?, domain);
    assert_eq!(
        retained_calls(
            query.store(),
            job.admitted(),
            &first,
            first_input.time_utc_ns,
            &control,
        )?,
        calls
    );
    assert_eq!(
        query
            .store()
            .managed_history(&grant.selection, "historical-graph", &control,)?,
        [first.clone(), second.clone()]
    );
    let fact = araphor_data::GraphFactV1 {
        record_id: records[0].id.clone(),
        value: araphor_data::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: false,
            reviewed_policy_revision: "historical-source".into(),
        },
    };
    let fact = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "Graph historical fact".into(),
            entity_key: vec![1],
            lifetime_key: source.key(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: araphor_data::ContextSensitivityV1::Tenant,
        body: serde_json::to_vec(&fact)?,
    };
    facts
        .supplied
        .lock()
        .map_err(|_| "historical fact fixture")?
        .push(fact.clone());
    query.store().commit_context(&fact)?;
    let changed = job.run(request("changed")?, &control).await?;
    let windows = query.store().graph_window_headers(&source, None)?;
    assert_eq!(windows.len(), 1);
    let (id, _, revision) = &windows[0];
    assert_ne!(id, &head.result_id);
    assert_eq!(*revision, changed.commit_revision);
    let replacement = query
        .store()
        .graph_result(source.tenant_id, id)?
        .ok_or("replacement Graph")?;
    assert_eq!(
        replacement.previous_result_id.as_ref(),
        Some(&head.result_id)
    );
    assert!(replacement.input_manifest.context.contains(&fact.key));
    assert_eq!(
        query
            .store()
            .processor_health(&scope)?
            .ok_or("historical Graph progress")?
            .consumed_cursor,
        3
    );
    assert_eq!(
        query
            .store()
            .graph_result(source.tenant_id, &head.result_id)?,
        original
    );
    assert_eq!(query.store().frozen_result(&head.result_id)?, body);
    assert_eq!(
        query
            .store()
            .package_evidence(source.tenant_id, std::slice::from_ref(&head.result_id))?,
        evidence
    );
    assert_eq!(
        retained_calls(
            query.store(),
            job.admitted(),
            &first,
            first_input.time_utc_ns,
            &control
        )?,
        calls
    );
    assert_eq!(
        query
            .store()
            .managed_history(&grant.selection, "historical-graph", &control)?,
        [first, second, changed]
    );
    assert_eq!(facts.calls.load(Ordering::SeqCst), 3);
    query.store().verify_state()?;
    drop(job);
    drop(host);
    assert_eq!(query.memory().input_reserved(), 0);
    Ok(())
}

#[tokio::test]
async fn managed_graph_crashes() -> TestResult {
    const ID: &str = "graph-crash";
    if let Some(root) = std::env::var_os("ARAPHOR_MANAGED_GRAPH_ROOT") {
        let root = std::path::PathBuf::from(root);
        let directory = tempfile::tempdir()?;
        let manifest = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json")
                .as_slice(),
        )?;
        let fixture = Fixture::stored(
            Target::Wasm,
            manifest.records.into_iter().take(3).collect(),
            directory,
            Arc::new(AnalysisStore::open(&root)?),
        )?;
        let host = crate::InstanceHost::with_graph_facts(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.facts.clone(),
        );
        let crate::instance::Restored::Present(job) = host
            .restore(fixture.source.tenant_id, ID, &fixture.control)
            .await?
        else {
            return Err("Graph crash instance restore".into());
        };
        let input: araphor_data::ManagedRequest =
            serde_json::from_slice(&std::fs::read(root.with_extension("request.json"))?)?;
        let store = Arc::clone(fixture.query.store());
        let source = fixture.source.clone();
        let id = input.id.clone();
        let now = input.time_utc_ns;
        let path = root.with_extension("cut.json");
        fixture.query.store().set_commit_hook(
            araphor_data::AnalysisCommitStage::BeforeResultCommit,
            move || write_cut(&path, &managed_cut(&store, &source, ID, Some(&id), now)?),
        )?;
        job.run(input, &fixture.control).await?;
        return Err("The Managed Graph crash did not occur".into());
    }
    for point in ["managed.before", "managed.after"] {
        let fixture = Fixture::target(Target::Wasm)?;
        let (grant, definition) = fixture.graph_definition().await?;
        let job = fixture
            .managed_graph(&grant, &definition, ID, "SELECT * FROM events")
            .await?;
        let original = job.admitted().clone();
        let before = fixture.query.store().meta()?;
        let domain = graph_cut(fixture.query.store(), &fixture.source)?;
        let usage = fixture
            .query
            .store()
            .retained_counts(fixture.source.tenant_id)?;
        let input = request("crash")?;
        let root = fixture._directory.path().join("data");
        std::fs::write(
            root.with_extension("request.json"),
            serde_json::to_vec(&input)?,
        )?;
        drop(job);
        let Fixture {
            query,
            control,
            source,
            records,
            authority,
            facts,
            _graph,
            _directory,
            ..
        } = fixture;
        drop(_graph);
        drop(query);
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "graph::native::tests::managed::restart::managed_graph_crashes",
            ])
            .env("ARAPHOR_MANAGED_GRAPH_ROOT", &root)
            .env("ARAPHOR_CRASH_ROOT", &root)
            .env("ARAPHOR_CRASH_POINT", point)
            .status()?;
        assert_eq!(status.code(), Some(73), "{point}");
        let store = Arc::new(AnalysisStore::open(&root)?);
        let prior: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.with_extension("cut.json"))?)?;
        let committed = point == "managed.after";
        let meta = store.meta()?;
        assert_eq!(meta.store_uuid, before.store_uuid);
        assert_eq!(meta.recovery_epoch, before.recovery_epoch);
        assert_eq!(meta.commit_revision, before.commit_revision + 2);
        let attempt = store
            .managed_attempt(source.tenant_id, ID, &input.id, &control)?
            .ok_or("crashed Graph attempt")?;
        let mut recorded = input.clone();
        recorded.frontier = attempt.request().frontier.clone();
        assert!(recorded.frontier.is_some());
        assert_eq!(attempt.request(), &recorded);
        assert_eq!(attempt.instance(), &original);
        assert_eq!(
            prior["meta"],
            serde_json::json!((
                before.store_uuid.to_string(),
                before.schema_version,
                before.recovery_epoch,
                before.commit_revision + 1,
            ))
        );
        assert_eq!(prior["instance"], serde_json::to_value(&original)?);
        assert_eq!(prior["graph"], domain);
        assert_eq!(prior["attempt"][0], serde_json::to_value(&recorded)?);
        assert_eq!(prior["attempt"][1], serde_json::to_value(&original)?);
        assert!(prior["attempt"][2].is_null());
        assert!(prior["attempt"][3].is_null());
        assert!(prior["history"]
            .as_array()
            .ok_or("prepublication Graph history")?
            .is_empty());
        assert!(prior["outputs"]
            .as_array()
            .ok_or("prepublication Graph outputs")?
            .is_empty());
        assert_eq!(prior["retained"][3].as_u64(), Some(usage.3));
        let current = store
            .managed_instance(source.tenant_id, ID, &control)?
            .ok_or("reopened Graph instance")?;
        let mut saved = original.clone();
        if let Some(receipt) = attempt.receipt() {
            assert!(committed);
            saved.progress = receipt.commit_revision;
        }
        assert_eq!(current, saved);
        if !committed {
            assert!(attempt.receipt().is_none());
            let terminal = araphor_data::ManagedTerminal {
                instance: ID.into(),
                attempt: input.id.clone(),
                revision: before.commit_revision + 2,
                exit: araphor_data::ManagedExit::Cancelled,
                suspended: false,
            };
            assert_eq!(attempt.terminal(), Some(&terminal));
            let mut expected = prior.clone();
            expected["meta"][3] = serde_json::json!(terminal.revision);
            expected["witnesses"]["read_revision"] = serde_json::json!(terminal.revision);
            expected["attempt"][3] = serde_json::to_value(&terminal)?;
            assert_eq!(
                managed_cut(&store, &source, ID, Some(&input.id), input.time_utc_ns)?,
                expected
            );
            assert_eq!(store.retained_counts(source.tenant_id)?.3, usage.3);
            assert!(store.graph_snapshot(&source)?.is_none());
            let scope = araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: source.clone(),
            };
            assert_eq!(
                store
                    .processor_health(&scope)?
                    .ok_or("uncommitted Graph progress")?
                    .consumed_cursor,
                0
            );
            let witnesses = store.witness_usage(source.tenant_id, input.time_utc_ns)?;
            assert_eq!(witnesses.referenced_bytes, 0);
            assert_eq!(witnesses.context_bytes, 0);
        } else {
            assert!(attempt.terminal().is_none());
            let receipt = attempt.receipt().ok_or("atomic Graph receipt")?;
            assert_eq!(receipt.results.len(), 3);
            assert_eq!(receipt.commit_revision, meta.commit_revision);
            assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
            assert!(receipt
                .results
                .values()
                .all(|reference| reference.commit_revision == receipt.commit_revision));
            let cut = managed_cut(&store, &source, ID, Some(&input.id), input.time_utc_ns)?;
            assert!(cut["outputs"][0]["calls"]
                .as_array()
                .ok_or("Graph crash call outputs")?
                .iter()
                .all(|call| !call["output"]["checkpoint"].is_null()));
            assert_eq!(
                cut["history"]
                    .as_array()
                    .ok_or("Graph crash history")?
                    .len(),
                1
            );
            assert_eq!(
                cut["outputs"]
                    .as_array()
                    .ok_or("Graph crash outputs")?
                    .len(),
                1
            );
            let scope = araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: source.clone(),
            };
            let head = store.processor_result(&scope)?.ok_or("atomic Graph head")?;
            assert_eq!(head.commit_revision, receipt.commit_revision);
            let graph = store
                .graph_result(source.tenant_id, &head.result_id)?
                .ok_or("atomic Graph body")?;
            assert!(!graph.graph.subjects.is_empty());
            assert_eq!(graph.input_manifest.evidence.len(), 3);
            assert_eq!(graph.input_manifest.context.len(), 3);
            assert_eq!(graph.input_positions.len(), 3);
            assert_eq!(graph.packages.len(), 3);
            assert_eq!(
                store.read_result(source.tenant_id, &head.result_id)?,
                Some(head.body.clone())
            );
            let (witnesses, contexts) =
                store.package_evidence(source.tenant_id, std::slice::from_ref(&head.result_id))?;
            assert_eq!(witnesses.len(), 3);
            assert_eq!(contexts.len(), 6);
            assert!(contexts
                .iter()
                .all(|reference| reference.commit_revision == receipt.commit_revision));
            assert_eq!(
                contexts
                    .iter()
                    .filter(|reference| reference.key.owner_id == "native-package-v1")
                    .count(),
                3
            );
            assert_eq!(
                store
                    .processor_health(&scope)?
                    .ok_or("atomic Graph progress")?
                    .consumed_cursor,
                3
            );
            let witness_usage = store.witness_usage(source.tenant_id, input.time_utc_ns)?;
            assert_eq!(
                witness_usage.referenced_bytes,
                records
                    .iter()
                    .map(|record| record.wire_record.len() as u64)
                    .sum::<u64>()
            );
            assert!(witness_usage.context_bytes > 0);
            assert_eq!(store.retained_counts(source.tenant_id)?.3, usage.3 + 5);
        }
        store.verify_state()?;
        let _graph = store.lease_graph(vec![AnalysisSelectionV1::tenant(source.tenant_id)])?;
        let query = Engine::new(store, Default::default())?;
        let host = crate::InstanceHost::with_graph_facts(Arc::clone(&query), authority, facts);
        let crate::instance::Restored::Present(job) =
            host.restore(source.tenant_id, ID, &control).await?
        else {
            return Err("atomic Graph instance restore".into());
        };
        let fence = managed_cut(
            query.store(),
            &source,
            ID,
            Some(&input.id),
            input.time_utc_ns,
        )?;
        if committed {
            assert_eq!(
                job.run(input.clone(), &control).await?,
                *attempt.receipt().ok_or("retained atomic receipt")?
            );
        } else {
            assert!(matches!(
                job.run(input.clone(), &control).await,
                Err(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Conflict,
                        field: "managed attempt terminated",
                        ..
                    }
                })
            ));
        }
        assert_eq!(
            managed_cut(
                query.store(),
                &source,
                ID,
                Some(&input.id),
                input.time_utc_ns
            )?,
            fence
        );
        query.store().verify_state()?;
        drop(job);
        drop(host);
        assert_eq!(query.memory().input_reserved(), 0);
        drop(_graph);
        drop(query);
        drop(_directory);
    }
    Ok(())
}

#[tokio::test]
async fn running_graph_reopens() -> TestResult {
    const ID: &str = "running-graph-crash";
    if let Some(root) = std::env::var_os("ARAPHOR_RUNNING_GRAPH_ROOT") {
        let root = std::path::PathBuf::from(root);
        let manifest = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../../../../mithril-e2e/fixtures/discovery/manifest.json")
                .as_slice(),
        )?;
        let fixture = Fixture::stored(
            Target::Wasm,
            manifest.records.into_iter().take(3).collect(),
            tempfile::tempdir()?,
            Arc::new(AnalysisStore::open(&root)?),
        )?;
        let current = fixture
            .query
            .store()
            .managed_instance(fixture.source.tenant_id, ID, &fixture.control)?
            .ok_or("running Graph child")?;
        assert!(current.running);
        let store = Arc::clone(fixture.query.store());
        let source = fixture.source.clone();
        let path = root.with_extension("running-cut.json");
        fixture.query.store().set_commit_hook(
            araphor_data::AnalysisCommitStage::BeforeResultCommit,
            move || {
                assert!(matches!(
                    store.managed_resume(source.tenant_id, ID, &AnalysisReadControl::default()),
                    Err(araphor_data::Error::Package {
                        code: Code::Incomplete,
                        field: "managed pending attempt",
                        ..
                    })
                ));
                write_cut(&path, &managed_cut(&store, &source, ID, None, 1)?)
            },
        )?;
        let host = crate::InstanceHost::with_graph_facts(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.facts.clone(),
        );
        let (stop, stopped) = watch::channel(false);
        let mut worker = tokio::spawn(host.serve(stopped, u64::MAX));
        let result = tokio::time::timeout(std::time::Duration::from_secs(60), &mut worker).await;
        stop.send_replace(true);
        match result {
            Ok(joined) => joined??,
            Err(_) => worker.await??,
        }
        return Err("The running Graph crash did not occur".into());
    }
    let fixture = Fixture::target(Target::Wasm)?;
    let (grant, definition) = fixture.graph_definition().await?;
    let job = fixture
        .managed_graph(&grant, &definition, ID, "SELECT * FROM events")
        .await?;
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let running = host
        .start(Arc::clone(&job), job.admitted().lifecycle, &fixture.control)
        .await?;
    let saved = running.admitted().clone();
    assert!(saved.running);
    assert_eq!(saved.progress, 0);
    assert!(fixture
        .query
        .store()
        .managed_history(&grant.selection, ID, &fixture.control)?
        .is_empty());
    drop((job, running, host));
    let Fixture {
        query,
        control,
        source,
        records,
        _graph,
        _directory,
        ..
    } = fixture;
    drop(_graph);
    drop(query);
    let root = _directory.path().join("data");
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "graph::native::tests::managed::restart::running_graph_reopens",
        ])
        .env("ARAPHOR_RUNNING_GRAPH_ROOT", &root)
        .env("ARAPHOR_CRASH_ROOT", &root)
        .env("ARAPHOR_CRASH_POINT", "managed.before")
        .status()?;
    assert_eq!(status.code(), Some(73));
    let store = Arc::new(AnalysisStore::open(&root)?);
    let prior: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.with_extension("running-cut.json"))?)?;
    assert_eq!(
        store.managed_instance(source.tenant_id, ID, &control)?,
        Some(saved.clone())
    );
    let (_, members) = store.active_managed(&control)?;
    assert_eq!(
        members,
        [araphor_data::ManagedMember {
            tenant: source.tenant_id,
            id: ID.into(),
            generation: saved.generation,
            lifecycle: saved.lifecycle
        }]
    );
    let completion = prior["meta"][3]
        .as_u64()
        .ok_or("pending Host revision")?
        .checked_add(1)
        .ok_or("startup Host revision")?;
    let resume = store.managed_resume(source.tenant_id, ID, &control)?;
    assert_eq!(resume.instance, saved);
    assert_eq!(resume.frontier, None);
    assert_eq!(resume.completed, completion);
    let status = store.managed_status(&grant.selection, ID, &control)?;
    assert_eq!(status.instance, saved);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Ready
    ));
    assert_eq!(status.status_progress, saved.progress);
    assert!(store
        .managed_history(&grant.selection, ID, &control)?
        .is_empty());
    let mut reopened = managed_cut(&store, &source, ID, None, 1)?;
    assert_eq!(reopened["meta"][3].as_u64(), Some(completion));
    assert!(
        reopened["retained"][0]
            .as_u64()
            .ok_or("startup Host logical charge")?
            > prior["retained"][0]
                .as_u64()
                .ok_or("pending Host logical charge")?
    );
    assert_eq!(
        reopened["witnesses"]["read_revision"].as_u64(),
        Some(completion)
    );
    reopened["witnesses"]["read_revision"] = prior["witnesses"]["read_revision"].clone();
    reopened["meta"][3] = prior["meta"][3].clone();
    reopened["retained"][0] = prior["retained"][0].clone();
    assert_eq!(reopened, prior);
    store.verify_state()?;
    let fixture = Fixture::stored(Target::Wasm, records, _directory, store)?;
    let baseline = fixture.query.memory().input_reserved();
    let (entered, guest) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entered, None)?;
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let mut notices = fixture.query.store().subscribe_revision();
    let (stop, stopped) = watch::channel(false);
    let worker = tokio::spawn(host.serve(stopped, u64::MAX));
    let resumed = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            let current = fixture
                .query
                .store()
                .managed_instance(source.tenant_id, ID, &control)?
                .ok_or("recovered running Graph")?;
            if current.progress > saved.progress {
                let history =
                    fixture
                        .query
                        .store()
                        .managed_history(&grant.selection, ID, &control)?;
                let receipt = history
                    .into_iter()
                    .find(|receipt| receipt.commit_revision == current.progress)
                    .ok_or("recovered running Graph receipt")?;
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>((current, receipt));
            }
            notices.changed().await?;
        }
    })
    .await;
    let diagnostic = resumed.is_err().then(|| {
        let seen = guest.try_recv();
        let finished = worker.is_finished();
        let facts = fixture.facts.calls.load(Ordering::SeqCst);
        let meta = fixture.query.store().meta();
        let status = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(2))
            .and_then(|read| {
                fixture
                    .query
                    .store()
                    .managed_status(&grant.selection, ID, &read)
            })
            .map(|status| {
                (
                    status.readiness,
                    status.status_progress,
                    status.instance.progress,
                    status.instance.running,
                    status.instance.generation,
                    status.instance.lifecycle,
                )
            });
        (meta, status, facts, seen, finished)
    });
    stop.send_replace(true);
    let joined = worker.await;
    let diagnosis = fixture
        .query
        .store()
        .managed_resume(source.tenant_id, ID, &control);
    assert_eq!(fixture.query.memory().input_reserved(), baseline);
    drop(fixture.query.store().lease_managed()?);
    joined??;
    let (current, receipt) = resumed.map_err(|error| {
        format!("Running Graph did not resume after interruption: {error}; pre_stop={diagnostic:?}; post_stop={diagnosis:?}")
    })??;
    assert!(current.running);
    assert_eq!(current.generation, saved.generation);
    assert_eq!(current.lifecycle, saved.lifecycle);
    assert_eq!(current.progress, receipt.commit_revision);
    assert_eq!(receipt.results.len(), 3);
    let graph = fixture
        .query
        .store()
        .graph_snapshot(&source)?
        .ok_or("recovered running Graph output")?;
    assert_eq!(graph.input_manifest.evidence.len(), 3);
    assert_eq!(graph.input_manifest.context.len(), 3);
    assert_eq!(graph.input_positions.len(), 3);
    assert_eq!(graph.packages.len(), 3);
    assert!(!graph.graph.subjects.is_empty());
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .query
            .store()
            .managed_history(&grant.selection, ID, &control)?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(
        retained_calls(fixture.query.store(), &current, &receipt, 1, &control)?
            .as_array()
            .ok_or("recovered Graph calls")?
            .len(),
        3
    );
    fixture.query.store().verify_state()?;
    Ok(())
}
