use super::*;

mod expiry;
mod history;
mod notices;
mod replay;
mod restart;
mod versions;

#[tokio::test]
async fn graph_conversion_failure_finishes() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let mut descriptor = Detector::Process.descriptor();
    descriptor.revision = "conversion".into();
    let mut program = Fixture::sql(&descriptor.exports[0])?;
    let key = araphor_data::GraphSubjectKeyV1 {
        tenant_id: fixture.source.tenant_id,
        authority: araphor_data::GraphSubjectAuthorityV1::Native {
            node_id: fixture.source.node_id.clone(),
            node_boot_id: fixture.source.node_boot_id,
            label_epoch: fixture.source.label_epoch,
        },
        kind: araphor_data::GraphSubjectKindV1::Task,
        identity: 1u64.to_be_bytes().to_vec(),
    };
    araphor_data::GraphValidate::validate(&key)?;
    let subjects = araphor_analysis_builtins::graph::Subject::encode(&[
        araphor_analysis_builtins::graph::Subject {
            record: u32::MAX,
            context: None,
            key,
        },
    ])?;
    let invalid = crate::graph::tests::execution::Fixture::rows(&subjects.batches)
        .map_err(|error| error.to_string())?;
    program.outputs.insert(
        "subjects".into(),
        format!(
            "SELECT * FROM ({invalid}) AS invalid_subject WHERE (SELECT COUNT(*) FROM records) = 3"
        ),
    );
    let artifact = PackageArtifactV1 {
        descriptor,
        implementations: vec![PackageImplementationV1::Sql {
            export: "detect".into(),
            program,
        }],
        fixtures: Vec::new(),
    };
    fixture.query.store().install_package_image(
        fixture.source.tenant_id,
        &araphor_data::PackageBundle::try_from(PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        })?,
        || Ok(()),
    )?;
    let sql = araphor_data::FindingV1::PACKAGES
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let revision = if index == 0 { "conversion" } else { "1" };
            format!(
                "SELECT * FROM \"{id}\".\"{revision}\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
            )
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let prepared = fixture.prepare_sql("*", "", sql).await?;
    let grant = prepared.grant.clone();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(prepared);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant,
        "conversion".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let input = request("invalid-subject")?;
    let failure = job
        .run(input.clone(), &fixture.control)
        .await
        .err()
        .ok_or("invalid Graph subject published")?;
    let mut error: &(dyn std::error::Error + 'static) = &failure;
    let invalid_record = loop {
        if matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::GraphInvalid {
                field: "graph output record",
                ..
            })
        ) {
            break true;
        }
        if let Some(crate::Error::Data { source }) = error.downcast_ref::<crate::Error>() {
            error = source;
            continue;
        }
        if let Some(crate::Error::Query { source }) = error.downcast_ref::<crate::Error>() {
            error = source;
            continue;
        }
        if let Some(araphor_query::Error::Data { source }) =
            error.downcast_ref::<araphor_query::Error>()
        {
            error = source;
            continue;
        }
        let Some(source) = error.source() else {
            break false;
        };
        error = source;
    };
    assert!(invalid_record, "{failure:?}");
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let saved = fixture
        .query
        .store()
        .managed_attempt(
            fixture.source.tenant_id,
            "conversion",
            &input.id,
            &fixture.control,
        )?
        .ok_or("Graph conversion attempt")?;
    assert_eq!(
        saved.terminal().ok_or("Graph conversion terminal")?.exit,
        araphor_data::ManagedExit::Failed(Code::Invalid)
    );
    assert!(saved.receipt().is_none());
    assert!(fixture.query.store().processor_result(&scope)?.is_none());
    let current = fixture
        .query
        .store()
        .managed_instance(fixture.source.tenant_id, "conversion", &fixture.control)?
        .ok_or("Graph instance")?;
    assert_eq!(current.progress, 0);
    let status = crate::Instance::read_status(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        current.grant.clone(),
        "conversion",
        &fixture.control,
    )
    .await?;
    assert_eq!(status.instance, current);
    assert_eq!(status.status_progress, 0);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let health = fixture
        .query
        .store()
        .processor_health(&scope)?
        .ok_or("failed Graph source progress")?;
    assert_eq!(
        health.state,
        araphor_data::ProcessorStateV1::ProcessingFailed
    );
    assert!(health.incomplete);
    assert!(fixture
        .query
        .store()
        .managed_history(&current.grant.selection, "conversion", &fixture.control)?
        .is_empty());
    assert!(fixture
        .query
        .store()
        .managed_selected(
            fixture.source.tenant_id,
            "conversion",
            &input.id,
            &fixture.control,
        )?
        .is_none());
    let prepared = fixture.prepare("").await?;
    let mut other_grant = prepared.grant.clone();
    other_grant.principal = "independent Graph fixture".into();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&other_grant, &definition)?;
    drop(prepared);
    let other = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        other_grant.clone(),
        "independent".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let other_receipt = other.run(request("independent")?, &fixture.control).await?;
    let other_status = fixture.query.store().managed_status(
        &other_grant.selection,
        "independent",
        &fixture.control,
    )?;
    assert_eq!(other_status.instance.grant, other_grant);
    assert_ne!(
        other_status.instance.grant.principal,
        current.grant.principal
    );
    assert_eq!(
        other_status.instance.progress,
        other_receipt.commit_revision
    );
    assert!(matches!(
        other_status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    let status = fixture.query.store().managed_status(
        &current.grant.selection,
        "conversion",
        &fixture.control,
    )?;
    assert_eq!(status.instance, current);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Invalid,
            ..
        }
    ));
    let health = fixture
        .query
        .store()
        .processor_health(&scope)?
        .ok_or("independent Graph source progress")?;
    assert_eq!(
        health.state,
        araphor_data::ProcessorStateV1::ProcessingFailed
    );
    assert_eq!(health.consumed_cursor, 3);
    assert!(health.incomplete);
    let before = fixture.query.store().meta()?;
    assert!(matches!(
        job.run(input, &fixture.control).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed attempt terminated",
                ..
            }
        })
    ));
    assert_eq!(fixture.query.store().meta()?, before);
    let record = fixture.records.last().ok_or("fourth Graph event")?;
    fixture.query.store().accept_validated_batch(
        fixture.source.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 4,
            last_cursor: 4,
            intake_utc_ns: 4,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let receipt = job.run(request("recovered")?, &fixture.control).await?;
    assert_eq!(receipt.results.len(), 3);
    let status = fixture.query.store().managed_status(
        &current.grant.selection,
        "conversion",
        &fixture.control,
    )?;
    assert_eq!(status.instance.progress, receipt.commit_revision);
    assert_eq!(status.status_progress, receipt.commit_revision);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Inactive
    ));
    assert_eq!(
        fixture
            .query
            .store()
            .managed_status(&other_grant.selection, "independent", &fixture.control)?
            .instance,
        other_status.instance
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &other_grant.selection,
            "independent",
            &fixture.control,
        )?,
        vec![other_receipt]
    );
    assert_eq!(
        fixture
            .query
            .store()
            .processor_result(&scope)?
            .ok_or("recovered Graph head")?
            .commit_revision,
        receipt.commit_revision
    );
    let health = fixture
        .query
        .store()
        .processor_health(&scope)?
        .ok_or("recovered Graph processor")?;
    assert_eq!(health.consumed_cursor, 4);
    assert_eq!(health.state, araphor_data::ProcessorStateV1::Current);
    assert!(!health.incomplete);
    Ok(())
}

impl Fixture {
    pub(super) fn admit_definition(
        &self,
        grant: &PackageGrantV1,
        definition: &araphor_discovery_definition::ResolvedDefinition,
    ) -> araphor_data::Result<()> {
        self.authority
            .commit_many(&[(grant, PackageActionV1::Install, None)], &mut || {
                self.query.store().admit_definition(
                    grant.selection.tenant_id,
                    definition,
                    || {
                        grant.remaining()?;
                        self.control.check()
                    },
                )?;
                Ok(())
            })
    }
}

pub(super) fn request(id: &str) -> TestResult<araphor_data::ManagedRequest> {
    Ok(araphor_data::ManagedRequest {
        id: id.into(),
        time_utc_ns: u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?,
        seed: Some(17),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    })
}

#[tokio::test]
async fn managed_restores_native_inputs() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let prepared = fixture.prepare("").await?;
    let grant = prepared.grant.clone();
    let definition = prepared.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(prepared);
    let job = GraphPublication::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
        grant.clone(),
        "native-graph-job".into(),
        fixture.source.clone(),
        "SELECT * FROM events".into(),
        definition,
        &fixture.control,
    )
    .await?;
    assert!(!job.admitted().running);
    assert!(job.admitted().grant.selection.sources.is_all());
    assert_eq!(
        job.admitted()
            .spec
            .destination
            .selection(&grant.selection)?
            .sources
            .as_slice(),
        std::slice::from_ref(&fixture.source)
    );
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    assert!(fixture.query.store().processor_result(&scope)?.is_none());
    let receipt = job.run(request("captured")?, &fixture.control).await?;
    assert_eq!(receipt.results.len(), 3);
    let graph_result = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("managed Graph head")?;
    assert_eq!(graph_result.commit_revision, receipt.commit_revision);
    let graph = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &graph_result.result_id)?
        .ok_or("managed Graph snapshot")?;
    assert_eq!(graph.input_manifest.evidence.len(), 3);
    assert_eq!(graph.input_positions.len(), 3);
    assert_eq!(graph.packages.len(), 3);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph progress")?
            .consumed_cursor,
        3
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    let saved = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "native-graph-job",
            &fixture.control,
        )?
        .ok_or("stored Graph job")?;
    assert_eq!(saved.progress, receipt.commit_revision);
    let host = crate::InstanceHost::with_graph_facts(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        fixture.facts.clone(),
    );
    let restored = host
        .admit_current(
            &saved,
            None,
            &Arc::new(fixture.control.within(None)?),
            fixture.query.memory().scope(),
        )
        .await?;
    assert_eq!(restored.admitted(), &saved);
    let (&call_id, reference) = receipt
        .results
        .first_key_value()
        .ok_or("Graph detector result")?;
    let original = fixture.query.store().managed_evaluation(
        restored.admitted(),
        &reference.result_id,
        &fixture.control,
    )?;
    let before = fixture.query.store().meta()?;
    let replay = restored
        .replay(&reference.result_id, &fixture.control)
        .await?;
    assert_eq!(replay.calls.len(), 1);
    let returned = replay
        .calls
        .get(&call_id)
        .ok_or("replayed Graph detector")?;
    let actual = returned.evaluation();
    assert_eq!(actual.context, original.context);
    assert_eq!(actual.parameters, original.parameters);
    assert_eq!(actual.inputs.len(), original.inputs.len());
    for (actual, original) in actual.inputs.iter().zip(&original.inputs) {
        assert_eq!(actual.data.name, original.data.name);
        assert_eq!(actual.data.batches, original.data.batches);
        assert_eq!(actual.revision, original.revision);
        assert_eq!(actual.coverage, original.coverage);
    }
    assert_eq!(fixture.query.store().meta()?, before);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &graph_result.result_id)?,
        Some(graph)
    );
    Ok(())
}

#[tokio::test]
async fn managed_expiry_without_head() -> TestResult {
    let donor = Fixture::target(Target::Sql)?;
    let (grant, definition) = donor.graph_definition().await?;
    let native = donor
        .managed_graph(&grant, &definition, "expiry-seed", "SELECT * FROM events")
        .await?;
    let input = request("expiry-seed")?;
    let generated = native.run(input.clone(), &donor.control).await?;
    assert_eq!(generated.results.len(), 3);
    let scope = donor.graph_scope();
    let head = donor
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Native Graph seed head")?;
    assert_eq!(head.commit_revision, generated.commit_revision);
    let id = head.result_id;
    let mut snapshot = donor
        .query
        .store()
        .graph_result(donor.source.tenant_id, &id)?
        .ok_or("Native Graph seed")?;
    assert!(snapshot.previous_result_id.is_none());
    assert_eq!(snapshot.context_notice_revision, 0);
    let body = donor
        .query
        .store()
        .read_result(donor.source.tenant_id, &id)?
        .ok_or("Native Graph seed body")?;
    assert_eq!(body, head.body);
    let (mut witnesses, references) = donor
        .query
        .store()
        .package_evidence(donor.source.tenant_id, std::slice::from_ref(&id))?;
    let original_snapshot = snapshot.clone();
    let original_witnesses = witnesses.clone();
    snapshot.witness_deadline_utc_ns = request("historical-input")?
        .time_utc_ns
        .checked_sub(1)
        .filter(|time| *time > 1)
        .ok_or("Historical Graph deadline")?;
    let created = snapshot
        .witness_deadline_utc_ns
        .checked_sub(araphor_data::GRAPH_WITNESS_TTL_NS)
        .filter(|time| *time != 0)
        .ok_or("Historical Graph creation time")?;
    for witness in &mut witnesses {
        witness.expires_utc_ns = snapshot.witness_deadline_utc_ns;
    }
    let mut restored = snapshot.clone();
    restored.witness_deadline_utc_ns = original_snapshot.witness_deadline_utc_ns;
    assert_eq!(restored, original_snapshot);
    let mut restored = witnesses.clone();
    for (restored, original) in restored.iter_mut().zip(&original_witnesses) {
        restored.expires_utc_ns = original.expires_utc_ns;
    }
    assert_eq!(restored, original_witnesses);
    let contexts = references
        .iter()
        .map(|reference| {
            donor
                .query
                .store()
                .context_version(&reference.key)?
                .ok_or_else(|| Code::Invalid.error("Native Graph seed context"))
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    assert_eq!(
        contexts
            .iter()
            .filter(|context| context.key.owner_id == "native-package-v1")
            .count(),
        3
    );
    let mut fixture = Fixture::with_records(Target::Sql, donor.records.clone())?;
    fixture.facts = Arc::clone(&donor.facts);
    assert_eq!(fixture.source, donor.source);
    assert_eq!(fixture.graph_scope(), scope);
    let store = fixture.query.store();
    let source = store
        .source_receipt(&fixture.source)?
        .ok_or("Graph seed source receipt")?;
    assert_eq!(
        Some(source.clone()),
        donor.query.store().source_receipt(&donor.source)?
    );
    assert_eq!(
        store.read_page(&fixture.source, 1)?.records,
        donor.query.store().read_page(&donor.source, 1)?.records
    );
    assert!(source.retained_floor < snapshot.first_cursor);
    assert!(store.processor_result(&scope)?.is_none());
    assert_eq!(
        store
            .processor_health(&scope)?
            .ok_or("Fresh Graph progress")?
            .consumed_cursor,
        0
    );
    let before = store.meta()?;
    let sources = grant.selection.source_revisions(before.commit_revision);
    let retained = store.commit_graph_snapshot(
        araphor_data::AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 0,
            coverage_revision: source.coverage_revision,
            context_revision: 0,
            result_id: id.clone(),
            body: Vec::new(),
            created_utc_ns: created,
            witnesses: witnesses.clone(),
            context_refs: Vec::new(),
        },
        araphor_data::analysis::CanonicalGraph::new(snapshot.clone())?,
        &contexts,
        &[],
        &sources,
        false,
        || {
            fixture.control.check()?;
            fixture.authority.check(&grant, PackageActionV1::Run)
        },
    )?;
    assert_eq!(retained.consumed_cursor, 0);
    assert_eq!(retained.commit_revision, before.commit_revision + 1);
    assert!(store.processor_result(&scope)?.is_none());
    assert_eq!(
        store
            .processor_health(&scope)?
            .ok_or("Retained Graph progress")?
            .consumed_cursor,
        0
    );
    assert_eq!(
        store.graph_result(fixture.source.tenant_id, &id)?,
        Some(snapshot.clone())
    );
    let body = store
        .read_result(fixture.source.tenant_id, &id)?
        .ok_or("Retained Graph header")?;
    let references = references
        .iter()
        .map(|reference| AnalysisContextRefV1 {
            key: reference.key.clone(),
            commit_revision: retained.commit_revision,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        store.package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?,
        (witnesses.clone(), references.clone())
    );
    for context in &contexts {
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
    }
    let headers = store.graph_window_headers(&fixture.source, None)?;
    assert_eq!(headers.len(), 1);
    let (result, header, revision) = headers.first().ok_or("Retained Graph seed window")?;
    assert_eq!(result, &id);
    assert_eq!(header.first_cursor, snapshot.first_cursor);
    assert_eq!(header.last_cursor, snapshot.last_cursor);
    assert_eq!(*revision, retained.commit_revision);
    let definition = fixture
        .query
        .admit_definition(
            grant.selection.tenant_id,
            GraphPublication::expiry_program(),
            Arc::new(fixture.control.within(None)?),
        )
        .await?;
    fixture.admit_definition(&grant, &definition)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let before = fixture.query.store().processor_result(&scope)?;
    assert!(before.is_none());
    let job = GraphPublication::admit_expiry(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        grant,
        "native-graph-expiry".into(),
        fixture.source.clone(),
        &fixture.control,
    )
    .await?;
    assert!(!job.admitted().running);
    let mut input = request("not-due")?;
    input.time_utc_ns = snapshot
        .witness_deadline_utc_ns
        .checked_sub(1)
        .filter(|time| *time != 0)
        .ok_or("Historical Graph early time")?;
    assert!(input.time_utc_ns < snapshot.witness_deadline_utc_ns);
    let receipt = job.run(input, &fixture.control).await?;
    assert!(receipt.results.is_empty());
    let attempt = fixture
        .query
        .store()
        .managed_attempt(
            fixture.source.tenant_id,
            "native-graph-expiry",
            "not-due",
            &fixture.control,
        )?
        .ok_or("completed expiry attempt")?;
    assert_eq!(attempt.receipt(), Some(&receipt));
    assert_eq!(fixture.query.store().processor_result(&scope)?, before);
    assert!(fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .is_some());
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Graph expiry progress")?
            .consumed_cursor,
        0
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &id)?,
        Some(snapshot.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &id)?,
        Some(body.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id),)?,
        (witnesses.clone(), references.clone())
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        headers
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert!(job.graph_owner().is_none());
    let raw = fixture.query.store().read_page(&fixture.source, 1)?.records;
    assert_eq!(
        raw,
        donor.query.store().read_page(&donor.source, 1)?.records
    );
    assert_eq!(raw.len(), 3);
    assert!(
        fixture
            .query
            .store()
            .source_receipt(&fixture.source)?
            .ok_or("Historical Graph source")?
            .retained_floor
            < snapshot.first_cursor
    );
    let (entry, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entry, None)?;
    let current = request("due")?;
    assert!(current.time_utc_ns >= snapshot.witness_deadline_utc_ns);
    let due = {
        let control = AnalysisReadControl::default();
        let work = job.run(current, &control);
        tokio::pin!(work);
        match tokio::time::timeout(std::time::Duration::from_secs(30), &mut work).await {
            Ok(receipt) => receipt?,
            Err(error) => {
                let cancelled = control.cancel();
                let joined = work.await;
                return Err(format!(
                    "Historical Graph expiry completion: {error}; cancel={cancelled:?}; joined={joined:?}"
                ).into());
            }
        }
    };
    assert!(due.results.is_empty());
    let heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    assert_eq!(heads.len(), 1);
    let (expired_id, _, revision) = heads.first().ok_or("Historical expired Graph head")?;
    assert_ne!(expired_id, &id);
    assert_eq!(*revision, due.commit_revision);
    let expected = Graph::expire(&snapshot, &id, snapshot.context_notice_revision)?;
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
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(expired_id))?,
        (Vec::new(), references.clone())
    );
    assert_eq!(fixture.query.store().processor_result(&scope)?, before);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Historical expired Graph progress")?
            .consumed_cursor,
        0
    );
    assert_eq!(
        fixture.query.store().read_page(&fixture.source, 1)?.records,
        raw
    );
    assert_eq!(
        fixture
            .query
            .store()
            .graph_result(fixture.source.tenant_id, &id)?,
        Some(snapshot)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .read_result(fixture.source.tenant_id, &id)?,
        Some(body)
    );
    assert_eq!(
        fixture
            .query
            .store()
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?,
        (witnesses, references)
    );
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    );
    Ok(())
}

#[tokio::test]
async fn managed_gate_is_native() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("WHERE source_cursor > 3").await?;
    let schema = Arc::clone(publication.prepared.plan.schema());
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let instance = fixture
        .managed_graph(
            &grant,
            &definition,
            "native-gate",
            "SELECT * FROM events WHERE source_cursor > 3",
        )
        .await?;
    instance
        .assert_graph_gate(&schema, request("native-gate")?)
        .await?;
    Ok(())
}

#[tokio::test]
async fn managed_gate_skips_calls() -> TestResult {
    for (target, predicate) in [
        (Target::Wasm, "WHERE source_cursor > 3"),
        (Target::Sql, "WHERE FALSE"),
    ] {
        let fixture = Fixture::target(target)?;
        let publication = fixture.prepare(predicate).await?;
        let grant = publication.grant.clone();
        let definition = publication.prepared.resolved().clone();
        fixture.admit_definition(&grant, &definition)?;
        drop(publication);
        let (entries, entered) = std::sync::mpsc::channel();
        fixture.query.guest_entry(entries, None)?;
        let instance = GraphPublication::admit(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.facts.clone(),
            grant.clone(),
            "empty-graph-gate".into(),
            fixture.source.clone(),
            format!("SELECT * FROM events {predicate}"),
            definition,
            &fixture.control,
        )
        .await?;
        let selection = instance
            .admitted()
            .spec
            .destination
            .selection(&grant.selection)?;
        let tables = araphor_data::AnalysisTableRequests::from([
            ("graph_manifest".into(), None),
            ("graph_state".into(), None),
        ]);
        let (_, dependency) =
            fixture
                .query
                .store()
                .dependency_revision_for(&selection, &tables, &fixture.control)?;
        let store = fixture.query.store();
        let before_instance = store
            .managed_instance(
                fixture.source.tenant_id,
                "empty-graph-gate",
                &fixture.control,
            )?
            .ok_or("empty Graph instance")?;
        assert_eq!(before_instance, *instance.admitted());
        assert_eq!(before_instance.progress, 0);
        assert!(store
            .managed_history(&grant.selection, "empty-graph-gate", &fixture.control)?
            .is_empty());
        assert!(fixture.graph_history()?.is_empty());
        assert!(store
            .graph_window_headers(&fixture.source, None)?
            .is_empty());
        let before = store.meta()?;
        let receipt = instance.run(request("no-input")?, &fixture.control).await?;
        assert!(receipt.results.is_empty());
        assert_eq!(
            receipt.commit_revision,
            before
                .commit_revision
                .checked_add(2)
                .ok_or("empty Graph revision")?
        );
        let mut expected_meta = before;
        expected_meta.commit_revision = receipt.commit_revision;
        assert_eq!(store.meta()?, expected_meta);
        let mut expected_instance = before_instance;
        expected_instance.progress = receipt.commit_revision;
        assert_eq!(
            store.managed_instance(
                fixture.source.tenant_id,
                "empty-graph-gate",
                &fixture.control
            )?,
            Some(expected_instance.clone())
        );
        assert_eq!(
            store.managed_history(&grant.selection, "empty-graph-gate", &fixture.control)?,
            std::slice::from_ref(&receipt)
        );
        let status =
            store.managed_status(&grant.selection, "empty-graph-gate", &fixture.control)?;
        assert_eq!(status.instance, expected_instance);
        assert_eq!(status.status_progress, receipt.commit_revision);
        assert!(matches!(
            status.readiness,
            araphor_data::PackageReadinessV1::Inactive
        ));
        assert!(fixture.graph_history()?.is_empty());
        assert!(store
            .graph_window_headers(&fixture.source, None)?
            .is_empty());
        assert_eq!(
            entered.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );
        assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            fixture
                .query
                .store()
                .dependency_revision_for(&selection, &tables, &fixture.control,)?
                .1,
            dependency
        );
        let scope = araphor_data::ProcessorScopeV1 {
            processor_id: araphor_data::GRAPH_PROCESSOR.into(),
            method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
            identity: fixture.source.clone(),
        };
        assert!(fixture.query.store().processor_result(&scope)?.is_none());
        assert_eq!(
            fixture
                .query
                .store()
                .processor_health(&scope)?
                .ok_or("Graph progress")?
                .consumed_cursor,
            0
        );
        assert_eq!(
            fixture
                .query
                .store()
                .managed_attempt(
                    fixture.source.tenant_id,
                    "empty-graph-gate",
                    "no-input",
                    &fixture.control,
                )?
                .ok_or("empty Graph attempt")?
                .receipt(),
            Some(&receipt)
        );
        drop(instance);
        drop(fixture.query.reserve_evaluation(fixture.source.tenant_id)?);
    }
    Ok(())
}

#[tokio::test]
async fn managed_expiry_reads_history() -> TestResult {
    let fixture = Fixture::target(Target::Sql)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "historical-expiry-seed",
            "SELECT * FROM events",
        )
        .await?;
    let seeded = owner.run(request("seed")?, &fixture.control).await?;
    let head = fixture
        .query
        .store()
        .processor_result(&fixture.graph_scope())?
        .ok_or("native Graph history head")?;
    assert_eq!(head.commit_revision, seeded.commit_revision);
    assert_eq!(seeded.results.len(), 3);
    let id = head.result_id;
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("Graph history")?;
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
        "graph-history-expiry".into(),
        fixture.source.clone(),
        &fixture.control,
    )
    .await?;
    let mut selection = instance
        .admitted()
        .spec
        .destination
        .selection(&instance.admitted().grant.selection)?;
    selection.select_graphs(araphor_data::Selection::All, None)?;
    selection.contexts = araphor_data::Selection::Exact(Vec::new());
    let managed = araphor_data::ManagedRead {
        instance: instance.admitted().clone(),
        expected: None,
        completed: None,
        rebuild: false,
        follow: false,
    };
    let schemas = AnalysisStore::table_schemas();
    let columns = BTreeMap::from([
        (
            "graph_manifest".into(),
            Some(std::collections::BTreeSet::from([
                schemas["graph_manifest"].index_of("snapshot")?,
                schemas["graph_manifest"].index_of("context_refs")?,
            ])),
        ),
        ("graph_state".into(), None),
    ]);
    let now = original.witness_deadline_utc_ns;
    let read = || araphor_data::AnalysisTableRead {
        requests: &columns,
        event_ranges: None,
        inputs: None,
        mode: araphor_data::AnalysisReadModeV1::Complete,
        now,
    };
    let ordinary = fixture.query.store().read_tables(
        &selection,
        read(),
        araphor_data::AnalysisExtractLimits::default(),
        &fixture.control,
    )?;
    assert_eq!(
        ordinary.tables["graph_manifest"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    assert!(!ordinary.extraction.witnesses.is_empty());
    assert!(ordinary
        .extraction
        .witnesses
        .iter()
        .all(|witness| witness.expires_utc_ns == now));
    let historical = fixture.query.store().read_managed_tables(
        &selection,
        &managed,
        read(),
        araphor_data::AnalysisExtractLimits::default(),
        &fixture.control,
    )?;
    assert!(historical.page.extraction.witnesses.is_empty());
    assert_eq!(
        historical
            .page
            .extraction
            .references
            .iter()
            .filter_map(|entry| entry.result())
            .collect::<Vec<_>>(),
        ordinary
            .extraction
            .references
            .iter()
            .filter_map(|entry| entry.result())
            .collect::<Vec<_>>()
    );
    let (_, contexts) = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?;
    assert_eq!(
        historical
            .page
            .extraction
            .references
            .iter()
            .filter_map(|entry| entry.context())
            .collect::<Vec<_>>(),
        contexts.iter().collect::<Vec<_>>()
    );
    assert!(historical
        .page
        .extraction
        .references
        .iter()
        .all(|entry| { entry.origins() == [araphor_data::AnalysisReferenceOriginV1::Graph] }));
    let mut historical_request = request("retained-history")?;
    historical_request.time_utc_ns = now;
    let attempt = fixture.query.store().register_managed_attempt(
        &historical.state,
        &historical_request,
        || Ok(()),
    )?;
    assert_eq!(attempt.request(), &historical_request);
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    for table in ["events", "context_versions"] {
        let mut forbidden = columns.clone();
        forbidden.insert(table.into(), None);
        assert!(fixture
            .query
            .store()
            .read_managed_tables(
                &selection,
                &managed,
                araphor_data::AnalysisTableRead {
                    requests: &forbidden,
                    event_ranges: None,
                    inputs: None,
                    mode: araphor_data::AnalysisReadModeV1::Complete,
                    now,
                },
                araphor_data::AnalysisExtractLimits::default(),
                &fixture.control,
            )
            .is_err());
    }
    let definition = fixture
        .query
        .admit_definition(
            fixture.source.tenant_id,
            Definition {
                name: "ordinary-graph-body".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline {
                        inline: "SELECT snapshot, context_refs FROM graph_manifest".into(),
                    },
                },
            },
            Arc::clone(&fixture.control),
        )
        .await?;
    fixture.admit_definition(&instance.admitted().grant, &definition)?;
    let ordinary = crate::Instance::admit(
        Arc::clone(&fixture.query),
        fixture.authority.clone(),
        instance.admitted().grant.clone(),
        "ordinary-graph-body".into(),
        definition,
        &fixture.control,
    )
    .await?;
    let ordinary = fixture.query.store().read_managed_tables(
        &selection,
        &araphor_data::ManagedRead {
            instance: ordinary.admitted().clone(),
            expected: None,
            completed: None,
            rebuild: false,
            follow: false,
        },
        read(),
        araphor_data::AnalysisExtractLimits::default(),
        &fixture.control,
    )?;
    assert!(!ordinary.page.extraction.witnesses.is_empty());
    let mut request = request("ordinary-expired-body")?;
    request.time_utc_ns = now;
    assert!(fixture
        .query
        .store()
        .register_managed_attempt(&ordinary.state, &request, || Ok(()))
        .is_err());
    let mut forged = instance.admitted().clone();
    forged.spec.definition = araphor_discovery_definition::ResolvedDefinition::new(
        Definition {
            name: "graph-expiry".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: "SELECT * FROM events".into(),
                },
            },
        },
        "SELECT * FROM events".into(),
        Vec::new(),
    )?;
    let host = crate::InstanceHost::new(Arc::clone(&fixture.query), fixture.authority.clone());
    assert!(host
        .admit_current(
            &forged,
            None,
            &Arc::new(fixture.control.within(None)?),
            fixture.query.memory().scope()
        )
        .await
        .is_err());
    Ok(())
}
