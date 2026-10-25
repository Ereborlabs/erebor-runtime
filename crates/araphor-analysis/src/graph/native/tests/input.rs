use super::*;

#[tokio::test]
async fn immutable_facts_precede_guests() -> TestResult {
    let fixture = Fixture::target(Target::Wasm)?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let seed = fixture
        .managed_graph(
            &grant,
            &definition,
            "immutable-seed",
            "SELECT * FROM events",
        )
        .await?;
    let receipt = seed
        .run(managed::request("seed")?, &fixture.control)
        .await?;
    assert_eq!(receipt.results.len(), 3);
    let (id, _, revision) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("original Graph window")?;
    assert_eq!(revision, receipt.commit_revision);
    let seed_state = fixture
        .query
        .store()
        .managed_instance(fixture.source.tenant_id, "immutable-seed", &fixture.control)?
        .ok_or("seed Graph instance")?;
    drop(seed);
    let original = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("original Graph input")?;
    let key = original
        .input_manifest
        .context
        .iter()
        .find(|key| key.owner_id == "graph-native-fixture")
        .ok_or("frozen fixture context")?;
    let context = fixture
        .query
        .store()
        .context_version(key)?
        .ok_or("retained fixture context")?;
    let head = fixture.query.store().processor_result(&original.scope)?;
    let notice = fixture
        .query
        .store()
        .graph_notice(&original.scope, &id, revision)?;
    let frozen = fixture.query.store().frozen_result(&id)?;
    let references = fixture
        .query
        .store()
        .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?;
    let (entries, entered) = std::sync::mpsc::channel();
    fixture.query.guest_entry(entries, None)?;
    for field in ["body", "valid-from", "valid-until", "sensitivity"] {
        let mut changed = context.clone();
        match field {
            "body" => changed.body.push(b' '),
            "valid-from" => changed.valid_from_utc_ns = Some(1),
            "valid-until" => changed.valid_until_utc_ns = Some(u64::MAX),
            "sensitivity" => {
                changed.sensitivity = araphor_data::ContextSensitivityV1::HostRestricted;
            }
            _ => unreachable!(),
        }
        *fixture
            .facts
            .changed
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(changed);
        let instance_id = format!("immutable-{field}");
        let owner = fixture
            .managed_graph(&grant, &definition, &instance_id, "SELECT * FROM events")
            .await?;
        let graph = owner
            .graph_owner()
            .ok_or("admitted immutable Graph owner")?;
        let projection = &graph.projection;
        let before_instance = owner.admitted().clone();
        assert!(!before_instance.running);
        assert_eq!(before_instance.progress, 0);
        let before_domain = fixture.graph_history()?;
        assert!(!before_domain.is_empty());
        let before_heads = fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?;
        let before_health = fixture.query.store().processor_health(&original.scope)?;
        let before_usage = fixture
            .query
            .store()
            .retained_usage(fixture.source.tenant_id)?;
        let before = fixture.query.store().meta()?;
        let input = managed::request("changed")?;
        assert!(input.time_utc_ns < original.witness_deadline_utc_ns);
        let error = owner
            .run(input.clone(), &fixture.control)
            .await
            .err()
            .ok_or("changed immutable Graph fact accepted")?;
        assert!(
            format!("{error:?}").contains("conflicting context version"),
            "{field}: {error:?}"
        );
        assert_eq!(projection.projections.load(Ordering::SeqCst), 0);
        assert_eq!(
            entered.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );
        let saved = fixture
            .query
            .store()
            .managed_attempt(
                fixture.source.tenant_id,
                &instance_id,
                &input.id,
                &fixture.control,
            )?
            .ok_or("immutable Graph attempt")?;
        let revision = before
            .commit_revision
            .checked_add(2)
            .ok_or("immutable revision overflow")?;
        assert_eq!(
            saved.terminal(),
            Some(&araphor_data::ManagedTerminal {
                instance: instance_id.clone(),
                attempt: input.id.clone(),
                revision,
                exit: araphor_data::ManagedExit::Failed(Code::Invalid),
                suspended: false,
            })
        );
        assert!(saved.receipt().is_none());
        assert_eq!(saved.instance(), &before_instance);
        let mut supplied = saved.request().clone();
        let frontier = supplied
            .frontier
            .take()
            .ok_or("immutable native frontier")?;
        assert_eq!(supplied, input);
        assert!(!frontier.pending);
        assert_eq!(frontier.next_change, Some(original.witness_deadline_utc_ns));
        let cursor = araphor_query::follow::Cursor::decode(&frontier.cursor)?;
        assert_eq!(cursor.encode()?, frontier.cursor);
        assert_eq!(cursor.read_revision(), before.commit_revision);
        assert_eq!(
            cursor.position(),
            StorePositionV1 {
                commit_revision: 0,
                ordinal: 0
            }
        );
        let status = fixture.query.store().managed_status(
            &grant.selection,
            &instance_id,
            &fixture.control,
        )?;
        assert_eq!(status.instance, before_instance);
        assert_eq!(status.status_progress, 0);
        assert!(
            matches!(status.readiness, araphor_data::PackageReadinessV1::Failed {
            code: Code::Invalid, field } if field == "model evaluation")
        );
        assert_eq!(
            fixture.query.store().managed_resume(
                fixture.source.tenant_id,
                &instance_id,
                &fixture.control
            )?,
            araphor_data::ManagedResume {
                instance: before_instance.clone(),
                frontier: Some(frontier),
                completed: revision
            }
        );
        let mut expected_meta = before;
        expected_meta.commit_revision = revision;
        assert_eq!(fixture.query.store().meta()?, expected_meta);
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance(fixture.source.tenant_id, &instance_id, &fixture.control)?
                .ok_or("failed immutable instance")?,
            before_instance
        );
        assert!(fixture
            .query
            .store()
            .managed_history(&grant.selection, &instance_id, &fixture.control)?
            .is_empty());
        assert!(fixture
            .query
            .store()
            .managed_selected(
                fixture.source.tenant_id,
                &instance_id,
                &input.id,
                &fixture.control
            )?
            .is_none());
        assert_eq!(fixture.graph_history()?, before_domain);
        assert_eq!(fixture.query.store().frozen_result(&id)?, frozen);
        assert_eq!(
            fixture
                .query
                .store()
                .graph_window_headers(&fixture.source, None)?,
            before_heads
        );
        assert_eq!(
            fixture.query.store().processor_result(&original.scope)?,
            head
        );
        let expected_health = before_health.map(|mut health| {
            health.read_revision = revision;
            health
        });
        assert_eq!(
            fixture.query.store().processor_health(&original.scope)?,
            expected_health
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_result(fixture.source.tenant_id, &id)?,
            Some(original.clone())
        );
        assert_eq!(
            fixture.query.store().context_version(key)?,
            Some(context.clone())
        );
        assert_eq!(
            fixture
                .query
                .store()
                .graph_notice(&original.scope, &id, receipt.commit_revision)?,
            notice
        );
        assert_eq!(
            fixture
                .query
                .store()
                .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?,
            references
        );
        assert_eq!(
            fixture
                .query
                .store()
                .managed_instance(fixture.source.tenant_id, "immutable-seed", &fixture.control)?
                .ok_or("retained seed instance")?,
            seed_state
        );
        assert_eq!(
            fixture.query.store().managed_history(
                &grant.selection,
                "immutable-seed",
                &fixture.control
            )?,
            std::slice::from_ref(&receipt)
        );
        let usage = fixture
            .query
            .store()
            .retained_usage(fixture.source.tenant_id)?;
        assert_eq!(
            (usage.1, usage.2, usage.3),
            (before_usage.1, before_usage.2, before_usage.3)
        );
        fixture.query.store().verify_state()?;
    }
    *fixture
        .facts
        .changed
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "immutable-restored",
            "SELECT * FROM events",
        )
        .await?;
    let graph = owner.graph_owner().ok_or("recovered Graph owner")?;
    let projection = &graph.projection;
    let observed = projection.observe_capture();
    let before_instance = fixture
        .query
        .store()
        .managed_instance(
            fixture.source.tenant_id,
            "immutable-restored",
            &fixture.control,
        )?
        .ok_or("restored immutable instance")?;
    let before_domain = fixture.graph_history()?;
    assert!(!before_domain.is_empty());
    let before_heads = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?;
    let before_health = fixture.query.store().processor_health(&original.scope)?;
    let before = fixture.query.store().meta()?;
    let repeated = owner
        .run(managed::request("restored")?, &fixture.control)
        .await?;
    let captured = observed.try_recv()?;
    assert_eq!(projection.projections.load(Ordering::SeqCst), 1);
    assert_eq!(captured.inputs.len(), 3);
    assert_eq!(projection.ports.len(), captured.inputs.len());
    for (port, input) in projection.ports.iter().zip(&captured.inputs) {
        assert_eq!(input.data.name, port.name);
        assert!(!input.data.batches.is_empty());
        assert!(input
            .data
            .batches
            .iter()
            .all(|batch| batch.schema().as_ref() == &port.schema));
    }
    assert!(captured
        .graph
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    let expected = araphor_data::FindingV1::PACKAGES
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(graph.calls.len(), expected.len());
    assert_eq!(
        graph
            .calls
            .values()
            .map(|call| call.package().package_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    for call in graph.calls.values() {
        let model = call
            .descriptor()
            .exports
            .iter()
            .find(|model| model.name == call.export())
            .ok_or("recovered Graph model")?;
        assert!(Graph::supports(model));
    }
    let (recovered_id, _, _) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("recovered Graph window")?;
    let recovered = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &recovered_id)?
        .ok_or("recovered Graph result")?;
    assert_eq!(recovered.packages.len(), expected.len());
    assert_eq!(
        recovered
            .packages
            .iter()
            .map(|package| package.package_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    assert_eq!(recovered_id, id);
    assert_eq!(recovered, original);
    assert_eq!(fixture.graph_history()?, before_domain);
    assert_eq!(fixture.query.store().frozen_result(&id)?, frozen);
    assert_eq!(
        fixture
            .query
            .store()
            .graph_window_headers(&fixture.source, None)?,
        before_heads
    );
    assert_eq!(
        fixture.query.store().processor_result(&original.scope)?,
        head
    );
    assert_eq!(
        fixture
            .query
            .store()
            .package_evidence(fixture.source.tenant_id, std::slice::from_ref(&id))?,
        references
    );
    assert_eq!(fixture.query.store().context_version(key)?, Some(context));
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(fixture.source.tenant_id, "immutable-seed", &fixture.control)?
            .ok_or("retained restored seed")?,
        seed_state
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "immutable-seed",
            &fixture.control
        )?,
        std::slice::from_ref(&receipt)
    );
    assert_eq!(repeated.results.len(), 3);
    assert_eq!(
        repeated.commit_revision,
        before
            .commit_revision
            .checked_add(2)
            .ok_or("restored revision overflow")?
    );
    let mut expected_meta = before;
    expected_meta.commit_revision = repeated.commit_revision;
    assert_eq!(fixture.query.store().meta()?, expected_meta);
    let mut expected_instance = before_instance;
    expected_instance.progress = repeated.commit_revision;
    assert_eq!(
        fixture
            .query
            .store()
            .managed_instance(
                fixture.source.tenant_id,
                "immutable-restored",
                &fixture.control
            )?
            .ok_or("restored Graph progress")?,
        expected_instance
    );
    assert_eq!(
        fixture.query.store().managed_history(
            &grant.selection,
            "immutable-restored",
            &fixture.control
        )?,
        std::slice::from_ref(&repeated)
    );
    let expected_health = before_health.map(|mut health| {
        health.read_revision = repeated.commit_revision;
        health
    });
    assert_eq!(
        fixture.query.store().processor_health(&original.scope)?,
        expected_health
    );
    let coverage = fixture
        .query
        .store()
        .source_receipt(&fixture.source)?
        .ok_or("restored source")?
        .coverage_revision;
    assert_eq!(
        fixture
            .query
            .store()
            .graph_notice(&original.scope, &id, receipt.commit_revision)?,
        Some((repeated.commit_revision, coverage))
    );
    assert_eq!(entered.try_recv(), Ok(()));
    assert_eq!(
        entered.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    );
    fixture.query.store().verify_state()?;
    Ok(())
}

#[tokio::test]
async fn native_input_spans_pages() -> TestResult {
    let manifest = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let template = manifest.records.first().ok_or("Graph input template")?;
    let boundary = araphor_data::analysis::MAX_ANALYSIS_PAGE_RECORDS;
    let count = u64::try_from(boundary.checked_add(1).ok_or("raw page count")?)?;
    assert!(
        template
            .wire_record
            .len()
            .checked_mul(boundary)
            .ok_or("raw page bytes")?
            <= araphor_data::analysis::MAX_ANALYSIS_PAGE_BYTES
    );
    let mut records = Vec::new();
    for cursor in 1..=count {
        let mut wire = template.decode()?;
        wire.ingested_utc_ns = i64::try_from(cursor)?;
        let bytes = Vec::<u8>::try_from(&wire)?;
        records.push(araphor_data::DiscoveryRecordV1::try_from((
            araphor_data::DiscoveryRecordIdV1 {
                durable_cursor: cursor,
                ..template.id.clone()
            },
            bytes.as_slice(),
        ))?);
    }
    let fixture = Fixture::with_records(Target::Sql, records)?;
    let first = fixture.query.store().read_page(&fixture.source, 1)?;
    let second = fixture.query.store().read_page(&fixture.source, count)?;
    assert_eq!(first.records.len(), boundary);
    assert_eq!(second.records.len(), 1);
    let expected = first
        .records
        .iter()
        .chain(&second.records)
        .zip(&fixture.records)
        .map(|(accepted, record)| (record.id.clone(), accepted.position))
        .collect::<Vec<_>>();
    let (observed, records) = std::sync::mpsc::channel();
    *fixture
        .facts
        .records
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(observed);
    let publication = fixture.prepare("ORDER BY source_cursor DESC").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "native-pages",
            "SELECT * FROM events ORDER BY source_cursor DESC",
        )
        .await?;
    let receipt = owner
        .run(managed::request("pages")?, &fixture.control)
        .await?;
    assert_eq!(receipt.results.len(), 3);
    let (id, header, revision) = fixture
        .query
        .store()
        .graph_window_headers(&fixture.source, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == 1)
        .ok_or("multiple-page Graph window")?;
    assert_eq!(header.last_cursor, count);
    assert_eq!(revision, receipt.commit_revision);
    let actual = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("Graph multiple-page input")?;
    assert_eq!(records.try_recv()?, fixture.records);
    assert_eq!(actual.input_positions, expected);
    assert_eq!(
        actual.input_manifest.evidence,
        fixture
            .records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!((actual.first_cursor, actual.last_cursor), (1, count));
    assert_eq!(fixture.facts.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&actual.scope)?
            .ok_or("multiple-page Graph progress")?
            .consumed_cursor,
        count
    );
    Ok(())
}

#[tokio::test]
async fn source_keeps_credential_join() -> TestResult {
    use crate::graph::tests::fixture::{credential_input_from, record, wire};
    use futures_util::StreamExt as _;
    let input = credential_input_from(256)?;
    let mut records = (1..256)
        .map(|cursor| {
            record(
                cursor,
                &wire(
                    cursor,
                    erebor_interceptor_abi::EffectPhysicalResultV1::UnknownAfterPreEffect,
                    2,
                    2,
                    [30; 16],
                ),
            )
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    records.extend(input.records);
    let fixture = Fixture::with_records(Target::Wasm, records)?;
    fixture
        .facts
        .supplied
        .lock()
        .map_err(|_| "Credential join facts")?
        .extend(input.facts);
    super::gates::report(&fixture, 1, &[([4; 16], 1, "HEALTHY")])?;
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "credential-join",
            "SELECT * FROM events",
        )
        .await?;
    let owner = fixture.running_graph(owner).await?;
    assert!(owner.admitted().running);
    let mut stream = owner.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        owner.admitted().lifecycle,
    )?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next()).await;
    let joined = stream.cancel_and_join(&fixture.control).await;
    if let Err(error) = joined {
        return Err(format!("Credential join cleanup: {error}; receive={received:?}").into());
    }
    let receipt = received?.ok_or("Credential join stream ended")??;
    let store = fixture.query.store();
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let head = store
        .processor_result(&scope)?
        .ok_or("Credential join source head")?;
    assert_eq!(head.commit_revision, receipt.commit_revision);
    let id = head.result_id;
    assert_eq!(
        store
            .processor_health(&scope)?
            .ok_or("Credential join progress")?
            .consumed_cursor,
        258
    );
    let graph = store
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("Credential join Graph")?;
    assert_eq!(graph.last_cursor, 258);
    let finding = graph
        .findings
        .iter()
        .find(|finding| finding.package_id == "HF-DW-001")
        .ok_or("Credential join finding")?;
    assert_eq!(finding.state, araphor_data::FindingStateV1::Confirmed);
    assert_eq!(
        finding
            .evidence
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        [256, 257, 258]
    );
    assert_eq!(
        store.graph_finding(fixture.source.tenant_id, &id, &finding.finding_id)?,
        Some(finding.clone())
    );
    assert!(store
        .graph_finding([99; 16], &id, &finding.finding_id)?
        .is_none());
    let current =
        store.graph_findings(fixture.source.tenant_id, None, None, usize::MAX, usize::MAX)?;
    let mut after = None;
    for receipt in current {
        assert_eq!(
            store.graph_findings(
                fixture.source.tenant_id,
                after.as_deref(),
                None,
                1,
                usize::MAX
            )?,
            std::slice::from_ref(&receipt)
        );
        after = Some(receipt.1.finding_id);
    }
    assert!(store
        .graph_findings(
            fixture.source.tenant_id,
            after.as_deref(),
            None,
            1,
            usize::MAX
        )?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn source_preserves_dense_findings() -> TestResult {
    use crate::graph::tests::fixture::{credential_input_from, fact, record, wire};
    use araphor_data::{FindingReasonV1, FindingStateV1, GraphFactV1, GraphFactValueV1};
    use erebor_interceptor_abi::EffectPhysicalResultV1::{
        DeniedBeforeEffect, UnknownAfterPreEffect,
    };
    use futures_util::StreamExt as _;
    let mut records = vec![record(1, &wire(1, UnknownAfterPreEffect, 2, 4, [20; 16]))?];
    for cursor in 2..=256 {
        records.push(record(
            cursor,
            &wire(cursor, DeniedBeforeEffect, 3, 13, [21; 16]),
        )?);
    }
    let template = credential_input_from(1)?;
    let values = template
        .facts
        .iter()
        .map(GraphFactV1::try_from)
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let credential = values
        .iter()
        .find(|fact| matches!(&fact.value, GraphFactValueV1::Credential { .. }))
        .ok_or("Dense credential fact")?;
    let authority = values
        .iter()
        .find(|fact| matches!(&fact.value, GraphFactValueV1::AuthorityUse { .. }))
        .ok_or("Dense authority fact")?;
    let mut facts = vec![fact(&records[0], 1, credential.value.clone())?];
    for index in 2..=67 {
        let mut value = authority.value.clone();
        if let GraphFactValueV1::AuthorityUse { request_id, .. } = &mut value {
            *request_id = Some(format!("request-{index}"));
        }
        facts.push(fact(&records[1], index, value)?);
    }
    assert_eq!(facts.len(), 67);
    let fixture = Fixture::with_records(Target::Wasm, records)?;
    fixture
        .facts
        .supplied
        .lock()
        .map_err(|_| "Dense Graph facts")?
        .extend(facts);
    fixture.coverage(1, Some("HEALTHY"))?;
    let started = std::time::Instant::now();
    let publication = fixture.prepare("").await?;
    let grant = publication.grant.clone();
    let definition = publication.prepared.resolved().clone();
    fixture.admit_definition(&grant, &definition)?;
    drop(publication);
    let owner = fixture
        .managed_graph(
            &grant,
            &definition,
            "dense-findings",
            "SELECT * FROM events",
        )
        .await?;
    let owner = fixture.running_graph(owner).await?;
    assert!(owner.admitted().running);
    let prepared = started.elapsed();
    let projection = &owner
        .graph_owner()
        .ok_or("dense running Graph owner")?
        .projection;
    let mut stream = owner.subscribe(
        Arc::new(AnalysisReadControl::default()),
        u64::MAX,
        owner.admitted().lifecycle,
    )?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(30), stream.next())
        .await
        .map_err(|error| {
            format!(
                "Dense Graph first receipt: {error}; elapsed={:?}; prepared={prepared:?}; first_capture={:?}; facts={}; projections={}",
                started.elapsed(),
                fixture.facts.first.lock().unwrap_or_else(|error| error.into_inner())
                    .map(|first| first.saturating_duration_since(started)),
                fixture.facts.calls.load(Ordering::SeqCst),
                projection.projections.load(Ordering::SeqCst),
            )
        });
    let joined = stream.cancel_and_join(&fixture.control).await;
    if let Err(error) = joined {
        return Err(format!("Dense Graph cleanup: {error}; receive={received:?}").into());
    }
    let receipt = received?.ok_or("Dense Graph stream ended")??;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: fixture.source.clone(),
    };
    let head = fixture
        .query
        .store()
        .processor_result(&scope)?
        .ok_or("Dense Graph source head")?;
    assert_eq!(head.commit_revision, receipt.commit_revision);
    let id = head.result_id;
    assert_eq!(
        fixture
            .query
            .store()
            .processor_health(&scope)?
            .ok_or("Dense Graph progress")?
            .consumed_cursor,
        256
    );
    let graph = fixture
        .query
        .store()
        .graph_result(fixture.source.tenant_id, &id)?
        .ok_or("Dense Graph result")?;
    assert_eq!(graph.last_cursor, 256);
    assert_eq!(graph.findings.len(), 256);
    let mut native = std::collections::BTreeSet::new();
    let mut credential = None;
    for finding in graph.findings {
        match finding.package_id.as_str() {
            "HF-PROC-001" => {
                assert_eq!(finding.reason, FindingReasonV1::UnexpectedEffect);
                assert_eq!(finding.evidence.len(), 1);
                assert!(native.insert(finding.evidence[0].clone()));
            }
            "HF-DW-001" => assert!(credential.replace(finding).is_none()),
            _ => return Err("Unexpected dense Graph finding".into()),
        }
    }
    assert_eq!(
        native,
        fixture.records[1..]
            .iter()
            .map(|record| record.id.clone())
            .collect::<std::collections::BTreeSet<_>>()
    );
    let credential = credential.ok_or("Dense credential finding")?;
    assert_eq!(
        credential.reason,
        FindingReasonV1::ContextualCredentialPivot
    );
    assert_eq!(credential.state, FindingStateV1::CoverageInsufficient);
    let expected = fixture
        .records
        .iter()
        .map(|record| record.id.clone())
        .collect::<Vec<_>>();
    assert_eq!(credential.revision.evidence, expected);
    assert_eq!(credential.evidence, expected);
    Ok(())
}
