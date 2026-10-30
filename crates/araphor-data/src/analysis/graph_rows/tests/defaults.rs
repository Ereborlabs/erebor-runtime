use super::*;
use crate::{
    AnalysisExtractLimits, AnalysisExtractionV1, AnalysisInputTables, AnalysisReadModeV1,
    AnalysisSelectionV1, AnalysisStore, AnalysisTableRead, GraphTraversalV1, ProcessorClassV1,
};

#[test]
fn native_row_defaults() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let edge = fixture.snapshot.graph.edges[0].clone();
    let from = fixture.snapshot.graph.subjects[edge.key.from as usize].clone();
    let to = fixture.snapshot.graph.subjects[edge.key.to as usize].clone();
    let mut edges = fixture
        .snapshot
        .graph
        .edges
        .iter()
        .map(|edge| {
            (
                edge.clone(),
                fixture.snapshot.graph.subjects[edge.key.from as usize].clone(),
                fixture.snapshot.graph.subjects[edge.key.to as usize].clone(),
            )
        })
        .collect::<Vec<_>>();
    for index in 0..4_097_u64 {
        let mut subject = to.clone();
        subject.identity = [b"resource-".as_slice(), &index.to_be_bytes()].concat();
        fixture.snapshot.graph.subjects.push(subject.clone());
        edges.push((edge.clone(), from.clone(), subject));
    }
    fixture.snapshot.graph.subjects.sort();
    fixture.snapshot.graph.subjects.dedup();
    fixture.snapshot.graph.edges = edges
        .into_iter()
        .map(
            |(mut edge, from, to)| -> std::result::Result<_, Box<dyn std::error::Error>> {
                edge.key.from = u32::try_from(
                    fixture
                        .snapshot
                        .graph
                        .subjects
                        .binary_search(&from)
                        .map_err(|_| "source subject")?,
                )?;
                edge.key.to = u32::try_from(
                    fixture
                        .snapshot
                        .graph
                        .subjects
                        .binary_search(&to)
                        .map_err(|_| "target subject")?,
                )?;
                Ok(edge)
            },
        )
        .collect::<std::result::Result<_, Box<dyn std::error::Error>>>()?;
    fixture
        .snapshot
        .graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    fixture.add_findings(1_025)?;
    fixture.snapshot.findings[0].finding_id = "a".repeat(4_097);
    fixture
        .snapshot
        .findings
        .sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    fixture.snapshot.validate()?;
    fixture.request.result_id = "graph:".to_owned() + &"x".repeat(257);
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.request.scope.identity.tenant_id;
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX)?
            .len(),
        fixture.snapshot.findings.len()
    );
    let reader = fixture.store.writer_access()?;
    let request = GraphTraversalV1 {
        seeds: vec![from],
        result_ids: vec![fixture.request.result_id.clone()],
        ..Default::default()
    };
    assert_eq!(request.max_hops, 1);
    assert_eq!(request.max_subjects, usize::MAX);
    assert_eq!(request.max_relationships, usize::MAX);
    request.validate()?;
    let control = AnalysisReadControl::default();
    let walk = crate::analysis::graph::traversal::read::GraphWalk::new(
        reader.get()?,
        &control,
        &request,
        &request.result_ids,
        false,
    )
    .run()?;
    assert!(walk.subjects.len() > 2_048);
    assert!(walk.edges.len() > 4_096);
    let mut bounded = request.clone();
    bounded.max_relationships = 4_096;
    assert!(matches!(
        crate::analysis::graph::traversal::read::GraphWalk::new(
            reader.get()?,
            &control,
            &bounded,
            &bounded.result_ids,
            false
        )
        .run(),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "graph traversal relationships",
            ..
        })
    ));
    bounded = request.clone();
    bounded.max_subjects = 2_048;
    assert!(matches!(
        crate::analysis::graph::traversal::read::GraphWalk::new(
            reader.get()?,
            &control,
            &bounded,
            &bounded.result_ids,
            false
        )
        .run(),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "graph traversal subjects",
            ..
        })
    ));
    bounded = request.clone();
    bounded.max_hops = 65;
    bounded.seeds = fixture.snapshot.graph.subjects[..65].to_vec();
    bounded.validate()?;
    assert!(crate::analysis::graph::traversal::read::GraphWalk::new(
        reader.get()?,
        &control,
        &bounded,
        &bounded.result_ids,
        false
    )
    .run()
    .is_ok());
    drop(reader);
    let path = fixture.store.root.clone();
    let snapshot = fixture.snapshot.clone();
    let id = fixture.request.result_id.clone();
    drop(fixture._graph);
    drop(fixture.store);
    let reopened = AnalysisStore::open(path)?;
    assert_eq!(reopened.graph_result(tenant, &id)?, Some(snapshot));
    assert_eq!(reopened.meta()?.commit_revision, receipt.commit_revision);
    Ok(())
}

#[test]
fn native_metadata_defaults() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.packages[0].coverage_predicate = "x".repeat(16 * 1024 * 1024 + 1);
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    fixture.snapshot.validate()?;
    assert!(fixture.request.body.len() > 16 * 1024 * 1024);
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    assert_eq!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?,
        receipt
    );
    let tenant = fixture.request.scope.identity.tenant_id;
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    let backup = fixture.store.root.join("backups").join("resources");
    fixture.store.backup(&backup)?;
    let restored_path = fixture._directory.path().join("restored");
    let restored = AnalysisStore::restore(&backup, &restored_path)?;
    assert_eq!(
        restored.graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    let path = fixture.store.root.clone();
    drop(fixture._graph);
    drop(fixture.store);
    let reopened = AnalysisStore::open(path)?;
    assert_eq!(
        reopened.graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot)
    );
    Ok(())
}

#[test]
fn native_result_defaults() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut request = fixture.request.clone();
    request.scope.processor_id = "resource-probe".into();
    request.result_id = "result:".to_owned() + &"x".repeat(257);
    fixture
        .store
        .register_processor(&request.scope, ProcessorClassV1::Optional, 1)?;
    request.body = vec![1; 16 * 1024 * 1024 + 1];
    let context = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: request.scope.identity.tenant_id,
            owner_id: "o".repeat(65_537),
            entity_key: vec![1; 257],
            lifetime_key: vec![2; 257],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    let mut contexts = (0..257_u64)
        .map(|index| {
            let mut value = context.clone();
            if index != 0 {
                value.key.entity_key = index.to_be_bytes().to_vec();
            }
            value
        })
        .collect::<Vec<_>>();
    contexts.sort_by(|left, right| left.key.cmp(&right.key));
    request.context_refs = fixture.store.commit_contexts(&contexts)?;
    request.context_revision = request
        .context_refs
        .iter()
        .map(|value| value.commit_revision)
        .max()
        .unwrap_or(0);
    assert!(request.request_meta()?.len() > 16 * 1024 * 1024);
    let receipt = fixture.store.commit_result(&request)?;
    assert_eq!(fixture.store.commit_result(&request)?, receipt);
    assert_eq!(
        fixture
            .store
            .read_result(request.scope.identity.tenant_id, &request.result_id)?,
        Some(request.body.clone())
    );
    let mut changed = request.clone();
    changed.body.push(2);
    assert!(matches!(
        fixture.store.commit_result(&changed),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    let path = fixture.store.root.clone();
    drop(fixture._graph);
    drop(fixture.store);
    let reopened = AnalysisStore::open(path)?;
    assert_eq!(
        reopened.read_result(request.scope.identity.tenant_id, &request.result_id)?,
        Some(request.body)
    );
    assert_eq!(
        reopened
            .context_heads(
                request.scope.identity.tenant_id,
                &context.key.owner_id,
                usize::MAX
            )?
            .len(),
        257
    );
    assert_eq!(
        reopened
            .context_heads(
                request.scope.identity.tenant_id,
                &context.key.owner_id,
                4_097
            )?
            .len(),
        257
    );
    assert!(reopened
        .context_heads(request.scope.identity.tenant_id, &context.key.owner_id, 0)
        .is_err());
    assert_eq!(reopened.context_version(&context.key)?, Some(context));
    Ok(())
}

#[test]
fn native_window_overlap() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.last_cursor = 1_025;
    fixture.request.consumed_cursor = 0;
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    fixture
        .store
        .commit_graph(&fixture.request, false, || Ok(()))?;
    let (graphs, _) =
        fixture
            .store
            .graph_window_page(&fixture.snapshot.scope.identity, 1_025, 1_025, None)?;
    assert_eq!(graphs.len(), 1);
    assert_eq!(graphs[0].1, fixture.snapshot);
    let (graphs, _) =
        fixture
            .store
            .graph_window_page(&fixture.snapshot.scope.identity, 1, 1_025, None)?;
    assert_eq!(graphs.len(), 1);
    Ok(())
}

#[test]
fn native_witness_defaults() -> TestResult {
    let fixture = CommitFixture::new()?;
    let source = fixture.request.scope.identity.clone();
    let page = fixture.store.read_page(&source, 1)?;
    let original = page.records.first().ok_or("source record")?;
    let record = crate::DiscoveryRecordV1::try_from((
        crate::DiscoveryRecordIdV1 {
            stream: source.clone(),
            cpu_id: 0,
            durable_cursor: 1,
        },
        original.framed_record.as_slice(),
    ))?;
    let original = record.decode()?;
    for first in (2..=8_193_u64).step_by(crate::EVIDENCE_BATCH_RECORDS) {
        let last = first
            .saturating_add(crate::EVIDENCE_BATCH_RECORDS as u64 - 1)
            .min(8_193);
        let mut framed = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..=last {
            let mut wire = original.clone();
            wire.observed_boottime_ns = cursor * 1_000;
            wire.decision_context
                .as_mut()
                .ok_or("decision context")?
                .original_kernel_sequence = cursor;
            framed.extend(Vec::<u8>::try_from(&wire)?);
            ends.push(framed.len());
        }
        fixture.store.accept_validated_batch(
            source.clone(),
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: last,
                intake_utc_ns: 1,
                frame_ends: ends,
                framed_records: framed.into(),
            },
        )?;
    }
    let mut request = fixture.request;
    request.scope.processor_id = "many-witnesses".into();
    fixture
        .store
        .register_processor(&request.scope, ProcessorClassV1::Optional, 1)?;
    request.body = vec![1];
    request.consumed_cursor = 8_193;
    let original = request.witnesses[0].clone();
    request.witnesses = (1..=8_193)
        .map(|cursor| crate::AnalysisWitnessV1 {
            cursor,
            ..original.clone()
        })
        .collect();
    let receipt = fixture.store.commit_result(&request)?;
    assert_eq!(fixture.store.commit_result(&request)?, receipt);
    let count: u64 = fixture.store.writer_access()?.get()?.query_row(
        "SELECT count(*) FROM evidence_refs WHERE ref_id = ?",
        params![&request.result_id],
        |row| row.get(0),
    )?;
    assert_eq!(count, 8_193);
    let before = fixture.store.meta()?;
    let captured = provenance_read(
        &fixture.store,
        std::slice::from_ref(&request.result_id),
        AnalysisExtractLimits::default(),
        true,
    )?;
    assert_eq!(captured.witnesses, request.witnesses);
    assert_eq!(fixture.store.meta()?, before);
    let path = fixture.store.root.clone();
    drop(fixture._graph);
    drop(fixture.store);
    let reopened = AnalysisStore::open(path)?;
    assert_eq!(
        reopened.read_result(source.tenant_id, &request.result_id)?,
        Some(vec![1])
    );
    assert_eq!(
        provenance_read(
            &reopened,
            std::slice::from_ref(&request.result_id),
            AnalysisExtractLimits::default(),
            true,
        )?
        .witnesses,
        request.witnesses
    );
    Ok(())
}

#[test]
fn native_subject_order() -> TestResult {
    let fixture = CommitFixture::new()?;
    let reader = Connection::open_in_memory()?;
    reader.execute_batch(&GraphRows::schema())?;
    NativeRows::bind(&reader, "first", 1, 1)?;
    let base = fixture.snapshot.graph.subjects[0].clone();
    let mut process = base.clone();
    process.kind = crate::GraphSubjectKindV1::Process;
    let mut provider = base.clone();
    provider.authority = crate::GraphSubjectAuthorityV1::Provider {
        authority_id: "provider".into(),
    };
    let mut kubernetes = base.clone();
    kubernetes.authority = crate::GraphSubjectAuthorityV1::Kubernetes {
        cluster_id: "cluster".into(),
    };
    let mut external = base.clone();
    external.authority = crate::GraphSubjectAuthorityV1::External {
        authority_id: "external".into(),
    };
    let mut subjects = vec![external, process, kubernetes, provider, base.clone()];
    subjects.sort();
    NativeRows::subjects(&reader, &subjects, 1, 1)?;
    assert_eq!(
        GraphRows::read_subjects(&reader, "first", subjects.len(), None)?,
        subjects
    );
    NativeRows::bind(&reader, "second", 1, 2)?;
    let mut earlier = base;
    if let crate::GraphSubjectAuthorityV1::Native { node_id, .. } = &mut earlier.authority {
        *node_id = "0".into();
    }
    subjects.push(earlier);
    subjects.sort();
    NativeRows::subjects(&reader, &subjects, 1, 2)?;
    assert_eq!(
        GraphRows::read_subjects(&reader, "second", subjects.len(), None)?,
        subjects
    );
    assert_eq!(
        GraphRows::read_subjects(&reader, "first", subjects.len() - 1, None)?,
        subjects[1..]
    );
    NativeRows::bind(&reader, "third", 1, 3)?;
    NativeRows::subjects(&reader, &subjects[1..], 1, 3)?;
    NativeRows::bind(&reader, "fourth", 1, 4)?;
    NativeRows::subjects(&reader, &subjects, 1, 4)?;
    assert_eq!(
        GraphRows::read_subjects(&reader, "third", subjects.len() - 1, None)?,
        subjects[1..]
    );
    assert_eq!(
        GraphRows::read_subjects(&reader, "fourth", subjects.len(), None)?,
        subjects
    );
    let values: u64 = reader.query_row(
        "SELECT count(*)::UBIGINT FROM graph_subject_values",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(values, subjects.len() as u64);
    let memberships: u64 = reader.query_row(
        "SELECT count(*)::UBIGINT FROM graph_producer_members WHERE member_kind=2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(memberships, subjects.len() as u64 + 1);
    Ok(())
}

#[test]
fn native_traversal_defaults() -> TestResult {
    let fixture = CommitFixture::new()?;
    let request = GraphTraversalV1 {
        seeds: vec![fixture.snapshot.graph.subjects[0].clone()],
        result_ids: vec!["x".repeat(1024 * 1024 + 1)],
        max_hops: u32::MAX,
        ..Default::default()
    };
    let json = serde_json::to_vec(&request)?;
    assert!(json.len() > 1024 * 1024);
    assert_eq!(GraphTraversalV1::try_from(json.as_slice())?, request);
    let mut duplicate = request.clone();
    duplicate.seeds.push(duplicate.seeds[0].clone());
    assert!(duplicate.validate().is_err());
    let mut empty = request;
    empty.result_ids[0].clear();
    assert!(empty.validate().is_err());
    Ok(())
}

fn provenance_read(
    store: &AnalysisStore,
    results: &[String],
    limits: AnalysisExtractLimits,
    inherit: bool,
) -> crate::Result<AnalysisExtractionV1> {
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.results = results.to_vec();
    let requests = Default::default();
    Ok(store
        .read_tables(
            &selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: inherit.then_some(AnalysisInputTables {
                    authorized: &selection,
                    outputs: &[],
                }),
                mode: AnalysisReadModeV1::Metadata,
                now: 10,
            },
            limits,
            &AnalysisReadControl::default(),
        )?
        .extraction)
}

#[test]
fn extracted_provenance_defaults() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut request = fixture.request.clone();
    request.scope.processor_id = "provenance-defaults".into();
    request.body = vec![1];
    fixture
        .store
        .register_processor(&request.scope, ProcessorClassV1::Optional, 1)?;
    let contexts = (0..257_u64)
        .map(|index| crate::AnalysisContextVersionV1 {
            key: crate::AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "provenance".into(),
                entity_key: index.to_be_bytes().to_vec(),
                lifetime_key: vec![1],
                owner_revision: 1,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: crate::ContextSensitivityV1::Tenant,
            body: vec![1],
        })
        .collect::<Vec<_>>();
    let contexts = fixture.store.commit_contexts(&contexts)?;
    request.context_revision = contexts
        .iter()
        .map(|reference| reference.commit_revision)
        .max()
        .unwrap_or(0);
    request.context_refs = contexts.clone();
    request.result_id = "provenance:0".into();
    let original = request.clone();
    let mut ids = Vec::new();
    for index in 0..65 {
        request.result_id = format!("provenance:{index}");
        if index != 0 {
            request.expected_cursor = request.consumed_cursor;
            request.context_refs = vec![contexts[0].clone()];
            request.witnesses[0].expires_utc_ns = request.created_utc_ns + 1;
        }
        fixture.store.commit_result(&request)?;
        ids.push(request.result_id.clone());
    }
    let before = fixture.store.meta()?;
    let changes = fixture.store.subscribe_revision();
    let direct = provenance_read(
        &fixture.store,
        &ids,
        AnalysisExtractLimits::default(),
        false,
    )?;
    assert!(direct.witnesses.is_empty());
    assert_eq!(direct.references.len(), 65);
    let captured = provenance_read(&fixture.store, &ids, AnalysisExtractLimits::default(), true)?;
    assert_eq!(
        captured
            .references
            .iter()
            .filter_map(crate::AnalysisReferenceV1::result)
            .count(),
        65
    );
    let retained = captured
        .references
        .iter()
        .filter_map(crate::AnalysisReferenceV1::context)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(retained, contexts);
    for reference in &captured.references {
        assert_eq!(
            reference.origins(),
            &[crate::AnalysisReferenceOriginV1::ExplicitResult]
        );
    }
    assert_eq!(captured.witnesses, request.witnesses);
    let bytes = direct
        .input_bytes
        .checked_add(original.request_meta()?.len() - 1)
        .ok_or("configured input bytes")?;
    let bounded = AnalysisExtractLimits {
        input_bytes: bytes,
        ..Default::default()
    };
    provenance_read(&fixture.store, &ids, bounded, false)?;
    for (limits, expected) in [
        (bounded, "selected input bytes"),
        (
            AnalysisExtractLimits {
                keys: Some(64),
                ..Default::default()
            },
            "selected input keys",
        ),
    ] {
        assert!(
            matches!(provenance_read(&fixture.store, &ids, limits, true), Err(crate::Error::AnalysisInputTooLarge { resource, .. }) if resource == expected)
        );
        assert_eq!(fixture.store.meta()?, before);
        assert!(!changes.has_changed()?);
    }
    assert_eq!(fixture.store.meta()?, before);
    assert!(!changes.has_changed()?);
    let path = fixture.store.root.clone();
    drop(fixture._graph);
    drop(fixture.store);
    let reopened = AnalysisStore::open(path)?;
    let captured = provenance_read(&reopened, &ids, AnalysisExtractLimits::default(), true)?;
    assert_eq!(
        captured
            .references
            .iter()
            .filter_map(crate::AnalysisReferenceV1::result)
            .count(),
        65
    );
    assert_eq!(
        captured
            .references
            .iter()
            .filter_map(crate::AnalysisReferenceV1::context)
            .cloned()
            .collect::<Vec<_>>(),
        contexts
    );
    assert_eq!(captured.witnesses, request.witnesses);
    let mut foreign_witness = original.clone();
    let crate::AnalysisStreamIdentityV1::Evidence(identity) =
        &mut foreign_witness.witnesses[0].identity
    else {
        return Err("evidence witness".into());
    };
    identity.tenant_id = [2; 16];
    let mut foreign_context = original.clone();
    foreign_context.context_refs[0].key.tenant_id = [2; 16];
    for (changed, expected) in [
        (
            foreign_witness,
            "the captured evidence witness has a foreign tenant",
        ),
        (
            foreign_context,
            "the captured evidence context has a foreign tenant",
        ),
    ] {
        reopened.writer_access()?.get()?.execute(
            "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
            params![changed.request_meta()?, original.result_id],
        )?;
        assert!(matches!(
            provenance_read(&reopened, std::slice::from_ref(&original.result_id), AnalysisExtractLimits::default(), true),
            Err(crate::Error::AnalysisState { reason, .. }) if reason == expected
        ));
        reopened.writer_access()?.get()?.execute(
            "UPDATE analysis_results SET request_meta = ? WHERE result_id = ?",
            params![original.request_meta()?, original.result_id],
        )?;
    }
    assert_eq!(
        provenance_read(&reopened, &ids, AnalysisExtractLimits::default(), true)?.witnesses,
        request.witnesses
    );
    Ok(())
}
