use super::*;

mod atomic;

mod bounds;
mod defaults;
mod encoding;
pub(in crate::analysis) mod fixture;
mod guards;
mod headers;
mod packages;
mod schema;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
use fixture::CommitFixture;

#[test]
fn graph_source_requires_native_identity() -> TestResult {
    let fixture = CommitFixture::new()?;
    let graph = &fixture.snapshot;
    let source = &graph.scope.identity;
    let mut wrong_boot = source.clone();
    wrong_boot.node_boot_id[0] ^= 1;
    let mut wrong_label = source.clone();
    wrong_label.label_epoch += 1;
    let mut wrong_epoch = source.clone();
    wrong_epoch.source_epoch += 1;
    let cases = [
        None,
        Some((source.key(), [9; 16])),
        Some((wrong_boot.key(), source.tenant_id)),
        Some((wrong_label.key(), source.tenant_id)),
        Some((wrong_epoch.key(), source.tenant_id)),
    ];
    for receipt in cases {
        let writer = Connection::open_in_memory()?;
        writer.execute_batch(
            "CREATE TABLE analysis_results (result_id VARCHAR, commit_revision UBIGINT);
             CREATE TABLE source_receipts (stream_key BLOB, tenant_id BLOB);",
        )?;
        writer.execute_batch(&GraphRows::schema())?;
        writer.execute("INSERT INTO analysis_results VALUES ('version', 1)", [])?;
        if let Some((key, tenant)) = receipt {
            writer.execute(
                "INSERT INTO source_receipts VALUES (?, ?)",
                params![key, tenant.as_slice()],
            )?;
        }
        assert!(matches!(
            GraphRows::insert_inputs(graph, &writer, "version"),
            Err(crate::Error::GraphInvalid {
                field: "graph evidence source",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn native_rows_integrity() -> TestResult {
    let fixture = CommitFixture::new()?;
    let graph = &fixture.snapshot;
    assert!(!graph.graph.subjects.is_empty());
    assert!(!graph.graph.edges.is_empty());
    assert!(!graph.findings.is_empty());
    let encoded_header = GraphRows::encode(graph)?;
    let metadata = GraphHeader::decode(&encoded_header)?;
    assert!(metadata.snapshot.findings.is_empty());
    assert!(metadata.snapshot.graph.subjects.is_empty());
    assert!(metadata.snapshot.graph.edges.is_empty());
    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
        tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
        method_version UBIGINT, first_cursor UBIGINT, facts_revision UBIGINT,
        coverage_revision UBIGINT, commit_revision UBIGINT);
        CREATE TABLE source_receipts (stream_key BLOB PRIMARY KEY,
        identity_json VARCHAR, tenant_id BLOB)",
    )?;
    writer.execute_batch(&GraphRows::schema())?;
    GraphRows::validate_tables(&writer)?;
    writer.execute(
        "INSERT INTO source_receipts VALUES (?, ?, ?)",
        params![
            graph.scope.identity.key(),
            serde_json::to_string(&graph.scope.identity)?,
            graph.scope.identity.tenant_id.as_slice()
        ],
    )?;
    writer.execute(
        "INSERT INTO analysis_results VALUES ('version', ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        params![
            graph.scope.identity.tenant_id.as_slice(),
            crate::GRAPH_PROCESSOR,
            &encoded_header,
            graph.scope.identity.key().as_slice(),
            graph.scope.method_version,
            graph.first_cursor,
            graph.context_notice_revision,
            fixture.request.coverage_revision
        ],
    )?;
    GraphRows::insert(graph, &writer, "version")?;
    let header = GraphRows::read_header(&writer, graph.scope.identity.tenant_id, "version")?
        .ok_or("missing header")?;
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        GraphRows::load_inputs(&writer, "version", &header, Some(&cancelled)),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(GraphRows::read(&writer, "version", &header)?, *graph);
    assert_eq!(
        serde_json::to_vec(&GraphRows::read(&writer, "version", &header)?)?,
        serde_json::to_vec(graph)?
    );
    {
        let transaction = writer.transaction()?;
        transaction.execute("DELETE FROM source_receipts", [])?;
        assert!(matches!(
            GraphRows::load_inputs(&transaction, "version", &header, None),
            Err(crate::Error::GraphInvalid {
                field: "graph evidence source",
                ..
            })
        ));
    }
    {
        let transaction = writer.transaction()?;
        let other = "versión";
        let mut next = graph.clone();
        next.last_cursor = 2;
        next.previous_result_id = Some("version".into());
        let mut added = next.input_manifest.evidence[0].clone();
        added.durable_cursor = 2;
        next.input_manifest.evidence.push(added.clone());
        next.input_positions = vec![
            (
                added,
                crate::StorePositionV1 {
                    commit_revision: 2,
                    ordinal: 0,
                },
            ),
            (
                graph.input_manifest.evidence[0].clone(),
                crate::StorePositionV1 {
                    commit_revision: 1,
                    ordinal: 0,
                },
            ),
            (
                graph.input_manifest.evidence[0].clone(),
                crate::StorePositionV1 {
                    commit_revision: 1,
                    ordinal: 0,
                },
            ),
        ];
        next.validate()?;
        transaction.execute(
            "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 2)",
            params![
                other,
                next.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(&next)?,
                next.scope.identity.key(),
                next.scope.method_version,
                next.first_cursor,
                next.context_notice_revision,
                fixture.request.coverage_revision
            ],
        )?;
        GraphRows::insert(&next, &transaction, other)?;
        let other_header =
            GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, other)?
                .ok_or("missing second header")?;
        assert_eq!(GraphRows::read(&transaction, other, &other_header)?, next);
        let old_header =
            GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, "version")?
                .ok_or("missing historical header")?;
        assert_eq!(
            GraphRows::read(&transaction, "version", &old_header)?,
            *graph
        );
        let mut removed = next.clone();
        removed.previous_result_id = Some(other.into());
        removed.input_manifest.evidence.remove(0);
        removed.input_positions.truncate(1);
        removed.graph.edges.clear();
        removed.graph.branches.clear();
        removed.graph.facts.clear();
        removed.findings.clear();
        removed.validate()?;
        transaction.execute(
            "INSERT INTO analysis_results VALUES ('removed', ?, ?, ?, ?, ?, ?, ?, ?, 3)",
            params![
                removed.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(&removed)?,
                removed.scope.identity.key(),
                removed.scope.method_version,
                removed.first_cursor,
                removed.context_notice_revision,
                fixture.request.coverage_revision
            ],
        )?;
        GraphRows::insert(&removed, &transaction, "removed")?;
        let mut reentered = next.clone();
        reentered.previous_result_id = Some("removed".into());
        reentered.validate()?;
        transaction.execute(
            "INSERT INTO analysis_results VALUES ('reentered', ?, ?, ?, ?, ?, ?, ?, ?, 4)",
            params![
                reentered.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(&reentered)?,
                reentered.scope.identity.key(),
                reentered.scope.method_version,
                reentered.first_cursor,
                reentered.context_notice_revision,
                fixture.request.coverage_revision
            ],
        )?;
        GraphRows::insert(&reentered, &transaction, "reentered")?;
        for (id, expected) in [
            ("version", graph),
            (other, &next),
            ("removed", &removed),
            ("reentered", &reentered),
        ] {
            let historical =
                GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, id)?
                    .ok_or("missing historical Graph")?;
            assert_eq!(GraphRows::read(&transaction, id, &historical)?, *expected);
        }
        transaction.execute(
            "DELETE FROM graph_edge_membership
             WHERE lineage_id = (SELECT lineage_id FROM graph_versions WHERE result_id = ?)
                 AND valid_from = (SELECT commit_revision FROM graph_versions WHERE result_id = ?)",
            params![other, other],
        )?;
        let seed = graph.findings[0].subject_id.clone();
        let control = AnalysisReadControl::default();
        let allowed = GraphRows::selected_subjects(
            &transaction,
            other,
            std::slice::from_ref(&seed),
            &control,
            true,
        )?;
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].0, seed);
        assert!(GraphRows::selected_subjects(
            &transaction,
            "removed",
            std::slice::from_ref(&seed),
            &control,
            true,
        )?
        .is_empty());
        for (id, allowed) in [(other, true), ("removed", false)] {
            let request = crate::GraphTraversalV1 {
                seeds: vec![seed.clone()],
                result_ids: vec![id.into()],
                max_hops: 0,
                ..Default::default()
            };
            let walk = crate::analysis::graph::traversal::read::GraphWalk::new(
                &transaction,
                &control,
                &request,
                &request.result_ids,
                true,
            )
            .run()?;
            assert_eq!(walk.subjects.len(), usize::from(allowed));
            assert!(walk.edges.is_empty());
        }
        let finding = &next.findings[0];
        let unrelated: u64 = transaction.query_row(
            "SELECT evidence_id FROM graph_evidence WHERE durable_cursor = 2",
            [],
            |row| row.get(0),
        )?;
        let source_ref: u64 = transaction.query_row(
            "SELECT source_ref FROM graph_evidence WHERE evidence_id = ?",
            params![unrelated],
            |row| row.get(0),
        )?;
        let wrong_ref = source_ref + 1;
        let mut wrong_source = graph.scope.identity.clone();
        wrong_source.node_boot_id[0] ^= 1;
        transaction.execute(
            "INSERT INTO source_receipts VALUES (?, ?, ?)",
            params![
                wrong_source.key(),
                serde_json::to_string(&wrong_source)?,
                wrong_source.tenant_id.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO graph_sources VALUES (?, ?, ?)",
            params![
                wrong_ref,
                wrong_source.key(),
                wrong_source.tenant_id.as_slice()
            ],
        )?;
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![wrong_ref, unrelated],
        )?;
        assert_eq!(
            GraphRows::read_finding(
                &transaction,
                other,
                &finding.finding_id,
                &other_header,
                None,
            )?,
            Some(finding.clone())
        );
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![source_ref, unrelated],
        )?;
        let referenced: u64 = transaction.query_row(
            "SELECT list_extract(evidence_refs, 1)::UBIGINT FROM graph_findings
             WHERE result_id = ? AND finding_id = ?",
            params![other, &finding.finding_id],
            |row| row.get(0),
        )?;
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![wrong_ref, referenced],
        )?;
        assert!(GraphRows::read_finding(
            &transaction,
            other,
            &finding.finding_id,
            &other_header,
            None,
        )
        .is_err());
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![source_ref, referenced],
        )?;
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![wrong_ref + 1, referenced],
        )?;
        assert!(GraphRows::read_finding(
            &transaction,
            other,
            &finding.finding_id,
            &other_header,
            None,
        )
        .is_err());
        transaction.execute(
            "UPDATE graph_evidence SET source_ref = ? WHERE evidence_id = ?",
            params![source_ref, referenced],
        )?;
        transaction.execute(
            "DELETE FROM graph_sources WHERE source_ref = ?",
            params![wrong_ref],
        )?;
        transaction.execute(
            "DELETE FROM source_receipts WHERE stream_key = ?",
            params![wrong_source.key()],
        )?;
        let reentry: u64 = transaction.query_row(
            "SELECT count(*)::UBIGINT FROM graph_evidence_membership
             WHERE lineage_id = 1 AND evidence_id = 1",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(reentry, 2);
        let finding_values: u64 = transaction.query_row(
            "SELECT count(*)::UBIGINT FROM graph_finding_values",
            [],
            |row| row.get(0),
        )?;
        let finding_memberships: u64 = transaction.query_row(
            "SELECT count(*)::UBIGINT FROM graph_finding_membership",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(finding_values, graph.findings.len() as u64);
        assert_eq!(finding_memberships, 2 * graph.findings.len() as u64);
        let mut window = next.clone();
        window.first_cursor = 2;
        window.previous_result_id = None;
        window.input_manifest.evidence.remove(0);
        window.input_positions.truncate(1);
        window.graph.edges.clear();
        window.graph.branches.clear();
        window.graph.facts.clear();
        window.findings.clear();
        window.validate()?;
        transaction.execute(
            "INSERT INTO analysis_results VALUES ('new-window', ?, ?, ?, ?, ?, ?, ?, ?, 5)",
            params![
                window.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(&window)?,
                window.scope.identity.key(),
                window.scope.method_version,
                window.first_cursor,
                window.context_notice_revision,
                fixture.request.coverage_revision
            ],
        )?;
        GraphRows::insert(&window, &transaction, "new-window")?;
        let window_header =
            GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, "new-window")?
                .ok_or("missing new window")?;
        assert_eq!(
            GraphRows::read(&transaction, "new-window", &window_header)?,
            window
        );
        let evidence_rows: u64 =
            transaction.query_row("SELECT count(*)::UBIGINT FROM graph_evidence", [], |row| {
                row.get(0)
            })?;
        assert_eq!(evidence_rows, 2);
        let source_rows: u64 =
            transaction.query_row("SELECT count(*)::UBIGINT FROM graph_sources", [], |row| {
                row.get(0)
            })?;
        assert_eq!(source_rows, 1);
        let subject_rows: u64 = transaction.query_row(
            "SELECT count(*)::UBIGINT FROM graph_subject_values",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(subject_rows, graph.graph.subjects.len() as u64);
        transaction.execute(
            "INSERT INTO analysis_results VALUES ('independent', ?, ?, ?, ?, ?, ?, ?, ?, 6)",
            params![
                graph.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(graph)?,
                graph.scope.identity.key().as_slice(),
                graph.scope.method_version,
                graph.first_cursor,
                graph.context_notice_revision,
                fixture.request.coverage_revision
            ],
        )?;
        GraphRows::insert(graph, &transaction, "independent")?;
        let independent =
            GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, "independent")?
                .ok_or("missing independent Graph")?;
        assert_eq!(
            GraphRows::read(&transaction, "independent", &independent)?,
            *graph
        );
        let shared: (u64, u64) = transaction.query_row(
            "SELECT (SELECT count(*)::UBIGINT FROM graph_finding_values),
                (SELECT count(*)::UBIGINT FROM graph_finding_membership)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(
            shared,
            (graph.findings.len() as u64, 3 * graph.findings.len() as u64)
        );
        transaction.rollback()?;
    }
    let retained: (u64, u64, u64) = writer.query_row(
        "SELECT (SELECT count(*)::UBIGINT FROM graph_versions),
                (SELECT count(*)::UBIGINT FROM graph_evidence),
                (SELECT count(*)::UBIGINT FROM graph_subject_values)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(retained, (1, 1, graph.graph.subjects.len() as u64));
    assert!(GraphRows::read_header(&writer, [9; 16], "version")?.is_none());
    assert_eq!(
        GraphRows::read_finding(
            &writer,
            "version",
            &graph.findings[0].finding_id,
            &header,
            None
        )?,
        Some(graph.findings[0].clone())
    );
    for mutation in [
        "DELETE FROM graph_subject_membership WHERE subject_id = 1",
        "UPDATE graph_finding_values SET severity = 'INVALID'",
        "DELETE FROM graph_finding_membership WHERE value_id = (SELECT min(value_id) FROM graph_finding_values)",
        "UPDATE graph_subject_values SET tenant_id = 'short'::BLOB WHERE subject_id = 1",
        "UPDATE graph_subject_values SET authority_rank = 255 WHERE subject_id = 1",
        "UPDATE graph_edge_values SET from_ref = 4294967295",
        "UPDATE graph_edge_values SET evidence_refs = [4294967295]::UBIGINT[]",
        "UPDATE graph_edge_values SET evidence_refs = [NULL]::UBIGINT[]",
        "UPDATE graph_edge_values SET property_ref = 4294967295",
        "UPDATE graph_edge_properties SET proof_quality = struct_update(proof_quality, source_authority := 255::UTINYINT)",
        "UPDATE graph_edge_properties SET proof_quality = struct_update(proof_quality, source_authority := NULL::UTINYINT)",
        "UPDATE graph_edge_properties SET required_coverage_interval_ids = ['short'::BLOB]",
        "UPDATE graph_edge_properties SET required_coverage_interval_ids = [NULL::BLOB]",
        "UPDATE graph_finding_values SET tenant_id = 'short'::BLOB",
        "UPDATE graph_finding_values SET effects = '{'::BLOB",
    ] {
        let transaction = writer.transaction()?;
        transaction.execute(mutation, [])?;
        assert!(
            GraphRows::read(&transaction, "version", &header).is_err(),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    {
        let transaction = writer.transaction()?;
        assert!(transaction
            .execute(
                "UPDATE graph_edge_values SET first_boottime_ns = last_boottime_ns + 1",
                []
            )
            .is_err());
        transaction.rollback()?;
    }
    for mutation in [
        "DELETE FROM graph_versions",
        "UPDATE graph_evidence SET durable_cursor = 0",
        "UPDATE graph_evidence_membership SET valid_to = valid_from",
    ] {
        let transaction = writer.transaction()?;
        transaction.execute(mutation, [])?;
        assert!(
            GraphRows::read_header(&transaction, graph.scope.identity.tenant_id, "version")
                .is_err(),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn native_edge_columns() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut empty = fixture.snapshot.graph.edges[0].clone();
    empty.key.evidence.clear();
    empty.required_coverage_interval_ids.clear();
    empty.proof_quality = crate::ProofQualityV1 {
        source_authority: crate::SourceAuthorityV1::Unauthenticated,
        local_subject_binding: crate::LocalSubjectBindingV1::None,
        remote_subject_binding: crate::RemoteSubjectBindingV1::None,
        operation_result_authority: crate::OperationResultAuthorityV1::Unknown,
        temporal_coverage: crate::TemporalCoverageV1::Unknown,
        integrity: crate::ProofIntegrityV1::Unverified,
    };
    let mut graph = fixture.snapshot.clone();
    graph.graph.edges[0] = empty;
    graph
        .graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    graph.validate()?;
    let mut request = fixture.request.clone();
    request.body.clear();
    fixture.store.commit_graph_snapshot(
        request,
        CanonicalGraph::new(graph.clone())?,
        &[],
        &[],
        &[],
        true,
        || Ok(()),
    )?;
    let writer = fixture.store.writer_access()?;
    let writer = writer.get()?;
    let rows = &graph.graph.edges;
    assert_eq!(
        GraphRows::read_edges(writer, &fixture.request.result_id, rows.len(), None)?,
        *rows
    );
    assert_eq!(
        GraphRows::selected_edges(
            writer,
            &fixture.request.result_id,
            &[0, 2],
            &AnalysisReadControl::default()
        )?,
        vec![rows[0].clone(), rows[2].clone()]
    );
    assert!(rows.iter().any(|row| row.key.evidence.is_empty()));
    assert!(rows.iter().any(|row| !row.key.evidence.is_empty()));
    let types: (String, String, String, String) = writer.query_row(
        "SELECT typeof(from_subject_id), typeof(evidence),
        typeof(proof_quality.source_authority), typeof(required_coverage_interval_ids)
        FROM graph_relationships WHERE result_id = ? AND ordinal = 0",
        params![fixture.request.result_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(
        types,
        (
            "UINTEGER".into(),
            "UINTEGER[]".into(),
            "UTINYINT".into(),
            "BLOB[]".into()
        )
    );
    Ok(())
}

#[test]
fn earlier_keys_keep_edge_membership() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut first = fixture.snapshot.clone();
    first.graph.edges.truncate(1);
    first.graph.branches.clear();
    first.graph.facts.clear();
    first.findings.clear();
    first.input_manifest.evidence[0].cpu_id = 1;
    first.validate()?;
    let from = first.graph.subjects[first.graph.edges[0].key.from as usize].clone();
    let to = first.graph.subjects[first.graph.edges[0].key.to as usize].clone();

    let mut second = first.clone();
    second.previous_result_id = Some("first".into());
    let mut earlier = first.input_manifest.evidence[0].clone();
    earlier.cpu_id = 0;
    second.input_manifest.evidence.insert(0, earlier);
    let mut subject = first.graph.subjects[0].clone();
    subject.identity = vec![0];
    second.graph.subjects.push(subject);
    second.graph.subjects.sort();
    second.graph.edges[0].key.from = second
        .graph
        .subjects
        .binary_search(&from)
        .map_err(|_| "missing from subject")? as u32;
    second.graph.edges[0].key.to = second
        .graph
        .subjects
        .binary_search(&to)
        .map_err(|_| "missing to subject")? as u32;
    second.graph.edges[0].key.evidence = vec![1];
    second.validate()?;

    let writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
            tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
            method_version UBIGINT, first_cursor UBIGINT, facts_revision UBIGINT,
            coverage_revision UBIGINT, commit_revision UBIGINT);
         CREATE TABLE source_receipts (stream_key BLOB PRIMARY KEY, tenant_id BLOB)",
    )?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute(
        "INSERT INTO source_receipts VALUES (?, ?)",
        params![
            first.scope.identity.key(),
            first.scope.identity.tenant_id.as_slice()
        ],
    )?;
    for (id, revision, graph) in [("first", 1, &first), ("second", 2, &second)] {
        writer.execute(
            "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                graph.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(graph)?,
                graph.scope.identity.key(),
                graph.scope.method_version,
                graph.first_cursor,
                graph.context_notice_revision,
                fixture.request.coverage_revision,
                revision
            ],
        )?;
        GraphRows::insert(graph, &writer, id)?;
        let header = GraphRows::read_header(&writer, graph.scope.identity.tenant_id, id)?
            .ok_or("missing graph version")?;
        assert_eq!(GraphRows::read(&writer, id, &header)?, *graph);
    }
    let counts: (u64, u64) = writer.query_row(
        "SELECT (SELECT count(*)::UBIGINT FROM graph_edge_values),
            (SELECT count(*)::UBIGINT FROM graph_edge_membership)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(counts, (1, 1));
    Ok(())
}

#[test]
fn edge_lookup_reuses_and_retries_large_batch() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut first = fixture.snapshot.clone();
    let edge = first.graph.edges[0].clone();
    let first_edge_count = crate::analysis::MAX_ANALYSIS_PAGE_RECORDS + 2;
    let mut extra_record = first.input_manifest.evidence[0].clone();
    extra_record.durable_cursor = 2;
    first.input_manifest.evidence.push(extra_record.clone());
    first.input_positions.push((
        extra_record,
        crate::StorePositionV1 {
            commit_revision: 2,
            ordinal: 0,
        },
    ));
    first.last_cursor = 2;
    first.graph.edges = (0..first_edge_count)
        .map(|index| {
            let mut edge = edge.clone();
            edge.key.package_id = format!("HF-PROC-001:{:03}", if index == 1 { 0 } else { index });
            if index == 1 {
                edge.key.evidence = vec![1];
            }
            edge
        })
        .collect();
    first
        .graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    first.graph.branches.clear();
    first.graph.facts.clear();
    first.findings.clear();
    first.validate()?;

    let mut second = first.clone();
    second.previous_result_id = Some("first".into());
    let mut added = edge;
    added.key.package_id = format!("HF-PROC-001:{first_edge_count:03}");
    second.graph.edges.push(added);
    second
        .graph
        .edges
        .sort_by(|left, right| left.key.cmp(&right.key));
    second.validate()?;

    let writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE analysis_results (result_id VARCHAR PRIMARY KEY,
            tenant_id BLOB, processor_id VARCHAR, body BLOB, stream_key BLOB,
            method_version UBIGINT, first_cursor UBIGINT, facts_revision UBIGINT,
            coverage_revision UBIGINT, commit_revision UBIGINT);
         CREATE TABLE source_receipts (stream_key BLOB PRIMARY KEY, tenant_id BLOB)",
    )?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute(
        "INSERT INTO source_receipts VALUES (?, ?)",
        params![
            first.scope.identity.key(),
            first.scope.identity.tenant_id.as_slice()
        ],
    )?;
    let mut second_ids = None;
    for (id, revision, graph) in [("first", 1, &first), ("second", 2, &second)] {
        writer.execute(
            "INSERT INTO analysis_results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id,
                graph.scope.identity.tenant_id.as_slice(),
                crate::GRAPH_PROCESSOR,
                GraphRows::encode(graph)?,
                graph.scope.identity.key(),
                graph.scope.method_version,
                graph.first_cursor,
                graph.context_notice_revision,
                fixture.request.coverage_revision,
                revision
            ],
        )?;
        let ids = GraphRows::insert(graph, &writer, id)?;
        if id == "second" {
            second_ids = Some(ids);
        }
        let header = GraphRows::read_header(&writer, graph.scope.identity.tenant_id, id)?
            .ok_or("missing graph version")?;
        assert_eq!(GraphRows::read(&writer, id, &header)?, *graph);
    }
    let counts: (u64, u64, u64) = writer.query_row(
        "SELECT (SELECT count(*)::UBIGINT FROM graph_edge_values),
            (SELECT count(*)::UBIGINT FROM graph_edge_membership),
            (SELECT count(*)::UBIGINT FROM graph_edge_properties)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let first_edge_count = u64::try_from(first_edge_count)?;
    assert_eq!(
        counts,
        (first_edge_count + 1, first_edge_count + 1, first_edge_count)
    );
    let ids = second_ids.ok_or("missing second graph IDs")?;
    let (lineage, revision): (u64, u64) = writer.query_row(
        "SELECT lineage_id, commit_revision FROM graph_versions WHERE result_id = 'second'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let edge_id: u64 = writer.query_row(
        "SELECT edge_id FROM graph_edge_values ORDER BY edge_id LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    let (property_ref, other_ref): (u64, u64) = writer.query_row(
        "SELECT property_ref,
            (SELECT max(property_ref)::UBIGINT FROM graph_edge_properties)
         FROM graph_edge_values WHERE edge_id = ?",
        params![edge_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_ne!(property_ref, other_ref);
    writer.execute(
        "UPDATE graph_edge_values SET property_ref = ? WHERE edge_id = ?",
        params![other_ref, edge_id],
    )?;
    assert!(GraphRows::validate_edge_values(&writer).is_err());
    writer.execute(
        "UPDATE graph_edge_values SET property_ref = ? WHERE edge_id = ?",
        params![property_ref, edge_id],
    )?;
    writer.execute(
        "UPDATE graph_edge_values SET last_boottime_ns = last_boottime_ns + 1 WHERE edge_id = ?",
        params![edge_id],
    )?;
    assert!(matches!(
        GraphRows::insert_edge_values(
            &writer,
            &second,
            &ids.subjects,
            &ids.evidence,
            lineage,
            revision
        ),
        Err(crate::Error::GraphInvalid {
            field: "duplicate graph edge value",
            ..
        })
    ));
    writer.execute(
        "UPDATE graph_edge_values SET last_boottime_ns = last_boottime_ns - 1 WHERE edge_id = ?",
        params![edge_id],
    )?;
    assert_eq!(
        GraphRows::insert_edge_values(
            &writer,
            &second,
            &ids.subjects,
            &ids.evidence,
            lineage,
            revision
        )?,
        ids.edges
    );
    Ok(())
}

#[test]
fn native_borrowed_columns() -> TestResult {
    let writer = Connection::open_in_memory()?;
    let kind = crate::GraphEdgeTypeV1::NativeEffect;
    let label = GraphRows::label(&kind)?;
    let roundtrip = writer.query_row("SELECT ?", params![label], |row| {
        Ok(GraphRows::label_column::<crate::GraphEdgeTypeV1>(row, 0))
    })??;
    assert_eq!(roundtrip, kind);
    let label = writer.query_row("SELECT 1 AS value", [], |row| {
        Ok(GraphRows::label_column::<crate::GraphEdgeTypeV1>(row, 0))
    })?;
    assert!(matches!(
        label,
        Err(crate::Error::AnalysisDatabase {
            source: duckdb::Error::InvalidColumnType(0, name, _),
            ..
        }) if name == "value"
    ));
    let label = writer.query_row("SELECT 'INVALID'", [], |row| {
        Ok(GraphRows::label_column::<crate::GraphEdgeTypeV1>(row, 0))
    })?;
    assert!(matches!(label, Err(crate::Error::GraphInvalid { .. })));
    let ordinal = writer.query_row("SELECT -1::BIGINT", [], |row| {
        Ok(GraphRows::column::<u32>(row, 0))
    })?;
    assert!(matches!(
        ordinal,
        Err(crate::Error::AnalysisDatabase {
            source: duckdb::Error::IntegralValueOutOfRange(0, -1),
            ..
        })
    ));
    Ok(())
}

#[test]
fn native_row_read_cancel() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let writer = fixture.store.writer_access()?;
    let writer = writer.get()?;
    let result = &fixture.request.result_id;
    let header = GraphRows::read_header(writer, fixture.snapshot.scope.identity.tenant_id, result)?
        .ok_or("missing header")?;
    let control = AnalysisReadControl::default();
    control.cancel()?;
    for read in [
        GraphRows::read_subjects(
            writer,
            result,
            fixture.snapshot.graph.subjects.len(),
            Some(&control),
        )
        .map(|_| ()),
        GraphRows::read_edges(
            writer,
            result,
            fixture.snapshot.graph.edges.len(),
            Some(&control),
        )
        .map(|_| ()),
        GraphRows::read_subjects(writer, result, usize::MAX, Some(&control)).map(|_| ()),
        GraphRows::read_edges(writer, result, usize::MAX, Some(&control)).map(|_| ()),
        GraphRows::read_findings(writer, result, &header, Some(&control)).map(|_| ()),
        GraphRows::read_finding(
            writer,
            result,
            &fixture.snapshot.findings[0].finding_id,
            &header,
            Some(&control),
        )
        .map(|_| ()),
        GraphRows::selected_subjects(
            writer,
            result,
            &fixture.snapshot.graph.subjects,
            &control,
            false,
        )
        .map(|_| ()),
        GraphRows::selected_edges(writer, result, &[0], &control).map(|_| ()),
    ] {
        assert!(matches!(
            read,
            Err(crate::Error::AnalysisReadCancelled { .. })
        ));
    }
    Ok(())
}

#[test]
fn native_finding_tenant() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let mut writer = fixture.store.writer_access()?;
    let transaction = writer.get_mut()?.transaction()?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let result = &fixture.request.result_id;
    let header = GraphRows::read_header(&transaction, tenant, result)?.ok_or("missing header")?;
    transaction.execute(
        "UPDATE graph_finding_values SET tenant_id = ?",
        params![[9_u8; 16].as_slice()],
    )?;
    assert!(matches!(
        GraphRows::read_finding(
            &transaction,
            result,
            &fixture.snapshot.findings[0].finding_id,
            &header,
            None
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph finding tenant",
            ..
        })
    ));
    assert!(GraphRows::read_findings(&transaction, result, &header, None).is_err());
    transaction.commit()?;
    drop(writer);
    assert!(matches!(
        fixture.store.graph_findings(tenant, None, None, usize::MAX),
        Err(crate::Error::GraphInvalid {
            field: "graph finding tenant",
            ..
        })
    ));
    Ok(())
}

#[test]
fn duplicate_finding_membership_rejected() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    let finding = &fixture.snapshot.findings[0].finding_id;
    let header = {
        let writer = fixture.store.writer_access()?;
        GraphRows::read_header(writer.get()?, tenant, &fixture.request.result_id)?
            .ok_or("missing finding header")?
    };
    fixture.store.fault_write(
        "INSERT INTO graph_finding_values
         SELECT value_id + 1000, * EXCLUDE (value_id) FROM graph_finding_values;
         INSERT INTO graph_finding_membership
         SELECT lineage_id, value_id + 1000, valid_from, valid_to
         FROM graph_finding_membership",
        &[],
    )?;
    let writer = fixture.store.writer_access()?;
    assert!(matches!(
        GraphRows::read_finding(
            writer.get()?,
            &fixture.request.result_id,
            finding,
            &header,
            None
        ),
        Err(crate::Error::GraphInvalid {
            field: "duplicate graph finding identity",
            ..
        })
    ));
    drop(writer);
    assert!(fixture
        .store
        .graph_finding(tenant, &fixture.request.result_id, finding)
        .is_err());
    assert!(fixture
        .store
        .graph_findings(tenant, None, Some(finding), usize::MAX)
        .is_err());
    let path = fixture.store.root.clone();
    drop(fixture._graph);
    drop(fixture.store);
    assert!(crate::AnalysisStore::open(path).is_err());
    Ok(())
}

#[test]
fn native_selected_corruption() -> TestResult {
    let fixture = CommitFixture::new()?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    assert_eq!(
        fixture
            .store
            .graph_findings(tenant, None, None, usize::MAX)?
            .len(),
        fixture.snapshot.findings.len()
    );
    let original: Vec<u8> = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT effects FROM graph_findings WHERE result_id = ? AND ordinal = 0",
            params![&fixture.request.result_id],
            |row| row.get(0),
        )?
    };
    fixture.store.fault_write(
        "UPDATE graph_finding_values SET effects = 'invalid'::BLOB WHERE finding_id = ?",
        params![&fixture.snapshot.findings[0].finding_id],
    )?;
    assert!(matches!(
        fixture.store.graph_findings(tenant, None, None, usize::MAX),
        Err(crate::Error::GraphNativeDecoding { .. })
    ));
    fixture.store.fault_write(
        "UPDATE graph_finding_values SET effects = ? WHERE finding_id = ?",
        params![original, &fixture.snapshot.findings[0].finding_id],
    )?;
    fixture.store.fault_write(
        "UPDATE analysis_results SET stream_key = repeat('x'::BLOB, ?) WHERE result_id = ?",
        params![
            (crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES + 1) as i64,
            &fixture.request.result_id
        ],
    )?;
    assert!(matches!(
        fixture
            .store
            .read_snapshot(|snapshot| GraphRows::read_header(
                snapshot,
                fixture.snapshot.scope.identity.tenant_id,
                &fixture.request.result_id
            )),
        Err(crate::Error::GraphInvalid {
            field: "graph header index",
            ..
        })
    ));
    assert!(matches!(
        fixture.store.graph_findings(
            fixture.snapshot.scope.identity.tenant_id,
            None,
            None,
            usize::MAX,
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph header index",
            ..
        })
    ));
    fixture.store.fault_write(
        "UPDATE analysis_results SET stream_key = ? WHERE result_id = ?",
        params![
            fixture.snapshot.scope.identity.key(),
            &fixture.request.result_id
        ],
    )?;
    assert_eq!(
        fixture
            .store
            .graph_findings(
                fixture.snapshot.scope.identity.tenant_id,
                None,
                None,
                usize::MAX
            )?
            .len(),
        1
    );
    Ok(())
}

#[test]
fn native_retry_rejects_corruption() -> TestResult {
    let fixture = CommitFixture::new()?;
    let receipt = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let result = &fixture.request.result_id;
    let original: (Vec<u8>, Vec<u8>, Vec<u8>) = {
        let mut writer = fixture.store.writer_access()?;
        writer.get_mut()?.query_row(
            "SELECT tenant_id, request_meta, body FROM analysis_results WHERE result_id = ?",
            params![result],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?
    };
    for (column, length, header) in [
        ("request_meta", 1024, false),
        ("body", 1024, true),
        ("tenant_id", 1024, false),
    ] {
        fixture.store.fault_write(
            &format!(
                "UPDATE analysis_results SET {column} = repeat('x'::BLOB, ?) WHERE result_id = ?"
            ),
            params![length as i64, result],
        )?;
        let error = fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))
            .err()
            .ok_or("the corrupted retry was accepted")?;
        if header {
            assert!(matches!(
                error,
                crate::Error::GraphInvalid {
                    field: "graph header format",
                    ..
                }
            ));
        } else if column == "request_meta" {
            assert!(matches!(error, crate::Error::AnalysisConflict { .. }));
        } else {
            assert!(matches!(error, crate::Error::AnalysisState { .. }));
        }
        fixture.store.fault_write(
            "UPDATE analysis_results SET tenant_id = ?, request_meta = ?, body = ? WHERE result_id = ?",
            params![original.0, original.1, original.2, result],
        )?;
        assert_eq!(
            fixture
                .store
                .commit_graph(&fixture.request, true, || Ok(()))?,
            receipt
        );
        assert_eq!(
            fixture.store.meta()?.commit_revision,
            receipt.commit_revision
        );
    }
    Ok(())
}

#[test]
fn native_membership_validation() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut sorted = fixture.snapshot.clone();
    let record = sorted.input_manifest.evidence[0].clone();
    let mut records = [0, 1, 2]
        .map(|cpu_id| {
            let mut record = record.clone();
            record.cpu_id = cpu_id;
            record
        })
        .to_vec();
    records.sort();
    sorted.input_manifest.evidence = records.clone();

    sorted.input_positions = vec![(
        records[1].clone(),
        crate::StorePositionV1 {
            commit_revision: 1,
            ordinal: 0,
        },
    )];
    for finding in &mut sorted.findings {
        finding.evidence = records.clone();
        let effect = finding.effects.first().ok_or("fixture effect")?.clone();
        finding.effects = records
            .iter()
            .map(|record| {
                let mut effect = effect.clone();
                effect.evidence = record.clone();
                effect
            })
            .collect();
    }
    for edge in &mut sorted.graph.edges {
        edge.key.evidence = vec![0, 1, 2];
    }
    sorted.validate()?;

    let rejected = |result: crate::Result<()>, expected: &'static str| {
        assert!(
            matches!(&result, Err(crate::Error::GraphInvalid { field, .. }) if *field == expected),
            "expected GraphInvalid/{expected}, got {result:?}"
        );
    };
    let mut absent = records[0].clone();
    absent.cpu_id = 3;

    let mut missing_position = sorted.clone();
    missing_position.input_positions[0].0 = absent.clone();
    rejected(missing_position.validate(), "graph snapshot");

    let mut missing_finding = sorted.findings[0].clone();
    missing_finding.evidence = vec![absent.clone()];
    for effect in &mut missing_finding.effects {
        effect.evidence = absent.clone();
    }
    rejected(
        sorted.input_manifest.validate_finding(&missing_finding),
        "finding revision",
    );

    let mut missing_effect = sorted.findings[0].clone();
    missing_effect.effects[0].evidence = absent.clone();
    rejected(
        sorted.input_manifest.validate_finding(&missing_effect),
        "finding revision",
    );

    for from in [true, false] {
        let mut missing_endpoint = sorted.clone();
        let mut edge = missing_endpoint.graph.edges[0].clone();
        let endpoint = if from {
            &mut edge.key.from
        } else {
            &mut edge.key.to
        };
        *endpoint = u32::try_from(missing_endpoint.graph.subjects.len())?;
        missing_endpoint.graph.edges = vec![edge];
        rejected(missing_endpoint.validate(), "graph edge proof");
    }

    let mut missing_edge_evidence = sorted.clone();
    let mut edge = missing_edge_evidence.graph.edges[0].clone();
    edge.key.evidence = vec![u32::try_from(records.len())?];
    missing_edge_evidence.graph.edges = vec![edge];
    rejected(missing_edge_evidence.validate(), "graph edge proof");

    let mut unsorted_manifest = sorted.clone();
    unsorted_manifest.input_manifest.evidence.reverse();

    unsorted_manifest.input_positions[0].1.commit_revision = 0;
    rejected(unsorted_manifest.validate(), "revision manifest");

    let mut unsorted_finding = sorted.findings[0].clone();
    unsorted_finding.evidence.reverse();
    unsorted_finding.effects.clear();
    rejected(
        sorted.input_manifest.validate_finding(&unsorted_finding),
        "finding revision",
    );

    let mut invalid_revision = sorted.input_manifest.clone();
    invalid_revision.evidence.reverse();
    rejected(
        invalid_revision.validate(sorted.scope.identity.tenant_id),
        "revision manifest",
    );

    let mut unsorted_subjects = sorted;
    unsorted_subjects.graph.subjects.reverse();
    unsorted_subjects.graph.edges.truncate(1);
    unsorted_subjects.graph.edges[0].key.from =
        u32::try_from(unsorted_subjects.graph.subjects.len())?;
    rejected(unsorted_subjects.validate(), "graph snapshot");
    Ok(())
}
