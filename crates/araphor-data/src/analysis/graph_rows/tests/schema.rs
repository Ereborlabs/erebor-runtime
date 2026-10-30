use super::*;

#[test]
fn standalone_graph_rejects_managed_producer_binding() -> TestResult {
    let fixture = CommitFixture::new()?;
    let source = &fixture.snapshot.scope.identity;
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute_batch("CREATE TABLE analysis_results(result_id VARCHAR PRIMARY KEY,tenant_id BLOB,processor_id VARCHAR,stream_key BLOB,commit_revision UBIGINT); CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER); CREATE TABLE managed_edges(tenant_id BLOB,result_id VARCHAR,dependency_id VARCHAR,commit_revision UBIGINT)")?;
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![
            source.key(),
            source.tenant_id.as_slice(),
            fixture.snapshot.input_manifest.evidence[0].cpu_id
        ],
    )?;
    writer.execute(
        "INSERT INTO graph_sources VALUES(1,?,?,?)",
        params![
            source.key(),
            source.tenant_id.as_slice(),
            GraphRows::encode_value(source)?
        ],
    )?;
    writer.execute("INSERT INTO analysis_results VALUES('call',?,'managed-package-v1',?,1),('standalone',?,'graph-findings',?,2)",params![source.tenant_id.as_slice(),source.key(),source.tenant_id.as_slice(),source.key()])?;
    writer.execute("INSERT INTO graph_producer_scopes VALUES(1,?,1,0,'instance',1,'package','revision','image',1,1),(2,?,1,2,NULL,NULL,NULL,NULL,NULL,1,2),(3,?,1,1,NULL,NULL,NULL,NULL,NULL,1,2)",params![source.tenant_id.as_slice(),source.tenant_id.as_slice(),source.tenant_id.as_slice()])?;
    writer.execute("INSERT INTO graph_producer_versions VALUES('call',1,1,NULL,0,0,0,0,NULL),('standalone:metadata',2,2,NULL,0,0,0,0,NULL),('standalone:publication',3,2,NULL,0,0,0,0,NULL)",[])?;
    writer.execute(
        "INSERT INTO graph_versions VALUES('standalone',2,'standalone:metadata',false,false)",
        [],
    )?;
    writer.execute("INSERT INTO graph_result_producers VALUES('standalone','standalone:metadata'),('standalone','standalone:publication')",[])?;
    let directory = tempfile::tempdir()?;
    GraphCallRows::validate(&writer, directory.path())?;
    writer.execute(
        "INSERT INTO graph_result_producers VALUES('standalone','call')",
        [],
    )?;
    assert!(GraphCallRows::validate(&writer, directory.path()).is_err());
    Ok(())
}

#[test]
fn native_schema_integrity() -> TestResult {
    let faults = [
        GraphRows::schema().replace("ordinal UINTEGER", "ordinal INTEGER"),
        GraphRows::schema().replace(
            "required_action VARCHAR",
            "required_action VARCHAR NOT NULL",
        ),
        GraphRows::schema().replace("tenant_id BLOB NOT NULL", "tenant_id BLOB"),
        GraphRows::schema().replace(
            "PRIMARY KEY (scope_id, member_kind, member_key, valid_from)",
            "UNIQUE (scope_id, member_kind, member_key, valid_from)",
        ),
        GraphRows::schema().replace(
            "PRIMARY KEY (result_id, producer_result_id)",
            "UNIQUE (result_id, producer_result_id)",
        ),
        GraphRows::schema().replace("subject_kind UTINYINT NOT NULL,", "subject_kind UTINYINT,"),
        GraphRows::schema().replace(
            "tenant_id BLOB NOT NULL,\n    authority_rank UTINYINT NOT NULL",
            "authority_rank UTINYINT NOT NULL,\n    tenant_id BLOB NOT NULL",
        ),
    ];
    for (index, schema) in faults.into_iter().enumerate() {
        assert_ne!(
            schema,
            GraphRows::schema(),
            "unchanged schema fault {index}"
        );
        let writer = Connection::open_in_memory()?;
        writer.execute_batch(&schema)?;
        assert!(
            matches!(
                GraphRows::validate_tables(&writer),
                Err(crate::Error::GraphInvalid {
                    field: "native graph schema",
                    ..
                })
            ),
            "accepted schema fault {index}"
        );
    }
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    GraphRows::validate_tables(&writer)?;
    writer.execute_batch("ALTER TABLE graph_producer_members ADD COLUMN extra INTEGER")?;
    assert!(GraphRows::validate_tables(&writer).is_err());
    let other = Connection::open_in_memory()?;
    other.execute_batch(&GraphRows::schema())?;
    GraphRows::validate_tables(&other)?;
    Ok(())
}

#[test]
fn native_schema_reopen() -> TestResult {
    for fault in [
        "ALTER TABLE graph_producer_members ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_subject_values ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_progress_values ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_edge_values ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_edge_properties ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_branch_values ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_producer_versions ADD COLUMN extra INTEGER",
        "DROP VIEW graph_selected_members",
        "DROP VIEW graph_relationships",
        "DROP VIEW graph_findings",
        "DROP VIEW graph_subjects; CREATE VIEW graph_subjects AS
            SELECT v.result_id, 0::UINTEGER AS ordinal, s.tenant_id,
                s.authority_rank, s.authority_text, s.authority_boot,
                s.authority_epoch, s.subject_kind, s.identity
            FROM graph_versions v CROSS JOIN graph_subject_values s WHERE FALSE",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        drop(crate::AnalysisStore::open(&root)?);
        let database = root.join("analysis.duckdb");
        {
            let writer = Connection::open(&database)?;
            writer.execute_batch(fault)?;
        }
        let before = std::fs::read(&database)?;
        assert!(
            crate::AnalysisStore::open(&root).is_err(),
            "accepted {fault}"
        );
        assert_eq!(std::fs::read(&database)?, before, "changed {fault}");
    }
    Ok(())
}

#[test]
fn shared_corruption_rejects_reopen() -> TestResult {
    for fault in [
        "UPDATE graph_subject_values SET authority_rank=3 WHERE authority_rank=0",
        "UPDATE graph_edge_values SET from_ref=from_ref+999999",
        "UPDATE graph_edge_values SET property_ref=property_ref+999999",
        "UPDATE graph_edge_properties SET property_hash=from_hex(repeat('00',32))",
        "UPDATE graph_edge_properties SET edge_rank=255",
        "UPDATE graph_edge_values SET value_hash=from_hex(repeat('00',32))",
        "UPDATE graph_evidence SET source_ref=source_ref+1",
        "UPDATE graph_sources SET tenant_id='wrong'::BLOB",
        "UPDATE graph_branch_values SET tenant_id='wrong'::BLOB",
        "UPDATE graph_branch_values SET body=body || from_hex('00')",
        "INSERT INTO graph_branch_values SELECT branch_id+999999,tenant_id,value_hash,from_hex('c1') FROM graph_branch_values LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,1,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,2,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,3,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,4,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,6,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
    ] {
        let fixture = CommitFixture::new()?;
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?;
        fixture.store.fault_write(fault, &[])?;
        let root = fixture._directory.path().join("analysis");
        let CommitFixture {
            store,
            _graph,
            _directory,
            ..
        } = fixture;
        drop(_graph);
        drop(store);
        let database = root.join("analysis.duckdb");
        let before = std::fs::read(&database)?;
        assert!(
            crate::AnalysisStore::open(&root).is_err(),
            "accepted {fault}"
        );
        assert_eq!(std::fs::read(&database)?, before, "changed {fault}");
    }
    Ok(())
}

#[test]
fn graph_result_rejects_live_evidence_cpu_change() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.graph.subjects.clear();
    fixture.snapshot.graph.edges.clear();
    fixture.snapshot.graph.branches.clear();
    fixture.snapshot.graph.facts.clear();
    fixture.snapshot.findings.clear();
    fixture.snapshot.validate()?;
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let tenant = fixture.snapshot.scope.identity.tenant_id;
    assert_eq!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    fixture
        .store
        .fault_write("UPDATE graph_evidence SET cpu_id=cpu_id+1", &[])?;
    assert!(matches!(
        fixture
            .store
            .graph_result(tenant, &fixture.request.result_id),
        Err(crate::Error::GraphInvalid {
            field: "graph evidence source",
            ..
        })
    ));
    Ok(())
}

#[test]
fn graph_commit_rejects_other_source_cpu() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    fixture.snapshot.graph.subjects.clear();
    fixture.snapshot.graph.edges.clear();
    fixture.snapshot.graph.branches.clear();
    fixture.snapshot.graph.facts.clear();
    fixture.snapshot.findings.clear();
    for record in &mut fixture.snapshot.input_manifest.evidence {
        record.cpu_id += 1;
    }
    for (record, _) in &mut fixture.snapshot.input_positions {
        record.cpu_id += 1;
    }
    fixture.snapshot.validate()?;
    fixture.request.body = serde_json::to_vec(&fixture.snapshot)?;
    assert!(matches!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(())),
        Err(crate::Error::GraphInvalid {
            field: "graph evidence source",
            ..
        })
    ));
    Ok(())
}
