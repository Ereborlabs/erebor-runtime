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
        GraphRows::schema().replace("unit_ref UBIGINT", "unit_ref UINTEGER"),
        GraphRows::schema().replace(
            "unit_ref UBIGINT NOT NULL DEFAULT 0",
            "unit_ref UBIGINT NOT NULL",
        ),
        GraphRows::schema().replace(
            "required_action VARCHAR",
            "required_action VARCHAR NOT NULL",
        ),
        GraphRows::schema().replace("tenant_id BLOB NOT NULL", "tenant_id BLOB"),
        GraphRows::schema().replace(
            "PRIMARY KEY (scope_id, unit_ref, member_kind, member_key, valid_from)",
            "UNIQUE (scope_id, unit_ref, member_kind, member_key, valid_from)",
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
        "INSERT INTO graph_producer_members SELECT 999999,0,0,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,1,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,2,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,3,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,4,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
        "INSERT INTO graph_producer_members SELECT 999999,0,6,member_key,value_ref,anchor_record_id,anchor_fact,reason_code,ordinal,valid_from,valid_to FROM graph_producer_members LIMIT 1",
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

#[test]
fn unit_history_keeps_shared_values_and_rejects_conflicts() -> TestResult {
    let fixture = CommitFixture::new()?;
    let source = &fixture.snapshot.scope.identity;
    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch(&GraphRows::schema())?;
    writer.execute_batch("CREATE TABLE analysis_results(result_id VARCHAR PRIMARY KEY,tenant_id BLOB,processor_id VARCHAR,stream_key BLOB,commit_revision UBIGINT); CREATE TABLE source_receipts(stream_key BLOB,tenant_id BLOB,cpu_id UINTEGER); CREATE TABLE managed_edges(tenant_id BLOB,result_id VARCHAR,dependency_id VARCHAR,commit_revision UBIGINT)")?;
    let record = fixture.snapshot.input_manifest.evidence[0].clone();
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![source.key(), source.tenant_id.as_slice(), record.cpu_id],
    )?;
    let source_ref = GraphRows::source_id(&writer, source)?;
    writer.execute(
        "INSERT INTO graph_producer_scopes VALUES(1,?,?,0,'instance',1,'package','revision','image',1,1)",
        params![source.tenant_id.as_slice(), source_ref],
    )?;
    let mut other = record.clone();
    other.durable_cursor += 1;
    let records = GraphRows::intern_records(&writer, source, &[record.clone(), other.clone()])?;
    let first = records[&record];
    let second = records[&other];
    let keys = &fixture.snapshot.graph.subjects[..2];
    let subjects = GraphRows::intern_subjects(&writer, keys)?;
    let member = |unit| -> Result<araphor_graph::Replacement> {
        Ok(araphor_graph::Replacement {
            unit: Some(unit),
            members: vec![araphor_graph::Member {
                kind: MemberKind::Subject as u8,
                key: GraphRows::member_key(&keys[0])?,
                value: subjects[&keys[0]],
                record: Some(unit),
                fact: None,
                reason: None,
                ordinal: 0,
            }],
        })
    };
    let empty = |unit| araphor_graph::Replacement {
        unit: Some(unit),
        members: Vec::new(),
    };
    for (revision, result, base, replacements, count) in [
        (1, "shared", None, vec![member(first)?, member(second)?], 1),
        (2, "survivor", Some("shared"), vec![empty(first)], 1),
        (3, "restored", Some("survivor"), vec![member(first)?], 1),
        (
            4,
            "cleared",
            Some("restored"),
            vec![empty(first), empty(second)],
            0,
        ),
    ] {
        GraphRows::version(&writer, result, 1, revision, base)?;
        writer.execute(
            "INSERT INTO analysis_results VALUES(?,?,'managed-package-v1',?,?)",
            params![result, source.tenant_id.as_slice(), source.key(), revision],
        )?;
        araphor_graph::Contributions::apply(&writer, 1, revision, &replacements, false)?;
        assert_eq!(
            writer.query_row(
                "SELECT subject_count FROM graph_producer_versions WHERE result_id=?",
                params![result],
                |row| row.get::<_, u64>(0),
            )?,
            count,
        );
    }
    assert_eq!(writer.query_row(
        "SELECT count(*) FROM graph_producer_members WHERE unit_ref=? AND valid_from=1 AND valid_to=4",
        params![second],
        |row| row.get::<_, u64>(0),
    )?, 1);
    let mut foreign = source.clone();
    foreign.source_epoch += 1;
    writer.execute(
        "INSERT INTO source_receipts VALUES(?,?,?)",
        params![foreign.key(), foreign.tenant_id.as_slice(), record.cpu_id],
    )?;
    let mut foreign_record = record;
    foreign_record.stream = foreign.clone();
    let foreign_ref =
        GraphRows::intern_records(&writer, &foreign, std::slice::from_ref(&foreign_record))?
            [&foreign_record];
    GraphRows::validate_history(&writer, fixture._directory.path())?;
    for fault in [
        format!("UPDATE graph_producer_members SET value_ref={} WHERE unit_ref={second}", subjects[&keys[1]]),
        format!("UPDATE graph_producer_members SET unit_ref=999999 WHERE unit_ref={first} AND valid_from=1"),
        format!("UPDATE graph_producer_members SET unit_ref={foreign_ref} WHERE unit_ref={first} AND valid_from=1"),
        "UPDATE graph_producer_scopes SET producer_kind=1,instance_id=NULL,call_id=NULL,package_id=NULL,package_revision=NULL,image_digest=NULL".into(),
        format!("INSERT INTO graph_producer_members SELECT * REPLACE(2::UBIGINT AS valid_from,4::UBIGINT AS valid_to) FROM graph_producer_members WHERE unit_ref={first} AND valid_from=1"),
        "UPDATE graph_producer_versions SET subject_count=2 WHERE commit_revision=1".into(),
    ] {
        let transaction = writer.transaction()?;
        transaction.execute_batch(&fault)?;
        assert!(
            matches!(
                GraphRows::validate_history(&transaction, fixture._directory.path()),
                Err(crate::Error::AnalysisState { .. })
            ),
            "accepted history fault: {fault}",
        );
    }
    GraphRows::validate_history(&writer, fixture._directory.path())?;
    Ok(())
}
