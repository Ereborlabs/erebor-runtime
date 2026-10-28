use super::*;

#[test]
fn native_schema_integrity() -> TestResult {
    let faults = [
        GraphRows::SCHEMA.replace("ordinal UINTEGER", "ordinal INTEGER"),
        GraphRows::SCHEMA.replace(
            "required_action VARCHAR",
            "required_action VARCHAR NOT NULL",
        ),
        GraphRows::SCHEMA.replace("tenant_id BLOB NOT NULL", "tenant_id BLOB"),
        GraphRows::SCHEMA.replace(
            "PRIMARY KEY (result_id, ordinal)",
            "UNIQUE (result_id, ordinal)",
        ),
        GraphRows::SCHEMA.replace(", UNIQUE (result_id, finding_id)", ""),
        GraphRows::SCHEMA.replace("subject_kind UTINYINT NOT NULL,", "subject_kind UTINYINT,"),
        GraphRows::SCHEMA.replace(
            "tenant_id BLOB NOT NULL, authority_rank UTINYINT NOT NULL",
            "authority_rank UTINYINT NOT NULL, tenant_id BLOB NOT NULL",
        ),
    ];
    for schema in faults {
        let writer = Connection::open_in_memory()?;
        writer.execute_batch(&schema)?;
        assert!(matches!(
            GraphRows::validate_tables(&writer),
            Err(crate::Error::GraphInvalid {
                field: "native graph schema",
                ..
            })
        ));
    }
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(GraphRows::SCHEMA)?;
    GraphRows::validate_tables(&writer)?;
    writer.execute_batch("ALTER TABLE graph_subject_membership ADD COLUMN extra INTEGER")?;
    assert!(GraphRows::validate_tables(&writer).is_err());
    let other = Connection::open_in_memory()?;
    other.execute_batch(GraphRows::SCHEMA)?;
    GraphRows::validate_tables(&other)?;
    Ok(())
}

#[test]
fn native_schema_reopen() -> TestResult {
    for fault in [
        "ALTER TABLE graph_subject_membership ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_subject_values ADD COLUMN extra INTEGER",
        "ALTER TABLE graph_relationships ALTER COLUMN first_boottime_ns TYPE BIGINT",
        "ALTER TABLE graph_findings ALTER COLUMN required_action SET NOT NULL",
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
        "UPDATE graph_subject_values SET authority_rank = 3 WHERE authority_rank = 0",
        "INSERT INTO graph_evidence_membership
         SELECT 999999, evidence_id, valid_from, valid_to
         FROM graph_evidence_membership LIMIT 1",
        "INSERT INTO graph_input_positions VALUES
         (999999, (SELECT evidence_id FROM graph_evidence LIMIT 1), 0, 1, 0, 1, NULL)",
        "INSERT INTO graph_subject_membership
         SELECT 999999, subject_id, valid_from, valid_to
         FROM graph_subject_membership LIMIT 1",
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
