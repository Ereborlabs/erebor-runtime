use super::*;

#[test]
fn context_changes_use_index() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let context = |revision| crate::AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "indexed-context".into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: vec![42],
    };
    store.commit_contexts(&(1..=16).map(context).collect::<Vec<_>>())?;
    let after = store.meta()?.commit_revision;
    let changes = (17..=22).map(context).collect::<Vec<_>>();
    store.commit_contexts(&changes)?;
    store.read_snapshot(|reader| {
        assert_index(reader, AnalysisStore::CONTEXT_CHANGES_SQL, params![after])?;
        for context in &changes {
            assert_index(
                reader,
                AnalysisStore::CONTEXT_VERSION_SQL,
                params![version_key(&context.key)?],
            )?;
        }
        Ok(())
    })?;
    Ok(())
}

fn assert_index(reader: &Connection, sql: &str, parameters: &[&dyn duckdb::ToSql]) -> Result<()> {
    let plan = reader
        .prepare(&format!("EXPLAIN ANALYZE {sql}"))
        .and_then(|mut statement| statement.query_row(parameters, |row| row.get::<_, String>(1)))
        .context(AnalysisDatabaseSnafu {
            operation: "inspect context change access path",
        })?;
    assert!(plan.contains("Index Scan"), "{plan}");
    Ok(())
}
