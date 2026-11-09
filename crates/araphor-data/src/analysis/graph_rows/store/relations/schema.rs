use std::sync::OnceLock;

use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, Relations, Result,
};
use duckdb::Connection;
use snafu::ResultExt as _;

impl Relations<'_> {
    pub const SCHEMA: &'static str = include_str!("schema.sql");

    pub fn schema() -> String {
        format!(
            "{}{}{}{}{}{}",
            Self::SCHEMA,
            crate::analysis::graph_rows::store::SubjectRows::SCHEMA,
            crate::analysis::graph_rows::store::RelationshipRows::SCHEMA,
            crate::analysis::graph_rows::store::FindingRows::SCHEMA,
            crate::analysis::graph_rows::store::StateRows::SCHEMA,
            araphor_graph::GraphStore::SCHEMA
        )
    }

    pub fn validate_tables(writer: &Connection) -> Result<()> {
        static EXPECTED: OnceLock<Vec<(String, String)>> = OnceLock::new();
        if EXPECTED.get().is_none() {
            let expected = Connection::open_in_memory().context(DatabaseSnafu {
                operation: "open Graph schema check",
            })?;
            expected
                .execute_batch(&Self::schema())
                .context(DatabaseSnafu {
                    operation: "create Graph schema check",
                })?;
            let _ = EXPECTED.set(Self::schema_shape(&expected)?);
        }
        if EXPECTED.get() != Some(&Self::schema_shape(writer)?) {
            return Err(NativeRows::invalid("native graph schema"));
        }
        Ok(())
    }

    fn schema_shape(writer: &Connection) -> Result<Vec<(String, String)>> {
        let mut statement = writer.prepare(
            "SELECT table_name, column_name || ':' || data_type || ':' || is_nullable || ':' || ordinal_position || ':' || coalesce(column_default, '')
             FROM information_schema.columns WHERE table_schema = 'main' AND starts_with(table_name, 'graph_')
             UNION ALL SELECT table_name, constraint_type || ':' || constraint_text
             FROM duckdb_constraints() WHERE schema_name = 'main' AND starts_with(table_name, 'graph_')
             UNION ALL SELECT view_name, replace(replace(sql, chr(34), ''), 'CROSS JOIN unnest(', ', unnest(') FROM duckdb_views()
             WHERE schema_name = 'main' AND starts_with(view_name, 'graph_') ORDER BY 1, 2"
        ).context(DatabaseSnafu { operation: "prepare Graph schema shape" })?;
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .context(DatabaseSnafu {
                operation: "read Graph schema shape",
            })?
            .collect::<duckdb::Result<_>>()
            .context(DatabaseSnafu {
                operation: "decode Graph schema shape",
            })
    }
}
