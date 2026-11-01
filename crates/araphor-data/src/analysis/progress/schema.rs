use std::{path::Path, sync::OnceLock};

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub(in crate::analysis) const PROCESSOR_SCHEMA: &str = include_str!("schema.sql");

    pub(in crate::analysis) fn validate_processors(reader: &Connection, root: &Path) -> Result<()> {
        static EXPECTED: OnceLock<Vec<Vec<(String, String)>>> = OnceLock::new();
        if !Self::schema_matches(
            reader,
            &EXPECTED,
            Self::PROCESSOR_SCHEMA,
            &[("processor_versions", "processor_progress")],
            [
                "open processor schema check",
                "create processor schema check",
            ],
        )? {
            return Self::reject_path(root, "the processor schema is invalid");
        }
        Ok(())
    }

    pub(in crate::analysis) fn schema_matches(
        reader: &Connection,
        expected: &OnceLock<Vec<Vec<(String, String)>>>,
        schema: &str,
        relations: &[(&str, &str)],
        operations: [&'static str; 2],
    ) -> Result<bool> {
        let shapes = |reader: &Connection| {
            relations
                .iter()
                .map(|(table, view)| Self::relation_shape(reader, table, view))
                .collect::<Result<Vec<_>>>()
        };
        if expected.get().is_none() {
            let connection = Connection::open_in_memory().context(AnalysisDatabaseSnafu {
                operation: operations[0],
            })?;
            connection
                .execute_batch(schema)
                .context(AnalysisDatabaseSnafu {
                    operation: operations[1],
                })?;
            let _ = expected.set(shapes(&connection)?);
        }
        Ok(expected.get() == Some(&shapes(reader)?))
    }

    pub(in crate::analysis) fn relation_shape(
        reader: &Connection,
        table: &str,
        view: &str,
    ) -> Result<Vec<(String, String)>> {
        let mut statement = reader
            .prepare(
                "SELECT table_name, column_name || ':' || data_type || ':' || is_nullable
                    || ':' || ordinal_position || ':' || coalesce(column_default, '')
                 FROM information_schema.columns WHERE table_schema = 'main'
                    AND table_name IN (?, ?)
                 UNION ALL SELECT table_name, constraint_type || ':' || constraint_text
                 FROM duckdb_constraints() WHERE schema_name = 'main'
                    AND table_name IN (?, ?)
                 UNION ALL SELECT table_name, 'table' FROM duckdb_tables()
                 WHERE schema_name = 'main' AND table_name IN (?, ?)
                 UNION ALL SELECT view_name, replace(sql, chr(34), '') FROM duckdb_views()
                 WHERE schema_name = 'main' AND view_name IN (?, ?)
                 ORDER BY 1, 2",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native relation shape",
            })?;
        statement
            .query_map(
                params![table, view, table, view, table, view, table, view],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read native relation shape",
            })?
            .collect::<duckdb::Result<_>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode native relation shape",
            })
    }
}
