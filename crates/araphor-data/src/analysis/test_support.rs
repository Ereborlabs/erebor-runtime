use duckdb::params;
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{AnalysisDatabaseSnafu, Result};

impl AnalysisStore {
    pub fn fault_write(&self, query: &str, values: &[&dyn duckdb::ToSql]) -> Result<()> {
        let mut writer = self.writer_access()?;
        let writer = writer.get_mut()?;
        writer
            .execute_batch("SET memory_limit = '-1'")
            .context(AnalysisDatabaseSnafu {
                operation: "set fixture memory limit",
            })?;
        let mutation = writer
            .execute(query, values)
            .and_then(|_| writer.execute_batch("FORCE CHECKPOINT"));
        let restored = writer.execute_batch(&format!(
            "SET memory_limit='{}'",
            self.storage
                .native_memory_bytes
                .map_or_else(|| "-1".to_owned(), |bytes| format!("{bytes}B"))
        ));
        mutation.context(AnalysisDatabaseSnafu {
            operation: "inject fixture mutation",
        })?;
        restored.context(AnalysisDatabaseSnafu {
            operation: "restore fixture memory limit",
        })?;
        Ok(())
    }
}

impl AnalysisStore {
    pub fn verify_state(&self) -> Result<()> {
        Self::validate_state(self.writer()?.get()?, &self.root)
    }

    pub fn frozen_result(&self, result_id: &str) -> Result<(Vec<u8>, Vec<u8>, u64)> {
        self.read_snapshot(|reader| {
            reader.query_row(
                "SELECT body, request_meta, commit_revision FROM analysis_results WHERE result_id = ?",
                params![result_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).context(AnalysisDatabaseSnafu { operation: "read frozen result fixture" })
        })
    }

    pub fn retained_usage(&self, tenant: [u8; 16]) -> Result<(u64, u64, u64, u64)> {
        self.read_snapshot(|reader| {
            reader.query_row(
                &format!("SELECT logical_bytes, coverage_count, context_count, result_count FROM ({}) WHERE tenant_id = ?", AnalysisStore::usage_projection()),
                params![tenant.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            ).context(AnalysisDatabaseSnafu { operation: "read tenant usage fixture" })
        })
    }
}
