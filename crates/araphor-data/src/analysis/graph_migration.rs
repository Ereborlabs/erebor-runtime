use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::graph_rows::{GraphHeader, GraphRows};
use super::quota::UsageChange;
use super::{AnalysisStore, StorageLimitsV1, ANALYSIS_SCHEMA_VERSION};
use crate::{AnalysisDatabaseSnafu, GraphSnapshotV1, IoSnafu, JsonSnafu, Result};

const STAGED_LIMIT: usize =
    4 * (GraphHeader::MAX_BYTES + GraphRows::MAX_ENCODING + GraphRows::MAX_CANONICAL_BYTES) + 4096;
const SPILL_RESERVE: u64 = 128 * 1024 * 1024;

mod staging;

type LegacyGraph = (String, Vec<u8>, Vec<u8>);

#[derive(Deserialize, Serialize)]
struct StagedGraph {
    result_id: String,
    tenant: [u8; 16],
    rows: GraphRows,
}

struct GraphMigration<'a> {
    root: &'a Path,
    file: File,
    count: u64,
    bytes: u64,
    rows: u64,
    tenants: BTreeSet<[u8; 16]>,
}

impl<'a> GraphMigration<'a> {
    fn convert(&mut self, transaction: &duckdb::Transaction<'_>) -> Result<()> {
        let mut length = [0_u8; 4];
        self.file
            .read_exact(&mut length)
            .context(IoSnafu { path: self.root })?;
        let length = u32::from_le_bytes(length) as u64;
        if length > STAGED_LIMIT as u64 {
            return AnalysisStore::reject_path(self.root, "the staged graph size is invalid");
        }
        let staged: StagedGraph = serde_json::from_reader((&mut self.file).take(length))
            .context(JsonSnafu { path: self.root })?;
        let original: Vec<u8> = transaction
            .query_row(
                "SELECT body FROM analysis_results WHERE result_id = ? AND tenant_id = ?",
                params![staged.result_id, staged.tenant.as_slice()],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read migrating graph body",
            })?;
        staged.rows.insert(transaction, &staged.result_id)?;
        let header = GraphHeader::decode(staged.rows.header())?;
        let rebuilt = GraphRows::read(transaction, &staged.result_id, &header)?;
        if header.body(&rebuilt, staged.rows.encoding())? != original {
            return AnalysisStore::reject_path(
                self.root,
                "the migrated graph reconstruction differs",
            );
        }
        transaction
            .execute(
                "UPDATE analysis_results SET body = ?, graph_encoding = ? WHERE result_id = ?",
                params![
                    staged.rows.header(),
                    staged.rows.encoding(),
                    staged.result_id
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "retire migrated graph body",
            })?;
        UsageChange::from(
            staged.rows.bytes(&staged.result_id)?
                + staged.rows.header().len() as i64
                + staged.rows.encoding().len() as i64
                - original.len() as i64,
        )
        .apply(transaction, &staged.tenant)?;
        Ok(())
    }
    fn install(&mut self, writer: &mut Connection, storage: StorageLimitsV1) -> Result<()> {
        let mut usage = AnalysisStore::storage_at(self.root, 0, 0)?;
        usage.file_bytes = usage.file_bytes.checked_add(self.bytes).ok_or_else(|| {
            crate::StorageCapacitySnafu {
                resource: "graph migration bytes",
            }
            .build()
        })?;
        let reserve = self
            .rows
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(SPILL_RESERVE))
            .ok_or_else(|| {
                crate::StorageCapacitySnafu {
                    resource: "graph migration bytes",
                }
                .build()
            })?;
        storage.check_terminal(usage, reserve)?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin native graph migration",
        })?;
        transaction
            .execute_batch(GraphRows::SCHEMA)
            .context(AnalysisDatabaseSnafu {
                operation: "create migrated graph rows",
            })?;
        transaction
            .execute_batch("ALTER TABLE analysis_results ADD COLUMN graph_encoding BLOB")
            .context(AnalysisDatabaseSnafu {
                operation: "add migrated graph encoding",
            })?;
        for _ in 0..self.count {
            self.convert(&transaction)?;
        }
        transaction
            .execute(
                "UPDATE store_meta SET schema_version = ?",
                params![ANALYSIS_SCHEMA_VERSION],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "set native graph schema version",
            })?;
        if self.count != 0 {
            for relation in ["graph_subjects", "graph_relationships", "graph_findings"] {
                transaction
                    .execute(
                        "INSERT INTO relation_revisions
                    SELECT ?, MAX(commit_revision) FROM analysis_results
                    WHERE processor_id = 'graph-findings' AND stream_key IS NOT NULL",
                        params![relation],
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "record migrated graph revisions",
                    })?;
            }
        }
        AnalysisStore::validate_tables(&transaction)?;
        AnalysisStore::validate_state(&transaction, self.root)?;
        for tenant in &self.tenants {
            AnalysisStore::check_logical_limits(&transaction, storage, *tenant, true)?;
        }
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit native graph migration",
        })
    }
}

impl AnalysisStore {
    pub(super) fn migrate_graphs(
        writer: &mut Connection,
        root: &Path,
        storage: StorageLimitsV1,
    ) -> Result<()> {
        Self::validate_legacy_graphs(writer, root)?;
        Self::validate_tables(writer)?;
        Self::validate_state(writer, root)?;
        let mut staged = GraphMigration::new(root)?;
        staged.stage(writer, storage)?;
        staged.install(writer, storage)
    }

    pub(super) fn validate_legacy_graphs(writer: &Connection, root: &Path) -> Result<()> {
        let native: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables
            WHERE table_name IN ('graph_subjects', 'graph_relationships', 'graph_findings'))",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate legacy graph schema",
            })?;
        if native {
            return Self::reject_path(root, "the legacy schema contains native graph tables");
        }
        let encoding: bool = writer
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'main' AND table_name = 'analysis_results'
                AND column_name = 'graph_encoding')",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate legacy graph encoding schema",
            })?;
        if encoding {
            return Self::reject_path(root, "the legacy schema contains native graph encoding");
        }
        Ok(())
    }

    fn next_graph(
        writer: &Connection,
        after: &str,
        include_body: bool,
    ) -> Result<Option<LegacyGraph>> {
        writer
            .query_row(
                "SELECT result_id, tenant_id, CASE WHEN ? THEN body ELSE ''::BLOB END FROM analysis_results
            WHERE processor_id = 'graph-findings' AND stream_key IS NOT NULL AND result_id > ?
            ORDER BY result_id LIMIT 1",
                params![include_body, after],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read graph validation result",
            })
    }

    pub(super) fn validate_graphs(writer: &Connection, root: &Path) -> Result<()> {
        for table in ["graph_subjects", "graph_relationships", "graph_findings"] {
            let tenant = if table == "graph_relationships" {
                ""
            } else {
                "AND r.tenant_id = g.tenant_id"
            };
            let invalid: bool = writer.query_row(&format!(
                "SELECT EXISTS(SELECT 1 FROM {table} g LEFT JOIN analysis_results r
                ON r.result_id = g.result_id {tenant}
                WHERE r.result_id IS NULL OR r.processor_id <> 'graph-findings' OR r.stream_key IS NULL
                OR r.commit_revision > COALESCE((SELECT last_changed_revision FROM relation_revisions
                    WHERE relation_name = '{table}'), 0))"
            ), [], |row| row.get(0)).context(AnalysisDatabaseSnafu { operation: "validate native graph references" })?;
            if invalid {
                return Self::reject_path(root, "a native graph row has no valid result");
            }
        }
        let mut after = String::new();
        while let Some((id, tenant, _)) = Self::next_graph(writer, &after, false)? {
            let tenant = tenant.try_into().map_err(|_| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the retained graph tenant is invalid",
                }
                .build()
            })?;
            let header = GraphRows::read_header(writer, tenant, &id)?.ok_or_else(|| {
                crate::AnalysisStateSnafu {
                    path: root,
                    reason: "the retained graph header is absent",
                }
                .build()
            })?;
            let rebuilt = GraphRows::read(writer, &id, &header)?;
            GraphRows::read_body(writer, &id, &header, &rebuilt)?;
            after = id;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
