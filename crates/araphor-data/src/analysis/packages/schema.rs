use std::path::Path;

use duckdb::Connection;
use snafu::ResultExt as _;

use crate::{AnalysisDatabaseSnafu, Result};

use super::super::AnalysisStore;

impl AnalysisStore {
    pub(in crate::analysis) const PACKAGE_SCHEMA: &'static str = "
        CREATE TABLE IF NOT EXISTS package_revisions (
            tenant_id BLOB NOT NULL, package_id VARCHAR NOT NULL, revision VARCHAR NOT NULL,
            descriptor BLOB NOT NULL, artifact BLOB NOT NULL, dependencies VARCHAR NOT NULL,
            commit_revision UBIGINT NOT NULL, encoded_bytes UBIGINT NOT NULL,
            PRIMARY KEY (tenant_id, package_id, revision)
        );
        CREATE TABLE IF NOT EXISTS package_activations (
            tenant_id BLOB NOT NULL, scope_id VARCHAR NOT NULL, package_id VARCHAR NOT NULL,
            export_name VARCHAR NOT NULL, revision VARCHAR NOT NULL, generation UBIGINT NOT NULL,
            checkpoint_revision UBIGINT NOT NULL, result_id VARCHAR, grant_id VARCHAR NOT NULL,
            metadata BLOB NOT NULL, active BOOLEAN NOT NULL, installed BOOLEAN NOT NULL,
            PRIMARY KEY (tenant_id, scope_id, package_id, export_name)
        );
        CREATE TABLE IF NOT EXISTS package_results (
            result_id VARCHAR PRIMARY KEY, tenant_id BLOB NOT NULL, scope_id VARCHAR NOT NULL,
            package_id VARCHAR NOT NULL, export_name VARCHAR NOT NULL, revision VARCHAR NOT NULL,
            window_id VARCHAR NOT NULL, datasets BLOB NOT NULL, checkpoint BLOB NOT NULL,
            dependencies VARCHAR NOT NULL, stale BOOLEAN NOT NULL, commit_meta BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS package_heads (
            tenant_id BLOB NOT NULL, scope_id VARCHAR NOT NULL, package_id VARCHAR NOT NULL,
            export_name VARCHAR NOT NULL, window_id VARCHAR NOT NULL, result_id VARCHAR NOT NULL,
            PRIMARY KEY (tenant_id, scope_id, package_id, export_name, window_id)
        );
        CREATE TABLE IF NOT EXISTS package_dependencies (
            tenant_id BLOB NOT NULL, result_id VARCHAR NOT NULL, dependency_id VARCHAR NOT NULL,
            commit_revision UBIGINT NOT NULL,
            PRIMARY KEY (result_id, dependency_id)
        );";

    pub(in crate::analysis) const PACKAGE_CHARGES: &'static str = "
        SELECT tenant_id, 256 + octet_length(encode(package_id)) + octet_length(encode(revision))
            + octet_length(descriptor) + encoded_bytes + octet_length(encode(dependencies)) AS bytes
            FROM package_revisions
        UNION ALL SELECT tenant_id, 256 + octet_length(encode(scope_id)) + octet_length(encode(package_id))
            + octet_length(encode(export_name)) + octet_length(encode(revision))
            + COALESCE(octet_length(encode(result_id)), 0) + octet_length(encode(grant_id)) + octet_length(metadata)
            FROM package_activations
        UNION ALL SELECT tenant_id, 256 + octet_length(encode(result_id)) + octet_length(encode(scope_id))
            + octet_length(encode(package_id)) + octet_length(encode(export_name)) + octet_length(encode(revision))
            + octet_length(encode(window_id)) + octet_length(datasets) + octet_length(checkpoint)
            + octet_length(encode(dependencies)) + octet_length(commit_meta) FROM package_results
        UNION ALL SELECT tenant_id, 256 + octet_length(encode(scope_id)) + octet_length(encode(package_id))
            + octet_length(encode(export_name)) + octet_length(encode(window_id)) + octet_length(encode(result_id))
            FROM package_heads
        UNION ALL SELECT tenant_id, 256 + octet_length(encode(result_id)) + octet_length(encode(dependency_id))
            FROM package_dependencies";

    pub(in crate::analysis) fn validate_packages(writer: &Connection, root: &Path) -> Result<()> {
        let revision_query =
            "SELECT 1 FROM package_revisions WHERE octet_length(tenant_id) <> 16
                OR length(package_id) NOT BETWEEN 1 AND 256 OR length(revision) NOT BETWEEN 1 AND 4096
                OR octet_length(encode(dependencies)) > 1048576 OR octet_length(descriptor) = 0
                OR encoded_bytes = 0
                OR octet_length(artifact) NOT BETWEEN 1 AND encoded_bytes OR commit_revision = 0
                OR commit_revision > (SELECT commit_revision FROM store_meta)";
        for (reason, query) in [
            ("invalid retained package revision", revision_query),
            ("invalid package activation", "SELECT 1 FROM package_activations a LEFT JOIN package_revisions p
                ON p.tenant_id = a.tenant_id AND p.package_id = a.package_id AND p.revision = a.revision
                WHERE octet_length(a.tenant_id) <> 16 OR length(a.scope_id) NOT BETWEEN 1 AND 256
                OR length(a.export_name) NOT BETWEEN 1 AND 256 OR length(a.grant_id) NOT BETWEEN 1 AND 256
                OR a.generation = 0 OR a.generation > (SELECT commit_revision FROM store_meta)
                OR (a.installed AND p.package_id IS NULL) OR (a.active AND NOT a.installed)
                OR a.grant_id = '' OR octet_length(a.metadata) > 1048576
                OR (a.result_id IS NULL AND a.checkpoint_revision <> 0)
                OR (a.result_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM package_results r JOIN analysis_results x USING (result_id)
                    WHERE r.result_id = a.result_id AND r.tenant_id = a.tenant_id AND r.scope_id = a.scope_id
                        AND r.package_id = a.package_id AND r.export_name = a.export_name
                        AND x.commit_revision = a.checkpoint_revision))"),
            ("invalid package result", "SELECT 1 FROM package_results r LEFT JOIN analysis_results x USING (result_id)
                LEFT JOIN package_revisions p ON p.tenant_id = r.tenant_id AND p.package_id = r.package_id AND p.revision = r.revision
                WHERE x.result_id IS NULL OR x.tenant_id <> r.tenant_id OR x.processor_id <> 'analysis-package'
                OR p.package_id IS NULL OR length(r.window_id) NOT BETWEEN 1 AND 256
                OR octet_length(encode(r.dependencies)) > 1048576
                OR octet_length(r.datasets) + octet_length(r.checkpoint) > 16777216
                OR octet_length(r.commit_meta) NOT BETWEEN 1 AND 16777216"),
            ("invalid package head", "SELECT 1 FROM package_heads h LEFT JOIN package_results r
                ON r.result_id = h.result_id AND r.tenant_id = h.tenant_id AND r.scope_id = h.scope_id
                    AND r.package_id = h.package_id AND r.export_name = h.export_name AND r.window_id = h.window_id
                WHERE r.result_id IS NULL"),
            ("invalid package dependency", "SELECT 1 FROM package_dependencies d
                LEFT JOIN package_results r ON r.result_id = d.result_id AND r.tenant_id = d.tenant_id
                LEFT JOIN analysis_results x ON x.result_id = d.dependency_id AND x.tenant_id = d.tenant_id
                WHERE r.result_id IS NULL OR x.result_id IS NULL OR x.commit_revision <> d.commit_revision"),
            ("invalid package freshness", "SELECT 1 FROM package_dependencies d JOIN package_results r ON r.result_id = d.result_id
                JOIN package_results p ON p.result_id = d.dependency_id WHERE NOT r.stale AND p.stale"),
        ] {
            let invalid: bool = writer
                .query_row(&format!("SELECT EXISTS ({query})"), [], |row| row.get(0))
                .context(AnalysisDatabaseSnafu { operation: "validate package state" })?;
            if invalid {
                return Self::reject_path(root, reason);
            }
        }
        Self::validate_package_contracts(writer, root)
    }
}
