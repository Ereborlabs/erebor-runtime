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
            commit_revision UBIGINT NOT NULL,
            PRIMARY KEY (tenant_id, package_id, revision)
        );
        CREATE TABLE IF NOT EXISTS package_images (
            tenant_id BLOB NOT NULL, package_id VARCHAR NOT NULL, revision VARCHAR NOT NULL,
            digest VARCHAR NOT NULL, commit_revision UBIGINT NOT NULL, installed BOOLEAN NOT NULL,
            PRIMARY KEY (tenant_id, package_id, revision)
        );
        CREATE TABLE IF NOT EXISTS discovery_definitions (
            tenant_id BLOB NOT NULL, name VARCHAR NOT NULL, revision VARCHAR NOT NULL,
            definition BLOB NOT NULL, commit_revision UBIGINT NOT NULL,
            PRIMARY KEY (tenant_id, name, revision)
        );";

    pub(in crate::analysis) fn validate_packages(writer: &Connection, root: &Path) -> Result<()> {
        let revision_query = "SELECT 1 FROM package_revisions WHERE octet_length(tenant_id) <> 16
                OR length(package_id) = 0 OR length(revision) = 0
                OR octet_length(descriptor) = 0
                OR octet_length(artifact) = 0 OR commit_revision = 0
                OR commit_revision > (SELECT commit_revision FROM store_meta)";
        for (reason, query) in [
            ("invalid retained package revision", revision_query),
            ("invalid retained package image", "SELECT 1 FROM package_images i LEFT JOIN package_revisions p
                ON p.tenant_id = i.tenant_id AND p.package_id = i.package_id AND p.revision = i.revision
                WHERE octet_length(i.tenant_id) <> 16 OR p.package_id IS NULL
                    OR NOT regexp_full_match(i.digest, 'sha256:[0-9a-f]{64}')
                    OR i.commit_revision = 0 OR i.commit_revision > (SELECT commit_revision FROM store_meta)
                    OR p.commit_revision > i.commit_revision"),
        ] {
            let invalid: bool = writer
                .query_row(&format!("SELECT EXISTS ({query})"), [], |row| row.get(0))
                .context(AnalysisDatabaseSnafu { operation: "validate package state" })?;
            if invalid {
                return Self::reject_path(root, reason);
            }
        }
        Self::validate_package_contracts(writer, root)?;
        Self::validate_definitions(writer, root)
    }
}
