use std::path::Path;

use duckdb::{params, Connection};
use snafu::ResultExt as _;

use super::{PackageCommitMetadata, PackageRevisionRefV1};
use crate::{AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub(super) fn validate_package_contracts(reader: &Connection, root: &Path) -> Result<()> {
        let mut statement = reader.prepare("SELECT tenant_id, package_id, revision, descriptor, dependencies FROM package_revisions")
            .context(AnalysisDatabaseSnafu { operation: "prepare retained package contracts" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read retained package contracts",
            })?;
        for row in rows {
            let (tenant, id, revision, descriptor, dependencies) =
                row.context(AnalysisDatabaseSnafu {
                    operation: "decode retained package contract",
                })?;
            let package: araphor_analysis_sdk::Package =
                serde_json::from_slice(&descriptor).context(JsonSnafu { path: root })?;
            if package.id != id || package.revision != revision || package.validate().is_err() {
                return Self::reject_path(root, "the retained package descriptor is invalid");
            }
            let dependencies: Vec<PackageRevisionRefV1> =
                serde_json::from_str(&dependencies).context(JsonSnafu { path: root })?;
            let declared: std::collections::BTreeSet<_> = package
                .dependencies
                .iter()
                .filter(|dependency| dependency.package != package.id)
                .map(|dependency| (dependency.package.as_str(), dependency.revision.as_str()))
                .collect();
            let retained: std::collections::BTreeSet<_> = dependencies
                .iter()
                .map(|dependency| (dependency.package_id.as_str(), dependency.revision.as_str()))
                .collect();
            if declared != retained || retained.len() != dependencies.len() {
                return Self::reject_path(root, "the retained package dependency closure differs");
            }
            for dependency in dependencies {
                let present: bool = reader
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM package_revisions
                    WHERE tenant_id = ? AND package_id = ? AND revision = ?)",
                        params![tenant, dependency.package_id, dependency.revision],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "validate retained package dependency",
                    })?;
                if !present {
                    return Self::reject_path(root, "the retained package dependency is absent");
                }
            }
        }
        let mut statement = reader.prepare("SELECT r.result_id, r.tenant_id, r.commit_meta, r.dependencies FROM package_results r")
            .context(AnalysisDatabaseSnafu { operation: "prepare retained package results" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read retained package results",
            })?;
        for row in rows {
            let (id, tenant, contract, dependencies) = row.context(AnalysisDatabaseSnafu {
                operation: "decode retained package result",
            })?;
            let contract: PackageCommitMetadata =
                serde_json::from_slice(&contract).context(JsonSnafu { path: root })?;
            if contract.result_id != id
                || contract.activation.key.tenant_id.as_slice() != tenant
                || serde_json::to_string(&contract.dependencies)
                    .context(JsonSnafu { path: root })?
                    != dependencies
            {
                return Self::reject_path(root, "the retained package result contract differs");
            }
            let result = Self::package_result_from(reader, contract.activation.key.tenant_id, &id)?
                .ok_or_else(|| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the retained package result is absent",
                    }
                    .build()
                })?;
            if result.key != contract.activation.key
                || result.revision != contract.activation.revision
                || result.window_id != contract.window_id
                || contract.source_revisions.len() > 64
                || contract
                    .source_revisions
                    .windows(2)
                    .any(|pair| pair[0].0 >= pair[1].0)
                || contract.source_revisions.iter().any(|(name, captured)| {
                    name.is_empty() || name.len() > 128 || *captured >= result.commit_revision
                })
            {
                return Self::reject_path(root, "the retained package result key differs");
            }
            let count: u64 = reader
                .query_row(
                    "SELECT count(*) FROM package_dependencies WHERE result_id = ?",
                    params![id],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "count retained package references",
                })?;
            if count != contract.dependencies.len() as u64 {
                return Self::reject_path(root, "the retained package references differ");
            }
            for dependency in contract.dependencies {
                let present: bool = reader
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM package_dependencies
                    WHERE result_id = ? AND dependency_id = ? AND commit_revision = ?)",
                        params![id, dependency.result_id, dependency.commit_revision],
                        |row| row.get(0),
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "validate retained package result reference",
                    })?;
                if !present {
                    return Self::reject_path(
                        root,
                        "the retained package result reference is absent",
                    );
                }
            }
        }
        Ok(())
    }
}
