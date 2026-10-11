use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{
    PackageActivationV1, PackageKeyV1, PackageResultV1, PackageRevisionV1, MAX_PACKAGE_ROWS,
};
use crate::{AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub(crate) fn package_revision(
        &self,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<PackageRevisionV1>> {
        self.read_snapshot(|reader| Self::package_from(reader, tenant, package, revision))
    }

    pub(super) fn package_from(
        reader: &Connection,
        tenant: [u8; 16],
        package: &str,
        revision: &str,
    ) -> Result<Option<PackageRevisionV1>> {
        let row = reader
            .query_row(
                "SELECT descriptor, artifact, dependencies FROM package_revisions
             WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![tenant.as_slice(), package, revision],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read package revision",
            })?;
        row.map(|(descriptor, artifact, dependencies)| {
            Ok(PackageRevisionV1 {
                tenant_id: tenant,
                package_id: package.into(),
                revision: revision.into(),
                descriptor,
                artifact,
                dependencies: serde_json::from_str(&dependencies).context(JsonSnafu {
                    path: "<package-dependencies>",
                })?,
            })
        })
        .transpose()
    }

    #[cfg(test)]
    pub(crate) fn package_revisions(&self, tenant: [u8; 16]) -> Result<Vec<PackageRevisionV1>> {
        self.read_snapshot(|reader| {
            let bytes: u64 = reader.query_row("SELECT COALESCE(SUM(octet_length(descriptor) + octet_length(artifact)), 0)::UBIGINT
                FROM package_revisions WHERE tenant_id = ?", params![tenant.as_slice()], |row| row.get(0))
                .context(AnalysisDatabaseSnafu { operation: "bound package list bytes" })?;
            if bytes > super::MAX_PACKAGE_BYTES as u64 { return self.reject("the package list exceeds its byte limit"); }
            let mut statement = reader.prepare(
                "SELECT package_id, revision FROM package_revisions WHERE tenant_id = ?
                 ORDER BY package_id, revision LIMIT ?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare package list" })?;
            let keys = statement.query_map(params![tenant.as_slice(), (MAX_PACKAGE_ROWS + 1) as u64],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).context(AnalysisDatabaseSnafu { operation: "list package revisions" })?
                .collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu { operation: "decode package list" })?;
            if keys.len() > MAX_PACKAGE_ROWS { return self.reject("the package list exceeds its row limit"); }
            keys.into_iter().map(|(package, revision)| {
                Self::package_from(reader, tenant, &package, &revision)?
                    .ok_or_else(|| self.state_error("the selected package revision is absent"))
            }).collect()
        })
    }

    pub(crate) fn package_activation(
        &self,
        key: &PackageKeyV1,
    ) -> Result<Option<PackageActivationV1>> {
        self.read_snapshot(|reader| Self::activation_from(reader, key))
    }

    pub(crate) fn package_installed(&self, key: &PackageKeyV1) -> Result<bool> {
        self.read_snapshot(|reader| {
            reader
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM package_activations WHERE tenant_id = ?
                 AND scope_id = ? AND package_id = ? AND export_name = ? AND installed)",
                    params![
                        key.tenant_id.as_slice(),
                        key.scope_id,
                        key.package_id,
                        key.export
                    ],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read package installation status",
                })
        })
    }

    pub(crate) fn package_activations(
        &self,
        tenant: [u8; 16],
        scope: &str,
        package: Option<&str>,
    ) -> Result<Vec<PackageActivationV1>> {
        self.read_snapshot(|reader| {
            let bytes: u64 = reader.query_row(
                "SELECT COALESCE(SUM(octet_length(metadata)), 0)::UBIGINT FROM package_activations
                 WHERE installed AND tenant_id = ? AND scope_id = ? AND (? IS NULL OR package_id = ?)",
                params![tenant.as_slice(), scope, package, package], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "bound package activation bytes" })?;
            if bytes > super::MAX_PACKAGE_BYTES as u64 {
                return self.reject("the package activations exceed their byte limit");
            }
            let mut statement = reader.prepare(
                "SELECT package_id, export_name FROM package_activations
                 WHERE installed AND tenant_id = ? AND scope_id = ? AND (? IS NULL OR package_id = ?)
                 ORDER BY package_id, export_name LIMIT ?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare scoped package activations" })?;
            let keys = statement.query_map(
                params![tenant.as_slice(), scope, package, package, (MAX_PACKAGE_ROWS + 1) as u64],
                |row| Ok(PackageKeyV1 { tenant_id: tenant, scope_id: scope.into(),
                    package_id: row.get(0)?, export: row.get(1)? }),
            ).context(AnalysisDatabaseSnafu { operation: "read scoped package activations" })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu { operation: "decode scoped package activations" })?;
            if keys.len() > MAX_PACKAGE_ROWS {
                return self.reject("the package activations exceed their row limit");
            }
            keys.into_iter().map(|key| Self::activation_from(reader, &key)?
                .ok_or_else(|| self.state_error("the selected package activation is absent"))).collect()
        })
    }

    pub(crate) fn package_activation_page(
        &self,
        after: Option<&PackageKeyV1>,
    ) -> Result<Vec<PackageActivationV1>> {
        let initial = PackageKeyV1 {
            tenant_id: [0; 16],
            scope_id: String::new(),
            package_id: String::new(),
            export: String::new(),
        };
        let key = after.unwrap_or(&initial);
        self.read_snapshot(|reader| {
            let mut statement = reader.prepare("SELECT tenant_id, scope_id, package_id, export_name FROM package_activations
                WHERE installed AND (? OR (tenant_id, scope_id, package_id, export_name) > (?, ?, ?, ?))
                ORDER BY tenant_id, scope_id, package_id, export_name LIMIT 32")
                .context(AnalysisDatabaseSnafu { operation: "prepare package activation page" })?;
            let keys = statement.query_map(params![after.is_none(), key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export], |row| {
                let tenant: Vec<u8> = row.get(0)?;
                Ok(PackageKeyV1 { tenant_id: tenant.try_into().map_err(|_| duckdb::Error::InvalidQuery)?,
                    scope_id: row.get(1)?, package_id: row.get(2)?, export: row.get(3)? })
            }).context(AnalysisDatabaseSnafu { operation: "read package activation page" })?
                .collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu { operation: "decode package activation page" })?;
            keys.into_iter().map(|key| Self::activation_from(reader, &key)?
                .ok_or_else(|| self.state_error("the selected package activation is absent"))).collect()
        })
    }

    pub(super) fn activation_from(
        reader: &Connection,
        key: &PackageKeyV1,
    ) -> Result<Option<PackageActivationV1>> {
        reader.query_row(
            "SELECT revision, generation, checkpoint_revision, result_id, grant_id, metadata, active
             FROM package_activations WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?",
            params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export],
            |row| Ok(PackageActivationV1 {
                key: key.clone(), revision: row.get(0)?, generation: row.get(1)?, checkpoint_revision: row.get(2)?,
                result_id: row.get(3)?, grant_id: row.get(4)?, metadata: row.get(5)?, active: row.get(6)?,
            }),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read package activation" })
    }

    pub(crate) fn package_result(
        &self,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<Option<PackageResultV1>> {
        self.read_snapshot(|reader| Self::package_result_from(reader, tenant, id))
    }

    pub(super) fn package_result_from(
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<Option<PackageResultV1>> {
        let row = reader.query_row(
            "SELECT r.scope_id, r.package_id, r.export_name, r.window_id, r.revision,
                x.request_meta, x.body, r.datasets, r.checkpoint, r.dependencies, x.commit_revision, r.stale, r.commit_meta
             FROM package_results r JOIN analysis_results x USING (result_id)
             WHERE r.tenant_id = ? AND r.result_id = ?",
            params![tenant.as_slice(), id],
            |row| Ok((PackageResultV1 {
                key: PackageKeyV1 { tenant_id: tenant, scope_id: row.get(0)?, package_id: row.get(1)?, export: row.get(2)? },
                activation: serde_json::from_slice::<super::PackageCommitMetadata>(&row.get::<_, Vec<u8>>(12)?)
                    .map_err(|error| duckdb::Error::FromSqlConversionFailure(12, duckdb::types::Type::Blob, Box::new(error)))?.activation,
                window_id: row.get(3)?, revision: row.get(4)?, result_id: id.into(), request: row.get(5)?,
                metadata: row.get(6)?, datasets: row.get(7)?, checkpoint: row.get(8)?, dependencies: Vec::new(),
                commit_revision: row.get(10)?, stale: row.get(11)?,
            }, row.get::<_, String>(9)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "read package result" })?;
        row.map(|(mut result, dependencies)| {
            result.dependencies = serde_json::from_str(&dependencies).context(JsonSnafu {
                path: "<result-dependencies>",
            })?;
            Ok(result)
        })
        .transpose()
    }

    pub(crate) fn package_results(&self, key: &PackageKeyV1) -> Result<Vec<PackageResultV1>> {
        self.read_snapshot(|reader| {
            let bytes: u64 = reader.query_row("SELECT COALESCE(SUM(octet_length(r.datasets) + octet_length(r.checkpoint)
                + octet_length(x.body) + octet_length(x.request_meta) + octet_length(r.commit_meta)
                + length(r.dependencies)), 0)::UBIGINT
                FROM package_heads h JOIN package_results r USING (result_id) JOIN analysis_results x USING (result_id)
                WHERE h.tenant_id = ? AND h.scope_id = ? AND h.package_id = ? AND h.export_name = ?",
                params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export], |row| row.get(0),
            ).context(AnalysisDatabaseSnafu { operation: "bound selected package results" })?;
            if bytes > super::MAX_PACKAGE_BYTES as u64 { return self.reject("the package results exceed their byte limit"); }
            let mut statement = reader.prepare(
                "SELECT result_id FROM package_heads
                 WHERE tenant_id = ? AND scope_id = ? AND package_id = ? AND export_name = ?
                 ORDER BY window_id LIMIT ?",
            ).context(AnalysisDatabaseSnafu { operation: "prepare package results" })?;
            let ids = statement.query_map(
                params![key.tenant_id.as_slice(), key.scope_id, key.package_id, key.export, (MAX_PACKAGE_ROWS + 1) as u64],
                |row| row.get::<_, String>(0),
            ).context(AnalysisDatabaseSnafu { operation: "select package results" })?
                .collect::<duckdb::Result<Vec<_>>>().context(AnalysisDatabaseSnafu { operation: "decode package result keys" })?;
            if ids.len() > MAX_PACKAGE_ROWS { return self.reject("the package results exceed their row limit"); }
            ids.into_iter().map(|id| Self::package_result_from(reader, key.tenant_id, &id)?
                .ok_or_else(|| self.state_error("the package result is absent"))).collect()
        })
    }
}
