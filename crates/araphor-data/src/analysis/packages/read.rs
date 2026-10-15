use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::{
    PackageActivationV1, PackageKeyV1, PackageResultV1, PackageRevisionV1, MAX_PACKAGE_ROWS,
};
use crate::{AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub(super) const RESULT_READ_BYTES: u64 = 64 * 1024 * 1024;

    pub(crate) fn package_current(
        &self,
        active: &PackageActivationV1,
        now: u64,
        changed: bool,
        control: &crate::AnalysisReadControl,
    ) -> Result<Option<Vec<u8>>> {
        let Some(id) = &active.result_id else {
            return Ok(None);
        };
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let row: Option<(Vec<u8>, Vec<u8>)> = reader.query_row(
                "SELECT x.body, r.commit_meta FROM package_results r
                 JOIN analysis_results x USING (result_id)
                 JOIN package_heads h USING (result_id)
                 JOIN package_activations a ON a.tenant_id = r.tenant_id
                    AND a.scope_id = r.scope_id AND a.package_id = r.package_id
                    AND a.export_name = r.export_name
                 WHERE r.tenant_id = ? AND r.result_id = ? AND NOT r.stale
                    AND a.active AND a.result_id = r.result_id AND a.generation = ?
                    AND a.checkpoint_revision = ? AND a.metadata = ?",
                params![active.key.tenant_id.as_slice(), id, active.generation,
                    active.checkpoint_revision, active.metadata],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().context(AnalysisDatabaseSnafu { operation: "read current package metadata" })?;
            let Some((body, metadata)) = row else { return Ok(None); };
            let metadata: super::PackageCommitMetadata = serde_json::from_slice(&metadata)
                .context(JsonSnafu { path: "<package-commit>" })?;
            if metadata.witnesses.iter().any(|witness| witness.expires_utc_ns <= now) {
                return Ok(None);
            }
            if !changed {
                return Ok(Some(body));
            }
            for (relation, captured) in &metadata.source_revisions {
                control.check()?;
                let changed: u64 = reader.query_row(
                    "SELECT COALESCE(MAX(last_changed_revision), 0)::UBIGINT
                     FROM relation_revisions WHERE relation_name = ?",
                    params![relation], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read package source notice" })?;
                if changed > *captured { return Ok(None); }
            }
            for dependency in &metadata.dependencies {
                control.check()?;
                let current: bool = reader.query_row(
                    "SELECT EXISTS(SELECT 1 FROM analysis_results x
                     LEFT JOIN package_results r USING (result_id)
                     WHERE x.tenant_id = ? AND x.result_id = ? AND x.commit_revision = ?
                        AND (r.result_id IS NULL OR (r.scope_id = ? AND NOT r.stale
                            AND EXISTS(SELECT 1 FROM package_heads h WHERE h.result_id = r.result_id))))",
                    params![active.key.tenant_id.as_slice(), dependency.result_id,
                        dependency.commit_revision, active.key.scope_id], |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read package dependency notice" })?;
                if !current { return Ok(None); }
            }
            for reference in &metadata.context_refs {
                control.check()?;
                let key = &reference.key;
                let current: bool = reader.query_row(
                    "SELECT EXISTS(SELECT 1 FROM context_versions WHERE tenant_id = ?
                     AND owner_id = ? AND entity_key = ? AND lifetime_key = ?
                     AND owner_revision = ? AND commit_revision = ?)",
                    params![key.tenant_id.as_slice(), key.owner_id, key.entity_key.as_slice(),
                        key.lifetime_key.as_slice(), key.owner_revision, reference.commit_revision],
                    |row| row.get(0),
                ).context(AnalysisDatabaseSnafu { operation: "read package context notice" })?;
                if !current { return Ok(None); }
            }
            Ok(Some(body))
        })
    }

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
            let mut statement = reader
                .prepare(
                    "SELECT package_id, revision FROM package_revisions WHERE tenant_id = ?
                 ORDER BY package_id, revision LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare package list",
                })?;
            let keys = statement
                .query_map(
                    params![tenant.as_slice(), (MAX_PACKAGE_ROWS + 1) as u64],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "list package revisions",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode package list",
                })?;
            if keys.len() > MAX_PACKAGE_ROWS {
                return self.reject("the package list exceeds its row limit");
            }
            keys.into_iter()
                .map(|(package, revision)| {
                    Self::package_from(reader, tenant, &package, &revision)?
                        .ok_or_else(|| self.state_error("the selected package revision is absent"))
                })
                .collect()
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
            if bytes > Self::RESULT_READ_BYTES { return self.reject("the package results exceed their byte limit"); }
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
