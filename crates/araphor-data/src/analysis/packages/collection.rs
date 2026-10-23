use duckdb::{params, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use super::PackageRevisionRefV1;
use crate::{AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    pub fn collect_package_admissions(&self) -> Result<()> {
        let mut after: Option<([u8; 16], String, String)> = None;
        loop {
            let page = self.read_snapshot(|reader| {
                let initial = ([0; 16], String::new(), String::new());
                let key = after.as_ref().unwrap_or(&initial);
                let mut statement = reader
                    .prepare(
                        "SELECT tenant_id, package_id, revision FROM package_revisions
                     WHERE ? OR (tenant_id, package_id, revision) > (?, ?, ?)
                     ORDER BY tenant_id, package_id, revision LIMIT 32",
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare artifact release page",
                    })?;
                let page = statement
                    .query_map(
                        params![after.is_none(), key.0.as_slice(), key.1, key.2],
                        |row| {
                            let tenant: Vec<u8> = row.get(0)?;
                            Ok((
                                tenant.try_into().map_err(|_| duckdb::Error::InvalidQuery)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read artifact release page",
                    })?
                    .collect::<duckdb::Result<Vec<([u8; 16], String, String)>>>()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode artifact release page",
                    })?;
                Ok(page)
            })?;
            if page.is_empty() {
                return Ok(());
            }
            after = page.last().cloned();
            for (tenant, package, revision) in page {
                self.collect_package(tenant, &package, &revision)?;
            }
        }
    }

    pub fn collect_package(&self, tenant: [u8; 16], package: &str, version: &str) -> Result<()> {
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin artifact release",
            })?;
        if !self.collect_package_rows(&transaction, tenant, package, version)? {
            return Ok(());
        }
        self.check_logical(&transaction, tenant, false)?;
        let revision = self.package_next(&transaction)?;
        Self::record_revision(
            &transaction,
            revision,
            &["package_revisions", "package_images"],
        )?;
        self.commit_metadata(transaction, "commit artifact release")?;
        self.revision.send_replace(revision);
        Ok(())
    }

    pub(super) fn collect_package_rows(
        &self,
        transaction: &Transaction<'_>,
        tenant: [u8; 16],
        package: &str,
        version: &str,
    ) -> Result<bool> {
        let dependencies = transaction
            .query_row(
                "SELECT dependencies FROM package_revisions
            WHERE tenant_id = ? AND package_id = ? AND revision = ?",
                params![tenant.as_slice(), package, version],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read artifact dependency references",
            })?;
        let Some(dependencies) = dependencies else {
            return Ok(false);
        };
        let dependencies: Vec<PackageRevisionRefV1> =
            serde_json::from_str(&dependencies).context(JsonSnafu {
                path: "<package-dependencies>",
            })?;
        let removed = transaction.execute(
            "DELETE FROM package_revisions p WHERE p.tenant_id = ? AND p.package_id = ? AND p.revision = ?
            AND NOT EXISTS (SELECT 1 FROM package_images i WHERE i.tenant_id = p.tenant_id
                AND i.package_id = p.package_id AND i.revision = p.revision AND i.installed)
            AND NOT EXISTS (SELECT 1 FROM discovery_definitions d,
                json_each(TRY_CAST(decode(d.definition) AS JSON), '$.images') j
                WHERE d.tenant_id = p.tenant_id
                    AND (j.value->'image'->>'package_id') = p.package_id
                    AND (j.value->'image'->>'revision') = p.revision)
            AND NOT EXISTS (SELECT 1 FROM package_activations a WHERE a.tenant_id = p.tenant_id
                AND a.installed AND ((a.package_id = p.package_id AND a.revision = p.revision)
                    OR (json_extract_string(TRY_CAST(decode(a.metadata) AS JSON), '$.root.package_id') = p.package_id
                        AND json_extract_string(TRY_CAST(decode(a.metadata) AS JSON), '$.root.revision') = p.revision)))
            AND NOT EXISTS (SELECT 1 FROM package_results r WHERE r.tenant_id = p.tenant_id
                AND r.package_id = p.package_id AND r.revision = p.revision)
            AND NOT EXISTS (SELECT 1 FROM context_versions c
                WHERE c.tenant_id = p.tenant_id AND c.owner_id = 'native-package-v1'
                    AND json_extract_string(TRY_CAST(CASE WHEN c.owner_id = 'native-package-v1'
                        THEN decode(c.body) ELSE NULL END AS JSON), '$.root.package_id') = p.package_id
                    AND json_extract_string(TRY_CAST(CASE WHEN c.owner_id = 'native-package-v1'
                        THEN decode(c.body) ELSE NULL END AS JSON), '$.root.revision') = p.revision)
            AND NOT EXISTS (SELECT 1 FROM context_versions c,
                json_each(TRY_CAST(CASE WHEN c.owner_id IN ('discovery-source-v1', 'graph-packages-v1')
                    THEN decode(c.body) ELSE NULL END AS JSON), '$.installed_packages') j
                WHERE c.tenant_id = p.tenant_id
                    AND c.owner_id IN ('discovery-source-v1', 'graph-packages-v1')
                    AND (((j.value->>'package_id') = p.package_id AND (j.value->>'revision') = p.revision)
                        OR ((j.value->'root'->>'package_id') = p.package_id
                            AND (j.value->'root'->>'revision') = p.revision)))
            AND NOT EXISTS (SELECT 1 FROM package_revisions d, json_each(d.dependencies) j
                WHERE d.tenant_id = p.tenant_id AND (j.value->>'package_id') = p.package_id
                    AND (j.value->>'revision') = p.revision)",
            params![tenant.as_slice(), package, version],
        ).context(AnalysisDatabaseSnafu { operation: "release unused package artifacts" })?;
        if removed != 0 {
            transaction.execute(
                "DELETE FROM package_images WHERE tenant_id = ? AND package_id = ? AND revision = ? AND NOT installed",
                params![tenant.as_slice(), package, version],
            ).context(AnalysisDatabaseSnafu { operation: "release uninstalled image record" })?;
            for dependency in dependencies {
                self.collect_package_rows(
                    transaction,
                    tenant,
                    &dependency.package_id,
                    &dependency.revision,
                )?;
            }
        }
        Ok(removed != 0)
    }
}
