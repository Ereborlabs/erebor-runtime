use duckdb::{params, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use super::PackageRevisionRefV1;
use crate::{AnalysisContextKeyV1, AnalysisDatabaseSnafu, AnalysisStore, JsonSnafu, Result};

impl AnalysisStore {
    const RELEASE_IMAGE: &str = "DELETE FROM package_images
        WHERE tenant_id = ? AND package_id = ? AND revision = ? AND NOT installed";

    pub fn collect_package_admissions(&self) -> Result<()> {
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin artifact release",
            })?;
        self.stage_package_context_roots(&transaction, None)?;
        {
            let mut statement = transaction
                .prepare("SELECT tenant_id, dependencies FROM package_revisions")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare artifact dependency references",
                })?;
            let rows = statement
                .query_map([], |row| {
                    let tenant: Vec<u8> = row.get(0)?;
                    let _: [u8; 16] = tenant.try_into().map_err(|_| duckdb::Error::InvalidQuery)?;
                    row.get::<_, String>(1)
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read artifact dependency references",
                })?;
            for row in rows {
                let dependencies = row.context(AnalysisDatabaseSnafu {
                    operation: "decode artifact dependency references",
                })?;
                serde_json::from_str::<Vec<PackageRevisionRefV1>>(&dependencies).context(
                    JsonSnafu {
                        path: "<package-dependencies>",
                    },
                )?;
            }
        }
        let mut tenants = std::collections::BTreeSet::new();
        {
            let mut cleanup =
                transaction
                    .prepare(Self::RELEASE_IMAGE)
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare uninstalled image release",
                    })?;
            loop {
                let removed = Self::release_package_rows(&transaction, None)?;
                if removed.is_empty() {
                    break;
                }
                for (tenant, package, version) in removed {
                    cleanup
                        .execute(params![tenant.as_slice(), package, version])
                        .context(AnalysisDatabaseSnafu {
                            operation: "release uninstalled image record",
                        })?;
                    tenants.insert(tenant);
                }
            }
        }
        Self::drop_package_context_roots(&transaction)?;
        if tenants.is_empty() {
            return Ok(());
        }
        for tenant in tenants {
            self.check_revision_limits(&transaction, tenant)?;
        }
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

    pub fn collect_package(&self, tenant: [u8; 16], package: &str, version: &str) -> Result<()> {
        let mut guard = self.writer()?;
        let transaction = guard
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin artifact release",
            })?;
        self.stage_package_context_roots(&transaction, Some(tenant))?;
        let removed = self.collect_package_rows(&transaction, tenant, package, version)?;
        Self::drop_package_context_roots(&transaction)?;
        if !removed {
            return Ok(());
        }
        self.check_revision_limits(&transaction, tenant)?;
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
        let removed = Self::release_package_rows(transaction, Some((tenant, package, version)))?;
        if !removed.is_empty() {
            transaction
                .execute(
                    Self::RELEASE_IMAGE,
                    params![tenant.as_slice(), package, version],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "release uninstalled image record",
                })?;
            for dependency in dependencies {
                self.collect_package_rows(
                    transaction,
                    tenant,
                    &dependency.package_id,
                    &dependency.revision,
                )?;
            }
        }
        Ok(!removed.is_empty())
    }

    pub(super) fn stage_package_context_roots(
        &self,
        transaction: &Transaction<'_>,
        tenant: Option<[u8; 16]>,
    ) -> Result<()> {
        transaction
            .execute_batch(
                "CREATE TEMPORARY TABLE temp.main.package_context_gc_roots (
                    tenant_id BLOB NOT NULL, package_id VARCHAR NOT NULL,
                    revision VARCHAR NOT NULL
                 )",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare package context roots",
            })?;
        let mut after: Option<Vec<u8>> = None;
        loop {
            let page = {
                let mut statement = transaction
                    .prepare(
                        "SELECT version_key, tenant_id, entity_key, lifetime_key,
                            owner_revision, valid_from_utc_ns, valid_until_utc_ns,
                            sensitivity, body, commit_revision
                         FROM context_versions WHERE owner_id = 'native-package-v1'
                            AND (CAST(? AS BLOB) IS NULL OR tenant_id = ?)
                            AND (CAST(? AS BLOB) IS NULL OR version_key > ?)
                         ORDER BY version_key LIMIT ?",
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native package context page",
                    })?;
                statement
                    .query_map(
                        params![
                            tenant.as_ref().map(|tenant| tenant.as_slice()),
                            tenant.as_ref().map(|tenant| tenant.as_slice()),
                            after.as_deref(),
                            after.as_deref(),
                            super::super::MAX_ANALYSIS_PAGE_RECORDS as u32
                        ],
                        |row| {
                            let tenant: Vec<u8> = row.get(1)?;
                            let tenant: [u8; 16] =
                                tenant.try_into().map_err(|_| duckdb::Error::InvalidQuery)?;
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                AnalysisContextKeyV1 {
                                    tenant_id: tenant,
                                    owner_id: "native-package-v1".into(),
                                    entity_key: row.get(2)?,
                                    lifetime_key: row.get(3)?,
                                    owner_revision: row.get(4)?,
                                },
                                (
                                    row.get::<_, Option<u64>>(5)?,
                                    row.get::<_, Option<u64>>(6)?,
                                    row.get::<_, String>(7)?,
                                    row.get::<_, Vec<u8>>(8)?,
                                    row.get::<_, u64>(9)?,
                                ),
                            ))
                        },
                    )
                    .context(AnalysisDatabaseSnafu {
                        operation: "read native package context page",
                    })?
                    .collect::<duckdb::Result<Vec<_>>>()
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode native package context page",
                    })?
            };
            if page.is_empty() {
                break;
            }
            let mut appender = transaction
                .appender_to_catalog_and_db("package_context_gc_roots", "temp", "main")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare native package root staging",
                })?;
            for (cursor, key, stored) in page {
                after = Some(cursor);
                let (context, _) = Self::decode_context_row(&self.root, key, stored)?;
                let root = context
                    .package_provenance()?
                    .ok_or_else(|| self.state_error("the native package context is absent"))?
                    .root;
                appender
                    .append_row(params![
                        context.key.tenant_id.as_slice(),
                        root.package_id,
                        root.revision
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "stage native package context root",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush native package context roots",
            })?;
        }
        Ok(())
    }

    pub(super) fn drop_package_context_roots(transaction: &Transaction<'_>) -> Result<()> {
        transaction
            .execute_batch("DROP TABLE temp.main.package_context_gc_roots")
            .context(AnalysisDatabaseSnafu {
                operation: "clear native package context roots",
            })
    }

    fn release_package_rows(
        transaction: &Transaction<'_>,
        key: Option<([u8; 16], &str, &str)>,
    ) -> Result<Vec<([u8; 16], String, String)>> {
        let mut statement = transaction.prepare(
            "DELETE FROM package_revisions p WHERE (? OR (p.tenant_id = ? AND p.package_id = ? AND p.revision = ?))
            AND NOT EXISTS (SELECT 1 FROM package_images i WHERE i.tenant_id = p.tenant_id
                AND i.package_id = p.package_id AND i.revision = p.revision AND i.installed)
            AND NOT EXISTS (SELECT 1 FROM discovery_definitions d,
                json_each(TRY_CAST(decode(d.definition) AS JSON), '$.images') j
                WHERE d.tenant_id = p.tenant_id
                    AND (j.value->'image'->>'package_id') = p.package_id
                    AND (j.value->'image'->>'revision') = p.revision)
            AND NOT EXISTS (SELECT 1 FROM temp.main.package_context_gc_roots c
                WHERE c.tenant_id = p.tenant_id AND c.package_id = p.package_id
                    AND c.revision = p.revision)
            AND NOT EXISTS (SELECT 1 FROM package_revisions d, json_each(d.dependencies) j
                WHERE d.tenant_id = p.tenant_id AND (j.value->>'package_id') = p.package_id
                    AND (j.value->>'revision') = p.revision)
            RETURNING tenant_id, package_id, revision"
        ).context(AnalysisDatabaseSnafu {
            operation: "prepare unused package release",
        })?;
        let rows = statement
            .query_map(
                params![
                    key.is_none(),
                    key.as_ref().map(|key| key.0.as_slice()),
                    key.as_ref().map(|key| key.1),
                    key.as_ref().map(|key| key.2)
                ],
                |row| {
                    let tenant: Vec<u8> = row.get(0)?;
                    Ok((
                        tenant.try_into().map_err(|_| duckdb::Error::InvalidQuery)?,
                        row.get(1)?,
                        row.get(2)?,
                    ))
                },
            )
            .context(AnalysisDatabaseSnafu {
                operation: "release unused package artifacts",
            })?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode released package keys",
            })
    }
}
