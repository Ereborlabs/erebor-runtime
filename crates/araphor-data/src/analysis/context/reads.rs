use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;

type StoredContextRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, u64, ContextRow);

impl AnalysisStore {
    pub fn context_tenant_page(
        &self,
        owner: &str,
        after: Option<[u8; 16]>,
    ) -> Result<Vec<[u8; 16]>> {
        self.read_snapshot(|reader| {
            let mut statement = reader.prepare("SELECT DISTINCT tenant_id FROM context_versions
                WHERE owner_id = ? AND (CAST(? AS BLOB) IS NULL OR tenant_id > ?) ORDER BY tenant_id LIMIT 256")
                .context(AnalysisDatabaseSnafu { operation: "prepare context tenants" })?;
            let rows = statement.query_map(params![owner, after.as_ref().map(|id| id.as_slice()), after.as_ref().map(|id| id.as_slice())],
                |row| row.get::<_, Vec<u8>>(0)).context(AnalysisDatabaseSnafu { operation: "read context tenants" })?;
            rows.map(|row| row.context(AnalysisDatabaseSnafu { operation: "decode context tenant" })?
                .try_into().map_err(|_| self.state_error("the context tenant is invalid"))).collect()
        })
    }

    pub fn context_version(
        &self,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<AnalysisContextVersionV1>> {
        if !key.valid() {
            return self.reject("the context version key is invalid");
        }
        self.read_snapshot(|reader| {
            Ok(self
                .read_context_cached_from(reader, &self.root, key)?
                .map(|(version, _)| version))
        })
    }

    pub fn context_head(
        &self,
        tenant: [u8; 16],
        owner: &str,
        entity: &[u8],
        lifetime: &[u8],
    ) -> Result<Option<AnalysisContextVersionV1>> {
        if tenant == [0; 16] || owner.is_empty() || entity.is_empty() || lifetime.is_empty() {
            return self.reject("the context head scope is invalid");
        }
        if owner == crate::NOTIFICATION_STATE_OWNER && lifetime == b"obligation" {
            return self.notification_state_head(tenant, entity);
        }
        self.read_snapshot(|reader| {
            let revision: Option<u64> = reader
                .query_row(
                    "SELECT MAX(owner_revision) FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND entity_key = ? AND lifetime_key = ?",
                    params![tenant.as_slice(), owner, entity, lifetime],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read exact context head",
                })?;
            let Some(owner_revision) = revision else {
                return Ok(None);
            };
            let key = AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: owner.into(),
                entity_key: entity.into(),
                lifetime_key: lifetime.into(),
                owner_revision,
            };
            Ok(self
                .read_context_cached_from(reader, &self.root, &key)?
                .map(|(version, _)| version))
        })
    }

    pub(in crate::analysis) fn read_context_from(
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        Self::read_context_row_from(connection, root, key)?
            .map(|result| {
                Self::validate_stored_context_packages(connection, &result.0)?;
                Ok(result)
            })
            .transpose()
    }

    pub(in crate::analysis) fn read_context_cached_from(
        &self,
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        self.read_context_verified_from(connection, root, key, &mut VerifiedPackages::default())
    }

    pub(in crate::analysis) fn read_context_verified_from(
        &self,
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
        verified: &mut VerifiedPackages,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        Self::read_context_row_from(connection, root, key)?
            .map(|result| {
                self.check_cached_provenance_with(connection, &result.0, verified)?;
                Ok(result)
            })
            .transpose()
    }

    pub(super) fn read_context_row_from(
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let version_key = super::version_key(key)?;
        let stored: Option<StoredContextRow> = connection
            .prepare_cached(
                "SELECT tenant_id, owner_id, entity_key, lifetime_key, owner_revision,
                    valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, commit_revision
                 FROM context_versions WHERE version_key = ?",
            )
            .and_then(|mut statement| {
                statement.query_row(params![version_key], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        (
                            row.get(5)?,
                            row.get(6)?,
                            row.get(7)?,
                            row.get(8)?,
                            row.get(9)?,
                        ),
                    ))
                })
            })
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read context version",
            })?;
        stored
            .map(
                |(tenant, owner_id, entity_key, lifetime_key, owner_revision, stored)| {
                    let tenant_id = tenant.try_into().map_err(|_| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the context version index tenant is invalid",
                        }
                        .build()
                    })?;
                    let stored_key = AnalysisContextKeyV1 {
                        tenant_id,
                        owner_id,
                        entity_key,
                        lifetime_key,
                        owner_revision,
                    };
                    if &stored_key != key {
                        return Self::reject_path(
                            root,
                            "the context version index has a foreign row",
                        );
                    }
                    Self::decode_context_row(root, stored_key, stored)
                },
            )
            .transpose()
    }

    pub(in crate::analysis) fn context_row(
        tenant: [u8; 16],
        owner: &str,
        row: &duckdb::Row<'_>,
    ) -> duckdb::Result<(AnalysisContextKeyV1, ContextRow)> {
        Ok((
            AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: owner.into(),
                entity_key: row.get(0)?,
                lifetime_key: row.get(1)?,
                owner_revision: row.get(2)?,
            },
            (
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            ),
        ))
    }

    pub(in crate::analysis) fn decode_context_row(
        root: &Path,
        key: AnalysisContextKeyV1,
        (from, until, sensitivity, body, revision): ContextRow,
    ) -> Result<(AnalysisContextVersionV1, u64)> {
        let sensitivity = match ContextSensitivityV1::try_from(sensitivity.as_str()) {
            Ok(value) => value,
            Err(()) => return Self::reject_path(root, "the context sensitivity is invalid"),
        };
        let result = AnalysisContextVersionV1 {
            key,
            valid_from_utc_ns: from,
            valid_until_utc_ns: until,
            sensitivity,
            body,
        };
        if !result.valid() || revision == 0 {
            return Self::reject_path(root, "the retained context version is invalid");
        }
        Ok((result, revision))
    }
}
