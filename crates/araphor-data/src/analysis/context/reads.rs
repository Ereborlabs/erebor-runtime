use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::*;

impl AnalysisStore {
    pub(crate) fn context_tenant_page(
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
            Ok(Self::read_context_from(reader, &self.root, key)?.map(|(version, _)| version))
        })
    }

    pub(crate) fn context_head(
        &self,
        tenant: [u8; 16],
        owner: &str,
        entity: &[u8],
        lifetime: &[u8],
    ) -> Result<Option<AnalysisContextVersionV1>> {
        if tenant == [0; 16]
            || owner.is_empty()
            || owner.len() > 128
            || !(1..=MAX_CONTEXT_KEY_BYTES).contains(&entity.len())
            || !(1..=MAX_CONTEXT_KEY_BYTES).contains(&lifetime.len())
        {
            return self.reject("the context head scope is invalid");
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
            Ok(Self::read_context_from(reader, &self.root, &key)?.map(|(version, _)| version))
        })
    }

    pub(in crate::analysis) fn read_context_from(
        connection: &Connection,
        root: &Path,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<(AnalysisContextVersionV1, u64)>> {
        let stored: Option<ContextRow> = connection
            .query_row(
                "SELECT valid_from_utc_ns, valid_until_utc_ns, sensitivity, body, commit_revision
                 FROM context_versions WHERE tenant_id = ? AND owner_id = ? AND entity_key = ?
                 AND lifetime_key = ? AND owner_revision = ?",
                params![
                    key.tenant_id.as_slice(),
                    key.owner_id,
                    key.entity_key.as_slice(),
                    key.lifetime_key.as_slice(),
                    key.owner_revision,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read context version",
            })?;
        stored
            .map(|stored| Self::decode_context_row(root, key.clone(), stored))
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
