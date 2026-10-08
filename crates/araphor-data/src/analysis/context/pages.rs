use duckdb::params;
use snafu::ResultExt as _;

use super::*;

impl AnalysisStore {
    pub(crate) fn context_head_page(
        &self,
        tenant: [u8; 16],
        owner: &str,
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16]
            || owner.is_empty()
            || owner.len() > 128
            || after
                .is_some_and(|key| !key.valid() || key.tenant_id != tenant || key.owner_id != owner)
        {
            return self.reject("the context page scope is invalid");
        }
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare(
                    "WITH heads AS (
                 SELECT entity_key, lifetime_key, MAX(owner_revision) AS owner_revision FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ? AND (CAST(? AS BLOB) IS NULL
                    OR entity_key > ? OR (entity_key = ? AND lifetime_key > ?))
                 GROUP BY entity_key, lifetime_key ORDER BY entity_key, lifetime_key LIMIT ?
                 ) SELECT h.entity_key, h.lifetime_key, h.owner_revision,
                    c.valid_from_utc_ns, c.valid_until_utc_ns, c.sensitivity, c.body, c.commit_revision
                 FROM heads h JOIN context_versions c ON c.tenant_id = ? AND c.owner_id = ?
                    AND c.entity_key = h.entity_key AND c.lifetime_key = h.lifetime_key
                    AND c.owner_revision = h.owner_revision
                 ORDER BY h.entity_key, h.lifetime_key",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare context head page",
                })?;
            let entity = after.map(|key| key.entity_key.as_slice());
            let lifetime = after.map(|key| key.lifetime_key.as_slice());
            let rows = statement
                .query_map(
                    params![
                        tenant.as_slice(),
                        owner,
                        entity,
                        entity,
                        entity,
                        lifetime,
                        crate::analysis::MAX_ANALYSIS_PAGE_RECORDS as u32,
                        tenant.as_slice(),
                        owner
                    ],
                    |row| Self::context_row(tenant, owner, row),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read context head page",
                })?;
            let mut versions = Vec::new();
            let mut bytes = 0usize;
            for row in rows {
                let (key, stored) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode context head page",
                })?;
                let (version, _) = Self::decode_context_row(&self.root, key, stored)?;
                let next_bytes = bytes
                    .checked_add(std::mem::size_of::<AnalysisContextVersionV1>())
                    .and_then(|bytes| bytes.checked_add(version.key.owner_id.len()))
                    .and_then(|bytes| bytes.checked_add(version.key.entity_key.len()))
                    .and_then(|bytes| bytes.checked_add(version.key.lifetime_key.len()))
                    .and_then(|bytes| bytes.checked_add(version.body.len()))
                    .ok_or_else(|| {
                        crate::AnalysisInputTooLargeSnafu {
                            resource: "context head page",
                        }
                        .build()
                    })?;
                if next_bytes > crate::analysis::MAX_ANALYSIS_PAGE_BYTES {
                    break;
                }
                bytes = next_bytes;
                versions.push(version);
            }
            Ok(versions)
        })
    }

    pub(crate) fn context_heads(
        &self,
        tenant: [u8; 16],
        owner: &str,
        limit: usize,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16]
            || owner.is_empty()
            || owner.len() > 128
            || !(1..=4096).contains(&limit)
        {
            return self.reject("the context head scope is invalid");
        }
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare(
                    "SELECT entity_key, lifetime_key, MAX(owner_revision) FROM context_versions
                 WHERE tenant_id = ? AND owner_id = ?
                 GROUP BY entity_key, lifetime_key ORDER BY entity_key, lifetime_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare context heads",
                })?;
            let rows = statement
                .query_map(
                    params![tenant.as_slice(), owner, (limit + 1) as u32],
                    |row| {
                        Ok(AnalysisContextKeyV1 {
                            tenant_id: tenant,
                            owner_id: owner.to_owned(),
                            entity_key: row.get(0)?,
                            lifetime_key: row.get(1)?,
                            owner_revision: row.get(2)?,
                        })
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read context heads",
                })?;
            let mut versions = Vec::new();
            for row in rows {
                let key = row.context(AnalysisDatabaseSnafu {
                    operation: "decode context head",
                })?;
                if versions.len() == limit {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "context heads",
                    }
                    .fail();
                }
                let (version, _) = Self::read_context_from(reader, &self.root, &key)?
                    .ok_or_else(|| self.state_error("the context head is absent"))?;
                versions.push(version);
            }
            Ok(versions)
        })
    }
}
