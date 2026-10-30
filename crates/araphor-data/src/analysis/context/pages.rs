use duckdb::params;
use snafu::ResultExt as _;

use super::*;

impl AnalysisStore {
    pub fn context_head_page(
        &self,
        tenant: [u8; 16],
        owner: &str,
        after: Option<&AnalysisContextKeyV1>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16]
            || owner.is_empty()
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
            for row in rows {
                let (key, stored) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode context head page",
                })?;
                let (version, _) = Self::decode_context_row(&self.root, key, stored)?;
                self.check_cached_provenance(reader, &version)?;
                versions.push(version);
            }
            Ok(versions)
        })
    }

    pub fn context_heads(
        &self,
        tenant: [u8; 16],
        owner: &str,
        limit: usize,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16] || owner.is_empty() || limit == 0 {
            return self.reject("the context head scope is invalid");
        }
        // NULL removes the early stop when its value does not fit native BIGINT.
        let limit_value = limit
            .checked_add(1)
            .and_then(|value| i64::try_from(value).ok());
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare_cached(
                    "WITH heads AS (
                     SELECT entity_key, lifetime_key, MAX(owner_revision) AS owner_revision
                     FROM context_versions WHERE tenant_id = ? AND owner_id = ?
                     GROUP BY entity_key, lifetime_key
                     ORDER BY entity_key, lifetime_key LIMIT ?
                 ) SELECT h.entity_key, h.lifetime_key, h.owner_revision,
                     c.valid_from_utc_ns, c.valid_until_utc_ns, c.sensitivity,
                     c.body, c.commit_revision, c.version_key
                 FROM heads h LEFT JOIN context_versions c
                     ON c.tenant_id = ? AND c.owner_id = ?
                     AND c.entity_key = h.entity_key AND c.lifetime_key = h.lifetime_key
                     AND c.owner_revision = h.owner_revision
                 ORDER BY h.entity_key, h.lifetime_key",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare context heads",
                })?;
            let mut rows = statement
                .query(params![
                    tenant.as_slice(),
                    owner,
                    limit_value,
                    tenant.as_slice(),
                    owner
                ])
                .context(AnalysisDatabaseSnafu {
                    operation: "read context heads",
                })?;
            let mut versions = Vec::new();
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance context heads",
            })? {
                if versions.len() == limit {
                    return crate::AnalysisInputTooLargeSnafu {
                        resource: "context heads",
                    }
                    .fail();
                }
                let present: Option<u64> = row.get(7).context(AnalysisDatabaseSnafu {
                    operation: "decode context head presence",
                })?;
                if present.is_none() {
                    return Err(self.state_error("the context head is absent"));
                }
                let (key, stored) =
                    Self::context_row(tenant, owner, row).context(AnalysisDatabaseSnafu {
                        operation: "decode context head",
                    })?;
                let index: Vec<u8> = row.get(8).context(AnalysisDatabaseSnafu {
                    operation: "decode context head index",
                })?;
                if index != super::version_key(&key)? {
                    return Self::reject_path(
                        &self.root,
                        "the context version index has a foreign row",
                    );
                }
                let (version, _) = Self::decode_context_row(&self.root, key, stored)?;
                self.check_cached_provenance(reader, &version)?;
                versions.push(version);
            }
            Ok(versions)
        })
    }
}
