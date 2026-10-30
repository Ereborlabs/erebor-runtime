use std::path::Path;

use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use super::AnalysisStore;
use crate::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisDatabaseSnafu, NotificationGrantV1,
    NotificationObligationV1, Result, NOTIFICATION_STATE_OWNER,
};

#[derive(Clone, Copy)]
pub enum NotificationLookup<'a> {
    Finding(&'a str, Option<&'a str>),
    Concern([u8; 16], &'a str),
}

const VALIDATION_PAGE_ROWS: i64 = 256;

pub(in crate::analysis) struct NotificationKeys {
    pub state: Vec<u8>,
    pub finding: Option<Vec<u8>>,
    pub concern: Option<Vec<u8>>,
}

impl NotificationKeys {
    pub(in crate::analysis) fn state(tenant: [u8; 16], notification: &[u8]) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(tenant, notification)).context(crate::AnalysisKeyEncodeSnafu)
    }

    fn lookup(tenant: [u8; 16], lookup: NotificationLookup<'_>) -> Result<Vec<u8>> {
        match lookup {
            NotificationLookup::Finding(finding, action) => {
                rmp_serde::to_vec(&(tenant, finding, action)).context(crate::AnalysisKeyEncodeSnafu)
            }
            NotificationLookup::Concern(concern, route) => {
                rmp_serde::to_vec(&(tenant, concern, route)).context(crate::AnalysisKeyEncodeSnafu)
            }
        }
    }

    pub fn from_context(context: &AnalysisContextVersionV1) -> Result<Self> {
        let state = NotificationObligationV1::try_from(context)?;
        let finding = state
            .finding
            .as_ref()
            .map(|finding| {
                Self::lookup(
                    state.key.tenant_id,
                    NotificationLookup::Finding(
                        &finding.finding_id,
                        state.required_action.as_deref(),
                    ),
                )
            })
            .transpose()?;
        let concern = state
            .unconfirmed_concern
            .as_ref()
            .zip(state.route.as_ref())
            .map(|(concern, route)| {
                Self::lookup(
                    state.key.tenant_id,
                    NotificationLookup::Concern(concern.concern_id, &route.route_id),
                )
            })
            .transpose()?;
        Ok(Self {
            state: Self::state(state.key.tenant_id, &state.key.notification_id)?,
            finding,
            concern,
        })
    }
}

impl AnalysisStore {
    pub(in crate::analysis) fn notification_state_head(
        &self,
        tenant: [u8; 16],
        entity: &[u8],
    ) -> Result<Option<AnalysisContextVersionV1>> {
        let state_key = NotificationKeys::state(tenant, entity)?;
        self.read_snapshot(|reader| {
            let head: Option<(u64, u64)> = reader
                .query_row(
                    "SELECT owner_revision, commit_revision FROM notification_heads
                     WHERE state_key = ?",
                    params![state_key.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "read exact notification head",
                })?;
            let Some((owner_revision, commit_revision)) = head else {
                return Ok(None);
            };
            let key = AnalysisContextKeyV1 {
                tenant_id: tenant,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: entity.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision,
            };
            let (context, stored_revision) = self
                .read_context_cached_from(reader, &self.root, &key)?
                .ok_or_else(|| self.state_error("the notification head has no context version"))?;
            if stored_revision != commit_revision
                || NotificationKeys::from_context(&context)?.state != state_key
            {
                return Err(self.state_error("the notification head differs from its context"));
            }
            Ok(Some(context))
        })
    }

    pub(in crate::analysis) fn write_notification_head(
        &self,
        writer: &Connection,
        context: &AnalysisContextVersionV1,
        commit_revision: u64,
        keys: &NotificationKeys,
    ) -> Result<()> {
        let prior: Option<u64> = writer
            .query_row(
                "SELECT owner_revision FROM notification_heads WHERE state_key = ?",
                params![keys.state.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read notification head",
            })?;
        if prior.is_some_and(|revision| revision > context.key.owner_revision) {
            return Ok(());
        }
        if prior == Some(context.key.owner_revision) {
            return self.reject("the notification head revision is duplicated");
        }
        if prior.is_some() {
            writer
                .execute(
                    "DELETE FROM notification_heads WHERE state_key = ?",
                    params![keys.state.as_slice()],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "replace notification head",
                })?;
        }
        writer
            .execute(
                "INSERT INTO notification_heads VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    keys.state.as_slice(),
                    context.key.tenant_id.as_slice(),
                    context.key.entity_key.as_slice(),
                    context.key.owner_revision,
                    commit_revision,
                    keys.finding.as_deref(),
                    keys.concern.as_deref(),
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert notification head",
            })?;
        Ok(())
    }

    pub(in crate::analysis) fn notification_head_revision(
        &self,
        reader: &Connection,
        key: &AnalysisContextKeyV1,
    ) -> Result<Option<u64>> {
        let state = NotificationKeys::state(key.tenant_id, &key.entity_key)?;
        reader
            .query_row(
                "SELECT owner_revision FROM notification_heads WHERE state_key = ?",
                params![state],
                |row| row.get(0),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read expected notification head",
            })
    }

    pub fn notification_states(
        &self,
        tenant: [u8; 16],
        lookup: NotificationLookup<'_>,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        if tenant == [0; 16] {
            return self.reject("the notification lookup tenant is invalid");
        }
        let (query, limit) = match lookup {
            NotificationLookup::Finding(id, _) if !id.is_empty() => (
                "SELECT entity_key, owner_revision, commit_revision, state_key
                 FROM notification_heads WHERE finding_key = ? ORDER BY entity_key LIMIT ?",
                self.storage
                    .notification_routes
                    .and_then(|limit| limit.checked_add(2))
                    .and_then(|limit| i64::try_from(limit).ok()),
            ),
            NotificationLookup::Concern(id, route)
                if id != [0; 16] && NotificationGrantV1::identifier(route, 64) =>
            {
                (
                    "SELECT entity_key, owner_revision, commit_revision, state_key
                     FROM notification_heads WHERE concern_key = ? ORDER BY entity_key LIMIT ?",
                    Some(2),
                )
            }
            _ => return self.reject("the notification lookup is invalid"),
        };
        let lookup_key = NotificationKeys::lookup(tenant, lookup)?;
        self.read_snapshot(|reader| {
            let mut statement = reader
                .prepare_cached(query)
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare notification lookup",
                })?;
            let heads = statement
                .query_map(params![lookup_key.as_slice(), limit], |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read notification heads",
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode notification heads",
                })?;
            heads
                .into_iter()
                .map(|(entity_key, owner_revision, commit_revision, state_key)| {
                    let key = AnalysisContextKeyV1 {
                        tenant_id: tenant,
                        owner_id: NOTIFICATION_STATE_OWNER.into(),
                        entity_key,
                        lifetime_key: b"obligation".to_vec(),
                        owner_revision,
                    };
                    let (context, stored_revision) =
                        Self::read_context_from(reader, &self.root, &key)?.ok_or_else(|| {
                            self.state_error("the notification head has no context version")
                        })?;
                    let keys = NotificationKeys::from_context(&context)?;
                    let matched = match lookup {
                        NotificationLookup::Finding(..) => keys.finding.as_deref(),
                        NotificationLookup::Concern(..) => keys.concern.as_deref(),
                    };
                    if stored_revision != commit_revision
                        || keys.state != state_key
                        || matched != Some(lookup_key.as_slice())
                    {
                        return Err(
                            self.state_error("the notification head lookup is inconsistent")
                        );
                    }
                    Ok(context)
                })
                .collect()
        })
    }

    pub(super) fn validate_notification_heads(writer: &Connection, root: &Path) -> Result<()> {
        let missing: bool = writer
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM (
                        SELECT tenant_id, entity_key, lifetime_key,
                            MAX(owner_revision) AS owner_revision
                        FROM context_versions WHERE owner_id = ?
                        GROUP BY tenant_id, entity_key, lifetime_key
                    ) c LEFT JOIN notification_heads h
                        ON h.tenant_id = c.tenant_id AND h.entity_key = c.entity_key
                    WHERE h.state_key IS NULL OR h.owner_revision <> c.owner_revision
                )",
                params![NOTIFICATION_STATE_OWNER],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate notification head coverage",
            })?;
        if missing {
            return Self::reject_path(root, "a notification context has no current head");
        }
        let mut after: Option<Vec<u8>> = None;
        loop {
            let mut statement = writer
                .prepare(
                    "SELECT tenant_id, entity_key, owner_revision, commit_revision,
                        state_key, finding_key, concern_key FROM notification_heads
                     WHERE CAST(? AS BLOB) IS NULL OR state_key > CAST(? AS BLOB)
                     ORDER BY state_key LIMIT ?",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare notification head validation",
                })?;
            let heads = statement
                .query_map(
                    params![after.as_deref(), after.as_deref(), VALIDATION_PAGE_ROWS],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, u64>(2)?,
                            row.get::<_, u64>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Option<Vec<u8>>>(5)?,
                            row.get::<_, Option<Vec<u8>>>(6)?,
                        ))
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read notification head validation",
                })?
                .collect::<std::result::Result<Vec<_>, _>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode notification head validation",
                })?;
            if heads.is_empty() {
                break;
            }
            for (
                tenant,
                entity_key,
                owner_revision,
                commit_revision,
                state_key,
                finding,
                concern,
            ) in heads
            {
                let tenant_id = tenant.try_into().map_err(|_| {
                    crate::AnalysisStateSnafu {
                        path: root,
                        reason: "the notification head tenant is invalid",
                    }
                    .build()
                })?;
                let key = AnalysisContextKeyV1 {
                    tenant_id,
                    owner_id: NOTIFICATION_STATE_OWNER.into(),
                    entity_key,
                    lifetime_key: b"obligation".to_vec(),
                    owner_revision,
                };
                let (context, stored_revision) = Self::read_context_from(writer, root, &key)?
                    .ok_or_else(|| {
                        crate::AnalysisStateSnafu {
                            path: root,
                            reason: "the notification head context is absent",
                        }
                        .build()
                    })?;
                let keys = NotificationKeys::from_context(&context)?;
                if stored_revision != commit_revision
                    || keys.state != state_key
                    || keys.finding != finding
                    || keys.concern != concern
                {
                    return Self::reject_path(
                        root,
                        "the notification head differs from its context",
                    );
                }
                after = Some(state_key);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
