use std::mem::size_of_val;

use super::*;
use crate::analysis::context::{version_key, VerifiedPackages};

impl AnalysisStore {
    const CONTEXT_CHANGES_SQL: &'static str =
        "SELECT tenant_id, owner_id, entity_key, lifetime_key, owner_revision,
            commit_revision, version_key
         FROM context_versions WHERE commit_revision > ?
         ORDER BY commit_revision, owner_id, entity_key, lifetime_key, owner_revision";

    pub(in crate::analysis::extraction) fn extract_context_changes(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        after: u64,
        owners: Option<&BTreeSet<String>>,
        budget: &mut ReadBudget<'_>,
        capture: &mut tables::Capture<'_>,
    ) -> Result<()> {
        if capture.read.projected("context_versions").is_none()
            || selection.contexts.is_empty()
            || owners.is_some_and(BTreeSet::is_empty)
        {
            return Ok(());
        }
        budget.check()?;
        let mut statement =
            snapshot
                .prepare_cached(Self::CONTEXT_CHANGES_SQL)
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare committed context changes",
                })?;
        let mut rows = statement
            .query(params![after])
            .context(AnalysisDatabaseSnafu {
                operation: "read committed context changes",
            })?;
        let control = budget.control;
        let mut verified = VerifiedPackages::default();
        let mut count = capture.key_count();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance committed context changes",
        })? {
            budget.check()?;
            let key = AnalysisContextKeyV1 {
                tenant_id: row
                    .get::<_, Vec<u8>>(0)
                    .context(AnalysisDatabaseSnafu {
                        operation: "decode changed context tenant",
                    })?
                    .try_into()
                    .map_err(|_| self.state_error("the changed context tenant is invalid"))?,
                owner_id: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "decode changed context owner",
                })?,
                entity_key: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode changed context entity",
                })?,
                lifetime_key: row.get(3).context(AnalysisDatabaseSnafu {
                    operation: "decode changed context lifetime",
                })?,
                owner_revision: row.get(4).context(AnalysisDatabaseSnafu {
                    operation: "decode changed context revision",
                })?,
            };
            let stored_key: Vec<u8> = row.get(6).context(AnalysisDatabaseSnafu {
                operation: "decode changed context index key",
            })?;
            let transient = size_of_val(&key)
                + key.owner_id.capacity()
                + key.entity_key.capacity()
                + key.lifetime_key.capacity()
                + stored_key.capacity();
            budget.charge(transient)?;
            if key.tenant_id != selection.tenant_id
                || owners.is_some_and(|owners| !owners.contains(&key.owner_id))
                || matches!(&selection.contexts, Selection::Exact(keys) if !keys.contains(&key))
            {
                budget.output.input_bytes -= transient;
                continue;
            }
            if stored_key != version_key(&key)? {
                return self.reject("the changed context index key is invalid");
            }
            let expected: u64 = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "decode changed context commit",
            })?;
            if expected <= after || expected > budget.output.meta.commit_revision {
                return self.reject("the context change exceeds its captured revision");
            }
            if budget
                .output
                .limits
                .keys
                .is_some_and(|limit| count >= limit)
            {
                return AnalysisInputTooLargeSnafu {
                    resource: "selected input keys",
                }
                .fail();
            }
            budget.check()?;
            let (context, revision) = self
                .read_context_verified_from(snapshot, &self.root, &key, &mut verified)?
                .ok_or_else(|| self.state_error("the changed context value is absent"))?;
            if revision != expected {
                return self.reject("the changed context value differs from its header");
            }
            let value_bytes = size_of_val(&context)
                + context.key.owner_id.capacity()
                + context.key.entity_key.capacity()
                + context.key.lifetime_key.capacity()
                + context.body.capacity();
            budget.charge(value_bytes)?;
            budget.output.scan(context.body.len())?;
            budget.output.reference_context(
                &context.key,
                revision,
                AnalysisReferenceOriginV1::Context,
            )?;
            capture.context(&context, revision, budget)?;
            count += 1;
            drop((context, key, stored_key));
            budget.output.input_bytes -= transient + value_bytes;
            #[cfg(any(test, feature = "test-fixtures"))]
            control.test_read_step()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
