use super::*;
use crate::{EvidenceIntakeIdentityV1, GraphInvalidSnafu};

#[cfg(test)]
pub(super) mod tests;

impl GraphAndFindingOwner {
    pub fn snapshot(&self, source: &EvidenceIntakeIdentityV1) -> Result<Option<GraphSnapshotV1>> {
        self.store.graph_snapshot(source)
    }

    pub fn snapshot_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
    ) -> Result<Option<GraphSnapshotV1>> {
        self.store.graph_result(tenant, result_id)
    }

    pub fn findings(&self, tenant: [u8; 16]) -> Result<Vec<FindingV1>> {
        Ok(self
            .current_findings(tenant)?
            .into_iter()
            .map(|(_, finding)| finding)
            .collect())
    }

    pub fn current_findings(&self, tenant: [u8; 16]) -> Result<Vec<(String, FindingV1)>> {
        self.select_current_findings(tenant, None, None, usize::MAX, usize::MAX)
    }

    pub fn next_current_findings(
        &self,
        tenant: [u8; 16],
        after_finding_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        if !(1..=crate::analysis::MAX_ANALYSIS_PAGE_RECORDS).contains(&limit) {
            return GraphInvalidSnafu {
                field: "finding page limit",
            }
            .fail();
        }
        self.select_current_findings(
            tenant,
            after_finding_id,
            None,
            limit,
            crate::analysis::MAX_RESULT_BYTES,
        )
    }

    pub fn next_current_finding(
        &self,
        tenant: [u8; 16],
        after_finding_id: Option<&str>,
    ) -> Result<Option<(String, FindingV1)>> {
        Ok(self
            .next_current_findings(tenant, after_finding_id, 1)?
            .pop())
    }

    pub fn current_finding(
        &self,
        tenant: [u8; 16],
        finding_id: &str,
    ) -> Result<Option<(String, FindingV1)>> {
        Ok(self
            .select_current_findings(
                tenant,
                None,
                Some(finding_id),
                1,
                crate::analysis::MAX_RESULT_BYTES,
            )?
            .pop())
    }

    fn select_current_findings(
        &self,
        tenant: [u8; 16],
        after_finding_id: Option<&str>,
        exact_finding_id: Option<&str>,
        limit: usize,
        bytes: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        if tenant == [0; 16]
            || [after_finding_id, exact_finding_id]
                .into_iter()
                .flatten()
                .any(|id| id.is_empty() || id.len() > 4096)
        {
            return GraphInvalidSnafu {
                field: "finding page scope",
            }
            .fail();
        }
        let _operation = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        self.store
            .graph_findings(tenant, after_finding_id, exact_finding_id, limit, bytes)
    }

    pub fn finding_result(
        &self,
        tenant: [u8; 16],
        result_id: &str,
        finding_id: &str,
    ) -> Result<Option<FindingV1>> {
        if finding_id.is_empty() || finding_id.len() > 4096 {
            return GraphInvalidSnafu {
                field: "finding reference",
            }
            .fail();
        }
        self.store.graph_finding(tenant, result_id, finding_id)
    }

    pub fn finding(
        &self,
        tenant: [u8; 16],
        id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
        revision.validate(tenant)?;
        self.store.graph_revision_finding(tenant, id, revision)
    }
}
