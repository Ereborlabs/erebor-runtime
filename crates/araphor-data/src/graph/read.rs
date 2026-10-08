use std::collections::BTreeMap;

use snafu::ResultExt as _;

use super::*;
use crate::{EvidenceIntakeIdentityV1, GraphEncodingSnafu, GraphInvalidSnafu};

#[cfg(test)]
pub(super) mod tests;

impl GraphAndFindingOwner {
    pub fn snapshot(&self, source: &EvidenceIntakeIdentityV1) -> Result<Option<GraphSnapshotV1>> {
        self.store
            .processor_result(&Self::scope(source))?
            .map(|result| GraphSnapshotV1::try_from(result.body.as_slice()))
            .transpose()
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
        let keys = self.current_finding_keys(tenant, after_finding_id, exact_finding_id, limit)?;
        self.read_current_findings(tenant, keys, bytes)
    }

    fn current_finding_keys(
        &self,
        tenant: [u8; 16],
        after_finding_id: Option<&str>,
        exact_finding_id: Option<&str>,
        limit: usize,
    ) -> Result<BTreeMap<String, (u64, String)>> {
        let mut selected = BTreeMap::<String, (u64, String)>::new();
        let mut after = None;
        loop {
            let page = self
                .store
                .graph_snapshots(tenant, None, after.as_deref(), true)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.0.clone());
            for (result_id, snapshot, revision) in page {
                for finding in snapshot.findings {
                    if after_finding_id.is_some_and(|id| finding.finding_id.as_str() <= id)
                        || exact_finding_id.is_some_and(|id| finding.finding_id != id)
                    {
                        continue;
                    }
                    if selected
                        .get(&finding.finding_id)
                        .is_some_and(|(previous, _)| *previous >= revision)
                    {
                        continue;
                    }
                    selected.insert(finding.finding_id, (revision, result_id.clone()));
                    if selected.len() > limit {
                        selected.pop_last();
                    }
                }
            }
        }
        Ok(selected)
    }

    fn read_current_findings(
        &self,
        tenant: [u8; 16],
        keys: BTreeMap<String, (u64, String)>,
        bytes: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        let mut current: Option<(String, GraphSnapshotV1)> = None;
        let mut budget = crate::discovery::InputByteLimit(bytes.saturating_sub(2));
        let mut findings = Vec::new();
        for (finding_id, (_, result_id)) in keys {
            if current.as_ref().is_none_or(|(id, _)| id != &result_id) {
                let graph = self
                    .store
                    .graph_result(tenant, &result_id)?
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "current graph result",
                        }
                        .build()
                    })?;
                current = Some((result_id.clone(), graph));
            }
            let (_, graph) = current.as_mut().ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "current graph result",
                }
                .build()
            })?;
            let index = graph
                .findings
                .iter()
                .position(|finding| finding.finding_id == finding_id)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "current finding reference",
                    }
                    .build()
                })?;
            let finding = graph.findings.swap_remove(index);
            if !findings.is_empty() {
                budget.0 = budget.0.saturating_sub(1);
            }
            if let Err(error) = serde_json::to_writer(&mut budget, &(&result_id, &finding)) {
                if findings.is_empty() {
                    return Err(error).context(GraphEncodingSnafu);
                }
                break;
            }
            findings.push((result_id, finding));
        }
        Ok(findings)
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
        Ok(self
            .store
            .graph_result(tenant, result_id)?
            .and_then(|snapshot| {
                snapshot
                    .findings
                    .into_iter()
                    .find(|finding| finding.finding_id == finding_id)
            }))
    }

    pub fn finding(
        &self,
        tenant: [u8; 16],
        id: &str,
        revision: &GraphRevisionV1,
    ) -> Result<Option<FindingV1>> {
        revision.validate(tenant)?;
        let mut after = None;
        loop {
            let page = self
                .store
                .graph_snapshots(tenant, None, after.as_deref(), false)?;
            if page.is_empty() {
                return Ok(None);
            }
            after = page.last().map(|row| row.0.clone());
            for (_, snapshot, _) in page {
                if let Some(finding) = snapshot
                    .findings
                    .into_iter()
                    .find(|finding| finding.finding_id == id && &finding.revision == revision)
                {
                    return Ok(Some(finding));
                }
            }
        }
    }
}
