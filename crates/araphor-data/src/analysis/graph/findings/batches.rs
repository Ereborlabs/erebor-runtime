use duckdb::{Connection, ToSql};

use super::*;
use crate::GraphEncodingSnafu;

struct FindingOutput {
    budget: Option<crate::discovery::InputByteLimit>,
    findings: Vec<(String, FindingV1)>,
}

impl FindingOutput {
    fn new(bytes: usize) -> Self {
        Self {
            budget: (bytes != usize::MAX)
                .then(|| crate::discovery::InputByteLimit(bytes.saturating_sub(2))),
            findings: Vec::new(),
        }
    }

    fn push(&mut self, id: String, finding: FindingV1) -> Result<bool> {
        if let Some(budget) = &mut self.budget {
            if !self.findings.is_empty() {
                budget.0 = budget.0.saturating_sub(1);
            }
            if let Err(error) = serde_json::to_writer(budget, &(&id, &finding)) {
                if self.findings.is_empty() {
                    return Err(error).context(GraphEncodingSnafu);
                }
                return Ok(false);
            }
        }
        self.findings.push((id, finding));
        Ok(true)
    }
}

impl FindingKey {
    fn batch_end(keys: &[Self], first: usize) -> usize {
        let mut bytes = 0_u64;
        let mut end = first;
        for key in keys[first..]
            .iter()
            .take(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
        {
            let charge = key
                .bytes
                .saturating_add((key.result.len() + key.finding.len() + 32) as u64);
            if bytes.saturating_add(charge) > GraphRows::MAX_CANONICAL_BYTES as u64 {
                break;
            }
            bytes += charge;
            end += 1;
        }
        end
    }
}

impl AnalysisStore {
    pub(super) fn collect_findings(
        &self,
        snapshot: &Connection,
        selection: FindingSelection,
        tenant: [u8; 16],
        bytes: usize,
    ) -> Result<Vec<(String, FindingV1)>> {
        let FindingSelection { keys, mut headers } = selection;
        let mut output = FindingOutput::new(bytes);
        let mut first = 0;
        while first < keys.len() {
            let end = FindingKey::batch_end(&keys, first);
            let complete = if end == first {
                let key = &keys[first];
                let header = self.cached_finding_header(snapshot, &mut headers, tenant, key)?;
                let finding =
                    GraphRows::read_finding(snapshot, &key.result, &key.finding, header, None)?
                        .ok_or_else(|| self.state_error("the current native finding is absent"))?;
                first += 1;
                output.push(key.result.clone(), finding)?
            } else {
                let complete = self.collect_batch(
                    snapshot,
                    &keys[first..end],
                    tenant,
                    &mut headers,
                    &mut output,
                )?;
                first = end;
                complete
            };
            if !complete {
                break;
            }
        }
        Ok(output.findings)
    }

    fn collect_batch(
        &self,
        snapshot: &Connection,
        keys: &[FindingKey],
        tenant: [u8; 16],
        headers: &mut FindingHeaders,
        output: &mut FindingOutput,
    ) -> Result<bool> {
        let positions = (0..keys.len())
            .map(|index| index as i64)
            .collect::<Vec<_>>();
        let values = keys
            .iter()
            .zip(&positions)
            .flat_map(|(key, position)| {
                [
                    &key.result as &dyn ToSql,
                    &key.finding as &dyn ToSql,
                    position as &dyn ToSql,
                ]
            })
            .collect::<Vec<_>>();
        let mut statement =
            snapshot
                .prepare(&Self::finding_query(keys.len()))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected native finding batch",
                })?;
        let mut rows = statement
            .query(values.as_slice())
            .context(AnalysisDatabaseSnafu {
                operation: "select current native findings",
            })?;
        let mut read = 0;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read current native finding batch",
        })? {
            let position: i64 = row.get(18).context(AnalysisDatabaseSnafu {
                operation: "decode native finding position",
            })?;
            if position != read as i64 || read >= keys.len() {
                return self.reject("the selected native finding is absent");
            }
            let key = &keys[read];
            let header = self.cached_finding_header(snapshot, headers, tenant, key)?;
            let finding = GraphRows::decode_finding(row, header)?;
            if !output.push(key.result.clone(), finding)? {
                return Ok(false);
            }
            read += 1;
        }
        if read != keys.len() {
            return self.reject("the selected native finding is absent");
        }
        Ok(true)
    }

    fn cached_finding_header<'a>(
        &self,
        snapshot: &Connection,
        headers: &'a mut FindingHeaders,
        tenant: [u8; 16],
        key: &FindingKey,
    ) -> Result<&'a GraphHeader> {
        if headers.get(&key.result).is_none() {
            let header = GraphRows::read_header(snapshot, tenant, &key.result)?
                .ok_or_else(|| self.state_error("the current graph header is absent"))?;
            headers.insert(key.result.clone(), header);
        }
        headers
            .get(&key.result)
            .ok_or_else(|| self.state_error("the current graph header is absent"))
    }
}
