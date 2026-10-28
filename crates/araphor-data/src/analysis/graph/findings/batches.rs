use duckdb::{Connection, ToSql};
use std::collections::BTreeMap;

use super::*;

impl AnalysisStore {
    pub(super) fn collect_findings(
        &self,
        snapshot: &Connection,
        keys: Vec<FindingKey>,
        tenant: [u8; 16],
    ) -> Result<Vec<(String, FindingV1)>> {
        let mut headers = BTreeMap::new();
        let mut output = Vec::new();
        for batch in keys.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            self.collect_batch(snapshot, batch, tenant, &mut headers, &mut output)?;
        }
        Ok(output)
    }

    fn collect_batch(
        &self,
        snapshot: &Connection,
        keys: &[FindingKey],
        tenant: [u8; 16],
        headers: &mut BTreeMap<String, GraphHeader>,
        output: &mut Vec<(String, FindingV1)>,
    ) -> Result<()> {
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
            output.push((key.result.clone(), finding));
            read += 1;
        }
        if read != keys.len() {
            return self.reject("the selected native finding is absent");
        }
        Ok(())
    }

    pub(super) fn cached_finding_header<'a>(
        &self,
        snapshot: &Connection,
        headers: &'a mut BTreeMap<String, GraphHeader>,
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
