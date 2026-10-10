use duckdb::Connection;
use std::collections::{BTreeMap, BTreeSet};

use super::*;

pub(super) struct FindingKey {
    pub(super) result: String,
    pub(super) finding: String,
    pub(super) bytes: u64,
}

#[derive(Default)]
pub(super) struct FindingSelection {
    pub(super) headers: FindingHeaders,
    pub(super) keys: Vec<FindingKey>,
}

#[derive(Default)]
pub(super) struct FindingHeaders {
    headers: BTreeMap<String, GraphHeader>,
    bytes: usize,
}

impl FindingHeaders {
    pub(super) fn get(&self, id: &str) -> Option<&GraphHeader> {
        self.headers.get(id)
    }

    pub(super) fn insert(&mut self, id: String, header: GraphHeader) {
        let charge = header.snapshot_bytes + 384;
        if self.bytes.saturating_add(charge) > GraphRows::MAX_CANONICAL_BYTES + 384 {
            self.headers.clear();
            self.bytes = 0;
        }
        self.bytes += charge;
        self.headers.insert(id, header);
    }
}

impl AnalysisStore {
    pub(super) fn preflight_findings(
        &self,
        snapshot: &Connection,
        tenant: [u8; 16],
        values: &[&dyn duckdb::ToSql],
    ) -> Result<FindingSelection> {
        let mut selection = FindingSelection {
            headers: FindingHeaders::default(),
            keys: self.selected_finding_keys(snapshot, values)?,
        };
        let results = selection
            .keys
            .iter()
            .map(|key| key.result.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut charges = BTreeMap::new();
        for ids in results.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            self.check_finding_versions(
                snapshot,
                tenant,
                ids,
                &mut selection.headers,
                &mut charges,
            )?;
        }
        drop(results);
        for key in &mut selection.keys {
            key.bytes = *charges
                .get(&key.result)
                .ok_or_else(|| self.state_error("the selected graph bounds are absent"))?;
        }
        Ok(selection)
    }

    fn selected_finding_keys(
        &self,
        snapshot: &Connection,
        values: &[&dyn duckdb::ToSql],
    ) -> Result<Vec<FindingKey>> {
        let mut statement =
            snapshot
                .prepare(Self::finding_selection())
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected native finding keys",
                })?;
        let mut rows = statement.query(values).context(AnalysisDatabaseSnafu {
            operation: "select native finding keys",
        })?;
        let mut keys = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read selected native finding keys",
        })? {
            let result: Option<String> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode selected graph reference",
            })?;
            let result =
                result.ok_or_else(|| self.state_error("the graph result reference is invalid"))?;
            let finding: Option<String> = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode selected native finding key",
            })?;
            let finding =
                finding.ok_or_else(|| self.state_error("the native finding key is invalid"))?;
            keys.push(FindingKey {
                result,
                finding,
                bytes: 0,
            });
        }
        Ok(keys)
    }

    fn check_finding_versions(
        &self,
        snapshot: &Connection,
        tenant: [u8; 16],
        ids: &[&str],
        headers: &mut FindingHeaders,
        charges: &mut BTreeMap<String, u64>,
    ) -> Result<()> {
        let maximum = GraphRows::MAX_CANONICAL_BYTES as u64;
        let header_bytes = GraphHeader::MAX_BYTES as u64;
        let stream_bytes = crate::EvidenceIntakeIdentityV1::MAX_KEY_BYTES as u64;
        let mut values = ids
            .iter()
            .map(|id| id as &dyn duckdb::ToSql)
            .collect::<Vec<_>>();
        values.extend([
            &maximum as &dyn duckdb::ToSql,
            &header_bytes as &dyn duckdb::ToSql,
            &stream_bytes as &dyn duckdb::ToSql,
        ]);
        let mut statement = snapshot
            .prepare(&Self::finding_preflight(ids.len()))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare selected native graph bounds",
            })?;
        let mut rows = statement
            .query(values.as_slice())
            .context(AnalysisDatabaseSnafu {
                operation: "select native graph bounds",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read selected native graph bounds",
        })? {
            let id: Option<String> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode bounded graph reference",
            })?;
            let id = id.ok_or_else(|| self.state_error("the graph result reference is invalid"))?;
            let included: bool = row.get(6).context(AnalysisDatabaseSnafu {
                operation: "decode bounded graph header marker",
            })?;
            let header = if included {
                self.finding_header(row, tenant)?
            } else {
                GraphRows::read_header(snapshot, tenant, &id)?
                    .ok_or_else(|| self.state_error("the current graph header is absent"))?
            };
            let stored: u64 = row.get(5).context(AnalysisDatabaseSnafu {
                operation: "decode selected native graph bytes",
            })?;
            header.check_bytes(&id, stored)?;
            headers.insert(id.clone(), header);
            charges.insert(id, stored);
        }
        for id in ids {
            if !charges.contains_key(*id) {
                return self.reject("the selected graph bounds are absent");
            }
        }
        Ok(())
    }
}
