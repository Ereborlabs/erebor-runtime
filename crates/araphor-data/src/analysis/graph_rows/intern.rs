use super::*;
use crate::GraphValidate as _;

pub(super) use araphor_graph::RelationshipValue as EdgeValue;

impl GraphRows {
    pub(super) fn intern_subjects(
        writer: &Connection,
        subjects: &[GraphSubjectKeyV1],
    ) -> Result<BTreeMap<GraphSubjectKeyV1, u64>> {
        araphor_graph::SubjectRows::intern(writer, subjects).map_err(Into::into)
    }

    pub(super) fn intern_edges(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
        edges: &[EdgeValue],
    ) -> Result<Vec<u64>> {
        araphor_graph::RelationshipRows::intern(writer, subjects, records, edges)
            .map_err(Into::into)
    }

    pub(super) fn intern_findings(
        writer: &Connection,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<crate::DiscoveryRecordIdV1, u64>,
        findings: &[FindingV1],
    ) -> Result<BTreeMap<String, u64>> {
        let references = findings
            .iter()
            .map(|finding| {
                finding.validate()?;
                Ok(araphor_graph::FindingRefs {
                    finding,
                    subject: *subjects
                        .get(&finding.subject_id)
                        .ok_or_else(|| Self::invalid("graph finding subject"))?,
                    evidence: finding
                        .evidence
                        .iter()
                        .map(|record| {
                            records
                                .get(record)
                                .copied()
                                .ok_or_else(|| Self::invalid("graph finding evidence"))
                        })
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        araphor_graph::FindingRows::intern(writer, &references).map_err(Into::into)
    }

    pub(super) fn intern_branches(
        writer: &Connection,
        tenant: [u8; 16],
        branches: &[GraphBranchV1],
    ) -> Result<Vec<u64>> {
        if branches.is_empty() {
            return Ok(Vec::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_branches(ordinal UBIGINT,tenant_id BLOB,value_hash BLOB,body BLOB)").context(AnalysisDatabaseSnafu {operation:"create Graph branch candidates"})?;
        {
            let mut appender =
                writer
                    .appender("graph_value_branches")
                    .context(AnalysisDatabaseSnafu {
                        operation: "open Graph branch candidates",
                    })?;
            for (ordinal, branch) in branches.iter().enumerate() {
                Self::check_branch(branch, tenant)?;
                let body = Self::encode_value(branch)?;
                appender
                    .append_row(params![
                        ordinal as u64,
                        tenant.as_slice(),
                        Self::hash(&body),
                        body
                    ])
                    .context(AnalysisDatabaseSnafu {
                        operation: "append Graph branch candidate",
                    })?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush Graph branch candidates",
            })?;
        }
        writer.execute_batch("INSERT INTO graph_branch_values SELECT nextval('graph_branch_values_seq'),c.* FROM (SELECT DISTINCT tenant_id,value_hash,body FROM graph_value_branches) c WHERE NOT EXISTS(SELECT 1 FROM graph_branch_values v WHERE v.tenant_id=c.tenant_id AND v.value_hash=c.value_hash AND v.body=c.body)").context(AnalysisDatabaseSnafu {operation:"intern Graph branch candidates"})?;
        let mut statement=writer.prepare("SELECT c.ordinal,v.branch_id FROM graph_value_branches c JOIN graph_branch_values v ON v.tenant_id=c.tenant_id AND v.value_hash=c.value_hash AND v.body=c.body ORDER BY c.ordinal").context(AnalysisDatabaseSnafu {operation:"prepare Graph branch references"})?;
        let mut rows = statement.query([]).context(AnalysisDatabaseSnafu {
            operation: "read Graph branch references",
        })?;
        let mut values = Vec::with_capacity(branches.len());
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance Graph branch references",
        })? {
            if Self::column::<u64>(row, 0)? != values.len() as u64 {
                return Err(Self::invalid("graph duplicate branch value"));
            }
            values.push(Self::column(row, 1)?);
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_branches")
            .context(AnalysisDatabaseSnafu {
                operation: "release Graph branch candidates",
            })?;
        if values.len() != branches.len() {
            return Err(Self::invalid("graph branch candidate count"));
        }
        Ok(values)
    }
}
