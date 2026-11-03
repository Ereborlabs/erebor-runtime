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
        let bodies = branches
            .iter()
            .map(|branch| {
                Self::check_branch(branch, tenant)?;
                Self::encode_value(branch)
            })
            .collect::<Result<Vec<_>>>()?;
        Self::intern_values(writer, tenant, MemberKind::Branch, bodies)
    }

    pub(super) fn intern_values(
        writer: &Connection,
        tenant: [u8; 16],
        kind: MemberKind,
        bodies: Vec<Vec<u8>>,
    ) -> Result<Vec<u64>> {
        let (table, column, sequence, operation) = match kind {
            MemberKind::Fact => (
                "graph_fact_values",
                "fact_id",
                "graph_fact_values_seq",
                "intern Graph metadata facts",
            ),
            MemberKind::Branch => (
                "graph_branch_values",
                "branch_id",
                "graph_branch_values_seq",
                "intern Graph branch candidates",
            ),
            _ => return Err(Self::invalid("graph typed value kind")),
        };
        let mut ids = vec![0; bodies.len()];
        let mut values = BTreeMap::<Vec<u8>, Vec<usize>>::new();
        for (ordinal, body) in bodies.into_iter().enumerate() {
            values.entry(body).or_default().push(ordinal);
        }
        if values.is_empty() {
            return Ok(ids);
        }
        let mut missing = Vec::new();
        let mut statement = writer
            .prepare(&format!(
                "WITH candidates AS MATERIALIZED (SELECT {column},tenant_id FROM {table} WHERE body=?)
                 SELECT {column} FROM candidates WHERE tenant_id=?"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare Graph typed value candidates",
            })?;
        for (body, ordinals) in &values {
            let mut rows = statement.query(params![body, tenant.as_slice()]).context(
                AnalysisDatabaseSnafu {
                    operation: "read Graph typed value candidates",
                },
            )?;
            let value = rows
                .next()
                .context(AnalysisDatabaseSnafu {
                    operation: "advance Graph typed value candidates",
                })?
                .map(|row| Self::column::<u64>(row, 0))
                .transpose()?;
            if value == Some(0)
                || rows
                    .next()
                    .context(AnalysisDatabaseSnafu {
                        operation: "check unique Graph typed value",
                    })?
                    .is_some()
            {
                return Err(Self::invalid("graph duplicate typed value"));
            }
            if let Some(value) = value {
                for ordinal in ordinals {
                    ids[*ordinal] = value;
                }
            } else {
                missing.push((body.as_slice(), ordinals.as_slice()));
            }
        }
        drop(statement);
        if !missing.is_empty() {
            let count = i64::try_from(missing.len())
                .map_err(|_| Self::invalid("graph typed value count"))?;
            let mut statement = writer
                .prepare(&format!("SELECT nextval('{sequence}') FROM range(?)"))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph typed value identities",
                })?;
            let allocated = statement
                .query_map(params![count], |row| row.get::<_, u64>(0))
                .context(AnalysisDatabaseSnafu {
                    operation: "allocate Graph typed value identities",
                })?
                .collect::<duckdb::Result<Vec<_>>>()
                .context(AnalysisDatabaseSnafu {
                    operation: "decode Graph typed value identities",
                })?;
            if allocated.len() != missing.len() || allocated.contains(&0) {
                return Err(Self::invalid("graph typed value count"));
            }
            drop(statement);
            let mut appender = writer.appender(table).context(AnalysisDatabaseSnafu {
                operation: "open Graph typed values",
            })?;
            for ((body, ordinals), value) in missing.into_iter().zip(allocated) {
                appender
                    .append_row(params![value, tenant.as_slice(), body])
                    .context(AnalysisDatabaseSnafu { operation })?;
                for ordinal in ordinals {
                    ids[*ordinal] = value;
                }
            }
            appender
                .flush()
                .context(AnalysisDatabaseSnafu { operation })?;
        }
        Ok(ids)
    }
}
