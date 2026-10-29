use super::{GraphHeader, GraphRows};
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, FindingV1, GraphInvalidSnafu, Result};
use araphor_graph::FindingRows;
use duckdb::{params, params_from_iter, types::Value, Connection, Row};
use snafu::ResultExt as _;
use std::collections::{BTreeMap, BTreeSet};

use crate::DiscoveryValidate as _;
use crate::{DiscoveryRecordIdV1, GraphSubjectKeyV1};

pub(in crate::analysis) type NativeFindingRefs = (
    BTreeMap<u64, GraphSubjectKeyV1>,
    BTreeMap<u64, DiscoveryRecordIdV1>,
);

impl GraphRows {
    fn finding(
        row: &Row<'_>,
        header: &GraphHeader,
        references: &NativeFindingRefs,
    ) -> Result<FindingV1> {
        let (subject_id, evidence_ids) = FindingRows::references(row)?;
        let subject = references.0.get(&subject_id).cloned().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph finding subject reference",
            }
            .build()
        })?;
        let evidence = evidence_ids
            .into_iter()
            .map(|id| {
                references.1.get(&id).cloned().ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph finding evidence reference",
                    }
                    .build()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let finding = FindingRows::decode(row, subject, evidence)?;
        if finding.tenant_id != header.snapshot.scope.identity.tenant_id {
            return GraphInvalidSnafu {
                field: "graph finding tenant",
            }
            .fail();
        }
        header.snapshot.input_manifest.validate_finding(&finding)?;
        Ok(finding)
    }

    pub(in crate::analysis) fn finding_references(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        selected: Option<&[&str]>,
        control: Option<&AnalysisReadControl>,
    ) -> Result<NativeFindingRefs> {
        let mut subject_ids = BTreeSet::new();
        let mut evidence_ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let all = selected.is_none();
        let selected = selected.unwrap_or(&[]);
        if !all && selected.is_empty() {
            return Ok((BTreeMap::new(), BTreeMap::new()));
        }
        let chunks: Vec<&[&str]> = if selected.is_empty() {
            vec![&[]]
        } else {
            selected
                .chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS)
                .collect()
        };
        for chunk in chunks {
            if let Some(control) = control {
                control.check()?;
            }
            let filter = if chunk.is_empty() {
                String::new()
            } else {
                format!(
                    " AND finding_id IN ({})",
                    std::iter::repeat_n("?", chunk.len())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let mut values = vec![Value::Text(result_id.into())];
            values.extend(chunk.iter().map(|name| Value::Text((*name).into())));
            let mut statement = writer
                .prepare(&format!(
                    "SELECT finding_id, subject_ref, evidence_refs FROM graph_findings
                     WHERE result_id = ?{filter}"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected finding references",
                })?;
            let mut rows = statement.query(params_from_iter(values.iter())).context(
                AnalysisDatabaseSnafu {
                    operation: "read selected finding references",
                },
            )?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance selected finding references",
            })? {
                if let Some(control) = control {
                    control.check()?;
                }
                let name: String = Self::column(row, 0)?;
                if !names.insert(name) {
                    return GraphInvalidSnafu {
                        field: "duplicate graph finding identity",
                    }
                    .fail();
                }
                let subject: u64 = Self::column(row, 1)?;
                subject_ids.insert(subject);
                for evidence in FindingRows::evidence_references(row, 2)? {
                    evidence_ids.insert(evidence);
                }
            }
        }
        if subject_ids.len() > header.subject_count || evidence_ids.len() > header.evidence_count {
            return GraphInvalidSnafu {
                field: "graph finding reference count",
            }
            .fail();
        }
        let mut subjects = BTreeMap::new();
        let subject_ids = subject_ids.into_iter().collect::<Vec<_>>();
        for chunk in subject_ids.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            if let Some(control) = control {
                control.check()?;
            }
            let filter = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut values = vec![Value::Text(result_id.into())];
            values.extend(chunk.iter().map(|id| Value::UBigInt(*id)));
            let mut statement = writer
                .prepare(&format!(
                    "SELECT 0::UINTEGER, s.tenant_id, s.authority_rank, s.authority_text,
                    s.authority_boot, s.authority_epoch, s.subject_kind, s.identity,
                    s.subject_id
                 FROM graph_versions v
                 JOIN graph_subject_membership m ON m.lineage_id = v.lineage_id
                    AND m.valid_from <= v.commit_revision
                    AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                 JOIN graph_subject_values s USING (subject_id)
                 WHERE v.result_id = ? AND s.subject_id IN ({filter})"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare finding subject references",
                })?;
            let mut rows = statement.query(params_from_iter(values.iter())).context(
                AnalysisDatabaseSnafu {
                    operation: "read finding subject references",
                },
            )?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance finding subject references",
            })? {
                if let Some(control) = control {
                    control.check()?;
                }
                let id: u64 = Self::column(row, 8)?;
                let subject = Self::decode_subject(row)?;
                if subject.tenant_id != header.snapshot.scope.identity.tenant_id
                    || subjects.insert(id, subject).is_some()
                {
                    return GraphInvalidSnafu {
                        field: "graph finding subject reference",
                    }
                    .fail();
                }
            }
        }
        if subjects.len() != subject_ids.len() {
            return GraphInvalidSnafu {
                field: "graph finding subject reference",
            }
            .fail();
        }

        let key = header.snapshot.scope.identity.key();
        let mut evidence = BTreeMap::new();
        let evidence_ids = evidence_ids.into_iter().collect::<Vec<_>>();
        for chunk in evidence_ids.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            if let Some(control) = control {
                control.check()?;
            }
            let filter = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut values = vec![Value::Text(result_id.into())];
            values.extend(chunk.iter().map(|id| Value::UBigInt(*id)));
            let mut statement = writer
                .prepare(&format!(
                    "SELECT e.evidence_id, s.stream_key, s.tenant_id, e.cpu_id, e.durable_cursor
                 FROM graph_versions v
                 JOIN graph_evidence_membership m ON m.lineage_id = v.lineage_id
                    AND m.valid_from <= v.commit_revision
                    AND (m.valid_to IS NULL OR m.valid_to > v.commit_revision)
                 JOIN graph_evidence e USING (evidence_id)
                 JOIN graph_sources s USING (source_ref)
                 WHERE v.result_id = ? AND e.evidence_id IN ({filter})"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare finding evidence references",
                })?;
            let mut rows = statement.query(params_from_iter(values.iter())).context(
                AnalysisDatabaseSnafu {
                    operation: "read finding evidence references",
                },
            )?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance finding evidence references",
            })? {
                if let Some(control) = control {
                    control.check()?;
                }
                let id: u64 = Self::column(row, 0)?;
                let stored: Vec<u8> = Self::column(row, 1)?;
                let tenant: Vec<u8> = Self::column(row, 2)?;
                if stored != key
                    || tenant.as_slice() != header.snapshot.scope.identity.tenant_id.as_slice()
                {
                    return GraphInvalidSnafu {
                        field: "graph finding evidence source",
                    }
                    .fail();
                }
                let record = DiscoveryRecordIdV1 {
                    stream: header.snapshot.scope.identity.clone(),
                    cpu_id: Self::column(row, 3)?,
                    durable_cursor: Self::column(row, 4)?,
                };
                if record.validate().is_err() || evidence.insert(id, record).is_some() {
                    return GraphInvalidSnafu {
                        field: "graph finding evidence reference",
                    }
                    .fail();
                }
            }
        }
        if evidence.len() != evidence_ids.len() {
            return GraphInvalidSnafu {
                field: "graph finding evidence reference",
            }
            .fail();
        }
        Ok((subjects, evidence))
    }
    pub(in crate::analysis) fn read_findings(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<FindingV1>> {
        let references = Self::finding_references(writer, result_id, header, None, control)?;
        Self::load(
            writer,
            "graph_findings",
            FindingRows::COLUMNS,
            result_id,
            header.finding_count,
            control,
            |row| Self::finding(row, header, &references),
        )
    }

    pub(in crate::analysis) fn read_finding(
        writer: &Connection,
        result_id: &str,
        finding_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Option<FindingV1>> {
        if let Some(control) = control {
            control.check()?;
        }
        let references =
            Self::finding_references(writer, result_id, header, Some(&[finding_id]), control)?;
        let mut statement = writer
            .prepare(&format!(
                "SELECT {} FROM graph_findings WHERE result_id = ? AND finding_id = ?",
                FindingRows::COLUMNS
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare selected native finding",
            })?;
        let mut rows =
            statement
                .query(params![result_id, finding_id])
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected native finding",
                })?;
        let decoded = match rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance selected native finding",
        })? {
            Some(row) => Some(Self::column_operation(
                Self::finding(row, header, &references),
                "read selected native finding",
            )?),
            None => None,
        };
        if rows
            .next()
            .context(AnalysisDatabaseSnafu {
                operation: "check selected native finding identity",
            })?
            .is_some()
        {
            return GraphInvalidSnafu {
                field: "duplicate graph finding identity",
            }
            .fail();
        }
        if let Some(control) = control {
            control.check()?;
        }
        Ok(decoded)
    }

    pub(in crate::analysis) fn finding_columns(table: &str) -> String {
        FindingRows::COLUMNS
            .split(',')
            .map(|column| {
                let column = column.trim();
                format!("{table}.{column}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(in crate::analysis) fn decode_finding(
        row: &Row<'_>,
        header: &GraphHeader,
        references: &NativeFindingRefs,
    ) -> Result<FindingV1> {
        Self::column_operation(
            Self::finding(row, header, references),
            "decode selected native finding",
        )
    }
}
