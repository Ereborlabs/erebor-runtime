use super::{GraphHeader, GraphRows};
use crate::{AnalysisDatabaseSnafu, AnalysisReadControl, FindingV1, GraphInvalidSnafu, Result};
use araphor_graph::FindingRows;
use duckdb::{params, Connection, Row};
use snafu::ResultExt as _;

impl GraphRows {
    fn finding(row: &Row<'_>, header: &GraphHeader) -> Result<FindingV1> {
        let finding = FindingRows::decode(row)?;
        if finding.tenant_id != header.snapshot.scope.identity.tenant_id {
            return GraphInvalidSnafu {
                field: "graph finding tenant",
            }
            .fail();
        }
        header.snapshot.input_manifest.validate_finding(&finding)?;
        Ok(finding)
    }
    pub(in crate::analysis) fn read_findings(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<FindingV1>> {
        Self::load(
            writer,
            "graph_findings",
            FindingRows::COLUMNS,
            result_id,
            header.finding_count,
            control,
            |row| Self::finding(row, header),
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
                Self::finding(row, header),
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
    ) -> Result<FindingV1> {
        Self::column_operation(Self::finding(row, header), "decode selected native finding")
    }
}
