use super::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, ContextSensitivityV1, FindingV1, GraphInvalidSnafu,
    Result,
};
use duckdb::{params, Appender, Connection, OptionalExt as _, Row};
use snafu::ResultExt as _;

const COLUMNS: &str = "ordinal, tenant_id, finding_id, package_id, package_version,
        subject_id, state, window_start_utc_ns, window_end_utc_ns, evidence,
        required_coverage_interval_ids, policy_provenance, effects, reason, severity,
        sensitivity, required_action, limits";

impl GraphRows {
    pub(super) fn insert_finding(
        writer: &mut Appender<'_>,
        result_id: &str,
        ordinal: usize,
        finding: &FindingV1,
    ) -> Result<()> {
        writer
            .append_row(params![
                result_id,
                u32::try_from(ordinal).map_err(|_| GraphInvalidSnafu {
                    field: "graph row ordinal"
                }
                .build())?,
                finding.tenant_id.as_slice(),
                &finding.finding_id,
                &finding.package_id,
                finding.package_version,
                Self::json(&finding.subject_id)?,
                Self::label(&finding.state)?,
                finding.window_start_utc_ns,
                finding.window_end_utc_ns,
                Self::json(&finding.evidence)?,
                Self::json(&finding.required_coverage_interval_ids)?,
                Self::json(&finding.policy_provenance)?,
                Self::json(&finding.effects)?,
                finding.reason.storage()?,
                Self::label(&finding.severity)?,
                <&str>::from(finding.sensitivity),
                &finding.required_action,
                Self::json(&finding.limits)?
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph finding",
            })?;
        Ok(())
    }

    fn finding(row: &Row<'_>, header: &GraphHeader) -> Result<FindingV1> {
        let finding = FindingV1 {
            tenant_id: Self::borrowed(row, 1, |value| value.as_blob())?
                .try_into()
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "finding tenant bytes",
                    }
                    .build()
                })?,
            finding_id: Self::column(row, 2)?,
            revision: header.snapshot.input_manifest.clone(),
            package_id: Self::column(row, 3)?,
            package_version: Self::column(row, 4)?,
            subject_id: Self::json_column(row, 5)?,
            state: Self::label_column(row, 6)?,
            window_start_utc_ns: Self::column(row, 7)?,
            window_end_utc_ns: Self::column(row, 8)?,
            evidence: Self::json_column(row, 9)?,
            required_coverage_interval_ids: Self::json_column(row, 10)?,
            policy_provenance: Self::json_column(row, 11)?,
            effects: Self::json_column(row, 12)?,
            reason: crate::FindingReasonV1::restore(Self::borrowed(row, 13, |value| {
                value.as_str()
            })?)?,
            severity: Self::label_column(row, 14)?,
            sensitivity: ContextSensitivityV1::try_from(Self::borrowed(row, 15, |value| {
                value.as_str()
            })?)
            .map_err(|_| {
                GraphInvalidSnafu {
                    field: "finding sensitivity",
                }
                .build()
            })?,
            required_action: Self::column(row, 16)?,
            limits: Self::json_column(row, 17)?,
        };
        if finding.tenant_id != header.snapshot.scope.identity.tenant_id {
            return GraphInvalidSnafu {
                field: "graph finding tenant",
            }
            .fail();
        }
        finding.validate()?;
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
            COLUMNS,
            result_id,
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
        let decoded = writer
            .query_row(
                &format!(
                    "SELECT {} FROM graph_findings WHERE result_id = ? AND finding_id = ?",
                    COLUMNS
                ),
                params![result_id, finding_id],
                |row| {
                    Ok((|| {
                        if let Some(control) = control {
                            control.check()?;
                        }
                        Self::column_operation(
                            Self::finding(row, header),
                            "read selected native finding",
                        )
                    })())
                },
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read selected native finding",
            })?;
        if let Some(control) = control {
            control.check()?;
        }
        let finding = decoded.transpose()?;
        if let Some(control) = control {
            control.check()?;
        }
        Ok(finding)
    }

    pub(in crate::analysis) fn finding_columns(table: &str) -> String {
        COLUMNS
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
