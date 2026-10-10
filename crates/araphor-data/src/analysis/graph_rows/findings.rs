use super::{GraphHeader, GraphRows};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, ContextSensitivityV1, FindingV1, GraphInvalidSnafu,
    Result,
};
use duckdb::{params, Connection, OptionalExt as _, Row, Statement};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FindingRow {
    tenant: Vec<u8>,
    finding: String,
    package: String,
    version: u64,
    subject: Vec<u8>,
    state: String,
    start: i64,
    end: i64,
    evidence: Vec<u8>,
    coverage: Vec<u8>,
    provenance: Vec<u8>,
    effects: Vec<u8>,
    reason: String,
    severity: String,
    sensitivity: String,
    action: Option<String>,
    limits: Vec<u8>,
}

impl FindingRow {
    pub(super) const COLUMNS: &str = "ordinal, tenant_id, finding_id, package_id, package_version,
        subject_id, state, window_start_utc_ns, window_end_utc_ns, evidence,
        required_coverage_interval_ids, policy_provenance, effects, reason, severity,
        sensitivity, required_action, limits";
    pub(super) const INSERT: &str = "INSERT INTO graph_findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    pub(super) fn encode(finding: &FindingV1) -> Result<Self> {
        Ok(Self {
            tenant: finding.tenant_id.to_vec(),
            finding: finding.finding_id.clone(),
            package: finding.package_id.clone(),
            version: finding.package_version,
            subject: GraphRows::json(&finding.subject_id)?,
            state: GraphRows::label(&finding.state)?,
            start: finding.window_start_utc_ns,
            end: finding.window_end_utc_ns,
            evidence: GraphRows::json(&finding.evidence)?,
            coverage: GraphRows::json(&finding.required_coverage_interval_ids)?,
            provenance: GraphRows::json(&finding.policy_provenance)?,
            effects: GraphRows::json(&finding.effects)?,
            reason: GraphRows::label(&finding.reason)?,
            severity: GraphRows::label(&finding.severity)?,
            sensitivity: <&str>::from(finding.sensitivity).to_owned(),
            action: finding.required_action.clone(),
            limits: GraphRows::json(&finding.limits)?,
        })
    }

    pub(super) fn insert(
        &self,
        writer: &mut Statement<'_>,
        result_id: &str,
        ordinal: usize,
    ) -> Result<()> {
        writer
            .execute(params![
                result_id,
                ordinal as u32,
                &self.tenant,
                &self.finding,
                &self.package,
                self.version,
                &self.subject,
                &self.state,
                self.start,
                self.end,
                &self.evidence,
                &self.coverage,
                &self.provenance,
                &self.effects,
                &self.reason,
                &self.severity,
                &self.sensitivity,
                &self.action,
                &self.limits
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph finding",
            })?;
        Ok(())
    }

    pub(super) fn bytes(&self) -> usize {
        256 + self.tenant.len()
            + self.finding.len()
            + self.package.len()
            + self.subject.len()
            + self.state.len()
            + self.evidence.len()
            + self.coverage.len()
            + self.provenance.len()
            + self.effects.len()
            + self.reason.len()
            + self.severity.len()
            + self.sensitivity.len()
            + self.action.as_ref().map_or(0, String::len)
            + self.limits.len()
    }

    fn columns(row: &Row<'_>) -> duckdb::Result<Self> {
        Ok(Self {
            tenant: row.get(1)?,
            finding: row.get(2)?,
            package: row.get(3)?,
            version: row.get(4)?,
            subject: row.get(5)?,
            state: row.get(6)?,
            start: row.get(7)?,
            end: row.get(8)?,
            evidence: row.get(9)?,
            coverage: row.get(10)?,
            provenance: row.get(11)?,
            effects: row.get(12)?,
            reason: row.get(13)?,
            severity: row.get(14)?,
            sensitivity: row.get(15)?,
            action: row.get(16)?,
            limits: row.get(17)?,
        })
    }

    fn decode(self, header: &GraphHeader) -> Result<FindingV1> {
        let finding = FindingV1 {
            tenant_id: self.tenant.try_into().map_err(|_| {
                GraphInvalidSnafu {
                    field: "finding tenant bytes",
                }
                .build()
            })?,
            finding_id: self.finding,
            revision: header.snapshot.input_manifest.clone(),
            package_id: self.package,
            package_version: self.version,
            subject_id: GraphRows::decode(&self.subject)?,
            state: GraphRows::parse(&self.state)?,
            window_start_utc_ns: self.start,
            window_end_utc_ns: self.end,
            evidence: GraphRows::decode(&self.evidence)?,
            required_coverage_interval_ids: GraphRows::decode(&self.coverage)?,
            policy_provenance: GraphRows::decode(&self.provenance)?,
            effects: GraphRows::decode(&self.effects)?,
            reason: GraphRows::parse(&self.reason)?,
            severity: GraphRows::parse(&self.severity)?,
            sensitivity: ContextSensitivityV1::try_from(self.sensitivity.as_str()).map_err(
                |_| {
                    GraphInvalidSnafu {
                        field: "finding sensitivity",
                    }
                    .build()
                },
            )?,
            required_action: self.action,
            limits: GraphRows::decode(&self.limits)?,
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
}

impl GraphRows {
    pub(in crate::analysis) fn read_findings(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<FindingV1>> {
        Self::load(
            writer,
            "graph_findings",
            FindingRow::COLUMNS,
            result_id,
            1024,
            control,
            FindingRow::columns,
        )?
        .into_iter()
        .map(|row| {
            if let Some(control) = control {
                control.check()?;
            }
            row.decode(header)
        })
        .collect()
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
        let encoded = writer
            .query_row(
                &format!(
                    "SELECT {} FROM graph_findings WHERE result_id = ? AND finding_id = ?",
                    FindingRow::COLUMNS
                ),
                params![result_id, finding_id],
                FindingRow::columns,
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read selected native finding",
            })?;
        if let Some(control) = control {
            control.check()?;
        }
        let finding = encoded.map(|row| row.decode(header)).transpose()?;
        if let Some(control) = control {
            control.check()?;
        }
        Ok(finding)
    }

    pub(in crate::analysis) fn finding_columns(table: &str) -> String {
        FindingRow::COLUMNS
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
        FindingRow::columns(row)
            .context(AnalysisDatabaseSnafu {
                operation: "decode selected native finding",
            })?
            .decode(header)
    }
}
