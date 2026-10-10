use super::GraphRows;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphInvalidSnafu, GraphSubjectKeyV1, Result,
};
use duckdb::{params, Connection, Row, Statement};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SubjectRow {
    tenant: Vec<u8>,
    kind: String,
    authority: Vec<u8>,
    identity: Vec<u8>,
}

impl SubjectRow {
    pub(super) const COLUMNS: &str = "ordinal, tenant_id, subject_kind, authority, identity";
    pub(super) const INSERT: &str = "INSERT INTO graph_subjects VALUES (?, ?, ?, ?, ?, ?)";

    pub(super) fn encode(subject: &GraphSubjectKeyV1) -> Result<Self> {
        Ok(Self {
            tenant: subject.tenant_id.to_vec(),
            kind: GraphRows::label(&subject.kind)?,
            authority: GraphRows::json(&subject.authority)?,
            identity: subject.identity.clone(),
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
                &self.kind,
                &self.authority,
                &self.identity
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph subject",
            })?;
        Ok(())
    }

    pub(super) fn bytes(&self) -> usize {
        256 + self.tenant.len() + self.kind.len() + self.authority.len() + self.identity.len()
    }

    fn columns(row: &Row<'_>) -> duckdb::Result<Self> {
        Ok(Self {
            tenant: row.get(1)?,
            kind: row.get(2)?,
            authority: row.get(3)?,
            identity: row.get(4)?,
        })
    }

    fn decode(self) -> Result<GraphSubjectKeyV1> {
        let subject = GraphSubjectKeyV1 {
            tenant_id: self.tenant.try_into().map_err(|_| {
                GraphInvalidSnafu {
                    field: "subject tenant bytes",
                }
                .build()
            })?,
            kind: GraphRows::parse(&self.kind)?,
            authority: GraphRows::decode(&self.authority)?,
            identity: self.identity,
        };
        subject.validate()?;
        Ok(subject)
    }
}

impl GraphRows {
    pub(in crate::analysis) fn read_subjects(
        writer: &Connection,
        result_id: &str,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphSubjectKeyV1>> {
        Self::load(
            writer,
            "graph_subjects",
            SubjectRow::COLUMNS,
            result_id,
            2048,
            control,
            SubjectRow::columns,
        )?
        .into_iter()
        .map(|row| {
            if let Some(control) = control {
                control.check()?;
            }
            row.decode()
        })
        .collect()
    }
}
