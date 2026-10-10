use super::GraphRows;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphInvalidSnafu, GraphSubjectKeyV1, Result,
};
use duckdb::{params, params_from_iter, types::Value, Connection, Row, Statement};
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
    pub(in crate::analysis) fn subject_permission() -> &'static str {
        "EXISTS (
            SELECT 1 FROM graph_findings finding
            WHERE finding.result_id = subject.result_id AND finding.subject_id = seed.subject_id
         ) OR EXISTS (
            SELECT 1 FROM graph_relationships edge
            WHERE edge.result_id = subject.result_id AND edge.evidence <> '[]'::BLOB
                AND (edge.from_subject_id = seed.subject_id OR edge.to_subject_id = seed.subject_id)
         )"
    }

    pub(in crate::analysis) fn subject_fields(subject: &GraphSubjectKeyV1) -> Result<[Value; 4]> {
        let row = SubjectRow::encode(subject)?;
        Ok([
            Value::Blob(row.tenant),
            Value::Text(row.kind),
            Value::Blob(row.authority),
            Value::Blob(row.identity),
        ])
    }

    pub(in crate::analysis) fn selected_subjects(
        reader: &Connection,
        result_id: &str,
        keys: &[GraphSubjectKeyV1],
        control: &AnalysisReadControl,
        binding_scope: bool,
    ) -> Result<Vec<GraphSubjectKeyV1>> {
        let mut selected = Vec::new();
        for keys in keys.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            control.check()?;
            let values = std::iter::repeat_n("(?, ?, ?, ?, ?)", keys.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut parameters = Vec::new();
            for key in keys {
                parameters.push(Value::Blob(Self::json(key)?));
                parameters.extend(Self::subject_fields(key)?);
            }
            parameters.push(Value::Text(result_id.to_owned()));
            parameters.push(Value::Boolean(binding_scope));
            let columns = SubjectRow::COLUMNS
                .split(',')
                .map(|column| format!("subject.{}", column.trim()))
                .collect::<Vec<_>>()
                .join(", ");
            let permission = Self::subject_permission();
            let mut statement = reader
                .prepare(&format!(
                    "WITH requested(subject_id, tenant_id, subject_kind, authority, identity)
                 AS (VALUES {values})
                 SELECT {columns} FROM graph_subjects subject JOIN requested seed
                 USING (tenant_id, subject_kind, authority, identity)
                 WHERE subject.result_id = ? AND (NOT ? OR {permission})
                 ORDER BY subject.ordinal"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected graph subjects",
                })?;
            let mut rows = statement
                .query(params_from_iter(parameters.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected graph subjects",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance selected graph subjects",
            })? {
                control.check()?;
                if selected.len() >= 2048 {
                    return GraphInvalidSnafu {
                        field: "selected graph subject count",
                    }
                    .fail();
                }
                selected.push(
                    SubjectRow::columns(row)
                        .context(AnalysisDatabaseSnafu {
                            operation: "decode selected graph subject columns",
                        })?
                        .decode()?,
                );
            }
        }
        selected.sort();
        control.check()?;
        Ok(selected)
    }

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
