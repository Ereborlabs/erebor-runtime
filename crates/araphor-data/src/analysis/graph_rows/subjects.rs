use super::GraphRows;
use crate::GraphValidate as _;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphInvalidSnafu, GraphSubjectKeyV1, Result,
};
use duckdb::{params, params_from_iter, types::Value, Appender, Connection, Row};
use snafu::ResultExt as _;

const COLUMNS: &str = "ordinal, tenant_id, subject_kind, authority, identity";

impl GraphRows {
    pub(super) fn insert_subject(
        writer: &mut Appender<'_>,
        result_id: &str,
        ordinal: usize,
        subject: &GraphSubjectKeyV1,
    ) -> Result<()> {
        writer
            .append_row(params![
                result_id,
                u32::try_from(ordinal).map_err(|_| GraphInvalidSnafu {
                    field: "graph row ordinal"
                }
                .build())?,
                subject.tenant_id.as_slice(),
                Self::label(&subject.kind)?,
                Self::json(&subject.authority)?,
                &subject.identity
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "insert native graph subject",
            })?;
        Ok(())
    }

    fn decode_subject(row: &Row<'_>) -> Result<GraphSubjectKeyV1> {
        let subject = GraphSubjectKeyV1 {
            tenant_id: Self::borrowed(row, 1, |value| value.as_blob())?
                .try_into()
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "subject tenant bytes",
                    }
                    .build()
                })?,
            kind: Self::label_column(row, 2)?,
            authority: Self::json_column(row, 3)?,
            identity: Self::column(row, 4)?,
        };
        subject.validate()?;
        Ok(subject)
    }
    pub(in crate::analysis) fn subject_permission(binding_scope: bool) -> &'static str {
        if !binding_scope {
            return "TRUE";
        }
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
        Ok([
            Value::Blob(subject.tenant_id.to_vec()),
            Value::Text(Self::label(&subject.kind)?),
            Value::Blob(Self::json(&subject.authority)?),
            Value::Blob(subject.identity.clone()),
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
            let columns = COLUMNS
                .split(',')
                .map(|column| format!("subject.{}", column.trim()))
                .collect::<Vec<_>>()
                .join(", ");
            let permission = Self::subject_permission(binding_scope);
            let mut statement = reader
                .prepare(&format!(
                    "WITH requested(subject_id, tenant_id, subject_kind, authority, identity)
                 AS (VALUES {values})
                 SELECT {columns} FROM graph_subjects subject JOIN requested seed
                 USING (tenant_id, subject_kind, authority, identity)
                 WHERE subject.result_id = ? AND ({permission})
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
                selected.push(Self::column_operation(
                    Self::decode_subject(row),
                    "decode selected graph subject columns",
                )?);
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
            COLUMNS,
            result_id,
            control,
            Self::decode_subject,
        )
    }
}
