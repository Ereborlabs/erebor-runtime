use duckdb::{params, Connection, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ResultExt as _;

use super::AnalysisReadControl;
use crate::{
    AnalysisDatabaseSnafu, GraphEncodingSnafu, GraphInvalidSnafu, GraphSnapshotV1, Result,
};

mod findings;
mod header;
mod headers;
mod read;
mod relationships;
mod schema;
mod subjects;
#[cfg(test)]
mod tests;

pub(super) use header::GraphHeader;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GraphRows {
    header: Vec<u8>,
    subjects: Vec<subjects::SubjectRow>,
    edges: Vec<relationships::RelationshipRow>,
    findings: Vec<findings::FindingRow>,
}

pub(crate) struct CanonicalGraph {
    snapshot: GraphSnapshotV1,
    body: Vec<u8>,
}

impl CanonicalGraph {
    #[cfg(test)]
    pub(crate) fn new(snapshot: GraphSnapshotV1) -> Result<Self> {
        Self::bounded(snapshot, GraphRows::MAX_CANONICAL_BYTES)
    }

    pub(crate) fn bounded(snapshot: GraphSnapshotV1, limit: usize) -> Result<Self> {
        snapshot.validate()?;
        let mut writer = araphor_analysis_sdk::wire::BoundedBuffer::new(
            limit.min(GraphRows::MAX_CANONICAL_BYTES) as u64,
        );
        if let Err(source) = serde_json::to_writer(&mut writer, &snapshot) {
            if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                return GraphInvalidSnafu {
                    field: "graph output bytes",
                }
                .fail();
            }
            return Err(source).context(GraphEncodingSnafu);
        }
        Ok(Self {
            snapshot,
            body: writer.finish(),
        })
    }

    pub(crate) fn snapshot(&self) -> &GraphSnapshotV1 {
        &self.snapshot
    }

    #[cfg(test)]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(in crate::analysis) fn into_parts(self) -> (GraphSnapshotV1, Vec<u8>) {
        (self.snapshot, self.body)
    }
}

impl GraphRows {
    pub(super) const MAX_CANONICAL_BYTES: usize = super::MAX_RESULT_BYTES;
    pub(super) fn encode_body(snapshot: &GraphSnapshotV1, body: &[u8]) -> Result<Self> {
        snapshot.validate()?;
        let canonical = Self::json(snapshot)?;
        if canonical != body {
            return GraphInvalidSnafu {
                field: "graph canonical bytes",
            }
            .fail();
        }
        Self::encode_canonical(snapshot, body)
    }

    pub(super) fn encode_canonical(snapshot: &GraphSnapshotV1, body: &[u8]) -> Result<Self> {
        snapshot.validate()?;
        Ok(Self {
            header: GraphHeader::encode(snapshot, body)?,
            subjects: snapshot
                .graph
                .subjects
                .iter()
                .map(subjects::SubjectRow::encode)
                .collect::<Result<_>>()?,
            edges: snapshot
                .graph
                .edges
                .iter()
                .map(relationships::RelationshipRow::encode)
                .collect::<Result<_>>()?,
            findings: snapshot
                .findings
                .iter()
                .map(findings::FindingRow::encode)
                .collect::<Result<_>>()?,
        })
    }

    pub(super) fn header(&self) -> &[u8] {
        &self.header
    }

    #[cfg(test)]
    pub(super) fn encode(snapshot: &GraphSnapshotV1) -> Result<Self> {
        Self::encode_body(snapshot, &Self::json(snapshot)?)
    }

    pub(super) fn insert(&self, writer: &Connection, result_id: &str) -> Result<()> {
        {
            let mut appender =
                writer
                    .appender("graph_subjects")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native graph subjects",
                    })?;
            for (ordinal, subject) in self.subjects.iter().enumerate() {
                subject.insert(&mut appender, result_id, ordinal)?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush native graph subjects",
            })?;
        }
        {
            let mut appender =
                writer
                    .appender("graph_relationships")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native graph relationships",
                    })?;
            for (ordinal, edge) in self.edges.iter().enumerate() {
                edge.insert(&mut appender, result_id, ordinal)?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush native graph relationships",
            })?;
        }
        {
            let mut appender =
                writer
                    .appender("graph_findings")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native graph findings",
                    })?;
            for (ordinal, finding) in self.findings.iter().enumerate() {
                finding.insert(&mut appender, result_id, ordinal)?;
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush native graph findings",
            })?;
        }
        Ok(())
    }

    pub(super) fn bytes(&self, result_id: &str) -> Result<i64> {
        let bytes = self
            .subjects
            .iter()
            .map(subjects::SubjectRow::bytes)
            .chain(self.edges.iter().map(relationships::RelationshipRow::bytes))
            .chain(self.findings.iter().map(findings::FindingRow::bytes))
            .try_fold(0_usize, |sum, bytes| {
                sum.checked_add(bytes)?.checked_add(result_id.len())
            })
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage bytes",
                }
                .build()
            })?;
        i64::try_from(bytes).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph storage bytes",
            }
            .build()
        })
    }

    pub(super) fn read(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
    ) -> Result<GraphSnapshotV1> {
        Self::check_bytes(writer, result_id, header)?;
        let mut snapshot = header.snapshot.clone();
        snapshot.graph.subjects = Self::read_subjects(writer, result_id, None)?;
        snapshot.graph.edges = Self::read_edges(writer, result_id, None)?;
        snapshot.findings = Self::read_findings(writer, result_id, header, None)?;
        if snapshot.graph.subjects.len() != header.subject_count
            || snapshot.graph.edges.len() != header.edge_count
            || snapshot.findings.len() != header.finding_count
            || Self::json(&snapshot)?.len() != header.snapshot_bytes
        {
            return GraphInvalidSnafu {
                field: "graph row counts or bytes",
            }
            .fail();
        }
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn load<T>(
        writer: &Connection,
        table: &str,
        columns: &str,
        result_id: &str,
        maximum: usize,
        control: Option<&AnalysisReadControl>,
        decode: impl Fn(&Row<'_>) -> duckdb::Result<T>,
    ) -> Result<Vec<T>> {
        let mut statement = writer
            .prepare(&format!(
                "SELECT {columns} FROM {table} WHERE result_id = ? ORDER BY ordinal"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare native graph rows",
            })?;
        let mut rows = statement
            .query(params![result_id])
            .context(AnalysisDatabaseSnafu {
                operation: "read native graph rows",
            })?;
        let mut values = Vec::new();
        loop {
            if let Some(control) = control {
                control.check()?;
            }
            let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance native graph rows",
            })?
            else {
                break;
            };
            if values.len() >= maximum
                || row.get::<_, u32>(0).context(AnalysisDatabaseSnafu {
                    operation: "read graph ordinal",
                })? as usize
                    != values.len()
            {
                return GraphInvalidSnafu {
                    field: "graph row ordinal",
                }
                .fail();
            }
            values.push(decode(row).context(AnalysisDatabaseSnafu {
                operation: "decode native graph columns",
            })?);
        }
        Ok(values)
    }

    fn json(value: &impl Serialize) -> Result<Vec<u8>> {
        serde_json::to_vec(value).context(GraphEncodingSnafu)
    }
    fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        serde_json::from_slice(bytes).context(GraphEncodingSnafu)
    }
    fn label(value: &impl Serialize) -> Result<String> {
        match serde_json::to_value(value).context(GraphEncodingSnafu)? {
            serde_json::Value::String(value) => Ok(value),
            _ => GraphInvalidSnafu {
                field: "graph scalar label",
            }
            .fail(),
        }
    }
    fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        serde_json::from_value(serde_json::Value::String(label.to_owned()))
            .context(GraphEncodingSnafu)
    }
}
