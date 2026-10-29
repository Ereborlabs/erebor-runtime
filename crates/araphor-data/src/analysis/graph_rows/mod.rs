use araphor_graph::{FindingRefs, FindingRows};
use duckdb::{
    params,
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
    Connection, Row,
};
use serde::{de::DeserializeOwned, Serialize};
use snafu::ResultExt as _;

use super::AnalysisReadControl;
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, GraphSnapshotV1, Result};

mod evidence;
mod findings;
pub(in crate::analysis) use findings::NativeFindingRefs;
mod header;
mod headers;
mod read;
mod relationships;
mod schema;
mod subjects;
#[cfg(test)]
pub(in crate::analysis) mod tests;

pub(super) use header::GraphHeader;

pub(super) struct GraphRows;

pub struct CanonicalGraph {
    snapshot: GraphSnapshotV1,
}

impl CanonicalGraph {
    pub fn new(snapshot: GraphSnapshotV1) -> Result<Self> {
        snapshot.validate()?;
        Ok(Self { snapshot })
    }

    pub fn snapshot(&self) -> &GraphSnapshotV1 {
        &self.snapshot
    }

    pub(in crate::analysis) fn into_snapshot(self) -> GraphSnapshotV1 {
        self.snapshot
    }
}

impl GraphRows {
    pub(super) fn encode(snapshot: &GraphSnapshotV1) -> Result<Vec<u8>> {
        snapshot.validate()?;
        GraphHeader::encode(snapshot)
    }

    pub(super) fn insert(
        snapshot: &GraphSnapshotV1,
        writer: &Connection,
        result_id: &str,
    ) -> Result<()> {
        let (lineage, revision, evidence) = Self::insert_inputs(snapshot, writer, result_id)?;
        let subjects = Self::insert_subjects(writer, &snapshot.graph.subjects, lineage, revision)?;
        {
            let mut appender =
                writer
                    .appender("graph_relationships")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare native graph relationships",
                    })?;
            Self::insert_edges(&mut appender, result_id, &snapshot.graph.edges)?;
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush native graph relationships",
            })?;
        }
        let findings = snapshot
            .findings
            .iter()
            .map(|finding| {
                let subject = *subjects.get(&finding.subject_id).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph finding subject reference",
                    }
                    .build()
                })?;
                let evidence = finding
                    .evidence
                    .iter()
                    .map(|record| {
                        if record.stream != snapshot.scope.identity {
                            return GraphInvalidSnafu {
                                field: "graph finding evidence source",
                            }
                            .fail();
                        }
                        evidence
                            .get(&(record.cpu_id, record.durable_cursor))
                            .copied()
                            .ok_or_else(|| {
                                GraphInvalidSnafu {
                                    field: "graph finding evidence reference",
                                }
                                .build()
                            })
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(FindingRefs {
                    finding,
                    subject,
                    evidence,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        FindingRows::apply(
            writer,
            snapshot.scope.identity.tenant_id,
            lineage,
            revision,
            &findings,
            crate::analysis::MAX_ANALYSIS_PAGE_RECORDS,
        )?;
        Ok(())
    }

    pub(super) fn read(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
    ) -> Result<GraphSnapshotV1> {
        Self::read_control(writer, result_id, header, None)
    }

    pub(super) fn read_control(
        writer: &Connection,
        result_id: &str,
        header: &GraphHeader,
        control: Option<&AnalysisReadControl>,
    ) -> Result<GraphSnapshotV1> {
        let mut snapshot = header.snapshot.clone();
        if snapshot.input_manifest.evidence.len() != header.evidence_count
            || snapshot.input_positions.len() != header.position_count
        {
            let (evidence, positions) = Self::load_inputs(writer, result_id, header, control)?;
            snapshot.input_manifest.evidence = evidence;
            snapshot.input_positions = positions;
        }
        snapshot.graph.subjects =
            Self::read_subjects(writer, result_id, header.subject_count, control)?;
        snapshot.graph.edges = Self::read_edges(writer, result_id, header.edge_count, control)?;
        snapshot.findings = Self::read_findings(writer, result_id, header, control)?;
        if snapshot.graph.subjects.len() != header.subject_count
            || snapshot.graph.edges.len() != header.edge_count
            || snapshot.findings.len() != header.finding_count
        {
            return GraphInvalidSnafu {
                field: "graph row counts",
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
        expected_count: usize,
        control: Option<&AnalysisReadControl>,
        decode: impl Fn(&Row<'_>) -> Result<T>,
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
        if let Some(control) = control {
            control.check()?;
        }
        let mut values = Vec::new();
        values.try_reserve_exact(expected_count).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph allocation byte bound",
            }
            .build()
        })?;
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
            if row.get::<_, u32>(0).context(AnalysisDatabaseSnafu {
                operation: "read graph ordinal",
            })? as usize
                != values.len()
                || values.len() >= expected_count
            {
                return GraphInvalidSnafu {
                    field: "graph row ordinal",
                }
                .fail();
            }
            if let Some(control) = control {
                control.check()?;
            }
            values.push(decode(row)?);
        }
        if values.len() != expected_count {
            return GraphInvalidSnafu {
                field: "graph row counts or bytes",
            }
            .fail();
        }
        Ok(values)
    }

    fn label(value: &impl Serialize) -> Result<String> {
        serde_plain::to_string(value).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph scalar label",
            }
            .build()
        })
    }
    fn parse<T: DeserializeOwned>(label: &str) -> Result<T> {
        serde_plain::from_str(label).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph scalar label",
            }
            .build()
        })
    }

    fn column<T: FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(AnalysisDatabaseSnafu {
            operation: "decode native graph columns",
        })
    }

    fn borrowed<'a, T>(
        row: &'a Row<'_>,
        index: usize,
        decode: impl FnOnce(ValueRef<'a>) -> FromSqlResult<T>,
    ) -> Result<T> {
        let native = || {
            let value = row.get_ref(index)?;
            let name = row.as_ref().column_name(index)?;
            decode(value).map_err(|source| match source {
                FromSqlError::InvalidType => {
                    duckdb::Error::InvalidColumnType(index, name.clone(), value.data_type())
                }
                FromSqlError::Other(source) => {
                    duckdb::Error::FromSqlConversionFailure(index, value.data_type(), source)
                }
                source => duckdb::Error::FromSqlConversionFailure(
                    index,
                    value.data_type(),
                    Box::new(source),
                ),
            })
        };
        native().context(AnalysisDatabaseSnafu {
            operation: "decode native graph columns",
        })
    }

    fn label_column<T: DeserializeOwned>(row: &Row<'_>, index: usize) -> Result<T> {
        Self::parse(Self::borrowed(row, index, |value| value.as_str())?)
    }

    fn column_operation<T>(result: Result<T>, operation: &'static str) -> Result<T> {
        result.map_err(|error| match error {
            crate::Error::AnalysisDatabase {
                source, location, ..
            } => crate::Error::AnalysisDatabase {
                operation,
                source,
                location,
            },
            error => error,
        })
    }
}
