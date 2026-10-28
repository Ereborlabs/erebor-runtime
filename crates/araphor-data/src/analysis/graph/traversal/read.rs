use duckdb::{params_from_iter, Connection, Row};
use snafu::ResultExt as _;

use crate::{
    AnalysisDatabaseSnafu, AnalysisInputTooLargeSnafu, AnalysisReadControl, GraphInvalidSnafu,
    GraphSubjectKeyV1, GraphTraversalV1, Result,
};

pub(in crate::analysis) struct GraphWalk<'a> {
    pub(super) reader: &'a Connection,
    pub(super) control: &'a AnalysisReadControl,
    pub(super) request: &'a GraphTraversalV1,
    pub(super) result_ids: &'a [String],
    pub(super) binding_scope: bool,
}

pub(in crate::analysis) struct WalkRows {
    pub(in crate::analysis) subjects: Vec<(GraphSubjectKeyV1, u32)>,
    pub(in crate::analysis) edges: Vec<(String, u32)>,
    pub(in crate::analysis) hop_boundary: bool,
}

impl<'a> GraphWalk<'a> {
    pub(in crate::analysis) fn new(
        reader: &'a Connection,
        control: &'a AnalysisReadControl,
        request: &'a GraphTraversalV1,
        result_ids: &'a [String],
        binding_scope: bool,
    ) -> Self {
        Self {
            reader,
            control,
            request,
            result_ids,
            binding_scope,
        }
    }

    pub(in crate::analysis) fn run(&self) -> Result<WalkRows> {
        self.control.check()?;
        if self.result_ids.is_empty() {
            return Ok(WalkRows {
                subjects: Vec::new(),
                edges: Vec::new(),
                hop_boundary: false,
            });
        }
        let (query, values) = self.query()?;
        let mut statement = self.reader.prepare(&query).context(AnalysisDatabaseSnafu {
            operation: "prepare native graph traversal",
        })?;
        let mut rows =
            statement
                .query(params_from_iter(values.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read native graph traversal",
                })?;
        let summary = rows
            .next()
            .context(AnalysisDatabaseSnafu {
                operation: "read native traversal bounds",
            })?
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph traversal summary",
                }
                .build()
            })?;
        let (mut output, count, edges) = self.summary(summary)?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance native graph traversal",
        })? {
            self.control.check()?;
            output.push(row, self.request.max_hops)?;
        }
        if output.subjects.len() != count || output.edges.len() != edges {
            return GraphInvalidSnafu {
                field: "graph traversal row counts",
            }
            .fail();
        }
        self.control.check()?;
        Ok(output)
    }

    fn summary(&self, summary: &Row<'_>) -> Result<(WalkRows, usize, usize)> {
        if summary.get::<_, u8>(0).context(AnalysisDatabaseSnafu {
            operation: "decode traversal summary kind",
        })? != 0
        {
            return GraphInvalidSnafu {
                field: "graph traversal summary",
            }
            .fail();
        }
        let count: u64 = summary.get(11).context(AnalysisDatabaseSnafu {
            operation: "decode traversal subject count",
        })?;
        let edges: u64 = summary.get(12).context(AnalysisDatabaseSnafu {
            operation: "decode traversal edge count",
        })?;
        if count > self.request.max_subjects as u64 {
            return AnalysisInputTooLargeSnafu {
                resource: "graph traversal subjects",
            }
            .fail();
        }
        if edges > self.request.max_relationships as u64 {
            return AnalysisInputTooLargeSnafu {
                resource: "graph traversal relationships",
            }
            .fail();
        }
        let mut output = WalkRows {
            subjects: Vec::new(),
            edges: Vec::new(),
            hop_boundary: summary.get(13).context(AnalysisDatabaseSnafu {
                operation: "decode traversal hop boundary",
            })?,
        };
        output
            .subjects
            .try_reserve_exact(count as usize)
            .map_err(Self::allocation)?;
        output
            .edges
            .try_reserve_exact(edges as usize)
            .map_err(Self::allocation)?;
        Ok((output, count as usize, edges as usize))
    }

    fn allocation(_: std::collections::TryReserveError) -> crate::Error {
        AnalysisInputTooLargeSnafu {
            resource: "graph traversal rows",
        }
        .build()
    }
}

impl WalkRows {
    fn push(&mut self, row: &Row<'_>, max_hops: u32) -> Result<()> {
        match row.get::<_, u8>(0).context(AnalysisDatabaseSnafu {
            operation: "decode traversal row kind",
        })? {
            1 => {
                let subject = crate::analysis::graph_rows::GraphRows::decode_subject(row)?;
                let depth = row.get(8).context(AnalysisDatabaseSnafu {
                    operation: "decode traversal depth",
                })?;
                if depth > max_hops {
                    return GraphInvalidSnafu {
                        field: "graph traversal depth",
                    }
                    .fail();
                }
                self.subjects.push((subject, depth));
            }
            2 => self.edges.push((
                row.get(9).context(AnalysisDatabaseSnafu {
                    operation: "decode traversal result identity",
                })?,
                row.get(10).context(AnalysisDatabaseSnafu {
                    operation: "decode traversal edge ordinal",
                })?,
            )),
            _ => {
                return GraphInvalidSnafu {
                    field: "graph traversal row kind",
                }
                .fail();
            }
        }
        Ok(())
    }
}
