use std::collections::{BTreeMap, BTreeSet};

use duckdb::Connection;
use snafu::ResultExt as _;

use crate::analysis::graph_rows::GraphRows;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphSubjectKeyV1, GraphTraversalDirectionV1,
    GraphTraversalV1, Result,
};

pub(in crate::analysis) struct GraphWalk<'a> {
    reader: &'a Connection,
    control: &'a AnalysisReadControl,
    request: &'a GraphTraversalV1,
    results: &'a [String],
    binding: bool,
}
pub(in crate::analysis) struct WalkRows {
    pub subjects: Vec<(GraphSubjectKeyV1, u32)>,
    pub edges: Vec<(String, u32)>,
    pub hop_boundary: bool,
}

impl<'a> GraphWalk<'a> {
    pub(in crate::analysis) fn new(
        reader: &'a Connection,
        control: &'a AnalysisReadControl,
        request: &'a GraphTraversalV1,
        results: &'a [String],
        binding: bool,
    ) -> Self {
        Self {
            reader,
            control,
            request,
            results,
            binding,
        }
    }

    pub(in crate::analysis) fn run(&self) -> Result<WalkRows> {
        let mut subjects = BTreeMap::new();
        let mut edges = BTreeSet::new();
        for id in self.results {
            for (key, _) in GraphRows::selected_subjects(
                self.reader,
                id,
                &self.request.seeds,
                self.control,
                self.binding,
            )? {
                subjects.entry(key).or_insert(0);
            }
        }
        let mut boundary = false;
        for depth in 0..=self.request.max_hops {
            self.control.check()?;
            let frontier = subjects
                .iter()
                .filter(|(_, found)| **found == depth)
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>();
            if frontier.is_empty() {
                break;
            }
            for id in self.results {
                let selected = GraphRows::selected_subjects(
                    self.reader,
                    id,
                    &frontier,
                    self.control,
                    self.binding,
                )?;
                if selected.is_empty() {
                    continue;
                }
                let values = std::iter::repeat_n("(?)", selected.len())
                    .collect::<Vec<_>>()
                    .join(",");
                let direction = match self.request.direction {
                    GraphTraversalDirectionV1::Outgoing => "e.from_subject_id=f.ordinal",
                    GraphTraversalDirectionV1::Incoming => "e.to_subject_id=f.ordinal",
                    GraphTraversalDirectionV1::Both => {
                        "(e.from_subject_id=f.ordinal OR e.to_subject_id=f.ordinal)"
                    }
                };
                let query=format!("WITH frontier(ordinal) AS (VALUES {values}) SELECT DISTINCT s.ordinal,s.tenant_id,s.authority_rank,s.authority_text,s.authority_boot,s.authority_epoch,s.subject_kind,s.identity,e.ordinal,e.edge_type FROM frontier f JOIN graph_relationships e ON {direction} LEFT JOIN graph_subjects s ON s.result_id=e.result_id AND s.ordinal=CASE WHEN e.from_subject_id=f.ordinal THEN e.to_subject_id ELSE e.from_subject_id END WHERE e.result_id=?");
                let mut parameters = selected
                    .iter()
                    .map(|(_, ordinal)| duckdb::types::Value::UInt(*ordinal))
                    .collect::<Vec<_>>();
                parameters.push(duckdb::types::Value::Text(id.clone()));
                let mut statement = self.reader.prepare(&query).context(AnalysisDatabaseSnafu {
                    operation: "prepare Graph walk frontier",
                })?;
                let mut rows = statement
                    .query(duckdb::params_from_iter(parameters.iter()))
                    .context(AnalysisDatabaseSnafu {
                        operation: "read Graph walk frontier",
                    })?;
                while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                    operation: "advance Graph walk frontier",
                })? {
                    self.control.check()?;
                    let kind: String = row.get(9).context(AnalysisDatabaseSnafu {
                        operation: "decode Graph walk edge kind",
                    })?;
                    if !self.request.edge_types.is_empty()
                        && !self.request.edge_types.iter().any(|wanted| {
                            serde_plain::to_string(wanted).ok().as_deref() == Some(kind.as_str())
                        })
                    {
                        continue;
                    }
                    let target = GraphRows::decode_subject(row)?;
                    if depth == self.request.max_hops {
                        boundary |= !subjects.contains_key(&target);
                        continue;
                    }
                    let ordinal: u32 = row.get(8).context(AnalysisDatabaseSnafu {
                        operation: "decode Graph walk edge",
                    })?;
                    edges.insert((id.clone(), ordinal));
                    subjects.entry(target).or_insert(depth + 1);
                    if subjects.len() > self.request.max_subjects {
                        return crate::AnalysisInputTooLargeSnafu {
                            resource: "graph traversal subjects",
                        }
                        .fail();
                    }
                    if edges.len() > self.request.max_relationships {
                        return crate::AnalysisInputTooLargeSnafu {
                            resource: "graph traversal relationships",
                        }
                        .fail();
                    }
                }
            }
        }
        Ok(WalkRows {
            subjects: subjects.into_iter().collect(),
            edges: edges.into_iter().collect(),
            hop_boundary: boundary,
        })
    }
}
