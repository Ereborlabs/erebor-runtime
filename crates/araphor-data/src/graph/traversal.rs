use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{GraphEdgeTypeV1, GraphSubjectAuthorityV1, GraphSubjectKeyV1};
use crate::{QueryInvalidSnafu, Result};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphTraversalDirectionV1 {
    #[default]
    Outgoing,
    Incoming,
    Both,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphTraversalV1 {
    pub seeds: Vec<GraphSubjectKeyV1>,
    pub result_ids: Vec<String>,
    pub direction: GraphTraversalDirectionV1,
    pub edge_types: Vec<GraphEdgeTypeV1>,
    pub max_hops: u32,
    pub max_subjects: usize,
    pub max_relationships: usize,
}

impl Default for GraphTraversalV1 {
    fn default() -> Self {
        Self {
            seeds: Vec::new(),
            result_ids: Vec::new(),
            direction: GraphTraversalDirectionV1::Outgoing,
            edge_types: Vec::new(),
            max_hops: 1,
            max_subjects: 2048,
            max_relationships: 4096,
        }
    }
}

impl GraphTraversalV1 {
    pub const MAX_BYTES: usize = 1024 * 1024;
    pub const MAX_SEEDS: usize = 64;
    pub const MAX_HOPS: u32 = 64;
    pub const MAX_SUBJECTS: usize = 65_536;
    pub const MAX_RELATIONSHIPS: usize = 131_072;

    pub fn validate(&self) -> Result<()> {
        if self.seeds.is_empty()
            || self.seeds.len() > Self::MAX_SEEDS
            || self.seeds.len() > self.max_subjects
            || self.seeds.iter().collect::<BTreeSet<_>>().len() != self.seeds.len()
            || self.seeds.iter().any(|seed| seed.validate().is_err())
            || self.result_ids.len() > 1024
            || self
                .result_ids
                .iter()
                .any(|id| id.is_empty() || id.len() > 256)
            || self.result_ids.iter().collect::<BTreeSet<_>>().len() != self.result_ids.len()
            || self.edge_types.iter().collect::<BTreeSet<_>>().len() != self.edge_types.len()
            || self.max_hops > Self::MAX_HOPS
            || !(1..=Self::MAX_SUBJECTS).contains(&self.max_subjects)
            || !(1..=Self::MAX_RELATIONSHIPS).contains(&self.max_relationships)
        {
            return QueryInvalidSnafu {
                field: "graph traversal",
            }
            .fail();
        }
        Ok(())
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.seeds.capacity() * std::mem::size_of::<GraphSubjectKeyV1>()
            + self
                .seeds
                .iter()
                .map(|seed| {
                    seed.identity.capacity()
                        + match &seed.authority {
                            GraphSubjectAuthorityV1::Native { node_id, .. } => node_id.capacity(),
                            GraphSubjectAuthorityV1::Provider { authority_id }
                            | GraphSubjectAuthorityV1::External { authority_id } => {
                                authority_id.capacity()
                            }
                            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => {
                                cluster_id.capacity()
                            }
                        }
                })
                .sum::<usize>()
            + self.result_ids.capacity() * std::mem::size_of::<String>()
            + self.result_ids.iter().map(String::capacity).sum::<usize>()
            + self.edge_types.capacity() * std::mem::size_of::<GraphEdgeTypeV1>()
    }
}

impl TryFrom<&[u8]> for GraphTraversalV1 {
    type Error = crate::Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return QueryInvalidSnafu {
                field: "graph traversal bytes",
            }
            .fail();
        }
        let request: Self = serde_json::from_slice(bytes).map_err(|_| {
            QueryInvalidSnafu {
                field: "graph traversal JSON",
            }
            .build()
        })?;
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphTraversalReceiptV1 {
    pub result_ids: Vec<String>,
    pub unique_subject_count: usize,
    pub versioned_subject_count: usize,
    pub relationship_count: usize,
    pub max_hops: u32,
    pub hop_boundary: bool,
}

impl GraphTraversalReceiptV1 {
    pub(crate) fn heap_bytes(&self) -> usize {
        self.result_ids.capacity() * std::mem::size_of::<String>()
            + self.result_ids.iter().map(String::capacity).sum::<usize>()
    }
}
