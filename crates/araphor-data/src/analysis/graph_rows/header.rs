use minicbor::{Decoder, Encoder};

use super::{layout::JsonLayout, GraphRows};
use crate::{GraphInvalidSnafu, GraphSnapshotV1, Result};

pub(in crate::analysis) struct GraphHeader {
    pub(in crate::analysis) snapshot: GraphSnapshotV1,
    pub(in crate::analysis) subject_count: usize,
    pub(in crate::analysis) edge_count: usize,
    pub(in crate::analysis) finding_count: usize,
    pub(in crate::analysis) snapshot_bytes: usize,
    source_bytes: usize,
}

impl GraphHeader {
    pub(in crate::analysis) const MAX_BYTES: usize = GraphRows::MAX_CANONICAL_BYTES + 128;

    pub(super) fn encode(
        snapshot: &GraphSnapshotV1,
        canonical: &[u8],
        source_bytes: usize,
    ) -> Result<Vec<u8>> {
        if canonical.len() > GraphRows::MAX_CANONICAL_BYTES
            || source_bytes > super::super::MAX_RESULT_BYTES
            || source_bytes == 0
        {
            return GraphInvalidSnafu {
                field: "graph result bytes",
            }
            .fail();
        }
        let mut metadata: serde_json::Value = GraphRows::decode(canonical)?;
        let _ = metadata["graph"]
            .as_object_mut()
            .and_then(|graph| graph.remove("subjects"));
        let _ = metadata["graph"]
            .as_object_mut()
            .and_then(|graph| graph.remove("edges"));
        let _ = metadata
            .as_object_mut()
            .and_then(|graph| graph.remove("findings"));
        let metadata = GraphRows::json(&metadata)?;
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(7)
            .and_then(|e| e.u32(1))
            .and_then(|e| e.u32(snapshot.graph.subjects.len() as u32))
            .and_then(|e| e.u32(snapshot.graph.edges.len() as u32))
            .and_then(|e| e.u32(snapshot.findings.len() as u32))
            .and_then(|e| e.u32(canonical.len() as u32))
            .and_then(|e| e.u32(source_bytes as u32))
            .and_then(|e| e.bytes(&metadata))
            .map_err(Self::error)?;
        Ok(bytes)
    }

    pub(in crate::analysis) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_BYTES {
            return GraphInvalidSnafu {
                field: "graph header bytes",
            }
            .fail();
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(Self::error)? != Some(7)
            || decoder.u32().map_err(Self::error)? != 1
        {
            return GraphInvalidSnafu {
                field: "graph header version",
            }
            .fail();
        }
        let subject_count = decoder.u32().map_err(Self::error)? as usize;
        let edge_count = decoder.u32().map_err(Self::error)? as usize;
        let finding_count = decoder.u32().map_err(Self::error)? as usize;
        let snapshot_bytes = decoder.u32().map_err(Self::error)? as usize;
        let source_bytes = decoder.u32().map_err(Self::error)? as usize;
        let metadata = decoder.bytes().map_err(Self::error)?;
        if subject_count > 2048
            || edge_count > 4096
            || finding_count > 1024
            || snapshot_bytes > GraphRows::MAX_CANONICAL_BYTES
            || source_bytes > super::super::MAX_RESULT_BYTES
            || source_bytes == 0
            || metadata.len() > GraphRows::MAX_CANONICAL_BYTES
            || metadata.len() > snapshot_bytes
            || decoder.position() != bytes.len()
        {
            return GraphInvalidSnafu {
                field: "graph header format",
            }
            .fail();
        }
        let mut metadata: serde_json::Value = GraphRows::decode(metadata)?;
        let graph = metadata
            .get_mut("graph")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| Self::error("graph metadata"))?;
        if graph
            .insert("subjects".to_owned(), serde_json::json!([]))
            .is_some()
            || graph
                .insert("edges".to_owned(), serde_json::json!([]))
                .is_some()
            || metadata
                .as_object_mut()
                .ok_or_else(|| Self::error("snapshot metadata"))?
                .insert("findings".to_owned(), serde_json::json!([]))
                .is_some()
        {
            return GraphInvalidSnafu {
                field: "duplicate graph rows",
            }
            .fail();
        }
        let snapshot: GraphSnapshotV1 = GraphRows::decode(&GraphRows::json(&metadata)?)?;
        snapshot.validate()?;
        if GraphRows::json(&snapshot.input_manifest)?
            .len()
            .checked_mul(finding_count)
            .is_none_or(|bytes| bytes > snapshot_bytes)
        {
            return GraphInvalidSnafu {
                field: "graph finding byte bound",
            }
            .fail();
        }
        Ok(Self {
            snapshot,
            subject_count,
            edge_count,
            finding_count,
            snapshot_bytes,
            source_bytes,
        })
    }

    pub(in crate::analysis) fn body(
        &self,
        snapshot: &GraphSnapshotV1,
        encoding: &[u8],
    ) -> Result<Vec<u8>> {
        let canonical = GraphRows::json(snapshot)?;
        if canonical.len() != self.snapshot_bytes {
            return GraphInvalidSnafu {
                field: "graph canonical bytes",
            }
            .fail();
        }
        let body = JsonLayout::replay(encoding, &canonical, self.source_bytes)?;
        if body.len() != self.source_bytes
            || (!encoding.is_empty() && GraphRows::decode::<GraphSnapshotV1>(&body)? != *snapshot)
        {
            return GraphInvalidSnafu {
                field: "graph encoding reconstruction",
            }
            .fail();
        }
        Ok(body)
    }

    pub(in crate::analysis) fn check_index(
        &self,
        tenant: [u8; 16],
        stream: &[u8],
        method: u64,
        first: u64,
    ) -> Result<()> {
        let graph = &self.snapshot;
        if graph.scope.identity.tenant_id != tenant
            || graph.scope.identity.key() != stream
            || graph.scope.method_version != method
            || graph.first_cursor != first
        {
            return GraphInvalidSnafu {
                field: "graph header index",
            }
            .fail();
        }
        Ok(())
    }

    pub(in crate::analysis) fn check_bytes(&self, result_id: &str, stored: u64) -> Result<()> {
        let count = self.subject_count + self.edge_count + self.finding_count;
        let maximum = self
            .snapshot_bytes
            .checked_add(count.checked_mul(256 + result_id.len()).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage byte bound",
                }
                .build()
            })?)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph storage byte bound",
                }
                .build()
            })?;
        if stored > maximum as u64 {
            return GraphInvalidSnafu {
                field: "graph storage byte bound",
            }
            .fail();
        }
        Ok(())
    }

    fn error(_: impl std::fmt::Display) -> crate::Error {
        GraphInvalidSnafu {
            field: "graph header format",
        }
        .build()
    }
}
