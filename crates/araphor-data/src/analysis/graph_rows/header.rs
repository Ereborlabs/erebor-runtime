use minicbor::{Decoder, Encoder};
use serde::ser::{Serialize, SerializeMap as _, Serializer};
use snafu::ResultExt as _;

use super::GraphRows;
use crate::{GraphInvalidSnafu, GraphSnapshotV1, Result};

pub(in crate::analysis) struct GraphHeader {
    pub(in crate::analysis) snapshot: GraphSnapshotV1,
    pub(in crate::analysis) subject_count: usize,
    pub(in crate::analysis) edge_count: usize,
    pub(in crate::analysis) finding_count: usize,
    pub(in crate::analysis) snapshot_bytes: usize,
}

impl GraphHeader {
    pub(in crate::analysis) const MAX_BYTES: usize = GraphRows::MAX_CANONICAL_BYTES + 128;

    pub(super) fn encode(snapshot: &GraphSnapshotV1, canonical: &[u8]) -> Result<Vec<u8>> {
        if canonical.len() > GraphRows::MAX_CANONICAL_BYTES || canonical.is_empty() {
            return GraphInvalidSnafu {
                field: "graph result bytes",
            }
            .fail();
        }
        let metadata =
            serde_json::to_value(HeaderMetadata(snapshot)).context(crate::GraphEncodingSnafu)?;
        let metadata = GraphRows::json(&metadata)?;
        let mut bytes = Vec::new();
        Encoder::new(&mut bytes)
            .array(6)
            .and_then(|e| e.u32(2))
            .and_then(|e| e.u32(snapshot.graph.subjects.len() as u32))
            .and_then(|e| e.u32(snapshot.graph.edges.len() as u32))
            .and_then(|e| e.u32(snapshot.findings.len() as u32))
            .and_then(|e| e.u32(canonical.len() as u32))
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
        if decoder.array().map_err(Self::error)? != Some(6)
            || decoder.u32().map_err(Self::error)? != 2
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
        let metadata = decoder.bytes().map_err(Self::error)?;
        if subject_count > 2048
            || edge_count > 4096
            || finding_count > 1024
            || snapshot_bytes > GraphRows::MAX_CANONICAL_BYTES
            || snapshot_bytes == 0
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
        })
    }

    pub(in crate::analysis) fn body(&self, snapshot: &GraphSnapshotV1) -> Result<Vec<u8>> {
        let canonical = GraphRows::json(snapshot)?;
        if canonical.len() != self.snapshot_bytes {
            return GraphInvalidSnafu {
                field: "graph canonical bytes",
            }
            .fail();
        }
        Ok(canonical)
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

struct HeaderMetadata<'a>(&'a GraphSnapshotV1);
struct GraphMetadata<'a>(&'a crate::GraphVersionV1);

impl Serialize for HeaderMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let snapshot = self.0;
        let mut map = serializer.serialize_map(Some(12))?;
        map.serialize_entry("schema_version", &snapshot.schema_version)?;
        map.serialize_entry("scope", &snapshot.scope)?;
        map.serialize_entry("first_cursor", &snapshot.first_cursor)?;
        map.serialize_entry("last_cursor", &snapshot.last_cursor)?;
        map.serialize_entry("input_manifest", &snapshot.input_manifest)?;
        map.serialize_entry("graph", &GraphMetadata(&snapshot.graph))?;
        map.serialize_entry("packages", &snapshot.packages)?;
        map.serialize_entry("missing_ranges", &snapshot.missing_ranges)?;
        map.serialize_entry("input_positions", &snapshot.input_positions)?;
        map.serialize_entry("previous_result_id", &snapshot.previous_result_id)?;
        map.serialize_entry("context_notice_revision", &snapshot.context_notice_revision)?;
        map.serialize_entry("witness_deadline_utc_ns", &snapshot.witness_deadline_utc_ns)?;
        map.end()
    }
}

impl Serialize for GraphMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("revision", &self.0.revision)?;
        map.serialize_entry("branches", &self.0.branches)?;
        map.serialize_entry("facts", &self.0.facts)?;
        map.end()
    }
}
