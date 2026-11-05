use crate::{
    error::InvalidSnafu, GraphFactV1, GraphPackageCheckpointV1, GraphRevisionV1, GraphSnapshotV1,
    GraphValidate as _, GraphVersionV1, Result,
};
use crate::source::{
    DiscoveryRecordIdV1, ProcessorScopeV1, StorePositionV1,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    pub schema_version: u32,
    pub scope: ProcessorScopeV1,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub input_manifest: GraphRevisionV1,
    pub facts: Vec<GraphFactV1>,
    pub packages: Vec<GraphPackageCheckpointV1>,
    pub missing_ranges: Vec<(u64, u64)>,
    pub input_positions: Vec<(DiscoveryRecordIdV1, StorePositionV1)>,
    pub previous_result_id: Option<String>,
    pub context_notice_revision: u64,
    pub witness_deadline_utc_ns: u64,
}

impl GraphManifest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .map_err(|_| {
                InvalidSnafu {
                    field: "graph metadata encoding",
                }
                .build()
            })?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let value = Self::deserialize(&mut decoder).map_err(|_| {
            InvalidSnafu {
                field: "graph metadata encoding",
            }
            .build()
        })?;
        if decoder.position() != bytes.len() as u64 {
            return InvalidSnafu {
                field: "graph metadata trailing bytes",
            }
            .fail();
        }
        value.validate()?;
        Ok(value)
    }

    pub fn from_snapshot(graph: &GraphSnapshotV1) -> Self {
        Self {
            schema_version: graph.schema_version,
            scope: graph.scope.clone(),
            first_cursor: graph.first_cursor,
            last_cursor: graph.last_cursor,
            input_manifest: graph.input_manifest.clone(),
            facts: graph.graph.facts.clone(),
            packages: graph.packages.clone(),
            missing_ranges: graph.missing_ranges.clone(),
            input_positions: graph.input_positions.clone(),
            previous_result_id: graph.previous_result_id.clone(),
            context_notice_revision: graph.context_notice_revision,
            witness_deadline_utc_ns: graph.witness_deadline_utc_ns,
        }
    }

    pub fn validate(&self) -> Result<()> {
        self.snapshot().validate()?;
        for fact in &self.facts {
            fact.validate()?;
            if fact.record_id.stream != self.scope.identity
                || self
                    .input_manifest
                    .evidence
                    .binary_search(&fact.record_id)
                    .is_err()
            {
                return Err(InvalidSnafu {
                    field: "graph fact evidence",
                }
                .build());
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> GraphSnapshotV1 {
        GraphSnapshotV1 {
            schema_version: self.schema_version,
            scope: self.scope.clone(),
            first_cursor: self.first_cursor,
            last_cursor: self.last_cursor,
            input_manifest: self.input_manifest.clone(),
            graph: GraphVersionV1 {
                subjects: Vec::new(),
                edges: Vec::new(),
                branches: Vec::new(),
                facts: self.facts.clone(),
            },
            findings: Vec::new(),
            packages: self.packages.clone(),
            missing_ranges: self.missing_ranges.clone(),
            input_positions: self.input_positions.clone(),
            previous_result_id: self.previous_result_id.clone(),
            context_notice_revision: self.context_notice_revision,
            witness_deadline_utc_ns: self.witness_deadline_utc_ns,
        }
    }
}
