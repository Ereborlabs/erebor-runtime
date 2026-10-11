use std::collections::HashMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use duckdb::core::LogicalTypeId::*;

use super::super::graph::{RELATIONSHIPS, SUBJECTS};
use super::super::input::InputField;
use crate::{AnalysisRelationV1, Result};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum GraphTable {
    Subjects,
    Relationships,
    Manifest,
}

const MANIFEST: &[InputField] = &[
    InputField("first_cursor", UBigint, "first accepted source cursor", ""),
    InputField("last_cursor", UBigint, "last accepted source cursor", ""),
    InputField(
        "previous_result_id",
        Varchar,
        "replaced graph result ID",
        "No prior result.",
    ),
    InputField(
        "subject_count",
        UBigint,
        "selected subject rows in this version",
        "",
    ),
    InputField(
        "relationship_count",
        UBigint,
        "selected relationship rows in this version",
        "",
    ),
    InputField("max_hops", UInteger, "requested traversal depth", ""),
    InputField(
        "hop_boundary",
        Boolean,
        "the selected traversal reaches its hop limit",
        "",
    ),
];

impl GraphTable {
    pub(super) const ALL: [Self; 3] = [Self::Subjects, Self::Relationships, Self::Manifest];

    pub(super) fn index(self) -> usize {
        match self {
            Self::Subjects => 0,
            Self::Relationships => 1,
            Self::Manifest => 2,
        }
    }

    pub(super) fn fields(self) -> impl Iterator<Item = &'static InputField> {
        let (base, extra) = match self {
            Self::Subjects => (SUBJECTS.columns, &[][..]),
            Self::Relationships => (RELATIONSHIPS.columns, &[][..]),
            Self::Manifest => (&SUBJECTS.columns[..6], MANIFEST),
        };
        base.iter()
            .chain(extra)
            .filter(move |field| self == Self::Manifest || field.0 != "graph_revision")
    }

    pub(super) fn schema(self) -> Result<Arc<sdk::Schema>> {
        let fields = self
            .fields()
            .map(|field| {
                let data_type = match field.1 {
                    Blob => sdk::DataType::Binary,
                    Varchar => sdk::DataType::Utf8,
                    UBigint => sdk::DataType::UInt64,
                    UInteger => sdk::DataType::UInt32,
                    Boolean => sdk::DataType::Boolean,
                    _ => {
                        return crate::QueryInvalidSnafu {
                            field: "graph input column type",
                        }
                        .fail()
                    }
                };
                Ok(
                    sdk::Field::new(field.0, data_type, !field.3.is_empty()).with_metadata(
                        HashMap::from([
                            (
                                "araphor.owner".into(),
                                "araphor-data.GraphAndFindingOwner".into(),
                            ),
                            ("araphor.description".into(), field.2.into()),
                            ("araphor.host_type".into(), Self::host_type(field).into()),
                            (
                                "araphor.encoding".into(),
                                if field.2.starts_with("JSON") {
                                    "serde-json-v1"
                                } else {
                                    "native"
                                }
                                .into(),
                            ),
                        ]),
                    ),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Arc::new(sdk::Schema::new(fields)))
    }

    fn host_type(field: &InputField) -> &'static str {
        match field.0 {
            "tenant_id" => "[u8;16]",
            "source_key" => "araphor-data.EvidenceIntakeIdentityV1",
            "graph_revision" => "araphor-data.GraphRevisionV1",
            "subject_id" | "from_subject_id" | "to_subject_id" => "araphor-data.GraphSubjectKeyV1",
            "authority" => "araphor-data.GraphSubjectAuthorityV1",
            "relationship_key" => "araphor-data.GraphEdgeKeyV1",
            "evidence" => "Vec<araphor-data.DiscoveryRecordIdV1>",
            "proof_quality" => "araphor-data.ProofQualityV1",
            "required_coverage_interval_ids" => "Vec<[u8;16]>",
            _ => match field.1 {
                Blob => "Vec<u8>",
                Varchar => "String",
                UBigint => "u64",
                UInteger => "u32",
                Boolean => "bool",
                _ => "unsupported",
            },
        }
    }

    pub(super) fn input_bytes(
        revision: &sdk::Revision,
        coverage: &sdk::Coverage,
        batches: [usize; 3],
    ) -> usize {
        let limits = coverage.limits.iter().fold(0usize, |bytes, value| {
            bytes
                .saturating_add(std::mem::size_of::<String>())
                .saturating_add(value.len())
        });
        let metadata = std::mem::size_of::<sdk::Input>()
            .saturating_add(revision.owner.len())
            .saturating_add(revision.id.len())
            .saturating_add(limits)
            .saturating_add(32);
        batches
            .into_iter()
            .fold(metadata.saturating_mul(3), |bytes, count| {
                bytes.saturating_add(count.saturating_mul(std::mem::size_of::<sdk::RecordBatch>()))
            })
    }

    pub(super) fn inputs(
        revision: &sdk::Revision,
        coverage: &sdk::Coverage,
        batches: [usize; 3],
    ) -> Vec<sdk::Input> {
        ["subjects", "relationships", "graph_manifest"]
            .into_iter()
            .zip(batches)
            .map(|(name, count)| sdk::Input {
                data: sdk::Dataset {
                    name: name.into(),
                    batches: Vec::with_capacity(count),
                },
                revision: revision.clone(),
                coverage: coverage.clone(),
            })
            .collect()
    }
}

impl TryFrom<AnalysisRelationV1> for GraphTable {
    type Error = crate::Error;

    fn try_from(value: AnalysisRelationV1) -> Result<Self> {
        match value {
            AnalysisRelationV1::GraphSubjects => Ok(Self::Subjects),
            AnalysisRelationV1::Relationships => Ok(Self::Relationships),
            AnalysisRelationV1::Results => Ok(Self::Manifest),
            _ => crate::QueryInvalidSnafu {
                field: "graph input relation",
            }
            .fail(),
        }
    }
}
