use std::sync::OnceLock;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};

use crate::arrow::{
    self,
    views::{AnchorRow, FindingValueRow},
};
use crate::{Anchor, FindingV1, RelationshipChange, SubjectChange};

pub struct DomainRelations;

#[derive(Clone, Debug)]
pub struct FindingMember {
    pub anchor: Anchor,
    pub value: FindingV1,
}

#[derive(Deserialize, Serialize)]
struct FindingRow {
    anchor: AnchorRow,
    value: FindingValueRow,
}

impl DomainRelations {
    pub const SUBJECTS: &'static str = "araphor_subjects_v1";
    pub const RELATIONSHIPS: &'static str = "araphor_relationships_v1";
    pub const FINDINGS: &'static str = "araphor_findings_v1";

    pub fn declarations() -> Vec<sdk::GraphRelation> {
        vec![
            sdk::GraphRelation {
                name: Self::SUBJECTS.into(),
                kind: sdk::GraphKind::Node,
                properties: SubjectChange::port().schema,
            },
            sdk::GraphRelation {
                name: Self::RELATIONSHIPS.into(),
                kind: sdk::GraphKind::Edge {
                    from: Self::SUBJECTS.into(),
                    to: Self::SUBJECTS.into(),
                },
                properties: RelationshipChange::port().schema,
            },
            sdk::GraphRelation {
                name: Self::FINDINGS.into(),
                kind: sdk::GraphKind::Node,
                properties: FindingMember::port().schema,
            },
        ]
    }

    pub fn key(value: &impl Serialize) -> sdk::Result<Vec<u8>> {
        rmp_serde::to_vec_named(value)
            .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Invalid, "Graph domain identity"))
    }

    pub fn subjects(relation: &sdk::GraphRelation) -> bool {
        relation.kind == sdk::GraphKind::Node && relation.properties == SubjectChange::port().schema
    }

    pub fn findings(relation: &sdk::GraphRelation) -> bool {
        relation.kind == sdk::GraphKind::Node && relation.properties == FindingMember::port().schema
    }

    pub fn relationships(relation: &sdk::GraphRelation, spec: &sdk::GraphSpec) -> bool {
        let sdk::GraphKind::Edge { from, to } = &relation.kind else {
            return false;
        };
        relation.properties == RelationshipChange::port().schema
            && [from, to]
                .into_iter()
                .all(|name| spec.relation(name).is_ok_and(Self::subjects))
    }
}

impl FindingMember {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<FindingRow>(DomainRelations::FINDINGS, &PORT)
    }

    pub fn encode(values: &[Self]) -> sdk::Result<sdk::Dataset> {
        arrow::encode(Self::port(), values, |value| FindingRow {
            anchor: AnchorRow::from(&value.anchor),
            value: FindingValueRow::from(&value.value),
        })
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        arrow::decode::<FindingRow, Self>(Self::port(), data, |row| {
            Ok(Self {
                anchor: row.anchor.try_into()?,
                value: row.value.try_into()?,
            })
        })
    }
}
