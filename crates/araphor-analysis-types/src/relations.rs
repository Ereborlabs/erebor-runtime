use std::sync::OnceLock;

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};

use crate::arrow::{
    self,
    views::{AnchorRow, ContextKeyRow, FindingValueRow, RecordIdRow, StateRow},
};
use crate::source::DiscoveryRecordIdV1;
use crate::{
    AnalysisContextKeyV1, Anchor, FindingV1, GraphPackageStateV1, Position, RelationshipChange,
    SubjectChange,
};

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
    pub const STATES: &'static str = "araphor_package_states_v1";
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
            sdk::GraphRelation {
                name: Self::STATES.into(),
                kind: sdk::GraphKind::Node,
                properties: GraphStateMember::port().schema,
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

    pub fn states(relation: &sdk::GraphRelation) -> bool {
        relation.kind == sdk::GraphKind::Node
            && relation.properties == GraphStateMember::port().schema
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphStateMember {
    pub record: Option<DiscoveryRecordIdV1>,
    pub position: Option<Position>,
    pub fact: Option<AnalysisContextKeyV1>,
    pub state: GraphPackageStateV1,
}

#[derive(Deserialize, Serialize)]
struct StateMemberRow {
    record: Option<RecordIdRow>,
    position: Option<Position>,
    fact: Option<ContextKeyRow>,
    state: StateRow,
}

impl GraphStateMember {
    pub fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<StateMemberRow>(DomainRelations::STATES, &PORT)
    }

    pub fn encode(values: &[Self]) -> sdk::Result<sdk::Dataset> {
        for value in values {
            value.validate()?;
        }
        arrow::encode(Self::port(), values, |value| StateMemberRow {
            record: value.record.as_ref().map(RecordIdRow::from),
            position: value.position,
            fact: value.fact.as_ref().map(ContextKeyRow::from),
            state: StateRow::from(&value.state),
        })
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        arrow::decode::<StateMemberRow, Self>(Self::port(), data, |row| {
            let value = Self {
                record: row.record.map(TryInto::try_into).transpose()?,
                position: row.position,
                fact: row.fact.map(TryInto::try_into).transpose()?,
                state: row.state.try_into()?,
            };
            value.validate()?;
            Ok(value)
        })
    }

    pub fn validate(&self) -> sdk::Result<()> {
        if self.record.is_some() != self.position.is_some()
            || self.record.is_none() && self.fact.is_some()
            || matches!(&self.state, GraphPackageStateV1::Declared(value) if value.is_empty())
        {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "Graph package state",
            ));
        }
        Ok(())
    }

    pub fn retained_expiry(mut self) -> Self {
        self.state = GraphPackageStateV1::CoverageInsufficient;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_codec_keeps_fallback() -> sdk::Result<()> {
        let fallback = GraphStateMember {
            record: None,
            position: None,
            fact: None,
            state: GraphPackageStateV1::Declared("0".into()),
        };
        let data = GraphStateMember::encode(std::slice::from_ref(&fallback))?;
        assert_eq!(GraphStateMember::decode(&data)?, [fallback.clone()]);
        let mut invalid = fallback;
        invalid.position = Some(Position {
            commit_revision: 1,
            ordinal: 0,
        });
        assert!(GraphStateMember::encode(&[invalid]).is_err());
        Ok(())
    }
}
