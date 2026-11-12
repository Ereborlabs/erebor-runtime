use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use araphor_analysis_types::{
    arrow::{
        self,
        views::{ContextKeyRow, RecordIdRow},
    },
    source::{DiscoveryRecordIdV1, EvidenceIntakeIdentityV1},
    values::{AnalysisContextKeyV1, GraphSubjectKeyV1},
};
use araphor_graph::{Direction, Transaction, Write};
use sdk::arrow_array::{Array, ArrayRef, BinaryArray, StructArray, UInt8Array};
use serde::{Deserialize, Serialize};

use super::{
    model::{Audit, Credential, Pod},
    sdk,
};

#[derive(Clone, Debug, Serialize)]
pub(super) enum Entity {
    Source(EvidenceIntakeIdentityV1),
    Record(DiscoveryRecordIdV1),
    Actor(GraphSubjectKeyV1, [u8; 16]),
    Credential([u8; 16], Credential),
    Request([u8; 16], String, String, String),
    Pod([u8; 16], Pod),
    Binding([u8; 16], String, String, String),
}

impl Entity {
    pub(super) fn key(&self) -> sdk::Result<Vec<u8>> {
        rmp_serde::to_vec(self).map_err(|_| Audit::invalid("causal entity key"))
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Source(_) => "source",
            Self::Record(_) => "record",
            Self::Actor(_, _) => "actor",
            Self::Credential(_, _) => "credential",
            Self::Request(_, _, _, _) => "request",
            Self::Pod(_, _) => "pod",
            Self::Binding(_, _, _, _) => "binding",
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Reference {
    pub record: DiscoveryRecordIdV1,
    pub context: AnalysisContextKeyV1,
    pub revision: u64,
    pub restricted: bool,
}

impl Reference {
    pub(super) fn owner(&self) -> sdk::Result<Vec<u8>> {
        rmp_serde::to_vec(&self.context).map_err(|_| Audit::invalid("causal owner key"))
    }
}

#[derive(Deserialize, Serialize)]
struct Property {
    record: RecordIdRow,
    context: ContextKeyRow,
    revision: u64,
    restricted: bool,
}

impl Property {
    fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Self>("causal_link", &PORT)
    }
}

#[derive(Deserialize, Serialize)]
struct Node {
    kind: String,
}

struct Link {
    from: Vec<u8>,
    to: Vec<u8>,
    label: Vec<u8>,
    reference: Reference,
}

#[derive(Default)]
pub(super) struct Edits {
    nodes: BTreeMap<(Vec<u8>, Vec<u8>), Node>,
    links: BTreeMap<(Vec<u8>, Vec<u8>), Link>,
}

impl Edits {
    pub(super) const NODES: &'static str = "causal_entities_v1";
    pub(super) const LINKS: &'static str = "causal_links_v1";

    pub(super) fn relations() -> Vec<sdk::GraphRelation> {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        vec![
            sdk::GraphRelation {
                name: Self::NODES.into(),
                kind: sdk::GraphKind::Node,
                properties: arrow::port::<Node>("causal_node", &PORT).schema,
            },
            sdk::GraphRelation {
                name: Self::LINKS.into(),
                kind: sdk::GraphKind::Edge {
                    from: Self::NODES.into(),
                    to: Self::NODES.into(),
                },
                properties: Property::port().schema,
            },
        ]
    }

    pub(super) fn link(
        &mut self,
        reference: &Reference,
        from: Entity,
        to: Entity,
        label: &'static [u8],
    ) -> sdk::Result<()> {
        let owner = reference.owner()?;
        let from_key = from.key()?;
        let to_key = to.key()?;
        for (key, entity) in [(&from_key, &from), (&to_key, &to)] {
            self.nodes.insert(
                (owner.clone(), key.clone()),
                Node {
                    kind: entity.kind().into(),
                },
            );
        }
        let key = rmp_serde::to_vec(&(&from_key, &to_key, label, &reference.record))
            .map_err(|_| Audit::invalid("causal edge key"))?;
        self.links.insert(
            (owner, key),
            Link {
                from: from_key,
                to: to_key,
                label: label.into(),
                reference: reference.clone(),
            },
        );
        Ok(())
    }

    pub(super) fn stage(self, graph: &Transaction<sdk::GraphTransport<'_>>) -> sdk::Result<()> {
        let relations = Self::relations();
        if !self.nodes.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.nodes.into_iter().unzip();
            let properties =
                serde_arrow::to_record_batch(relations[0].properties.fields(), &values).map_err(
                    |error| {
                        sdk::Error::from(sdk::arrow_schema::ArrowError::ExternalError(Box::new(
                            error,
                        )))
                    },
                )?;
            let mut columns = Self::keys(&keys);
            columns.push(Arc::new(StructArray::new(
                properties.schema().fields().clone(),
                properties.columns().to_vec(),
                None,
            )));
            graph
                .stage_nodes(
                    Self::NODES,
                    sdk::RecordBatch::try_new(
                        Arc::new(relations[0].engine().command_schema()),
                        columns,
                    )?,
                )
                .map_err(sdk::Error::backend)?;
        }
        if !self.links.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.links.into_iter().unzip();
            let rows = values
                .iter()
                .map(|value| Property {
                    record: RecordIdRow::from(&value.reference.record),
                    context: ContextKeyRow::from(&value.reference.context),
                    revision: value.reference.revision,
                    restricted: value.reference.restricted,
                })
                .collect::<Vec<_>>();
            let properties = serde_arrow::to_record_batch(relations[1].properties.fields(), &rows)
                .map_err(|error| {
                    sdk::Error::from(sdk::arrow_schema::ArrowError::ExternalError(Box::new(
                        error,
                    )))
                })?;
            let mut columns = Self::keys(&keys);
            columns.push(Arc::new(BinaryArray::from_iter_values(
                values.iter().map(|value| value.from.as_slice()),
            )));
            columns.push(Arc::new(BinaryArray::from_iter_values(
                values.iter().map(|value| value.to.as_slice()),
            )));
            columns.push(Arc::new(BinaryArray::from_iter_values(
                values.iter().map(|value| value.label.as_slice()),
            )));
            columns.push(Arc::new(StructArray::new(
                properties.schema().fields().clone(),
                properties.columns().to_vec(),
                None,
            )));
            graph
                .stage_edges(
                    Self::LINKS,
                    sdk::RecordBatch::try_new(
                        Arc::new(relations[1].engine().command_schema()),
                        columns,
                    )?,
                )
                .map_err(sdk::Error::backend)?;
        }
        Ok(())
    }

    fn keys(keys: &[(Vec<u8>, Vec<u8>)]) -> Vec<ArrayRef> {
        vec![
            Arc::new(BinaryArray::from_iter_values(
                keys.iter().map(|key| key.0.as_slice()),
            )),
            Arc::new(BinaryArray::from_iter_values(
                keys.iter().map(|key| key.1.as_slice()),
            )),
            Arc::new(UInt8Array::from(vec![Write::Add as u8; keys.len()])),
        ]
    }

    pub(super) fn seeds(&self) -> BTreeSet<Vec<u8>> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.kind != "source")
            .map(|(key, _)| key.1.clone())
            .collect()
    }

    pub(super) fn restrict(&mut self, restricted: bool) {
        for link in self.links.values_mut() {
            link.reference.restricted |= restricted;
        }
    }

    pub(super) fn frontier(
        graph: &Transaction<sdk::GraphTransport<'_>>,
        seeds: BTreeSet<Vec<u8>>,
    ) -> sdk::Result<BTreeSet<Reference>> {
        let mut pending = seeds;
        let mut visited = BTreeSet::new();
        let mut references = BTreeSet::new();
        while !pending.is_empty() {
            let current = std::mem::take(&mut pending);
            visited.extend(current.iter().cloned());
            let keys = current.iter().map(Vec::as_slice).collect::<Vec<_>>();
            for batch in graph
                .neighbors(Self::LINKS, &keys, Direction::Either)
                .map_err(sdk::Error::backend)?
            {
                let binary = |name| -> sdk::Result<&BinaryArray> {
                    batch
                        .column_by_name(name)
                        .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
                        .filter(|array| array.null_count() == 0)
                        .ok_or_else(|| Audit::invalid("causal graph link identity"))
                };
                let from = binary("from")?;
                let to = binary("to")?;
                let labels = binary("label")?;
                let properties = batch
                    .column_by_name("properties")
                    .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                    .filter(|array| array.null_count() == 0)
                    .ok_or_else(|| Audit::invalid("causal graph link properties"))?;
                let native = sdk::RecordBatch::try_new(
                    Arc::new(Property::port().schema),
                    properties.columns().to_vec(),
                )?;
                let rows: Vec<Property> =
                    serde_arrow::from_record_batch(&native).map_err(|error| {
                        sdk::Error::from(sdk::arrow_schema::ArrowError::ExternalError(Box::new(
                            error,
                        )))
                    })?;
                for (row, value) in rows.into_iter().enumerate() {
                    references.insert(Reference {
                        record: value.record.try_into()?,
                        context: value.context.try_into()?,
                        revision: value.revision,
                        restricted: value.restricted,
                    });
                    for key in [from.value(row), to.value(row)] {
                        if labels.value(row) == b"source" && key == from.value(row) {
                            continue;
                        }
                        if !visited.contains(key) {
                            pending.insert(key.to_vec());
                        }
                    }
                }
            }
        }
        Ok(references)
    }
}
