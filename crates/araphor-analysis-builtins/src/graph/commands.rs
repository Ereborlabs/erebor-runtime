use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_types::{DomainRelations, FindingMember, GraphStateMember};
use sdk::arrow_array::{Array as _, ArrayRef, BinaryArray, StructArray, UInt8Array};

use super::*;

#[derive(Default)]
pub struct GraphCommands {
    subjects: BTreeMap<(Vec<u8>, Vec<u8>), SubjectChange>,
    edges: BTreeMap<(Vec<u8>, Vec<u8>), RelationshipChange>,
    findings: BTreeMap<(Vec<u8>, Vec<u8>), FindingMember>,
    states: BTreeMap<(Vec<u8>, Vec<u8>), GraphStateMember>,
}

impl GraphCommands {
    pub fn expire(
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
    ) -> sdk::Result<sdk::Output> {
        let mut commands = Self::default();
        for (owners, data) in Self::owned(graph, DomainRelations::SUBJECTS, SubjectChange::port())?
        {
            for (row, value) in SubjectChange::decode(&data)?.into_iter().enumerate() {
                commands.subject(owners.value(row), value)?;
            }
        }
        for (owners, data) in Self::owned(
            graph,
            DomainRelations::RELATIONSHIPS,
            RelationshipChange::port(),
        )? {
            for (row, value) in RelationshipChange::decode(&data)?.into_iter().enumerate() {
                let value = value.retained_expiry();
                let key = (
                    owners.value(row).to_vec(),
                    DomainRelations::key(&value.key)?,
                );
                commands.edges.entry(key).or_insert(value);
            }
        }
        for (owners, data) in Self::owned(graph, DomainRelations::FINDINGS, FindingMember::port())?
        {
            for (row, value) in FindingMember::decode(&data)?.into_iter().enumerate() {
                commands.finding(owners.value(row), value.retained_expiry())?;
            }
        }
        for (owners, data) in Self::owned(graph, DomainRelations::STATES, GraphStateMember::port())?
        {
            for (row, value) in GraphStateMember::decode(&data)?.into_iter().enumerate() {
                commands.state(owners.value(row), value.retained_expiry())?;
            }
        }
        graph.clear_scope().map_err(sdk::Error::backend)?;
        commands.stage(graph)?;
        Ok(sdk::Output {
            datasets: vec![SubjectChange::encode(&[])?],
            ..Default::default()
        })
    }

    fn owned(
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
        relation: &str,
        port: sdk::Port,
    ) -> sdk::Result<Vec<(BinaryArray, sdk::Dataset)>> {
        graph
            .owned(relation)
            .map_err(sdk::Error::backend)?
            .into_iter()
            .map(|batch| {
                let owners = batch
                    .column_by_name("owner")
                    .and_then(|array| array.as_any().downcast_ref::<BinaryArray>())
                    .ok_or_else(|| Computation::invalid("graph retained owner"))?;
                let properties = batch
                    .column_by_name("properties")
                    .and_then(|array| array.as_any().downcast_ref::<StructArray>())
                    .ok_or_else(|| Computation::invalid("graph retained properties"))?;
                if owners.null_count() != 0 || properties.null_count() != 0 {
                    return Err(Computation::invalid("graph retained null"));
                }
                let native = sdk::RecordBatch::try_new(
                    Arc::new(sdk::Schema::new(properties.fields().clone())),
                    properties.columns().to_vec(),
                )?;
                Ok((
                    owners.clone(),
                    sdk::Dataset {
                        name: port.name.clone(),
                        batches: vec![sdk::Dataset::normalize_batch(
                            native,
                            Arc::new(port.schema.clone()),
                        )?],
                    },
                ))
            })
            .collect()
    }

    pub fn subject(&mut self, owner: &[u8], value: SubjectChange) -> sdk::Result<()> {
        let key = (owner.to_vec(), DomainRelations::key(&value.key)?);
        if self.subjects.get(&key).is_some_and(|prior| prior != &value) {
            return Err(Computation::invalid("graph subject duplicate"));
        }
        self.subjects.insert(key, value);
        Ok(())
    }

    pub fn edge(&mut self, owner: &[u8], value: RelationshipChange) -> sdk::Result<()> {
        let key = (owner.to_vec(), DomainRelations::key(&value.key)?);
        if self.edges.get(&key).is_some_and(|prior| prior != &value) {
            return Err(Computation::invalid("graph relationship duplicate"));
        }
        self.edges.insert(key, value);
        Ok(())
    }

    pub fn finding(&mut self, owner: &[u8], value: FindingMember) -> sdk::Result<()> {
        let key = (
            owner.to_vec(),
            DomainRelations::key(&value.value.finding_id)?,
        );
        if self
            .findings
            .get(&key)
            .is_some_and(|prior| prior.anchor != value.anchor || prior.value != value.value)
        {
            return Err(Computation::invalid("graph finding duplicate"));
        }
        self.findings.insert(key, value);
        Ok(())
    }

    pub fn state(&mut self, owner: &[u8], value: GraphStateMember) -> sdk::Result<()> {
        let key = (owner.to_vec(), DomainRelations::key(&value.record)?);
        if self.states.get(&key).is_some_and(|prior| prior != &value) {
            return Err(Computation::invalid("graph state duplicate"));
        }
        self.states.insert(key, value);
        Ok(())
    }

    pub fn stage(
        self,
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
    ) -> sdk::Result<()> {
        let declarations = DomainRelations::declarations();
        if !self.subjects.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.subjects.into_iter().unzip();
            Self::nodes(
                graph,
                &declarations[0],
                keys,
                SubjectChange::encode(&values)?,
            )?;
        }
        if !self.edges.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.edges.into_iter().unzip();
            let from = values
                .iter()
                .map(|value| DomainRelations::key(&value.key.from))
                .collect::<sdk::Result<Vec<_>>>()?;
            let to = values
                .iter()
                .map(|value| DomainRelations::key(&value.key.to))
                .collect::<sdk::Result<Vec<_>>>()?;
            let labels = values
                .iter()
                .map(|value| DomainRelations::key(&value.key.edge_type))
                .collect::<sdk::Result<Vec<_>>>()?;
            let data = RelationshipChange::encode(&values)?;
            let mut columns = Self::keys(&keys);
            for values in [&from, &to, &labels] {
                columns.push(Arc::new(BinaryArray::from_iter_values(
                    values.iter().map(Vec::as_slice),
                )));
            }
            columns.push(Self::properties(data)?);
            graph
                .stage_edges(
                    &declarations[1].name,
                    sdk::RecordBatch::try_new(
                        Arc::new(declarations[1].engine().command_schema()),
                        columns,
                    )?,
                )
                .map_err(sdk::Error::backend)?;
        }
        if !self.findings.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.findings.into_iter().unzip();
            Self::nodes(
                graph,
                &declarations[2],
                keys,
                FindingMember::encode(&values)?,
            )?;
        }
        if !self.states.is_empty() {
            let (keys, values): (Vec<_>, Vec<_>) = self.states.into_iter().unzip();
            Self::nodes(
                graph,
                &declarations[3],
                keys,
                GraphStateMember::encode(&values)?,
            )?;
        }
        Ok(())
    }

    pub(super) fn nodes(
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
        relation: &sdk::GraphRelation,
        keys: Vec<(Vec<u8>, Vec<u8>)>,
        data: sdk::Dataset,
    ) -> sdk::Result<()> {
        let mut columns = Self::keys(&keys);
        columns.push(Self::properties(data)?);
        graph
            .stage_nodes(
                &relation.name,
                sdk::RecordBatch::try_new(Arc::new(relation.engine().command_schema()), columns)?,
            )
            .map_err(sdk::Error::backend)
    }

    fn keys(keys: &[(Vec<u8>, Vec<u8>)]) -> Vec<ArrayRef> {
        vec![
            Arc::new(BinaryArray::from_iter_values(
                keys.iter().map(|key| key.0.as_slice()),
            )),
            Arc::new(BinaryArray::from_iter_values(
                keys.iter().map(|key| key.1.as_slice()),
            )),
            Arc::new(UInt8Array::from(vec![
                araphor_graph::Write::Add as u8;
                keys.len()
            ])),
        ]
    }

    fn properties(data: sdk::Dataset) -> sdk::Result<ArrayRef> {
        let [batch] = data.batches.as_slice() else {
            return Err(Computation::invalid("graph command property batches"));
        };
        Ok(Arc::new(StructArray::new(
            batch.schema().fields().clone(),
            batch.columns().to_vec(),
            None,
        )))
    }
}
