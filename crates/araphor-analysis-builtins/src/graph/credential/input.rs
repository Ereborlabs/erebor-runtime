use std::sync::OnceLock;

use araphor_analysis_types::arrow::{self, views::RecordIdRow};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::*;

#[derive(Deserialize, Serialize)]
struct Candidate {
    record: RecordIdRow,
    tag: String,
    task_cookie: Option<u64>,
    process_instance_id: Option<ByteBuf>,
    principal_id: Option<String>,
    object_id: Option<ByteBuf>,
    socket_object_id: Option<ByteBuf>,
}

pub(in crate::graph) struct CandidateInput;

impl CandidateInput {
    const RELATION: &'static str = "credential_candidates_v1";

    fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Candidate>(Self::RELATION, &PORT)
    }

    pub(in crate::graph) fn relation() -> sdk::GraphRelation {
        sdk::GraphRelation {
            name: Self::RELATION.into(),
            kind: sdk::GraphKind::Node,
            properties: Self::port().schema,
        }
    }

    pub(in crate::graph) fn stage(
        computation: &Computation,
        rows: impl IntoIterator<Item = u32>,
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
    ) -> sdk::Result<()> {
        let mut keys = Vec::new();
        let mut values = Vec::new();
        for row in rows {
            let record = computation.record(row)?;
            for (_, fact) in computation.facts(row) {
                let mut value = Candidate {
                    record: RecordIdRow::from(&record.id),
                    tag: String::new(),
                    task_cookie: None,
                    process_instance_id: None,
                    principal_id: None,
                    object_id: None,
                    socket_object_id: None,
                };
                match &fact.value {
                    FactValue::Credential {
                        object_id,
                        principal_id,
                        ..
                    } => {
                        value.tag = "CREDENTIAL".into();
                        value.task_cookie = Some(record.effect.task_cookie);
                        value.process_instance_id = record
                            .process_instance_id
                            .map(|id| ByteBuf::from(id.to_vec()));
                        value.principal_id = principal_id.clone();
                        value.object_id = Some(ByteBuf::from(object_id.to_vec()));
                    }
                    FactValue::AuthorityUse {
                        task_cookie,
                        process_instance_id,
                        principal_id,
                        credential_object_id,
                        socket_object_id,
                        ..
                    } => {
                        value.tag = "AUTHORITY_USE".into();
                        value.task_cookie = *task_cookie;
                        value.process_instance_id =
                            process_instance_id.map(|id| ByteBuf::from(id.to_vec()));
                        value.principal_id = Some(principal_id.clone());
                        value.object_id = credential_object_id.map(|id| ByteBuf::from(id.to_vec()));
                        value.socket_object_id =
                            socket_object_id.map(|id| ByteBuf::from(id.to_vec()));
                    }
                    FactValue::Channel {
                        socket_object_id, ..
                    } => {
                        value.tag = "CHANNEL".into();
                        value.task_cookie = Some(record.effect.task_cookie);
                        value.process_instance_id = record
                            .process_instance_id
                            .map(|id| ByteBuf::from(id.to_vec()));
                        value.socket_object_id = Some(ByteBuf::from(socket_object_id.to_vec()));
                    }
                    _ => continue,
                }
                keys.push((
                    araphor_analysis_types::DomainRelations::key(&record.id)?,
                    araphor_analysis_types::DomainRelations::key(&fact.key)?,
                ));
                values.push(value);
            }
        }
        if values.is_empty() {
            return Ok(());
        }
        let data = arrow::encode(Self::port(), &values, |value| value)?;
        super::super::commands::GraphCommands::nodes(graph, &Self::relation(), keys, data)
    }
}
