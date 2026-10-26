use std::sync::{Mutex, PoisonError};

use araphor_data::{
    ManagedGraphOperation, PackageRequestV1 as Request, PackageResponseV1 as Response,
};
use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor::{
    self as wire, query_frame::Payload, query_value::Kind, PackageOperationRequest,
};
use futures_util::{future::BoxFuture, FutureExt as _};
use serde_json::{json, Value};

use super::{Incident, Observed};
use crate::platform::TestResult;

impl Incident {
    pub(super) async fn progress(&self, client: &AraphorClient, output: &Mutex<Vec<Value>>) {
        let sources = self
            .records
            .keys()
            .map(|record| record.stream.clone())
            .collect::<std::collections::BTreeSet<_>>();
        let mut reads: Vec<BoxFuture<'_, ()>> = Vec::new();
        for source in sources {
            let query = source.clone();
            reads.push(async move {
                let source = query;
                output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                    "source": source, "read": "graph_state", "started": true,
                }));
                match client.query(wire::QueryRequest {
                    sql: "SELECT contiguous_cursor, coverage_revision, consumed_cursor, current_result_id, processor_present, retired FROM graph_state WHERE source_key = $1".into(),
                    parameters: vec![wire::QueryValue {
                        kind: Some(Kind::Binary(source.key())),
                    }],
                    follow: false,
                    ..Default::default()
                }).await {
                    Ok(mut stream) => {
                        output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                            "source": source, "read": "graph_state", "opened": true,
                            "columns": ["contiguous_cursor", "coverage_revision", "consumed_cursor",
                                "current_result_id", "processor_present", "retired"],
                        }));
                        loop {
                            let frame = match stream.message().await {
                                Ok(Some(frame)) => frame,
                                Ok(None) => {
                                    output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                                        "source": source, "read": "graph_state", "eof": true,
                                    }));
                                    break;
                                }
                                Err(error) => {
                                    output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                                        "source": source, "read": "graph_state", "error": error.to_string(),
                                    }));
                                    break;
                                }
                            };
                            let terminal = matches!(
                                &frame.payload,
                                Some(Payload::Error(_) | Payload::Terminal(_))
                            );
                            let value = match frame.payload {
                                Some(Payload::Rows(rows)) => json!({
                                    "limited": rows.limited,
                                    "rows": rows.rows.into_iter().map(|row| {
                                        row.values.into_iter().map(|value| match value.kind {
                                            Some(Kind::Null(_)) => Value::Null,
                                            Some(Kind::Unsigned(value)) => json!(value),
                                            Some(Kind::Text(value)) => json!(value),
                                            Some(Kind::Boolean(value)) => json!(value),
                                            None => json!({"missing": true}),
                                            _ => json!({"error": "unexpected graph_state value"}),
                                        }).collect::<Vec<_>>()
                                    }).collect::<Vec<_>>(),
                                }),
                                Some(Payload::Checkpoint(_)) => json!({"checkpoint": true}),
                                Some(Payload::Error(error)) => json!({
                                    "error": {"code": error.code, "reason": error.reason},
                                }),
                                Some(Payload::Terminal(terminal)) => json!({"terminal": terminal.reason}),
                                Some(Payload::Metadata(_)) => json!({"metadata": true}),
                                Some(Payload::Health(_)) => json!({"health": true}),
                                None => json!({"missing_payload": true}),
                            };
                            output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                                "source": source, "read": "graph_state",
                                "read_revision": frame.read_revision, "operation": frame.operation,
                                "frame": value,
                            }));
                            if terminal {
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                            "source": source, "read": "graph_state", "error": error.to_string(),
                        }));
                    }
                }
            }.boxed());
            for operation in [
                ManagedGraphOperation::Evaluate,
                ManagedGraphOperation::Expire,
            ] {
                let id = operation.instance_id(&source);
                for (read, request) in [
                    (
                        "InspectInstance",
                        Request::InspectInstance {
                            instance_id: id.clone(),
                        },
                    ),
                    (
                        "InspectInstanceHistory",
                        Request::InspectInstanceHistory {
                            instance_id: id.clone(),
                        },
                    ),
                ] {
                    let source = source.clone();
                    let id = id.clone();
                    reads.push(async move {
                        output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                            "source": source, "instance": id, "read": read, "started": true,
                        }));
                        let result = match Observed::inspect(client, read, request).await {
                            Ok(Response::Instance(status)) if read == "InspectInstance" => json!({
                                "id": status.id, "generation": status.generation,
                                "lifecycle": status.lifecycle, "running": status.running,
                                "removed": status.removed, "progress": status.progress,
                                "readiness": status.readiness, "status_progress": status.status_progress,
                            }),
                            Ok(Response::History(history)) if read == "InspectInstanceHistory" => {
                                json!({
                                    "history": history.into_iter().rev().take(3).map(|receipt| json!({
                                        "attempt": receipt.attempt, "commit_revision": receipt.commit_revision,
                                        "selected": receipt.selected, "calls": receipt.results,
                                    })).collect::<Vec<_>>(),
                                })
                            }
                            Ok(_) => json!({"error": "unexpected package response"}),
                            Err(error) => json!({"error": error.to_string()}),
                        };
                        output.lock().unwrap_or_else(PoisonError::into_inner).push(json!({
                            "source": source, "instance": id, "read": read, "result": result,
                        }));
                    }.boxed());
                }
            }
        }
        futures_util::future::join_all(reads).await;
    }
}

impl Observed {
    pub(super) async fn identity(&self, client: &AraphorClient) -> TestResult<Vec<Value>> {
        // The fixture uses one definition and does not update it.
        let Response::Definition(definition) = Self::inspect(
            client,
            "InspectDefinition",
            Request::InspectDefinition {
                name: "mithril-control-graph".into(),
                revision: None,
            },
        )
        .await?
        else {
            return Err("physical definition identity".into());
        };
        let definition_revision = definition.digest()?;
        let mut identities = Vec::new();
        for (graph, revision, snapshot) in &self.graphs {
            let id = ManagedGraphOperation::Evaluate.instance_id(&snapshot.scope.identity);
            let Response::History(history) = Self::inspect(
                client,
                "InspectInstanceHistory",
                Request::InspectInstanceHistory {
                    instance_id: id.clone(),
                },
            )
            .await?
            else {
                return Err("physical receipt identity".into());
            };
            let receipt = history
                .into_iter()
                .find(|receipt| receipt.commit_revision == *revision)
                .ok_or("physical Graph commit has no atomic call receipt")?;
            assert_eq!(receipt.instance, id);
            assert!(!receipt.results.is_empty());
            let mut calls = Vec::new();
            for (call, reference) in &receipt.results {
                let Response::Result(result) = Self::inspect(
                    client,
                    "ReadInstanceResult",
                    Request::ReadInstanceResult {
                        instance_id: id.clone(),
                        result_id: reference.result_id.clone(),
                    },
                )
                .await?
                else {
                    return Err("physical call identity".into());
                };
                assert_eq!(result.instance_id, id);
                assert_eq!(result.result_id, reference.result_id);
                assert_eq!(result.commit_revision, reference.commit_revision);
                assert!(definition.images.contains(&result.image));
                let Response::Image(image) = Self::inspect(
                    client,
                    "InspectImage",
                    Request::InspectImage {
                        package_id: result.image.image.package_id.clone(),
                        revision: Some(result.image.image.revision.clone()),
                    },
                )
                .await?
                else {
                    return Err("physical installed image identity".into());
                };
                assert_eq!(image.root, result.image.image);
                assert_eq!(image.digest, result.image.digest);
                assert!(image.artifacts.iter().any(|artifact| {
                    artifact.descriptor.id == result.package.package_id
                        && artifact.descriptor.revision == result.package.revision
                        && artifact.implementations.iter().any(|implementation| {
                            implementation.target == result.context.target
                                && implementation.artifact == result.context.artifact
                                && implementation.exports.contains(&result.export)
                        })
                }));
                calls.push(json!({
                    "call": call, "result_id": result.result_id, "image": result.image,
                    "package": result.package, "export": result.export,
                    "context": result.context, "commit_revision": result.commit_revision,
                }));
            }
            identities.push(json!({
                "graph_result_id": graph, "commit_revision": revision,
                "source": snapshot.scope.identity, "instance_id": id,
                "definition_revision": definition_revision,
                "definition": definition, "receipt": receipt, "calls": calls,
            }));
        }
        Ok(identities)
    }

    async fn inspect(
        client: &AraphorClient,
        operation: &str,
        request: Request,
    ) -> TestResult<Response> {
        let response = client
            .package_operation(PackageOperationRequest {
                definition: request.encode()?,
                selection: None,
            })
            .await
            .map_err(|error| format!("incident {operation}: {error}"))?;
        Ok(Response::from_bytes(&response.result)?)
    }
}
