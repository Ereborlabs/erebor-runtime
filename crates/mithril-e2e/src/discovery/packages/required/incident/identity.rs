use araphor_data::{
    ManagedGraphOperation, PackageRequestV1 as Request, PackageResponseV1 as Response,
};
use erebor_runtime_client::AraphorClient;
use erebor_runtime_ipc::araphor::PackageOperationRequest;
use serde_json::{json, Value};

use super::Observed;
use crate::platform::TestResult;

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
