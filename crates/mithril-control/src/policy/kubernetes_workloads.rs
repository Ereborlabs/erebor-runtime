use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::routing::post;
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use k8s_openapi::api::core::v1::{
    Binding, Container, Node, NodeSelector, NodeSelectorTerm, Pod, ServiceAccount,
};
use kube::core::admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation};
use kube::core::DynamicObject;
use kube::{Api, Client, ResourceExt as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use snafu::ensure;

use super::{
    ContainerKindV1, DaemonSetNodeConstraintsV1, KubernetesNodeReadinessOwner, LabelOperatorV1,
    PolicyDesiredStateOwner, PolicyDocumentV1, WorkloadSelectorV1,
    KUBERNETES_LABEL_EPOCH_ANNOTATION, KUBERNETES_NODE_BOOT_ANNOTATION,
    KUBERNETES_NODE_ID_ANNOTATION, KUBERNETES_NODE_UID_ANNOTATION, KUBERNETES_NOT_READY_TAINT,
    KUBERNETES_READY_LABEL,
};
use crate::error::InvalidConfigurationSnafu;
use crate::{ControlPlane, Result};

pub const KUBERNETES_PROFILE_ANNOTATION: &str = "mithril.erebor.dev/profile-id";
pub const KUBERNETES_SOURCE_ANNOTATION: &str = "mithril.erebor.dev/policy-source-revision";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesAdmissionHttpConfigV1 {
    pub listen: SocketAddr,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub maximum_request_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodAdmissionFactsV1 {
    pub cluster_uid: String,
    pub namespace_uid: String,
    pub controller_uid: Option<String>,
    pub service_account_uid: String,
    pub labels: BTreeMap<String, String>,
    pub containers: Vec<ContainerAdmissionFactV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerAdmissionFactV1 {
    pub name: String,
    pub kind: ContainerKindV1,
    pub image: String,
}

#[derive(Clone)]
struct KubernetesAdmissionOwner {
    kube: Client,
    control: ControlPlane,
    policies: PolicyDesiredStateOwner,
    nodes: KubernetesNodeReadinessOwner,
}

impl KubernetesAdmissionHttpConfigV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.tls_certificate_path.is_absolute()
                && self.tls_private_key_path.is_absolute()
                && (1_024..=4 * 1_024 * 1_024).contains(&self.maximum_request_bytes),
            InvalidConfigurationSnafu {
                reason: "Kubernetes admission needs absolute TLS paths and a bounded request size",
            }
        );
        Ok(())
    }
}

impl KubernetesAdmissionOwner {
    async fn admit(&self, request: &AdmissionRequest<DynamicObject>) -> Result<AdmissionResponse> {
        ensure!(
            !request.uid.is_empty() && !request.dry_run,
            InvalidConfigurationSnafu {
                reason: "Kubernetes admission requires a persisted request with a UID",
            }
        );
        let response = AdmissionResponse::from(request);
        if request.kind.group.is_empty()
            && request.kind.version == "v1"
            && request.kind.kind == "Node"
            && matches!(request.operation, Operation::Create | Operation::Update)
        {
            let mut node: Node = request_object(request)?;
            let constraints = self.nodes.live_constraints(self.kube.clone()).await?;
            let ready = node.metadata.uid.as_deref().is_some_and(|uid| {
                self.control
                    .bind_kubernetes_node_session(&node.name_any(), uid)
                    .is_ok()
                    && self
                        .control
                        .ready_kubernetes_node_sessions(Duration::from_secs(
                            self.nodes.config().session_ttl_seconds,
                        ))
                        .iter()
                        .any(|session| {
                            session.kubernetes_node_name == node.name_any()
                                && session.kubernetes_node_uid == uid
                        })
            });
            if !ready {
                node = mutate_node_quarantine(node, &constraints);
            }
            return response_with_diff(response, request, &node);
        }
        if request.kind.group.is_empty()
            && request.kind.version == "v1"
            && request.kind.kind == "Pod"
            && request.resource.resource == "pods"
            && request.sub_resource.is_none()
            && matches!(request.operation, Operation::Create | Operation::Update)
        {
            let pod: Pod = request_object(request)?;
            let namespace = request
                .namespace
                .as_deref()
                .ok_or_else(|| admission_error("Pod admission request has no namespace"))?;
            let facts = self.pod_facts(namespace, &pod).await?;
            let matches = self
                .policies
                .live_policies_in_namespace(namespace)?
                .into_iter()
                .filter(|(_, policy, _)| policy_matches_pod(policy, &facts))
                .collect::<Vec<_>>();
            ensure!(
                matches.len() <= 1,
                InvalidConfigurationSnafu {
                    reason: "more than one compiled WorkloadProtectionProfile matches the Pod",
                }
            );
            let Some((source, policy, compiled)) = matches.first() else {
                return Ok(response);
            };
            ensure!(
                *compiled,
                InvalidConfigurationSnafu {
                    reason: "the matching WorkloadProtectionProfile is not compiled",
                }
            );
            let constraints = self.nodes.live_constraints(self.kube.clone()).await?;
            let mutated = mutate_protected_pod(
                pod,
                &constraints,
                policy.profile_id(),
                &source.policy_source_revision_id,
            )?;
            return response_with_diff(response, request, &mutated);
        }
        if request.kind.group.is_empty()
            && request.kind.version == "v1"
            && request.kind.kind == "Binding"
            && request.resource.resource == "pods"
            && request.sub_resource.as_deref() == Some("binding")
            && request.operation == Operation::Create
        {
            let binding: Binding = request_object(request)?;
            self.validate_binding(request, &binding).await?;
            return Ok(response);
        }
        Err(admission_error(
            "the admission request is outside the registered Mithril rules",
        ))
    }

    async fn pod_facts(&self, namespace: &str, pod: &Pod) -> Result<PodAdmissionFactsV1> {
        let namespaces = Api::<k8s_openapi::api::core::v1::Namespace>::all(self.kube.clone());
        let namespace_uid = namespaces
            .get(namespace)
            .await
            .map_err(|error| admission_error(format!("read Pod namespace: {error}")))?
            .metadata
            .uid
            .ok_or_else(|| admission_error("Pod namespace has no UID"))?;
        let spec = pod
            .spec
            .as_ref()
            .ok_or_else(|| admission_error("Pod has no specification"))?;
        let service_account_name = spec.service_account_name.as_deref().unwrap_or("default");
        let service_accounts = Api::<ServiceAccount>::namespaced(self.kube.clone(), namespace);
        let service_account_uid = service_accounts
            .get(service_account_name)
            .await
            .map_err(|error| admission_error(format!("read Pod ServiceAccount: {error}")))?
            .metadata
            .uid
            .ok_or_else(|| admission_error("Pod ServiceAccount has no UID"))?;
        Ok(pod_admission_facts(
            pod,
            self.policies.cluster_uid(),
            &namespace_uid,
            &service_account_uid,
        ))
    }

    async fn validate_binding(
        &self,
        request: &AdmissionRequest<DynamicObject>,
        binding: &Binding,
    ) -> Result<()> {
        let namespace = request
            .namespace
            .as_deref()
            .ok_or_else(|| admission_error("Pod binding has no namespace"))?;
        let pod_name = (!request.name.is_empty())
            .then_some(request.name.as_str())
            .or(binding.metadata.name.as_deref())
            .ok_or_else(|| admission_error("Pod binding has no Pod name"))?;
        let node_name = binding
            .target
            .name
            .as_deref()
            .ok_or_else(|| admission_error("Pod binding has no target Node"))?;
        let pods = Api::<Pod>::namespaced(self.kube.clone(), namespace);
        let pod = pods
            .get(pod_name)
            .await
            .map_err(|error| admission_error(format!("read Pod before binding: {error}")))?;
        ensure!(
            pod.spec
                .as_ref()
                .and_then(|spec| spec.node_name.as_deref())
                .is_none_or(str::is_empty),
            InvalidConfigurationSnafu {
                reason: "Pod is already bound before scheduler-binding admission",
            }
        );
        if pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(KUBERNETES_PROFILE_ANNOTATION))
            .is_none()
        {
            return Ok(());
        }
        let nodes = Api::<Node>::all(self.kube.clone());
        let node = nodes
            .get(node_name)
            .await
            .map_err(|error| admission_error(format!("read scheduler-selected Node: {error}")))?;
        ensure!(
            binding
                .target
                .kind
                .as_deref()
                .is_none_or(|kind| kind == "Node")
                && binding
                    .target
                    .api_version
                    .as_deref()
                    .is_none_or(|version| version == "v1")
                && binding
                    .target
                    .uid
                    .as_ref()
                    .is_none_or(|uid| node.metadata.uid.as_ref() == Some(uid)),
            InvalidConfigurationSnafu {
                reason: "Pod binding target identity does not match the selected Node",
            }
        );
        let constraints = self.nodes.live_constraints(self.kube.clone()).await?;
        validate_selected_node(
            &node,
            &constraints,
            &self.control,
            Duration::from_secs(self.nodes.config().session_ttl_seconds),
        )
    }

    async fn review(
        State(owner): State<Arc<Self>>,
        Json(review): Json<AdmissionReview<DynamicObject>>,
    ) -> Json<AdmissionReview<DynamicObject>> {
        let request = match review.try_into() {
            Ok(request) => request,
            Err(error) => return Json(AdmissionResponse::invalid(error).into_review()),
        };
        let response = match owner.admit(&request).await {
            Ok(response) => response,
            Err(error) => AdmissionResponse::from(&request).deny(error.to_string()),
        };
        Json(response.into_review())
    }

    fn router(self: Arc<Self>, maximum_request_bytes: usize) -> Router {
        Router::new()
            .route("/admit", post(Self::review))
            .layer(DefaultBodyLimit::max(maximum_request_bytes))
            .with_state(self)
    }
}

pub async fn serve_kubernetes_admission(
    config: KubernetesAdmissionHttpConfigV1,
    control: ControlPlane,
    policies: PolicyDesiredStateOwner,
    nodes: KubernetesNodeReadinessOwner,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    config.validate()?;
    let owner = Arc::new(KubernetesAdmissionOwner {
        kube: Client::try_default()
            .await
            .map_err(|error| admission_error(format!("load Kubernetes client: {error}")))?,
        control,
        policies,
        nodes,
    });
    let tls =
        RustlsConfig::from_pem_file(&config.tls_certificate_path, &config.tls_private_key_path)
            .await
            .map_err(|error| admission_error(format!("load Kubernetes admission TLS: {error}")))?;
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        shutdown.await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
    });
    axum_server::bind_rustls(config.listen, tls)
        .handle(handle)
        .serve(
            owner
                .router(config.maximum_request_bytes)
                .into_make_service(),
        )
        .await
        .map_err(|error| admission_error(format!("Kubernetes admission server failed: {error}")))
}

#[must_use]
pub fn pod_admission_facts(
    pod: &Pod,
    cluster_uid: &str,
    namespace_uid: &str,
    service_account_uid: &str,
) -> PodAdmissionFactsV1 {
    let spec = pod.spec.as_ref();
    let mut containers = Vec::new();
    if let Some(spec) = spec {
        containers.extend(spec.init_containers.iter().flatten().map(|container| {
            container_fact(
                container,
                if container.restart_policy.as_deref() == Some("Always") {
                    ContainerKindV1::Sidecar
                } else {
                    ContainerKindV1::Init
                },
            )
        }));
        containers.extend(
            spec.containers
                .iter()
                .map(|container| container_fact(container, ContainerKindV1::Application)),
        );
        containers.extend(spec.ephemeral_containers.iter().flatten().map(|container| {
            ContainerAdmissionFactV1 {
                name: container.name.clone(),
                kind: ContainerKindV1::Ephemeral,
                image: container.image.clone().unwrap_or_default(),
            }
        }));
    }
    let controller_uid = pod
        .metadata
        .owner_references
        .iter()
        .flatten()
        .find(|owner| owner.controller == Some(true))
        .map(|owner| owner.uid.clone());
    PodAdmissionFactsV1 {
        cluster_uid: cluster_uid.to_owned(),
        namespace_uid: namespace_uid.to_owned(),
        controller_uid,
        service_account_uid: service_account_uid.to_owned(),
        labels: pod.metadata.labels.clone().unwrap_or_default(),
        containers,
    }
}

#[must_use]
pub fn policy_matches_pod(policy: &PolicyDocumentV1, facts: &PodAdmissionFactsV1) -> bool {
    policy
        .workload_selectors
        .iter()
        .any(|selector| selector_matches_pod(selector, facts))
}

pub fn mutate_protected_pod(
    mut pod: Pod,
    constraints: &DaemonSetNodeConstraintsV1,
    profile_id: &str,
    source_revision_id: &str,
) -> Result<Pod> {
    let spec = pod
        .spec
        .as_mut()
        .ok_or_else(|| admission_error("protected Pod has no specification"))?;
    ensure!(
        spec.node_name.as_deref().is_none_or(str::is_empty),
        InvalidConfigurationSnafu {
            reason: "protected Pod cannot set spec.nodeName",
        }
    );
    ensure!(
        !spec.tolerations.iter().flatten().any(|toleration| {
            toleration.key.as_deref() == Some(KUBERNETES_NOT_READY_TAINT)
                || (toleration.key.as_deref().is_none_or(str::is_empty)
                    && toleration.operator.as_deref() == Some("Exists"))
        }),
        InvalidConfigurationSnafu {
            reason: "protected Pod cannot tolerate the Mithril quarantine taint",
        }
    );
    let node_selector = spec.node_selector.get_or_insert_default();
    add_required_node_label(node_selector, KUBERNETES_READY_LABEL, "true")?;
    for (key, value) in &constraints.node_selector {
        add_required_node_label(node_selector, key, value)?;
    }
    combine_required_affinity(
        &mut spec.affinity,
        constraints.required_node_affinity.as_ref(),
    );
    let annotations = pod.metadata.annotations.get_or_insert_default();
    annotations.insert(
        KUBERNETES_PROFILE_ANNOTATION.to_owned(),
        profile_id.to_owned(),
    );
    annotations.insert(
        KUBERNETES_SOURCE_ANNOTATION.to_owned(),
        source_revision_id.to_owned(),
    );
    Ok(pod)
}

#[must_use]
pub fn mutate_node_quarantine(mut node: Node, constraints: &DaemonSetNodeConstraintsV1) -> Node {
    if !constraints.matches_node(&node) {
        return node;
    }
    if let Some(labels) = node.metadata.labels.as_mut() {
        labels.remove(KUBERNETES_READY_LABEL);
    }
    if let Some(annotations) = node.metadata.annotations.as_mut() {
        annotations.remove(KUBERNETES_NODE_ID_ANNOTATION);
        annotations.remove(KUBERNETES_NODE_UID_ANNOTATION);
        annotations.remove(KUBERNETES_NODE_BOOT_ANNOTATION);
        annotations.remove(KUBERNETES_LABEL_EPOCH_ANNOTATION);
    }
    let taints = node
        .spec
        .get_or_insert_default()
        .taints
        .get_or_insert_default();
    if !taints
        .iter()
        .any(|taint| taint.key == KUBERNETES_NOT_READY_TAINT)
    {
        taints.push(k8s_openapi::api::core::v1::Taint {
            effect: "NoSchedule".to_owned(),
            key: KUBERNETES_NOT_READY_TAINT.to_owned(),
            time_added: None,
            value: Some("true".to_owned()),
        });
    }
    node
}

pub fn validate_selected_node(
    node: &Node,
    constraints: &DaemonSetNodeConstraintsV1,
    control: &ControlPlane,
    session_ttl: Duration,
) -> Result<()> {
    ensure!(
        constraints.matches_node(node)
            && node
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(KUBERNETES_READY_LABEL))
                .is_some_and(|value| value == "true"),
        InvalidConfigurationSnafu {
            reason: "scheduler selected a Node outside the live ready Mithril set",
        }
    );
    let name = node.name_any();
    let annotations = node.metadata.annotations.as_ref();
    let session = control
        .ready_kubernetes_node_sessions(session_ttl)
        .into_iter()
        .find(|session| session.kubernetes_node_name == name)
        .ok_or_else(|| admission_error("scheduler-selected Node has no current ready session"))?;
    ensure!(
        annotations.and_then(|values| values.get(KUBERNETES_NODE_ID_ANNOTATION))
            == Some(&session.node_id)
            && annotations.and_then(|values| values.get(KUBERNETES_NODE_BOOT_ANNOTATION))
                == Some(&hex::encode(&session.node_boot_id))
            && annotations.and_then(|values| values.get(KUBERNETES_LABEL_EPOCH_ANNOTATION))
                == Some(&session.label_epoch.to_string())
            && node.metadata.uid.as_ref() == Some(&session.kubernetes_node_uid)
            && annotations.and_then(|values| values.get(KUBERNETES_NODE_UID_ANNOTATION))
                == Some(&session.kubernetes_node_uid),
        InvalidConfigurationSnafu {
            reason: "scheduler-selected Node projection is stale or belongs to another session",
        }
    );
    Ok(())
}

fn selector_matches_pod(selector: &WorkloadSelectorV1, facts: &PodAdmissionFactsV1) -> bool {
    selector.cluster_uids.contains(&facts.cluster_uid)
        && selector.namespace_uids.contains(&facts.namespace_uid)
        && optional_value_matches(&selector.controller_uids, facts.controller_uid.as_deref())
        && optional_value_matches(
            &selector.service_account_uids,
            Some(&facts.service_account_uid),
        )
        && selector.pod_label_requirements.iter().all(|requirement| {
            let value = facts.labels.get(&requirement.key);
            match requirement.operator {
                LabelOperatorV1::In => {
                    value.is_some_and(|value| requirement.values.contains(value))
                }
                LabelOperatorV1::NotIn => {
                    value.is_some_and(|value| !requirement.values.contains(value))
                }
                LabelOperatorV1::Exists => value.is_some(),
                LabelOperatorV1::DoesNotExist => value.is_none(),
            }
        })
        && facts.containers.iter().any(|container| {
            (selector.container_names.is_empty()
                || selector.container_names.contains(&container.name))
                && (selector.container_kinds.is_empty()
                    || selector.container_kinds.contains(&container.kind))
                && (selector.image_digests.is_empty()
                    || selector
                        .image_digests
                        .iter()
                        .any(|digest| image_matches(&container.image, digest)))
        })
}

fn optional_value_matches(expected: &[String], actual: Option<&str>) -> bool {
    expected.is_empty() || actual.is_some_and(|actual| expected.iter().any(|value| value == actual))
}

fn image_matches(image: &str, expected: &str) -> bool {
    image == expected
        || image
            .rsplit_once('@')
            .is_some_and(|(_, digest)| digest == expected)
}

fn container_fact(container: &Container, kind: ContainerKindV1) -> ContainerAdmissionFactV1 {
    ContainerAdmissionFactV1 {
        name: container.name.clone(),
        kind,
        image: container.image.clone().unwrap_or_default(),
    }
}

fn add_required_node_label(
    selector: &mut BTreeMap<String, String>,
    key: &str,
    value: &str,
) -> Result<()> {
    ensure!(
        selector.get(key).is_none_or(|existing| existing == value),
        InvalidConfigurationSnafu {
            reason: format!("protected Pod node selector conflicts with required label `{key}`"),
        }
    );
    selector.insert(key.to_owned(), value.to_owned());
    Ok(())
}

fn combine_required_affinity(
    affinity: &mut Option<k8s_openapi::api::core::v1::Affinity>,
    daemon_set_required: Option<&NodeSelector>,
) {
    let Some(daemon_set_required) = daemon_set_required else {
        return;
    };
    let affinity = affinity.get_or_insert_default();
    let node_affinity = affinity.node_affinity.get_or_insert_default();
    let pod_required = node_affinity
        .required_during_scheduling_ignored_during_execution
        .take();
    node_affinity.required_during_scheduling_ignored_during_execution = Some(NodeSelector {
        node_selector_terms: cross_product_terms(pod_required.as_ref(), Some(daemon_set_required)),
    });
}

fn cross_product_terms(
    left: Option<&NodeSelector>,
    right: Option<&NodeSelector>,
) -> Vec<NodeSelectorTerm> {
    let left = left.map_or_else(
        || vec![NodeSelectorTerm::default()],
        |selector| selector.node_selector_terms.clone(),
    );
    let right = right.map_or_else(
        || vec![NodeSelectorTerm::default()],
        |selector| selector.node_selector_terms.clone(),
    );
    left.iter()
        .flat_map(|left| {
            right.iter().map(|right| NodeSelectorTerm {
                match_expressions: merge_optional_vec(
                    left.match_expressions.as_ref(),
                    right.match_expressions.as_ref(),
                ),
                match_fields: merge_optional_vec(
                    left.match_fields.as_ref(),
                    right.match_fields.as_ref(),
                ),
            })
        })
        .collect()
}

fn merge_optional_vec<T: Clone>(left: Option<&Vec<T>>, right: Option<&Vec<T>>) -> Option<Vec<T>> {
    let mut combined = left.cloned().unwrap_or_default();
    combined.extend(right.cloned().unwrap_or_default());
    (!combined.is_empty()).then_some(combined)
}

fn request_object<T: DeserializeOwned>(request: &AdmissionRequest<DynamicObject>) -> Result<T> {
    let object = request
        .object
        .as_ref()
        .ok_or_else(|| admission_error("admission request has no object"))?;
    serde_json::from_value(
        serde_json::to_value(object)
            .map_err(|error| admission_error(format!("encode admission object: {error}")))?,
    )
    .map_err(|error| admission_error(format!("decode admission object: {error}")))
}

fn response_with_diff<T: Serialize>(
    response: AdmissionResponse,
    request: &AdmissionRequest<DynamicObject>,
    mutated: &T,
) -> Result<AdmissionResponse> {
    let original = request
        .object
        .as_ref()
        .ok_or_else(|| admission_error("admission request has no object"))?;
    let original = serde_json::to_value(original)
        .map_err(|error| admission_error(format!("encode admission object: {error}")))?;
    let mutated = serde_json::to_value(mutated)
        .map_err(|error| admission_error(format!("encode mutated object: {error}")))?;
    response
        .with_patch(json_patch::diff(&original, &mutated))
        .map_err(|error| admission_error(format!("encode admission patch: {error}")))
}

fn admission_error(reason: impl Into<String>) -> crate::Error {
    InvalidConfigurationSnafu {
        reason: reason.into(),
    }
    .build()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::core::v1::{
        Affinity, Container, Node, NodeAffinity, NodeSelector, NodeSelectorRequirement,
        NodeSelectorTerm, NodeSpec, Pod, PodSpec, Toleration,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use kube::core::admission::{AdmissionResponse, AdmissionReview};
    use kube::core::DynamicObject;

    use super::{
        mutate_node_quarantine, mutate_protected_pod, pod_admission_facts, policy_matches_pod,
        DaemonSetNodeConstraintsV1, KUBERNETES_NOT_READY_TAINT, KUBERNETES_READY_LABEL,
    };
    use crate::{ContainerKindV1, PolicyDocumentV1};

    const POLICY: &str = include_str!("../../tests/fixtures/policy-v1.yaml");

    fn pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                namespace: Some("tenant-a".to_owned()),
                labels: Some(BTreeMap::from([("app".to_owned(), "worker".to_owned())])),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "converter".to_owned(),
                    image: Some("registry.example/converter@sha256:converter".to_owned()),
                    ..Container::default()
                }],
                ..PodSpec::default()
            }),
            ..Pod::default()
        }
    }

    fn constraints() -> DaemonSetNodeConstraintsV1 {
        DaemonSetNodeConstraintsV1 {
            node_selector: BTreeMap::from([("pool".to_owned(), "protected".to_owned())]),
            required_node_affinity: Some(NodeSelector {
                node_selector_terms: vec![NodeSelectorTerm {
                    match_expressions: Some(vec![NodeSelectorRequirement {
                        key: "zone".to_owned(),
                        operator: "In".to_owned(),
                        values: Some(vec!["a".to_owned(), "b".to_owned()]),
                    }]),
                    ..NodeSelectorTerm::default()
                }],
            }),
        }
    }

    #[test]
    fn matching_profile_is_derived_from_pod_facts() -> Result<(), Box<dyn std::error::Error>> {
        let policy =
            PolicyDocumentV1::parse(std::path::Path::new("policy-v1.yaml"), POLICY.as_bytes())?;
        let facts = pod_admission_facts(
            &pod(),
            "55555555-5555-4555-8555-555555555555",
            "66666666-6666-4666-8666-666666666666",
            "77777777-7777-4777-8777-777777777777",
        );
        assert!(policy_matches_pod(&policy, &facts));
        assert_eq!(facts.containers[0].kind, ContainerKindV1::Application);
        let mut wrong_account = facts;
        wrong_account.service_account_uid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
        assert!(!policy_matches_pod(&policy, &wrong_account));
        Ok(())
    }

    #[test]
    fn protected_pod_keeps_scheduler_choice_and_combines_affinity() -> crate::Result<()> {
        let mut pod = pod();
        if let Some(spec) = pod.spec.as_mut() {
            spec.affinity = Some(Affinity {
                node_affinity: Some(NodeAffinity {
                    required_during_scheduling_ignored_during_execution: Some(NodeSelector {
                        node_selector_terms: vec![NodeSelectorTerm {
                            match_expressions: Some(vec![NodeSelectorRequirement {
                                key: "disk".to_owned(),
                                operator: "In".to_owned(),
                                values: Some(vec!["ssd".to_owned()]),
                            }]),
                            ..NodeSelectorTerm::default()
                        }],
                    }),
                    ..NodeAffinity::default()
                }),
                ..Affinity::default()
            });
        }
        let pod = mutate_protected_pod(pod, &constraints(), "profile-a", "source-a")?;
        let spec = pod
            .spec
            .as_ref()
            .ok_or_else(|| super::admission_error("mutated test Pod lost its specification"))?;
        assert!(spec.node_name.is_none());
        assert_eq!(
            spec.node_selector
                .as_ref()
                .and_then(|selector| selector.get(KUBERNETES_READY_LABEL))
                .map(String::as_str),
            Some("true")
        );
        let requirements = spec
            .affinity
            .as_ref()
            .and_then(|affinity| affinity.node_affinity.as_ref())
            .and_then(|affinity| {
                affinity
                    .required_during_scheduling_ignored_during_execution
                    .as_ref()
            })
            .and_then(|selector| selector.node_selector_terms.first())
            .and_then(|term| term.match_expressions.as_ref())
            .map_or(0, Vec::len);
        assert_eq!(requirements, 2);
        Ok(())
    }

    #[test]
    fn protected_pod_rejects_node_and_taint_bypasses() {
        let mut direct = pod();
        if let Some(spec) = direct.spec.as_mut() {
            spec.node_name = Some("node-a".to_owned());
        }
        assert!(mutate_protected_pod(direct, &constraints(), "profile-a", "source-a").is_err());

        let mut tolerant = pod();
        if let Some(spec) = tolerant.spec.as_mut() {
            spec.tolerations = Some(vec![Toleration {
                key: Some(KUBERNETES_NOT_READY_TAINT.to_owned()),
                operator: Some("Exists".to_owned()),
                effect: Some("NoSchedule".to_owned()),
                ..Toleration::default()
            }]);
        }
        assert!(mutate_protected_pod(tolerant, &constraints(), "profile-a", "source-a").is_err());
    }

    #[test]
    fn conflicting_existing_selector_is_rejected() {
        let mut pod = pod();
        if let Some(spec) = pod.spec.as_mut() {
            spec.node_selector = Some(BTreeMap::from([("pool".to_owned(), "general".to_owned())]));
        }
        assert!(mutate_protected_pod(pod, &constraints(), "profile-a", "source-a").is_err());
    }

    #[test]
    fn eligible_node_create_clears_forged_readiness_and_adds_quarantine() {
        let node = Node {
            metadata: ObjectMeta {
                name: Some("node-a".to_owned()),
                labels: Some(BTreeMap::from([
                    ("pool".to_owned(), "protected".to_owned()),
                    ("zone".to_owned(), "a".to_owned()),
                    (KUBERNETES_READY_LABEL.to_owned(), "true".to_owned()),
                ])),
                ..ObjectMeta::default()
            },
            spec: Some(NodeSpec::default()),
            ..Node::default()
        };
        let node = mutate_node_quarantine(node, &constraints());
        assert!(node
            .metadata
            .labels
            .as_ref()
            .is_none_or(|labels| !labels.contains_key(KUBERNETES_READY_LABEL)));
        assert!(node
            .spec
            .as_ref()
            .and_then(|spec| spec.taints.as_ref())
            .is_some_and(|taints| {
                taints
                    .iter()
                    .any(|taint| taint.key == KUBERNETES_NOT_READY_TAINT)
            }));
    }

    #[test]
    fn admission_response_contains_scheduler_constraint_patch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let review: AdmissionReview<DynamicObject> = serde_json::from_value(serde_json::json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "request-a",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "name": "worker",
                "namespace": "tenant-a",
                "operation": "CREATE",
                "userInfo": {},
                "object": pod()
            }
        }))?;
        let request = review.try_into()?;
        let mutated = mutate_protected_pod(
            super::request_object(&request)?,
            &constraints(),
            "profile-a",
            "source-a",
        )?;
        let response =
            super::response_with_diff(AdmissionResponse::from(&request), &request, &mutated)?;
        let patch = response.patch.ok_or("admission response has no patch")?;
        let patch: serde_json::Value = serde_json::from_slice(&patch)?;
        assert!(patch.as_array().is_some_and(|operations| {
            operations.iter().any(|operation| {
                operation
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|path| path.contains("nodeSelector"))
            })
        }));
        Ok(())
    }
}
