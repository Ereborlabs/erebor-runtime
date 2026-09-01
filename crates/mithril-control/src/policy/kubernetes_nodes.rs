use std::collections::BTreeMap;
use std::time::Duration;

use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{
    Node, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm, Taint,
};
use kube::api::{ListParams, Patch, PatchParams, WatchEvent, WatchParams};
use kube::{Api, Client, ResourceExt as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snafu::ensure;
use tokio_stream::StreamExt as _;

use crate::error::InvalidConfigurationSnafu;
use crate::{ControlPlane, KubernetesNodeSessionV1, Result};

use super::kubernetes::next_continuation_token;

pub const KUBERNETES_READY_LABEL: &str = "mithril.erebor.dev/ready";
pub const KUBERNETES_NODE_ID_ANNOTATION: &str = "mithril.erebor.dev/node-id";
pub const KUBERNETES_NODE_UID_ANNOTATION: &str = "mithril.erebor.dev/node-uid";
pub const KUBERNETES_NODE_BOOT_ANNOTATION: &str = "mithril.erebor.dev/node-boot-id";
pub const KUBERNETES_LABEL_EPOCH_ANNOTATION: &str = "mithril.erebor.dev/label-epoch";
pub const KUBERNETES_NOT_READY_TAINT: &str = "mithril.erebor.dev/not-ready";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesNodeControlConfigV1 {
    pub daemon_set_namespace: String,
    pub daemon_set_name: String,
    pub session_ttl_seconds: u64,
    pub reconcile_interval_ms: u64,
}

#[derive(Clone, Debug, PartialEq)]
/// Contains the scheduling constraints that Control derives from the live DaemonSet.
pub struct DaemonSetNodeConstraintsV1 {
    pub node_selector: BTreeMap<String, String>,
    pub required_node_affinity: Option<NodeSelector>,
}

#[derive(Clone)]
/// Owns the Mithril readiness label, identity annotations, and quarantine taint.
pub struct KubernetesNodeReadinessOwner {
    config: KubernetesNodeControlConfigV1,
}

impl KubernetesNodeControlConfigV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            kubernetes_dns_name_is_valid(&self.daemon_set_namespace)
                && kubernetes_dns_name_is_valid(&self.daemon_set_name)
                && self.session_ttl_seconds > 0
                && self.reconcile_interval_ms > 0,
            InvalidConfigurationSnafu {
                reason:
                    "Kubernetes node control requires DaemonSet names and nonzero timing bounds",
            }
        );
        Ok(())
    }
}

impl KubernetesNodeReadinessOwner {
    pub fn new(config: KubernetesNodeControlConfigV1) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    #[must_use]
    pub const fn config(&self) -> &KubernetesNodeControlConfigV1 {
        &self.config
    }

    pub async fn live_constraints(&self, client: Client) -> Result<DaemonSetNodeConstraintsV1> {
        // The DaemonSet Pod template is the only node-pool authority for this flow.
        let daemon_sets = Api::<DaemonSet>::namespaced(client, &self.config.daemon_set_namespace);
        let daemon_set = daemon_sets
            .get(&self.config.daemon_set_name)
            .await
            .map_err(|error| {
                InvalidConfigurationSnafu {
                    reason: format!("read the mithril-node DaemonSet: {error}"),
                }
                .build()
            })?;
        DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set)
    }

    pub async fn run_kubernetes(self, control: ControlPlane) {
        loop {
            let Ok(client) = Client::try_default().await else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            self.run_client(client, control.clone()).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn run_client(&self, client: Client, control: ControlPlane) {
        let daemon_sets =
            Api::<DaemonSet>::namespaced(client.clone(), &self.config.daemon_set_namespace);
        let nodes = Api::<Node>::all(client);
        loop {
            let Ok(daemon_set) = daemon_sets.get(&self.config.daemon_set_name).await else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };
            let Ok(constraints) = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set) else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };
            let Ok(node_resource_version) = self
                .reconcile_node_snapshot(&nodes, &constraints, &control)
                .await
            else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };

            // Any DaemonSet change invalidates the derived node set and starts a complete relist.
            let daemon_set_resource_version = daemon_set.resource_version().unwrap_or_default();
            let daemon_set_watch = daemon_sets
                .watch(
                    &WatchParams::default()
                        .fields(&format!("metadata.name={}", self.config.daemon_set_name))
                        .timeout(240),
                    &daemon_set_resource_version,
                )
                .await;
            let node_watch = nodes
                .watch(&WatchParams::default().timeout(240), &node_resource_version)
                .await;
            let (Ok(daemon_set_watch), Ok(node_watch)) = (daemon_set_watch, node_watch) else {
                continue;
            };
            tokio::pin!(daemon_set_watch);
            tokio::pin!(node_watch);
            let interval =
                tokio::time::sleep(Duration::from_millis(self.config.reconcile_interval_ms));
            tokio::pin!(interval);
            loop {
                tokio::select! {
                    _ = &mut interval => break,
                    event = daemon_set_watch.next() => {
                        match event {
                            Some(Ok(WatchEvent::Bookmark(_))) => {}
                            Some(Ok(_)) | Some(Err(_)) | None => break,
                        }
                    }
                    event = node_watch.next() => {
                        match event {
                            Some(Ok(WatchEvent::Added(node) | WatchEvent::Modified(node))) => {
                                self.reconcile_node(&nodes, &constraints, &control, &node).await;
                            }
                            Some(Ok(WatchEvent::Deleted(_))) | Some(Ok(WatchEvent::Bookmark(_))) => {}
                            Some(Ok(WatchEvent::Error(_))) | Some(Err(_)) | None => break,
                        }
                    }
                }
            }
        }
    }

    async fn reconcile_node_snapshot(
        &self,
        nodes: &Api<Node>,
        constraints: &DaemonSetNodeConstraintsV1,
        control: &ControlPlane,
    ) -> Result<String> {
        let mut continuation = None::<String>;
        let mut resource_version = None::<String>;
        // Finish this snapshot before the watch starts. An unvisited page must
        // not bypass the initial readiness projection.
        loop {
            let mut params = ListParams::default().limit(500);
            if let Some(token) = &continuation {
                params = params.continue_token(token);
            }
            let page = nodes.list(&params).await.map_err(|error| {
                InvalidConfigurationSnafu {
                    reason: format!("list Kubernetes Nodes: {error}"),
                }
                .build()
            })?;
            for node in page.items {
                self.reconcile_node(nodes, constraints, control, &node)
                    .await;
            }
            resource_version = page.metadata.resource_version.or(resource_version);
            continuation =
                next_continuation_token(continuation.as_deref(), page.metadata.continue_, "Node")?;
            if continuation.is_none() {
                break;
            }
        }
        resource_version
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                InvalidConfigurationSnafu {
                    reason: "the Kubernetes Node snapshot has no resource version".to_owned(),
                }
                .build()
            })
    }

    async fn reconcile_node(
        &self,
        nodes: &Api<Node>,
        constraints: &DaemonSetNodeConstraintsV1,
        control: &ControlPlane,
        node: &Node,
    ) {
        let name = node.name_any();
        let Some(node_uid) = node.metadata.uid.as_deref() else {
            return;
        };
        // Bind the session to the API object UID before the session can project readiness.
        let _result = control.bind_kubernetes_node_session(&name, node_uid);
        let completed = control
            .completed_kubernetes_node_decommission(&name, node_uid)
            .unwrap_or(false);
        let decommissioning = control
            .decommissioning_kubernetes_node(&name, node_uid)
            .ok()
            .flatten();
        let sessions = control
            .ready_kubernetes_node_sessions(Duration::from_secs(self.config.session_ttl_seconds));
        let session = sessions.iter().find(|session| {
            session.kubernetes_node_name == name && session.kubernetes_node_uid == node_uid
        });
        let patch = if completed {
            node_decommission_cleanup_patch(node)
        } else {
            node_projection_patch(node, constraints, session)
        };
        let result = nodes
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await;
        if let (Ok(projected), Some(decommissioning)) = (result, decommissioning) {
            if node_has_decommission_quarantine(&projected, &decommissioning) {
                let _result = control
                    .confirm_node_decommission_quarantine(&decommissioning)
                    .await;
            }
        }
    }
}

impl DaemonSetNodeConstraintsV1 {
    pub fn from_daemon_set(daemon_set: &DaemonSet) -> Result<Self> {
        let pod_spec = daemon_set
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .ok_or_else(|| {
                InvalidConfigurationSnafu {
                    reason: "the mithril-node DaemonSet has no Pod template specification"
                        .to_owned(),
                }
                .build()
            })?;
        // A fixed nodeName would bypass scheduler choice and cannot define a node pool.
        ensure!(
            pod_spec.node_name.as_deref().is_none_or(str::is_empty),
            InvalidConfigurationSnafu {
                reason: "the mithril-node DaemonSet cannot select one node with spec.nodeName",
            }
        );
        let required_node_affinity = pod_spec
            .affinity
            .as_ref()
            .and_then(|affinity| affinity.node_affinity.as_ref())
            .and_then(|affinity| {
                affinity
                    .required_during_scheduling_ignored_during_execution
                    .clone()
            });
        if let Some(selector) = &required_node_affinity {
            validate_node_selector(selector)?;
        }
        Ok(Self {
            node_selector: pod_spec.node_selector.clone().unwrap_or_default(),
            required_node_affinity,
        })
    }

    #[must_use]
    pub fn matches_node(&self, node: &Node) -> bool {
        let labels = node.metadata.labels.as_ref();
        let selector_matches = self
            .node_selector
            .iter()
            .all(|(key, expected)| labels.and_then(|labels| labels.get(key)) == Some(expected));
        selector_matches
            && self.required_node_affinity.as_ref().is_none_or(|selector| {
                selector
                    .node_selector_terms
                    .iter()
                    .any(|term| node_selector_term_matches(term, node))
            })
    }
}

#[must_use]
pub fn node_projection_patch(
    node: &Node,
    constraints: &DaemonSetNodeConstraintsV1,
    session: Option<&KubernetesNodeSessionV1>,
) -> Value {
    let eligible = constraints.matches_node(node);
    let session = session.filter(|session| {
        node.metadata.name.as_ref() == Some(&session.kubernetes_node_name)
            && node.metadata.uid.as_ref() == Some(&session.kubernetes_node_uid)
    });
    // Eligibility and an exact live session are both necessary to remove quarantine.
    let ready = eligible && session.is_some();
    let mut taints = node
        .spec
        .as_ref()
        .and_then(|spec| spec.taints.clone())
        .unwrap_or_default();
    // Preserve every non-Mithril taint because this owner has no authority over it.
    taints.retain(|taint| taint.key != KUBERNETES_NOT_READY_TAINT);
    if eligible && !ready {
        taints.push(Taint {
            effect: "NoSchedule".to_owned(),
            key: KUBERNETES_NOT_READY_TAINT.to_owned(),
            time_added: None,
            value: Some("true".to_owned()),
        });
    }
    // Keep identity during a temporary readiness loss only for the same Node object.
    let retained_identity = eligible
        .then_some(node.metadata.annotations.as_ref())
        .flatten()
        .filter(|annotations| {
            annotations.get(KUBERNETES_NODE_UID_ANNOTATION) == node.metadata.uid.as_ref()
        });
    let (ready_label, node_id, node_uid, boot_id, label_epoch) =
        session.filter(|_| ready).map_or_else(
            || {
                (
                    Value::Null,
                    retained_annotation(retained_identity, KUBERNETES_NODE_ID_ANNOTATION),
                    retained_annotation(retained_identity, KUBERNETES_NODE_UID_ANNOTATION),
                    retained_annotation(retained_identity, KUBERNETES_NODE_BOOT_ANNOTATION),
                    retained_annotation(retained_identity, KUBERNETES_LABEL_EPOCH_ANNOTATION),
                )
            },
            |session| {
                (
                    json!("true"),
                    json!(session.node_id),
                    json!(session.kubernetes_node_uid),
                    json!(hex::encode(&session.node_boot_id)),
                    json!(session.label_epoch.to_string()),
                )
            },
        );
    json!({
        "metadata": {
            "labels": { KUBERNETES_READY_LABEL: ready_label },
            "annotations": {
                KUBERNETES_NODE_ID_ANNOTATION: node_id,
                KUBERNETES_NODE_UID_ANNOTATION: node_uid,
                KUBERNETES_NODE_BOOT_ANNOTATION: boot_id,
                KUBERNETES_LABEL_EPOCH_ANNOTATION: label_epoch,
            }
        },
        "spec": { "taints": taints }
    })
}

fn node_decommission_cleanup_patch(node: &Node) -> Value {
    let mut taints = node
        .spec
        .as_ref()
        .and_then(|spec| spec.taints.clone())
        .unwrap_or_default();
    taints.retain(|taint| taint.key != KUBERNETES_NOT_READY_TAINT);
    json!({
        "metadata": {
            "labels": { KUBERNETES_READY_LABEL: Value::Null },
            "annotations": {
                KUBERNETES_NODE_ID_ANNOTATION: Value::Null,
                KUBERNETES_NODE_UID_ANNOTATION: Value::Null,
                KUBERNETES_NODE_BOOT_ANNOTATION: Value::Null,
                KUBERNETES_LABEL_EPOCH_ANNOTATION: Value::Null,
            }
        },
        "spec": { "taints": taints }
    })
}

fn node_has_decommission_quarantine(node: &Node, session: &KubernetesNodeSessionV1) -> bool {
    let labels = node.metadata.labels.as_ref();
    let annotations = node.metadata.annotations.as_ref();
    labels
        .and_then(|labels| labels.get(KUBERNETES_READY_LABEL))
        .is_none()
        && annotations.and_then(|values| values.get(KUBERNETES_NODE_ID_ANNOTATION))
            == Some(&session.node_id)
        && annotations.and_then(|values| values.get(KUBERNETES_NODE_UID_ANNOTATION))
            == Some(&session.kubernetes_node_uid)
        && annotations.and_then(|values| values.get(KUBERNETES_NODE_BOOT_ANNOTATION))
            == Some(&hex::encode(&session.node_boot_id))
        && annotations.and_then(|values| values.get(KUBERNETES_LABEL_EPOCH_ANNOTATION))
            == Some(&session.label_epoch.to_string())
        && node
            .spec
            .as_ref()
            .and_then(|spec| spec.taints.as_ref())
            .is_some_and(|taints| {
                taints.iter().any(|taint| {
                    taint.key == KUBERNETES_NOT_READY_TAINT
                        && taint.effect == "NoSchedule"
                        && taint.value.as_deref() == Some("true")
                })
            })
}

fn retained_annotation(annotations: Option<&BTreeMap<String, String>>, key: &str) -> Value {
    annotations
        .and_then(|values| values.get(key))
        .map_or(Value::Null, |value| json!(value))
}

fn validate_node_selector(selector: &NodeSelector) -> Result<()> {
    // Reject field selectors and operators that the local matcher cannot reproduce exactly.
    ensure!(
        !selector.node_selector_terms.is_empty()
            && selector.node_selector_terms.iter().all(|term| {
                term.match_fields.as_ref().is_none_or(Vec::is_empty)
                    && term.match_expressions.as_ref().is_none_or(|requirements| {
                        requirements.iter().all(requirement_is_supported)
                    })
            }),
        InvalidConfigurationSnafu {
            reason: "the mithril-node DaemonSet uses unsupported required node affinity",
        }
    );
    Ok(())
}

fn requirement_is_supported(requirement: &NodeSelectorRequirement) -> bool {
    match requirement.operator.as_str() {
        "In" | "NotIn" => requirement
            .values
            .as_ref()
            .is_some_and(|values| !values.is_empty()),
        "Exists" | "DoesNotExist" => requirement.values.as_ref().is_none_or(Vec::is_empty),
        _ => false,
    }
}

fn node_selector_term_matches(term: &NodeSelectorTerm, node: &Node) -> bool {
    term.match_fields.as_ref().is_none_or(Vec::is_empty)
        && term.match_expressions.as_ref().is_none_or(|requirements| {
            requirements.iter().all(|requirement| {
                let value = node
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(&requirement.key));
                let values = requirement.values.as_deref().unwrap_or_default();
                match requirement.operator.as_str() {
                    "In" => value.is_some_and(|value| values.contains(value)),
                    "NotIn" => value.is_some_and(|value| !values.contains(value)),
                    "Exists" => value.is_some(),
                    "DoesNotExist" => value.is_none(),
                    _ => false,
                }
            })
        })
}

fn kubernetes_dns_name_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::convert::Infallible;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, HeaderValue, Method, Request, Response};
    use k8s_openapi::api::apps::v1::{DaemonSet, DaemonSetSpec};
    use k8s_openapi::api::core::v1::{
        Affinity, Node, NodeAffinity, NodeSelector, NodeSelectorRequirement, NodeSelectorTerm,
        NodeSpec, PodSpec, PodTemplateSpec, Taint,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
    use kube::{client::Body as KubeBody, Client};
    use serde_json::json;
    use tokio::sync::Mutex;
    use tower::service_fn;

    use super::{
        node_decommission_cleanup_patch, node_has_decommission_quarantine, node_projection_patch,
        DaemonSetNodeConstraintsV1, KubernetesNodeControlConfigV1, KubernetesNodeReadinessOwner,
        KubernetesNodeSessionV1, KUBERNETES_LABEL_EPOCH_ANNOTATION,
        KUBERNETES_NODE_BOOT_ANNOTATION, KUBERNETES_NODE_ID_ANNOTATION,
        KUBERNETES_NODE_UID_ANNOTATION, KUBERNETES_NOT_READY_TAINT, KUBERNETES_READY_LABEL,
    };
    use crate::{ControlPlane, TrustGenerationV1};

    fn daemon_set() -> DaemonSet {
        DaemonSet {
            metadata: ObjectMeta {
                name: Some("mithril-node".to_owned()),
                namespace: Some("mithril-system".to_owned()),
                ..ObjectMeta::default()
            },
            spec: Some(DaemonSetSpec {
                selector: LabelSelector::default(),
                template: PodTemplateSpec {
                    spec: Some(PodSpec {
                        containers: Vec::new(),
                        node_selector: Some(BTreeMap::from([(
                            "pool".to_owned(),
                            "protected".to_owned(),
                        )])),
                        affinity: Some(Affinity {
                            node_affinity: Some(NodeAffinity {
                                required_during_scheduling_ignored_during_execution: Some(
                                    NodeSelector {
                                        node_selector_terms: vec![NodeSelectorTerm {
                                            match_expressions: Some(vec![
                                                NodeSelectorRequirement {
                                                    key: "zone".to_owned(),
                                                    operator: "In".to_owned(),
                                                    values: Some(vec![
                                                        "a".to_owned(),
                                                        "b".to_owned(),
                                                    ]),
                                                },
                                            ]),
                                            ..NodeSelectorTerm::default()
                                        }],
                                    },
                                ),
                                ..NodeAffinity::default()
                            }),
                            ..Affinity::default()
                        }),
                        ..PodSpec::default()
                    }),
                    ..PodTemplateSpec::default()
                },
                ..DaemonSetSpec::default()
            }),
            ..DaemonSet::default()
        }
    }

    fn node(name: &str, pool: &str, zone: &str) -> Node {
        Node {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                uid: Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned()),
                labels: Some(BTreeMap::from([
                    ("pool".to_owned(), pool.to_owned()),
                    ("zone".to_owned(), zone.to_owned()),
                ])),
                ..ObjectMeta::default()
            },
            spec: Some(NodeSpec::default()),
            ..Node::default()
        }
    }

    #[test]
    fn daemon_set_constraints_select_nodes_without_selecting_one_node() -> crate::Result<()> {
        let constraints = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set())?;
        assert!(constraints.matches_node(&node("node-a", "protected", "a")));
        assert!(constraints.matches_node(&node("node-b", "protected", "b")));
        assert!(!constraints.matches_node(&node("node-c", "general", "a")));
        assert!(!constraints.matches_node(&node("node-d", "protected", "c")));
        Ok(())
    }

    #[test]
    fn eligible_node_stays_quarantined_without_current_ready_session() -> crate::Result<()> {
        let constraints = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set())?;
        let patch = node_projection_patch(&node("node-a", "protected", "a"), &constraints, None);
        assert_eq!(
            patch.pointer("/metadata/labels/mithril.erebor.dev~1ready"),
            Some(&serde_json::Value::Null)
        );
        assert_eq!(
            patch
                .pointer("/spec/taints/0/key")
                .and_then(serde_json::Value::as_str),
            Some(KUBERNETES_NOT_READY_TAINT)
        );
        Ok(())
    }

    #[test]
    fn ready_session_removes_quarantine_and_projects_identity() -> crate::Result<()> {
        let constraints = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set())?;
        let session = KubernetesNodeSessionV1 {
            node_id: "enrolled-node-a".to_owned(),
            kubernetes_node_name: "node-a".to_owned(),
            kubernetes_node_uid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            node_boot_id: vec![7; 16],
            label_epoch: 9,
        };
        let patch = node_projection_patch(
            &node("node-a", "protected", "a"),
            &constraints,
            Some(&session),
        );
        assert_eq!(
            patch
                .pointer("/metadata/labels/mithril.erebor.dev~1ready")
                .and_then(serde_json::Value::as_str),
            Some("true")
        );
        assert!(patch
            .pointer("/spec/taints")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty));
        assert_eq!(KUBERNETES_READY_LABEL, "mithril.erebor.dev/ready");
        Ok(())
    }

    #[test]
    fn replaced_node_cannot_inherit_a_ready_session_by_name() -> crate::Result<()> {
        let constraints = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set())?;
        let session = KubernetesNodeSessionV1 {
            node_id: "enrolled-node-a".to_owned(),
            kubernetes_node_name: "node-a".to_owned(),
            kubernetes_node_uid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_owned(),
            node_boot_id: vec![7; 16],
            label_epoch: 9,
        };
        let patch = node_projection_patch(
            &node("node-a", "protected", "a"),
            &constraints,
            Some(&session),
        );
        assert_eq!(
            patch.pointer("/metadata/labels/mithril.erebor.dev~1ready"),
            Some(&serde_json::Value::Null)
        );
        assert!(patch
            .pointer("/spec/taints")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|taints| !taints.is_empty()));
        Ok(())
    }

    #[test]
    fn decommission_exec_requires_exact_quarantine_readback_and_completion_cleans_projection(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let session = KubernetesNodeSessionV1 {
            node_id: "enrolled-node-a".to_owned(),
            kubernetes_node_name: "node-a".to_owned(),
            kubernetes_node_uid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
            node_boot_id: vec![7; 16],
            label_epoch: 9,
        };
        let mut quarantined = node("node-a", "protected", "a");
        quarantined.metadata.annotations = Some(BTreeMap::from([
            (
                KUBERNETES_NODE_ID_ANNOTATION.to_owned(),
                session.node_id.clone(),
            ),
            (
                KUBERNETES_NODE_UID_ANNOTATION.to_owned(),
                session.kubernetes_node_uid.clone(),
            ),
            (
                KUBERNETES_NODE_BOOT_ANNOTATION.to_owned(),
                hex::encode(&session.node_boot_id),
            ),
            (
                KUBERNETES_LABEL_EPOCH_ANNOTATION.to_owned(),
                session.label_epoch.to_string(),
            ),
        ]));
        let spec = quarantined
            .spec
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the node fixture must contain a spec"))?;
        spec.taints = Some(vec![Taint {
            effect: "NoSchedule".to_owned(),
            key: KUBERNETES_NOT_READY_TAINT.to_owned(),
            time_added: None,
            value: Some("true".to_owned()),
        }]);
        assert!(node_has_decommission_quarantine(&quarantined, &session));

        let mut wrong_boot = session.clone();
        wrong_boot.node_boot_id = vec![8; 16];
        assert!(!node_has_decommission_quarantine(&quarantined, &wrong_boot));
        let spec = quarantined
            .spec
            .as_mut()
            .ok_or_else(|| std::io::Error::other("the node fixture must contain a spec"))?;
        spec.taints = None;
        assert!(!node_has_decommission_quarantine(&quarantined, &session));

        let cleanup = node_decommission_cleanup_patch(&quarantined);
        for path in [
            "/metadata/labels/mithril.erebor.dev~1ready",
            "/metadata/annotations/mithril.erebor.dev~1node-id",
            "/metadata/annotations/mithril.erebor.dev~1node-uid",
            "/metadata/annotations/mithril.erebor.dev~1node-boot-id",
            "/metadata/annotations/mithril.erebor.dev~1label-epoch",
        ] {
            assert_eq!(cleanup.pointer(path), Some(&serde_json::Value::Null));
        }
        Ok(())
    }

    #[test]
    fn unsupported_required_affinity_is_rejected() -> crate::Result<()> {
        let mut daemon_set = daemon_set();
        let requirement = daemon_set
            .spec
            .as_mut()
            .and_then(|spec| spec.template.spec.as_mut())
            .and_then(|spec| spec.affinity.as_mut())
            .and_then(|affinity| affinity.node_affinity.as_mut())
            .and_then(|affinity| {
                affinity
                    .required_during_scheduling_ignored_during_execution
                    .as_mut()
            })
            .and_then(|selector| selector.node_selector_terms.first_mut())
            .and_then(|term| term.match_expressions.as_mut())
            .and_then(|requirements| requirements.first_mut());
        let Some(requirement) = requirement else {
            return Err(crate::Error::InvalidConfiguration {
                reason: "the test affinity requirement is absent".to_owned(),
                location: snafu::Location::default(),
            });
        };
        requirement.operator = "Gt".to_owned();
        assert!(DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set).is_err());
        Ok(())
    }

    #[test]
    fn empty_daemon_set_constraints_leave_scheduler_choice_open() -> crate::Result<()> {
        let mut daemon_set = daemon_set();
        let pod_spec = daemon_set
            .spec
            .as_mut()
            .and_then(|spec| spec.template.spec.as_mut())
            .ok_or_else(|| crate::Error::InvalidConfiguration {
                reason: "test DaemonSet has no Pod specification".to_owned(),
                location: snafu::Location::default(),
            })?;
        pod_spec.node_selector = None;
        pod_spec.affinity = None;
        let constraints = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set)?;
        assert!(constraints.matches_node(&node("node-a", "general", "c")));
        assert!(constraints.matches_node(&node("node-b", "protected", "a")));
        Ok(())
    }

    #[test]
    fn daemon_set_selector_change_removes_stale_readiness_projection() -> crate::Result<()> {
        let original = DaemonSetNodeConstraintsV1::from_daemon_set(&daemon_set())?;
        let mut changed_daemon_set = daemon_set();
        changed_daemon_set
            .spec
            .as_mut()
            .and_then(|spec| spec.template.spec.as_mut())
            .and_then(|spec| spec.node_selector.as_mut())
            .ok_or_else(|| crate::Error::InvalidConfiguration {
                reason: "test DaemonSet has no node selector".to_owned(),
                location: snafu::Location::default(),
            })?
            .insert("pool".to_owned(), "next".to_owned());
        let changed = DaemonSetNodeConstraintsV1::from_daemon_set(&changed_daemon_set)?;
        let mut selected = node("node-a", "protected", "a");
        selected
            .metadata
            .labels
            .get_or_insert_default()
            .insert(KUBERNETES_READY_LABEL.to_owned(), "true".to_owned());
        selected
            .spec
            .get_or_insert_default()
            .taints
            .get_or_insert_default()
            .push(Taint {
                effect: "NoSchedule".to_owned(),
                key: KUBERNETES_NOT_READY_TAINT.to_owned(),
                time_added: None,
                value: Some("true".to_owned()),
            });
        assert!(original.matches_node(&selected));
        assert!(!changed.matches_node(&selected));
        let patch = node_projection_patch(&selected, &changed, None);
        assert_eq!(
            patch.pointer("/metadata/labels/mithril.erebor.dev~1ready"),
            Some(&serde_json::Value::Null)
        );
        assert!(patch
            .pointer("/spec/taints")
            .and_then(serde_json::Value::as_array)
            .is_some_and(Vec::is_empty));
        Ok(())
    }

    #[tokio::test]
    async fn node_snapshot_reconciles_every_page_before_returning_its_cursor() -> crate::Result<()>
    {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let service_requests = requests.clone();
        let service = service_fn(move |request: Request<KubeBody>| {
            let service_requests = service_requests.clone();
            async move {
                let method = request.method().clone();
                let uri = request.uri().to_string();
                service_requests
                    .lock()
                    .await
                    .push((method.clone(), uri.clone()));
                let value = if method == Method::GET {
                    let second_page = uri.contains("continue=next");
                    let count = if second_page { 1 } else { 500 };
                    let offset = if second_page { 500 } else { 0 };
                    let items = (offset..offset + count)
                        .map(|index| {
                            json!({
                                "apiVersion": "v1",
                                "kind": "Node",
                                "metadata": {
                                    "name": format!("node-{index}"),
                                    "uid": format!("{index:08x}-0000-4000-8000-000000000000")
                                }
                            })
                        })
                        .collect::<Vec<_>>();
                    json!({
                        "apiVersion": "v1",
                        "kind": "NodeList",
                        "metadata": {
                            "resourceVersion": "snapshot-42",
                            "continue": if second_page { "" } else { "next" }
                        },
                        "items": items
                    })
                } else {
                    json!({
                        "apiVersion": "v1",
                        "kind": "Node",
                        "metadata": {"name": "patched-node"}
                    })
                };
                let mut response = Response::new(Body::from(value.to_string()));
                response.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                Ok::<_, Infallible>(response)
            }
        });
        let client = Client::new(service, "default");
        let nodes = kube::Api::<Node>::all(client);
        let owner = KubernetesNodeReadinessOwner::new(KubernetesNodeControlConfigV1 {
            daemon_set_namespace: "mithril-system".to_owned(),
            daemon_set_name: "mithril-node".to_owned(),
            session_ttl_seconds: 30,
            reconcile_interval_ms: 100,
        })?;
        let control = ControlPlane::new(
            Vec::new(),
            TrustGenerationV1 {
                generation: 1,
                bundle_digest: "0".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
        );
        let cursor = owner
            .reconcile_node_snapshot(
                &nodes,
                &DaemonSetNodeConstraintsV1 {
                    node_selector: BTreeMap::new(),
                    required_node_affinity: None,
                },
                &control,
            )
            .await?;
        let requests = requests.lock().await;
        assert_eq!(cursor, "snapshot-42");
        assert_eq!(
            requests
                .iter()
                .filter(|(method, _)| method == Method::GET)
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|(method, _)| method == Method::PATCH)
                .count(),
            501
        );
        assert!(requests
            .iter()
            .any(|(_, uri)| uri.contains("continue=next")));
        Ok(())
    }
}
