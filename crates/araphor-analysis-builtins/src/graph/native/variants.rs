use super::super::*;
use super::invalid;
use super::views::*;
use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeAuthorityRow {
    node_id: String,
    node_boot_id: ByteBuf,
    label_epoch: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityIdRow {
    authority_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClusterRow {
    cluster_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityRow {
    tag: String,
    native: Option<NativeAuthorityRow>,
    provider: Option<AuthorityIdRow>,
    kubernetes: Option<ClusterRow>,
    external: Option<AuthorityIdRow>,
}
impl From<&GraphSubjectAuthorityV1> for AuthorityRow {
    fn from(v: &GraphSubjectAuthorityV1) -> Self {
        let mut row = Self {
            tag: String::new(),
            native: None,
            provider: None,
            kubernetes: None,
            external: None,
        };
        match v {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => {
                row.tag = "NATIVE".into();
                row.native = Some(NativeAuthorityRow {
                    node_id: node_id.clone(),
                    node_boot_id: ByteBuf::from(node_boot_id.to_vec()),
                    label_epoch: *label_epoch,
                });
            }
            GraphSubjectAuthorityV1::Provider { authority_id } => {
                row.tag = "PROVIDER".into();
                row.provider = Some(AuthorityIdRow {
                    authority_id: authority_id.clone(),
                });
            }
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => {
                row.tag = "KUBERNETES".into();
                row.kubernetes = Some(ClusterRow {
                    cluster_id: cluster_id.clone(),
                });
            }
            GraphSubjectAuthorityV1::External { authority_id } => {
                row.tag = "EXTERNAL".into();
                row.external = Some(AuthorityIdRow {
                    authority_id: authority_id.clone(),
                });
            }
        }
        row
    }
}
impl TryFrom<AuthorityRow> for GraphSubjectAuthorityV1 {
    type Error = sdk::Error;
    fn try_from(v: AuthorityRow) -> sdk::Result<Self> {
        if [
            v.native.is_some(),
            v.provider.is_some(),
            v.kubernetes.is_some(),
            v.external.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            != 1
        {
            return Err(invalid("graph native authority payload"));
        }
        match v.tag.as_str() {
            "NATIVE" => v
                .native
                .map(|row| {
                    Ok(Self::Native {
                        node_id: row.node_id,
                        node_boot_id: id(row.node_boot_id)?,
                        label_epoch: row.label_epoch,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native authority tag"))),
            "PROVIDER" => v
                .provider
                .map(|row| Self::Provider {
                    authority_id: row.authority_id,
                })
                .ok_or_else(|| invalid("graph native authority tag")),
            "KUBERNETES" => v
                .kubernetes
                .map(|row| Self::Kubernetes {
                    cluster_id: row.cluster_id,
                })
                .ok_or_else(|| invalid("graph native authority tag")),
            "EXTERNAL" => v
                .external
                .map(|row| Self::External {
                    authority_id: row.authority_id,
                })
                .ok_or_else(|| invalid("graph native authority tag")),
            _ => Err(invalid("graph native authority tag")),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContextRow {
    subject: SubjectKeyRow,
    action_id: String,
    classification: GraphContextActionV1,
    proof_quality: ProofRow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialRow {
    object_id: ByteBuf,
    expected_access: bool,
    reviewed_policy_revision: String,
    completion: Option<CompletionRow>,
    proof_quality: ProofRow,
    principal_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BaselineRow {
    role_id: u32,
    state_id: u32,
    outside_reviewed_baseline: bool,
    reviewed_policy_revision: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ParentRow {
    parent: SubjectKeyRow,
    child: SubjectKeyRow,
    proof_quality: ProofRow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AuthorityUseRow {
    authority_id: String,
    process_instance_id: Option<ByteBuf>,
    task_cookie: Option<u64>,
    credential_object_id: Option<ByteBuf>,
    socket_object_id: Option<ByteBuf>,
    request_id: Option<String>,
    credential_lease_id: Option<String>,
    principal_id: String,
    operation_id: String,
    outside_reviewed_behavior: bool,
    proof_quality: ProofRow,
    workload_binding: Option<SubjectKeyRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ChannelRow {
    task_cookie: u64,
    process_instance_id: ByteBuf,
    socket_object_id: ByteBuf,
    authority_id: String,
    carried_request_id: String,
    credential_lease_id: String,
    principal_id: String,
    operation_id: String,
    proof_quality: ProofRow,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FactValueRow {
    tag: String,
    policy: Option<PolicyRow>,
    activation: Option<ActivationRow>,
    context: Option<ContextRow>,
    credential: Option<CredentialRow>,
    baseline: Option<BaselineRow>,
    native_parent: Option<ParentRow>,
    authority_use: Option<AuthorityUseRow>,
    channel: Option<ChannelRow>,
    kubernetes: Option<KubernetesRow>,
}
impl From<&GraphFactValueV1> for FactValueRow {
    fn from(v: &GraphFactValueV1) -> Self {
        let mut row = Self {
            tag: String::new(),
            policy: None,
            activation: None,
            context: None,
            credential: None,
            baseline: None,
            native_parent: None,
            authority_use: None,
            channel: None,
            kubernetes: None,
        };
        match v {
            GraphFactValueV1::Policy(value) => {
                row.tag = "POLICY".into();
                row.policy = Some(PolicyRow::from(value));
            }
            GraphFactValueV1::Activation(value) => {
                row.tag = "ACTIVATION".into();
                row.activation = Some(ActivationRow::from(value));
            }
            GraphFactValueV1::Context {
                subject,
                action_id,
                classification,
                proof_quality,
            } => {
                row.tag = "CONTEXT".into();
                row.context = Some(ContextRow {
                    subject: SubjectKeyRow::from(subject),
                    action_id: action_id.clone(),
                    classification: *classification,
                    proof_quality: ProofRow::from(proof_quality),
                });
            }
            GraphFactValueV1::Credential {
                object_id,
                expected_access,
                reviewed_policy_revision,
                completion,
                proof_quality,
                principal_id,
            } => {
                row.tag = "CREDENTIAL".into();
                row.credential = Some(CredentialRow {
                    object_id: ByteBuf::from(object_id.to_vec()),
                    expected_access: *expected_access,
                    reviewed_policy_revision: reviewed_policy_revision.clone(),
                    completion: completion.as_ref().map(CompletionRow::from),
                    proof_quality: ProofRow::from(proof_quality),
                    principal_id: principal_id.clone(),
                });
            }
            GraphFactValueV1::Baseline {
                role_id,
                state_id,
                outside_reviewed_baseline,
                reviewed_policy_revision,
            } => {
                row.tag = "BASELINE".into();
                row.baseline = Some(BaselineRow {
                    role_id: *role_id,
                    state_id: *state_id,
                    outside_reviewed_baseline: *outside_reviewed_baseline,
                    reviewed_policy_revision: reviewed_policy_revision.clone(),
                });
            }
            GraphFactValueV1::NativeParent {
                parent,
                child,
                proof_quality,
            } => {
                row.tag = "NATIVE_PARENT".into();
                row.native_parent = Some(ParentRow {
                    parent: SubjectKeyRow::from(parent),
                    child: SubjectKeyRow::from(child),
                    proof_quality: ProofRow::from(proof_quality),
                });
            }
            GraphFactValueV1::AuthorityUse {
                authority_id,
                process_instance_id,
                task_cookie,
                credential_object_id,
                socket_object_id,
                request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                outside_reviewed_behavior,
                proof_quality,
                workload_binding,
            } => {
                row.tag = "AUTHORITY_USE".into();
                row.authority_use = Some(AuthorityUseRow {
                    authority_id: authority_id.clone(),
                    process_instance_id: process_instance_id
                        .map(|value| ByteBuf::from(value.to_vec())),
                    task_cookie: *task_cookie,
                    credential_object_id: credential_object_id
                        .map(|value| ByteBuf::from(value.to_vec())),
                    socket_object_id: socket_object_id.map(|value| ByteBuf::from(value.to_vec())),
                    request_id: request_id.clone(),
                    credential_lease_id: credential_lease_id.clone(),
                    principal_id: principal_id.clone(),
                    operation_id: operation_id.clone(),
                    outside_reviewed_behavior: *outside_reviewed_behavior,
                    proof_quality: ProofRow::from(proof_quality),
                    workload_binding: workload_binding.as_ref().map(SubjectKeyRow::from),
                });
            }
            GraphFactValueV1::Channel {
                task_cookie,
                process_instance_id,
                socket_object_id,
                authority_id,
                carried_request_id,
                credential_lease_id,
                principal_id,
                operation_id,
                proof_quality,
            } => {
                row.tag = "CHANNEL".into();
                row.channel = Some(ChannelRow {
                    task_cookie: *task_cookie,
                    process_instance_id: ByteBuf::from(process_instance_id.to_vec()),
                    socket_object_id: ByteBuf::from(socket_object_id.to_vec()),
                    authority_id: authority_id.clone(),
                    carried_request_id: carried_request_id.clone(),
                    credential_lease_id: credential_lease_id.clone(),
                    principal_id: principal_id.clone(),
                    operation_id: operation_id.clone(),
                    proof_quality: ProofRow::from(proof_quality),
                });
            }
            GraphFactValueV1::Kubernetes(value) => {
                row.tag = "KUBERNETES".into();
                row.kubernetes = Some(KubernetesRow::from(value));
            }
        }
        row
    }
}
impl TryFrom<FactValueRow> for GraphFactValueV1 {
    type Error = sdk::Error;
    fn try_from(v: FactValueRow) -> sdk::Result<Self> {
        if [
            v.policy.is_some(),
            v.activation.is_some(),
            v.context.is_some(),
            v.credential.is_some(),
            v.baseline.is_some(),
            v.native_parent.is_some(),
            v.authority_use.is_some(),
            v.channel.is_some(),
            v.kubernetes.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count()
            != 1
        {
            return Err(invalid("graph native fact payload"));
        }
        match v.tag.as_str() {
            "POLICY" => v
                .policy
                .map(|row| row.try_into().map(Self::Policy))
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "ACTIVATION" => v
                .activation
                .map(|row| row.try_into().map(Self::Activation))
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "CONTEXT" => v
                .context
                .map(|row| {
                    Ok(Self::Context {
                        subject: row.subject.try_into()?,
                        action_id: row.action_id,
                        classification: row.classification,
                        proof_quality: row.proof_quality.try_into()?,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "CREDENTIAL" => v
                .credential
                .map(|row| {
                    Ok(Self::Credential {
                        object_id: id(row.object_id)?,
                        expected_access: row.expected_access,
                        reviewed_policy_revision: row.reviewed_policy_revision,
                        completion: row.completion.map(TryInto::try_into).transpose()?,
                        proof_quality: row.proof_quality.try_into()?,
                        principal_id: row.principal_id,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "BASELINE" => v
                .baseline
                .map(|row| {
                    Ok(Self::Baseline {
                        role_id: row.role_id,
                        state_id: row.state_id,
                        outside_reviewed_baseline: row.outside_reviewed_baseline,
                        reviewed_policy_revision: row.reviewed_policy_revision,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "NATIVE_PARENT" => v
                .native_parent
                .map(|row| {
                    Ok(Self::NativeParent {
                        parent: row.parent.try_into()?,
                        child: row.child.try_into()?,
                        proof_quality: row.proof_quality.try_into()?,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "AUTHORITY_USE" => v
                .authority_use
                .map(|row| {
                    Ok(Self::AuthorityUse {
                        authority_id: row.authority_id,
                        process_instance_id: row.process_instance_id.map(id).transpose()?,
                        task_cookie: row.task_cookie,
                        credential_object_id: row.credential_object_id.map(id).transpose()?,
                        socket_object_id: row.socket_object_id.map(id).transpose()?,
                        request_id: row.request_id,
                        credential_lease_id: row.credential_lease_id,
                        principal_id: row.principal_id,
                        operation_id: row.operation_id,
                        outside_reviewed_behavior: row.outside_reviewed_behavior,
                        proof_quality: row.proof_quality.try_into()?,
                        workload_binding: row
                            .workload_binding
                            .map(TryInto::try_into)
                            .transpose()?,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "CHANNEL" => v
                .channel
                .map(|row| {
                    Ok(Self::Channel {
                        task_cookie: row.task_cookie,
                        process_instance_id: id(row.process_instance_id)?,
                        socket_object_id: id(row.socket_object_id)?,
                        authority_id: row.authority_id,
                        carried_request_id: row.carried_request_id,
                        credential_lease_id: row.credential_lease_id,
                        principal_id: row.principal_id,
                        operation_id: row.operation_id,
                        proof_quality: row.proof_quality.try_into()?,
                    })
                })
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            "KUBERNETES" => v
                .kubernetes
                .map(|row| row.try_into().map(Self::Kubernetes))
                .unwrap_or_else(|| Err(invalid("graph native fact tag"))),
            _ => Err(invalid("graph native fact tag")),
        }
    }
}
