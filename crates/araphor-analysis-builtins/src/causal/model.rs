use araphor_analysis_types::{
    source::DiscoveryRecordIdV1,
    values::{
        GraphSubjectKeyV1, GraphSubjectKindV1, OperationResultAuthorityV1, ProofIntegrityV1,
        ProofQualityV1, RemoteSubjectBindingV1, SourceAuthorityV1,
    },
};
use serde::{Deserialize, Serialize};

use super::sdk;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub authority: String,
    pub lease: String,
    pub principal: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pod {
    pub cluster: String,
    pub uid: String,
    pub created_revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub cluster: String,
    pub audit: String,
    pub carried: String,
    pub credential: Credential,
    pub socket: [u8; 16],
    pub credential_origin: Origin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub record: DiscoveryRecordIdV1,
    pub proof: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostMount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Container {
    pub name: String,
    pub privileged: bool,
    pub host_mounts: Vec<HostMount>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub pod: Pod,
    pub binding: String,
    pub node: String,
    pub boot: [u8; 16],
    pub label_epoch: u64,
    pub container: String,
    pub container_name: String,
    pub cgroup: u64,
    pub admission: String,
    pub task: u64,
    pub process: [u8; 16],
    pub scheduled_by: Origin,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Succeeded,
    Denied,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Action {
    CredentialAccess {
        credential: Credential,
        object: [u8; 16],
        completion: String,
        result: i64,
        bytes: u64,
    },
    TokenRequest {
        request: Request,
        issued: Option<Credential>,
    },
    PodCreate {
        request: Request,
        pod: Option<Pod>,
        containers: Vec<Container>,
    },
    PodScheduled {
        pod: Pod,
        created_by: Origin,
        binding: String,
        node: String,
    },
    ContainerAdmitted {
        runtime: Runtime,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub schema_version: u32,
    pub record: DiscoveryRecordIdV1,
    pub task: u64,
    pub process: [u8; 16],
    pub outcome: Outcome,
    pub status_code: Option<u32>,
    pub proof: ProofQualityV1,
    pub action: Action,
}

impl Credential {
    fn valid(&self) -> bool {
        !self.authority.is_empty() && !self.lease.is_empty() && !self.principal.is_empty()
    }
}

impl Pod {
    fn valid(&self) -> bool {
        !self.cluster.is_empty() && !self.uid.is_empty() && !self.created_revision.is_empty()
    }
}

impl Request {
    fn valid(&self) -> bool {
        !self.cluster.is_empty()
            && !self.audit.is_empty()
            && !self.carried.is_empty()
            && self.credential.valid()
            && self.socket != [0; 16]
            && self.credential_origin.valid()
    }
}

impl Origin {
    fn valid(&self) -> bool {
        self.record.stream.valid() && self.record.durable_cursor > 0 && !self.proof.is_empty()
    }
}

impl Audit {
    pub const OWNER: &'static str = "mithril-control/causal-audit";

    pub fn decode(bytes: &[u8]) -> sdk::Result<Self> {
        rmp_serde::from_slice::<serde::de::IgnoredAny>(bytes)
            .map_err(|_| Self::invalid("causal audit encoding"))?;
        let value: Self =
            rmp_serde::from_slice(bytes).map_err(|_| Self::invalid("causal audit encoding"))?;
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> sdk::Result<Vec<u8>> {
        self.validate()?;
        rmp_serde::to_vec_named(self).map_err(|_| Self::invalid("causal audit encoding"))
    }

    pub fn validate(&self) -> sdk::Result<()> {
        if self.schema_version != 1
            || !self.record.stream.valid()
            || self.record.durable_cursor == 0
            || self.task == 0
            || self.process == [0; 16]
        {
            return Err(Self::invalid("causal audit identity"));
        }
        if self.status_code.is_some_and(|code| match self.outcome {
            Outcome::Succeeded => !(200..300).contains(&code),
            Outcome::Denied => !matches!(code, 401 | 403),
            Outcome::Failed => (200..300).contains(&code),
        }) {
            return Err(Self::invalid("causal audit outcome"));
        }
        let valid = match &self.action {
            Action::CredentialAccess {
                credential,
                object,
                completion,
                result,
                bytes,
            } => {
                credential.valid()
                    && *object != [0; 16]
                    && !completion.is_empty()
                    && match self.outcome {
                        Outcome::Succeeded => {
                            *result > 0 && u64::try_from(*result).ok() == Some(*bytes)
                        }
                        Outcome::Denied | Outcome::Failed => *result < 0 && *bytes == 0,
                    }
            }
            Action::TokenRequest { request, issued } => {
                request.valid()
                    && request.credential_origin.record.stream.tenant_id
                        == self.record.stream.tenant_id
                    && match self.outcome {
                        Outcome::Succeeded => issued.as_ref().is_some_and(Credential::valid),
                        Outcome::Denied | Outcome::Failed => issued.is_none(),
                    }
            }
            Action::PodCreate {
                request,
                pod,
                containers,
                ..
            } => {
                request.valid()
                    && request.credential_origin.record.stream.tenant_id
                        == self.record.stream.tenant_id
                    && pod
                        .as_ref()
                        .is_none_or(|pod| pod.valid() && pod.cluster == request.cluster)
                    && (self.outcome != Outcome::Succeeded || pod.is_some())
                    && !containers.is_empty()
                    && containers
                        .iter()
                        .map(|container| &container.name)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == containers.len()
                    && containers.iter().all(|container| {
                        !container.name.is_empty()
                            && container.host_mounts.iter().all(|mount| {
                                mount.host_path.starts_with('/')
                                    && mount.container_path.starts_with('/')
                            })
                    })
            }
            Action::PodScheduled {
                pod,
                created_by,
                binding,
                node,
            } => {
                pod.valid()
                    && !binding.is_empty()
                    && !node.is_empty()
                    && created_by.valid()
                    && created_by.record.stream.tenant_id == self.record.stream.tenant_id
            }
            Action::ContainerAdmitted { runtime } => {
                runtime.pod.valid()
                    && !runtime.binding.is_empty()
                    && !runtime.node.is_empty()
                    && runtime.boot != [0; 16]
                    && runtime.label_epoch > 0
                    && !runtime.container.is_empty()
                    && !runtime.container_name.is_empty()
                    && runtime.cgroup > 0
                    && !runtime.admission.is_empty()
                    && runtime.node == self.record.stream.node_id
                    && runtime.boot == self.record.stream.node_boot_id
                    && runtime.label_epoch == self.record.stream.label_epoch
                    && runtime.task == self.task
                    && runtime.process == self.process
                    && runtime.scheduled_by.valid()
                    && runtime.scheduled_by.record.stream.tenant_id == self.record.stream.tenant_id
            }
        };
        if !valid {
            return Err(Self::invalid("causal audit action"));
        }
        Ok(())
    }

    pub(super) fn actor(&self) -> GraphSubjectKeyV1 {
        GraphSubjectKeyV1::native(
            &self.record.stream,
            GraphSubjectKindV1::Task,
            self.task.to_be_bytes().to_vec(),
        )
    }

    pub(super) fn qualified(&self) -> bool {
        matches!(
            self.proof.integrity,
            ProofIntegrityV1::Signed
                | ProofIntegrityV1::AuthenticatedChannel
                | ProofIntegrityV1::LocalAttested
        ) && matches!(
            self.proof.source_authority,
            SourceAuthorityV1::SignedCoordinator
                | SourceAuthorityV1::AuthoritativeProvider
                | SourceAuthorityV1::AuthenticatedMeasurement
        ) && matches!(
            self.proof.remote_subject_binding,
            RemoteSubjectBindingV1::ExactRequest
                | RemoteSubjectBindingV1::ExactSession
                | RemoteSubjectBindingV1::ExactObject
        ) && match self.outcome {
            Outcome::Succeeded => {
                self.proof.operation_result_authority
                    == OperationResultAuthorityV1::AuthoritativeSucceeded
            }
            Outcome::Denied => {
                self.proof.operation_result_authority
                    == OperationResultAuthorityV1::AuthoritativeDenied
            }
            Outcome::Failed => matches!(
                self.proof.operation_result_authority,
                OperationResultAuthorityV1::AuthoritativeDenied
                    | OperationResultAuthorityV1::ObservedAttempt
            ),
        }
    }

    pub(super) fn invalid(field: &'static str) -> sdk::Error {
        sdk::Error::contract(sdk::ErrorCode::Invalid, field)
    }
}
