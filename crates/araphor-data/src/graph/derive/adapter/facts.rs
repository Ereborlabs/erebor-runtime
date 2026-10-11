use super::*;

impl GraphDerivation<'_> {
    pub(super) fn algorithm_fact(
        &self,
        index: usize,
        fact: &GraphFactV1,
    ) -> Result<algorithm::Fact> {
        let row = self
            .input
            .records
            .iter()
            .position(|record| record.id == fact.record_id)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph fact record",
                }
                .build()
            })?;
        let record = &self.input.records[row];
        let value = match &fact.value {
            GraphFactValueV1::NativeParent {
                child,
                proof_quality,
                ..
            } => algorithm::FactValue::Parent {
                child_task: if child.kind == GraphSubjectKindV1::Task {
                    child
                        .identity
                        .as_slice()
                        .try_into()
                        .ok()
                        .map(u64::from_be_bytes)
                } else {
                    None
                },
                child_process: if child.kind == GraphSubjectKindV1::Process {
                    child.identity.as_slice().try_into().ok()
                } else {
                    None
                },
                qualified: proof_quality.temporal_coverage == TemporalCoverageV1::Complete
                    && matches!(
                        proof_quality.integrity,
                        ProofIntegrityV1::Signed
                            | ProofIntegrityV1::AuthenticatedChannel
                            | ProofIntegrityV1::LocalAttested
                    ),
            },
            GraphFactValueV1::Baseline {
                role_id,
                state_id,
                outside_reviewed_baseline,
                reviewed_policy_revision,
            } => algorithm::FactValue::Baseline {
                role: *role_id,
                state: *state_id,
                outside: *outside_reviewed_baseline,
                reviewed: self.reviewed_policy(record, reviewed_policy_revision),
            },
            GraphFactValueV1::Context { classification, .. } => algorithm::FactValue::Context {
                classification: match classification {
                    GraphContextActionV1::OutsideAuthority => {
                        algorithm::ContextClass::OutsideAuthority
                    }
                    GraphContextActionV1::InMemory => algorithm::ContextClass::InMemory,
                    GraphContextActionV1::PayloadUnobservable => {
                        algorithm::ContextClass::PayloadUnobservable
                    }
                },
            },
            GraphFactValueV1::Credential { .. } => self.credential_fact(record, &fact.value)?,
            GraphFactValueV1::AuthorityUse { .. } => Self::authority_fact(&fact.value)?,
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
            } => algorithm::FactValue::Channel(algorithm::Channel {
                task: *task_cookie,
                process: *process_instance_id,
                socket: *socket_object_id,
                authority: authority_id.clone(),
                request: carried_request_id.clone(),
                lease: credential_lease_id.clone(),
                principal: principal_id.clone(),
                operation: operation_id.clone(),
                successful: Self::qualified_result(*proof_quality)
                    && proof_quality.operation_result_authority
                        == OperationResultAuthorityV1::AuthoritativeSucceeded,
            }),
            GraphFactValueV1::Kubernetes(stage) => {
                algorithm::FactValue::Kubernetes(algorithm::Kubernetes {
                    qualified: stage.proof_quality.source_authority
                        == SourceAuthorityV1::AuthoritativeProvider
                        && stage.proof_quality.temporal_coverage == TemporalCoverageV1::Complete
                        && matches!(
                            stage.proof_quality.integrity,
                            ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
                        ),
                    request: stage.carried_request_id.is_some(),
                    audit: stage.audit_id.is_some(),
                    object: stage.object_uid.is_some(),
                    version: stage.resource_version.is_some(),
                    owner: stage.owner_uid.is_some(),
                    pod: stage.pod_uid.is_some(),
                    node: stage.node_id.is_some(),
                    container: stage.full_container_id.is_some(),
                    admission: stage.remote_admission_id.is_some(),
                })
            }
            _ => algorithm::FactValue::Other,
        };
        Ok(algorithm::Fact {
            identity: self.facts[..index]
                .iter()
                .position(|previous| previous == fact)
                .unwrap_or(index) as u64,
            record: row as u64,
            value,
        })
    }
}
