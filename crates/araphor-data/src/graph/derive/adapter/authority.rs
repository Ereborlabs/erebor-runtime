use super::*;

impl GraphDerivation<'_> {
    pub(super) fn authority_fact(value: &GraphFactValueV1) -> Result<algorithm::FactValue> {
        let GraphFactValueV1::AuthorityUse {
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
        } = value
        else {
            return GraphInvalidSnafu {
                field: "graph AuthorityUse input",
            }
            .fail();
        };
        Ok(algorithm::FactValue::Authority(algorithm::Authority {
            id: authority_id.clone(),
            process: *process_instance_id,
            task: *task_cookie,
            credential: *credential_object_id,
            socket: *socket_object_id,
            request: request_id.clone(),
            lease: credential_lease_id.clone(),
            principal: principal_id.clone(),
            operation: operation_id.clone(),
            outside: *outside_reviewed_behavior,
            workload: workload_binding
                .as_ref()
                .map(|subject| subject.identity.clone()),
            contextual: matches!(
                proof_quality.source_authority,
                SourceAuthorityV1::AuthoritativeProvider | SourceAuthorityV1::SignedCoordinator
            ) && matches!(
                proof_quality.integrity,
                ProofIntegrityV1::Signed | ProofIntegrityV1::AuthenticatedChannel
            ),
            direct: proof_quality.source_authority == SourceAuthorityV1::AuthoritativeProvider
                && matches!(
                    proof_quality.remote_subject_binding,
                    RemoteSubjectBindingV1::ExactRequest | RemoteSubjectBindingV1::ExactSession
                )
                && matches!(
                    proof_quality.operation_result_authority,
                    OperationResultAuthorityV1::AuthoritativeSucceeded
                        | OperationResultAuthorityV1::AuthoritativeDenied
                )
                && Self::qualified_result(*proof_quality),
            result: match proof_quality.operation_result_authority {
                OperationResultAuthorityV1::AuthoritativeSucceeded => {
                    algorithm::ResultAuthority::Succeeded
                }
                OperationResultAuthorityV1::AuthoritativeDenied => {
                    algorithm::ResultAuthority::Denied
                }
                _ => algorithm::ResultAuthority::Other,
            },
        }))
    }
}
