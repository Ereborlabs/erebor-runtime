use super::*;

impl GraphDerivation<'_> {
    pub(super) fn credential_fact(
        &self,
        record: &DiscoveryRecordV1,
        value: &GraphFactValueV1,
    ) -> Result<algorithm::FactValue> {
        let GraphFactValueV1::Credential {
            object_id,
            expected_access,
            reviewed_policy_revision,
            completion,
            proof_quality,
            principal_id,
        } = value
        else {
            return GraphInvalidSnafu {
                field: "graph Credential input",
            }
            .fail();
        };
        Ok(algorithm::FactValue::Credential(algorithm::Credential {
            object: *object_id,
            expected: *expected_access,
            reviewed: self.reviewed_policy(record, reviewed_policy_revision),
            successful: Self::qualified_result(*proof_quality)
                && proof_quality.operation_result_authority
                    == OperationResultAuthorityV1::AuthoritativeSucceeded,
            completion: completion.as_ref().map(Self::algorithm_completion),
            principal: principal_id.clone(),
        }))
    }
    fn algorithm_completion(value: &GraphReadCompletionV1) -> algorithm::Completion {
        algorithm::Completion {
            owner: value.owner.clone(),
            id: value.completion_id.clone(),
            task: value.task_cookie,
            process: value.process_instance_id,
            object: value.object_id,
            file_description: value.file_description_id.clone(),
            path: match value.path {
                GraphReadPathV1::Read => algorithm::ReadPath::Read,
                GraphReadPathV1::Mmap => algorithm::ReadPath::Mmap,
                GraphReadPathV1::InheritedFd => algorithm::ReadPath::InheritedFd,
                GraphReadPathV1::IoUring => algorithm::ReadPath::IoUring,
                GraphReadPathV1::Memory => algorithm::ReadPath::Memory,
            },
            result: value.result,
            bytes: value.byte_count,
            lease: value.credential_lease_id.clone(),
            principal: value.principal_id.clone(),
        }
    }
}
