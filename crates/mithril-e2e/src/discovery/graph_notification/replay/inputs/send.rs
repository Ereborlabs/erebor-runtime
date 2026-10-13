use super::*;

impl ReplayQualification {
    pub(in super::super) fn send_input(
        &self,
        source_id: u8,
        name: &str,
        denied: bool,
    ) -> std::result::Result<(DiscoveryRecordV1, Option<GraphFactV1>), Box<dyn StdError>> {
        let mut raw = GraphNotificationQualification::native(1, denied);
        raw.effect_family = KernelEffectFamilyV1::Network as u16;
        raw.operation = KernelEffectOperationV1::Send as u16;
        let source = self.accept(source_id, &[raw])?;
        let record = self.record(&source, 1)?;
        if !denied {
            self.policy(&record)?;
            self.inputs.insert(
                GraphFactV1 {
                    record_id: record.id.clone(),
                    value: GraphFactValueV1::Baseline {
                        role_id: 1,
                        state_id: 1,
                        outside_reviewed_baseline: true,
                        reviewed_policy_revision: "recorded-reviewed-source".into(),
                    },
                },
                "network-baseline",
                1,
            )?;
        }
        let provider = if name == "provider-write" {
            let provider = GraphFactV1 {
                record_id: record.id.clone(),
                value: GraphFactValueV1::AuthorityUse {
                    authority_id: "recorded-provider".into(),
                    process_instance_id: None,
                    task_cookie: None,
                    credential_object_id: None,
                    socket_object_id: None,
                    request_id: Some("recorded-publication-43".into()),
                    credential_lease_id: None,
                    principal_id: "recorded-publisher".into(),
                    operation_id: "publication.write".into(),
                    outside_reviewed_behavior: true,
                    proof_quality: ProofQualityV1 {
                        source_authority: SourceAuthorityV1::AuthoritativeProvider,
                        local_subject_binding: LocalSubjectBindingV1::None,
                        remote_subject_binding: RemoteSubjectBindingV1::ExactRequest,
                        operation_result_authority:
                            OperationResultAuthorityV1::AuthoritativeSucceeded,
                        temporal_coverage: TemporalCoverageV1::Complete,
                        integrity: ProofIntegrityV1::Signed,
                    },
                    workload_binding: None,
                },
            };
            self.inputs
                .insert(provider.clone(), "provider-publication-result", 1)?;
            Some(provider)
        } else {
            None
        };
        Ok((record, provider))
    }
}
