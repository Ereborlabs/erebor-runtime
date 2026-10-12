use super::super::*;

impl ReplayQualification {
    pub(super) fn incident_cards() -> crate::platform::TestResult<Vec<Card>> {
        Ok(serde_json::from_slice(include_bytes!(
            "../../../../../fixtures/discovery/incident-cards-v1.json"
        ))?)
    }

    pub(super) fn card_input(
        &self,
        card: &Card,
        source_id: u8,
    ) -> crate::platform::TestResult<EvidenceIntakeIdentityV1> {
        let mut denied = GraphNotificationQualification::native(1, true);
        denied.effect_family = card.family;
        denied.operation = card.operation;
        let mut control = GraphNotificationQualification::native(2, false);
        control.effect_family = card.family;
        control.operation = card.operation;
        let source = self.accept(source_id, &[denied, control])?;
        let record = self.record(&source, 2)?;
        for (index, (action, classification)) in card.contexts.iter().enumerate() {
            self.inputs.insert(
                GraphFactV1 {
                    record_id: record.id.clone(),
                    value: GraphFactValueV1::Context {
                        subject: GraphSubjectKeyV1 {
                            tenant_id: source.tenant_id,
                            authority: GraphSubjectAuthorityV1::External {
                                authority_id: format!("{}-context", card.id),
                            },
                            kind: GraphSubjectKindV1::External,
                            identity: action.as_bytes().to_vec(),
                        },
                        action_id: action.clone(),
                        classification: *classification,
                        proof_quality: ProofQualityV1 {
                            source_authority: SourceAuthorityV1::AuthenticatedMeasurement,
                            local_subject_binding: LocalSubjectBindingV1::None,
                            remote_subject_binding: RemoteSubjectBindingV1::Contextual,
                            operation_result_authority: OperationResultAuthorityV1::Contextual,
                            temporal_coverage: TemporalCoverageV1::Unknown,
                            integrity: ProofIntegrityV1::AuthenticatedChannel,
                        },
                    },
                },
                &format!("context-{source_id}-{index}"),
                1,
            )?;
        }
        Ok(source)
    }

    pub(super) fn contradiction_input(
        &self,
        record: &DiscoveryRecordV1,
        value: PolicyObservationProvenanceV1,
    ) -> crate::platform::TestResult<()> {
        self.inputs.insert(
            GraphFactV1 {
                record_id: record.id.clone(),
                value: GraphFactValueV1::Policy(value),
            },
            "contradictory-policy",
            1,
        )?;
        Ok(())
    }

    pub(super) fn partial_node_input(
        &self,
        source: &EvidenceIntakeIdentityV1,
        remote: &EvidenceIntakeIdentityV1,
    ) -> crate::platform::TestResult<()> {
        self.inputs.insert(
            GraphFactV1 {
                record_id: self.record(source, 1)?.id,
                value: GraphFactValueV1::Kubernetes(KubernetesStageProofV1 {
                    cluster_id: "recorded-cluster".into(),
                    carried_request_id: Some("recorded-cross-node-request".into()),
                    audit_id: Some("recorded-cross-node-audit".into()),
                    object_uid: Some("recorded-object".into()),
                    resource_version: Some("recorded-version".into()),
                    owner_uid: Some("recorded-owner".into()),
                    pod_uid: Some("recorded-pod".into()),
                    node_id: Some(remote.node_id.clone()),
                    full_container_id: None,
                    remote_admission_id: None,
                    proof_quality: Self::proof(),
                }),
            },
            "cross-node-scheduled",
            1,
        )?;
        Ok(())
    }
}
