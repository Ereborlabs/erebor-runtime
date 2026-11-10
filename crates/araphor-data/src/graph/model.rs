use crate::DiscoveryValidate as _;
use crate :: { AnalysisContextVersionV1 , DiscoveryCoverageV1 , DiscoveryRecordIdV1 , DiscoveryRecordV1 , EvidenceIntakeIdentityV1 , GraphInvalidSnafu , Result } ;
pub use araphor_analysis_types :: { DeclaredFindingReasonV1 , FindingReasonV1 , FindingSeverityV1 , FindingV1 , GraphBranchStateV1 , GraphBranchV1 , GraphCauseV1 , GraphContextActionV1 , GraphCoverageKeyV1 , GraphEdgeKeyV1 , GraphEdgeTypeV1 , GraphEdgeV1 , GraphEffectV1 , GraphFactV1 , GraphFactValueV1 , GraphPackageCheckpointV1 , GraphPackageStateV1 , GraphPhysicalResultV1 , GraphPolicyActivationV1 , GraphReadCompletionV1 , GraphReadPathV1 , GraphRevisionV1 , GraphSnapshotV1 , GraphSubjectAuthorityV1 , GraphSubjectKeyV1 , GraphSubjectKindV1 , GraphValidate , GraphVersionV1 , KubernetesStageProofV1 , PolicyObservationProvenanceV1 , PolicyProvenanceStateV1 } ;
use snafu::ResultExt as _;
use std::collections::BTreeSet;

impl TryFrom<&AnalysisContextVersionV1> for GraphFactV1 {
    type Error = crate::Error;

    fn try_from(context: &AnalysisContextVersionV1) -> Result<Self> {
        if !context.key.valid() || context.key.owner_revision == 0 {
            return GraphInvalidSnafu {
                field: "graph context version",
            }
            .fail();
        }
        let value = Self::decode_context(&context.body).context(crate::GraphNativeDecodingSnafu)?;
        value.validate()?;
        if value.record_id.stream.tenant_id != context.key.tenant_id {
            return GraphInvalidSnafu {
                field: "graph context tenant",
            }
            .fail();
        }
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct GraphReplayInputV1 {
    pub source: EvidenceIntakeIdentityV1,
    pub records: Vec<DiscoveryRecordV1>,
    pub input_positions: Vec<(DiscoveryRecordIdV1, crate::StorePositionV1)>,
    pub coverage: Vec<DiscoveryCoverageV1>,
    pub coverage_keys: Vec<GraphCoverageKeyV1>,
    pub facts: Vec<AnalysisContextVersionV1>,
    pub missing_ranges: Vec<(u64, u64)>,
}

impl GraphReplayInputV1 {
    pub fn validate(&self) -> Result<()> {
        if !self.source.valid() || self.records.is_empty() {
            return GraphInvalidSnafu {
                field: "replay input",
            }
            .fail();
        }
        let mut ids = BTreeSet::new();
        for record in &self.records {
            record.decode()?;
            if record.id.stream != self.source || !ids.insert(&record.id) {
                return GraphInvalidSnafu {
                    field: "replay record identity",
                }
                .fail();
            }
        }
        let mut positioned = BTreeSet::new();
        let mut positions = BTreeSet::new();
        for (id, position) in &self.input_positions {
            if !ids.contains(id)
                || position.commit_revision == 0
                || !positioned.insert(id)
                || !positions.insert(position)
            {
                return GraphInvalidSnafu {
                    field: "replay input position",
                }
                .fail();
            }
        }
        if positioned != ids {
            return GraphInvalidSnafu {
                field: "replay input position",
            }
            .fail();
        }
        for range in &self.coverage {
            range.validate()?;
            if range.stream != self.source {
                return GraphInvalidSnafu {
                    field: "replay coverage source",
                }
                .fail();
            }
        }
        for fact in &self.facts {
            let decoded = GraphFactV1::try_from(fact)?;
            if decoded.record_id.stream != self.source || !ids.contains(&decoded.record_id) {
                return GraphInvalidSnafu {
                    field: "replay fact source",
                }
                .fail();
            }
            if let GraphFactValueV1::Policy(policy) = &decoded.value {
                if policy.state == PolicyProvenanceStateV1::Exact {
                    let activation = policy
                        .activation_acknowledgement
                        .as_ref()
                        .and_then(|key| self.facts.iter().find(|fact| &fact.key == key))
                        .ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "unretained activation reference",
                            }
                            .build()
                        })?;
                    let activation = GraphFactV1::try_from(activation)?;
                    let GraphFactValueV1::Activation(ack) = activation.value else {
                        return GraphInvalidSnafu {
                            field: "activation reference type",
                        }
                        .fail();
                    };
                    if activation.record_id != decoded.record_id
                        || ack.node_id != policy.source.node_id
                        || ack.node_boot_id.as_slice() != policy.source.node_boot_id
                        || ack.label_epoch != policy.source.label_epoch
                        || ack.state != "ACTIVE"
                        || ack.profile_generation_ref_id != Some(policy.profile_generation_ref_id)
                        || Some(&ack.candidate_content_id) != policy.candidate_content_id.as_ref()
                        || Some(&ack.policy_source_revision_id)
                            != policy.policy_source_revision_id.as_ref()
                        || Some(&ack.target_snapshot_digest)
                            != policy.target_snapshot_digest.as_ref()
                        || ack.node_bound_generation_digest != policy.node_bound_generation_digest
                        || ack.readback_digest.is_none()
                        || ack.probe_result_digest.is_none()
                    {
                        return GraphInvalidSnafu {
                            field: "activation exact join",
                        }
                        .fail();
                    }
                }
            }
        }
        Ok(())
    }
}
