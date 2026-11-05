use std::sync::Arc;

use araphor_analysis_builtins::causal::model::{Action, Audit, Outcome};
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisReadControl,
    AnalysisStore, ContextSensitivityV1, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1,
    LocalSubjectBindingV1, OperationResultAuthorityV1, PackageErrorCodeV1 as Code,
    ProofIntegrityV1, ProofQualityV1, RemoteSubjectBindingV1, SourceAuthorityV1,
    TemporalCoverageV1,
};

#[derive(Clone, Copy)]
pub enum CausalRole {
    Completion,
    ApiAudit,
    Scheduler,
    Runtime,
}

pub struct CollectedAction {
    pub record: DiscoveryRecordIdV1,
    pub revision: u64,
    pub task: u64,
    pub process: [u8; 16],
    pub outcome: Outcome,
    pub status_code: Option<u32>,
    pub action: Action,
}

pub struct CausalCollector {
    data: Arc<AnalysisStore>,
    store: crate::ControlStore,
    tenant: [u8; 16],
    node: String,
    role: CausalRole,
}

impl crate::ControlPlane {
    pub fn causal_collector(
        &self,
        tenant: [u8; 16],
        node: &str,
        role: CausalRole,
    ) -> crate::Result<CausalCollector> {
        let allowed = self
            .allowed_nodes()
            .get(node)
            .ok_or_else(|| Code::Denied.error("causal collector node"))?;
        if uuid::Uuid::parse_str(&allowed.tenant_id)
            .ok()
            .map(|id| *id.as_bytes())
            != Some(tenant)
        {
            return Err(Code::Denied.error("causal collector tenant").into());
        }
        Ok(CausalCollector {
            data: self
                .analysis_store()
                .ok_or_else(|| Code::Incomplete.error("causal collector Data owner"))?,
            store: self
                .evidence
                .as_ref()
                .map(crate::EvidenceIntakeOwner::store)
                .ok_or_else(|| Code::Incomplete.error("causal collector Control owner"))?,
            tenant,
            node: node.into(),
            role,
        })
    }
}

impl CausalCollector {
    pub fn submit(
        &self,
        inputs: Vec<CollectedAction>,
        control: &AnalysisReadControl,
    ) -> crate::Result<Vec<AnalysisContextRefV1>> {
        let mut contexts = Vec::with_capacity(inputs.len());
        for input in inputs {
            control.check()?;
            self.check_source(&input.record)?;
            let (role, remote) = match (self.role, &input.action) {
                (CausalRole::Completion, Action::CredentialAccess { .. }) => {
                    ("completion", RemoteSubjectBindingV1::ExactObject)
                }
                (CausalRole::ApiAudit, Action::TokenRequest { .. } | Action::PodCreate { .. })
                    if input.status_code.is_some() =>
                {
                    ("api", RemoteSubjectBindingV1::ExactRequest)
                }
                (CausalRole::Scheduler, Action::PodScheduled { .. }) => {
                    ("scheduler", RemoteSubjectBindingV1::ExactObject)
                }
                (CausalRole::Runtime, Action::ContainerAdmitted { .. }) => {
                    ("runtime", RemoteSubjectBindingV1::ExactObject)
                }
                _ => {
                    return Err(Code::Denied
                        .error("causal collector action permission")
                        .into())
                }
            };
            if input.revision == 0 {
                return Err(Code::Invalid
                    .error("causal collector observation revision")
                    .into());
            }
            let proof = ProofQualityV1 {
                source_authority: SourceAuthorityV1::AuthenticatedMeasurement,
                local_subject_binding: LocalSubjectBindingV1::ExactTask,
                remote_subject_binding: remote,
                operation_result_authority: match input.outcome {
                    Outcome::Succeeded => OperationResultAuthorityV1::AuthoritativeSucceeded,
                    Outcome::Denied => OperationResultAuthorityV1::AuthoritativeDenied,
                    Outcome::Failed => OperationResultAuthorityV1::ObservedAttempt,
                },
                temporal_coverage: TemporalCoverageV1::Unknown,
                integrity: ProofIntegrityV1::AuthenticatedChannel,
            };
            let audit = Audit {
                schema_version: 1,
                record: input.record,
                task: input.task,
                process: input.process,
                outcome: input.outcome,
                status_code: input.status_code,
                action: input.action,
                proof,
            };
            let body = audit
                .encode()
                .map_err(|_| Code::Invalid.error("causal collector observation"))?;
            let entity = rmp_serde::to_vec(&(role, &audit.record))
                .map_err(|_| Code::Invalid.error("causal collector observation key"))?;
            contexts.push(AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: self.tenant,
                    owner_id: Audit::OWNER.into(),
                    entity_key: entity,
                    lifetime_key: audit.record.stream.key(),
                    owner_revision: input.revision,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::HostRestricted,
                body,
            });
        }
        Ok(self
            .data
            .commit_contexts_guarded(&contexts, || control.check())?)
    }

    fn check_source(&self, record: &DiscoveryRecordIdV1) -> crate::Result<()> {
        let source: &EvidenceIntakeIdentityV1 = &record.stream;
        if source.tenant_id != self.tenant
            || source.node_id != self.node
            || !source.valid()
            || self
                .data
                .source_binding(
                    self.tenant,
                    &self.node,
                    source.source_id,
                    source.source_epoch,
                )?
                .as_ref()
                != Some(source)
        {
            return Err(Code::Denied.error("causal collector source binding").into());
        }
        let session = self.store.evidence_session_for_stream(
            &self.node,
            source.node_boot_id,
            Some(source.label_epoch),
        )?;
        let receipt = self
            .data
            .source_receipt(source)?
            .ok_or_else(|| Code::Missing.error("causal collector source receipt"))?;
        if session.label_epoch != source.label_epoch
            || receipt.cpu_id != record.cpu_id
            || record.durable_cursor == 0
            || record.durable_cursor > receipt.contiguous_cursor
            || record.durable_cursor <= receipt.retained_floor
        {
            return Err(Code::Denied.error("causal collector record scope").into());
        }
        Ok(())
    }
}
