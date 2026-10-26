use araphor_data::EvidenceDecisionCatalogV1;
use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;

use super::super::Observed;
use crate::platform::{Task, TestResult};

impl Observed {
    pub(super) fn check_physical(
        &self,
        task: &Task,
        snapshot: &MithrilObservationSnapshot,
        expected: &serde_json::Value,
    ) -> TestResult<()> {
        let prior = &expected["notice"];
        assert_eq!(
            serde_json::to_value(&self.notice.failure)?,
            prior["failure"]
        );
        assert_eq!(
            self.notice.acknowledged,
            prior["acknowledged"]
                .as_bool()
                .ok_or("paired acknowledgement")?
        );
        let first = prior["first_seen"]
            .as_u64()
            .ok_or("paired first-seen time")?;
        let deadline = prior["deadline"].as_u64().ok_or("paired deadline")?;
        assert_eq!(
            self.notice.deadline.checked_sub(self.notice.first_seen),
            deadline.checked_sub(first)
        );
        let attempts: Vec<araphor_data::NotificationAttemptV1> =
            serde_json::from_value(prior["attempts"].clone())?;
        assert_eq!(self.notice.attempts.len(), attempts.len());
        for (actual, before) in self.notice.attempts.iter().zip(attempts) {
            assert_eq!(actual.kind, before.kind);
            assert_eq!(actual.result, before.result);
        }
        assert!(snapshot.kernel_ready && snapshot.effect_health_available);
        assert_eq!(snapshot.pending_evidence_records, 0);
        let boot = uuid::Uuid::parse_str(&snapshot.node_boot_id)?.into_bytes();
        for (record, reason, result) in [
            (&self.records[0], "EXACT_POLICY_DENY", -libc::EACCES),
            (&self.records[1], "APPLICATION_DEFAULT_ALLOW", 0),
        ] {
            assert_eq!(
                record.id.stream.node_id,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
            );
            assert_eq!(record.id.stream.node_boot_id, boot);
            assert_eq!(record.id.stream.label_epoch, snapshot.label_epoch);
            let wire = record.decode()?;
            let context = wire
                .decision_context
                .as_ref()
                .ok_or("physical decision context")?;
            let native = snapshot
                .recent_effects
                .iter()
                .find(|event| {
                    event.source_cpu_id == record.id.cpu_id
                        && Some(event.source_sequence) == record.original_kernel_sequence
                })
                .ok_or("accepted physical effect is absent from the Node snapshot")?;
            assert!(task.matches_effect(
                native,
                reason,
                KernelEffectFamilyV1::File,
                KernelEffectOperationV1::OpenRead,
                result
            ));
            assert_eq!(wire.task_cookie, native.task_cookie);
            assert_eq!(wire.reason, native.reason_code);
            assert_eq!(wire.kernel_result, native.kernel_result);
            assert_eq!(wire.observed_boottime_ns, native.observed_boottime_ns);
            assert_eq!(
                hex::encode(&context.process_instance_id),
                native.process_instance_id
            );
            assert_eq!(
                hex::encode(&context.entry_instance_id),
                native.entry_instance_id
            );
            assert_eq!(hex::encode(&context.binding_id), native.binding_id);
            assert_eq!(
                context.profile_generation_ref_id,
                native.profile_generation_ref_id
            );
            assert_eq!(context.role_id, native.active_role_id);
            assert_eq!(context.state_id, native.process_state_vector_id);
            assert_eq!(context.entry_rule_id, native.admitted_entry_rule_id);
        }
        let wire = self.records[0].decode()?;
        let catalog = EvidenceDecisionCatalogV1::from_context(
            wire.decision_context
                .as_ref()
                .ok_or("protected catalog context")?,
        )?
        .ok_or("protected signed policy catalog")?;
        assert_eq!(catalog.node_boot_id.to_be_bytes(), boot);
        assert_eq!(
            catalog.profile_generation_ref_id,
            wire.profile_generation_ref_id
                .ok_or("protected generation")?
        );
        assert_eq!(
            catalog.binding_id.to_be_bytes().as_slice(),
            wire.decision_context
                .as_ref()
                .ok_or("protected binding")?
                .binding_id
                .as_slice()
        );
        Ok(())
    }
}
