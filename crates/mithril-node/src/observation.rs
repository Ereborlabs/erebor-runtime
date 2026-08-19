use std::collections::VecDeque;
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use erebor_interceptor_abi::{
    EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
    EffectPhysicalResultV1, Id128V1,
};
use erebor_runtime_ipc::v1::MithrilEffectObservation;
use zerocopy::FromBytes as _;

const DEFAULT_RECENT_EFFECT_CAPACITY: usize = 1_024;

#[derive(Clone)]
pub struct EffectObservationStore {
    inner: Arc<Inner>,
}

struct Inner {
    recent: Mutex<RecentEffects>,
    capacity: usize,
    decoder_errors: AtomicU64,
}

struct RecentEffects {
    events: VecDeque<MithrilEffectObservation>,
    cursor: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectObservationHealth {
    pub attempted: u64,
    pub emitted: u64,
    pub lost: u64,
    pub unresolved: u64,
    pub decoder_errors: u64,
}

impl Default for EffectObservationStore {
    fn default() -> Self {
        Self::new(DEFAULT_RECENT_EFFECT_CAPACITY)
    }
}

impl EffectObservationStore {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                recent: Mutex::new(RecentEffects {
                    events: VecDeque::with_capacity(capacity),
                    cursor: 0,
                }),
                capacity,
                decoder_errors: AtomicU64::new(0),
            }),
        }
    }

    pub fn record_bytes(&self, bytes: &[u8]) {
        let Ok(event) = EffectObservationV1::read_from_bytes(bytes) else {
            self.inner.decoder_errors.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let mut recent = self.lock_recent();
        recent.cursor = recent.cursor.saturating_add(1);
        if self.inner.capacity == 0 {
            return;
        }
        if recent.events.len() == self.inner.capacity {
            recent.events.pop_front();
        }
        recent.events.push_back(to_ipc(event));
    }

    #[must_use]
    pub fn recent(&self) -> Vec<MithrilEffectObservation> {
        self.lock_recent().events.iter().cloned().collect()
    }

    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.lock_recent().cursor
    }

    #[must_use]
    pub fn recent_since(&self, cursor: u64) -> Vec<MithrilEffectObservation> {
        let recent = self.lock_recent();
        let first_cursor = recent.cursor - recent.events.len() as u64;
        let skip = cursor.saturating_sub(first_cursor);
        if skip >= recent.events.len() as u64 {
            return Vec::new();
        }
        recent.events.iter().skip(skip as usize).cloned().collect()
    }

    #[must_use]
    pub fn health(&self, per_cpu_bytes: Option<&[u8]>) -> EffectObservationHealth {
        let mut health = EffectObservationHealth {
            decoder_errors: self.inner.decoder_errors.load(Ordering::Relaxed),
            ..EffectObservationHealth::default()
        };
        let Some(bytes) = per_cpu_bytes else {
            return health;
        };
        let width = mem::size_of::<EffectObservationHealthV1>();
        if bytes.is_empty() || !bytes.len().is_multiple_of(width) {
            health.decoder_errors = health.decoder_errors.saturating_add(1);
            return health;
        }
        for chunk in bytes.chunks_exact(width) {
            let Ok(cpu) = EffectObservationHealthV1::read_from_bytes(chunk) else {
                health.decoder_errors = health.decoder_errors.saturating_add(1);
                continue;
            };
            health.attempted = health.attempted.saturating_add(cpu.attempted);
            health.emitted = health.emitted.saturating_add(cpu.emitted);
            health.lost = health.lost.saturating_add(cpu.lost);
            health.unresolved = health.unresolved.saturating_add(cpu.unresolved);
        }
        health
    }

    fn lock_recent(&self) -> MutexGuard<'_, RecentEffects> {
        self.inner
            .recent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

fn to_ipc(event: EffectObservationV1) -> MithrilEffectObservation {
    MithrilEffectObservation {
        observed_boottime_ns: event.observed_boottime_ns,
        task_cookie: event.task_cookie,
        profile_generation_ref_id: event.profile_generation_ref_id,
        process_lineage_id: id_hex(event.process_lineage_id),
        process_instance_id: id_hex(event.process_instance_id),
        entry_instance_id: id_hex(event.entry_instance_id),
        authority_domain_id: id_hex(event.authority_domain_id),
        binding_id: id_hex(event.binding_id),
        execution_set_id: id_hex(event.execution_set_id),
        mount_namespace_inode: event.file_object.mount_namespace_inode,
        mount_id_unique: event.file_object.mount_id_unique,
        filesystem_device: event.file_object.filesystem_device,
        inode: event.file_object.inode,
        inode_generation: event.file_object.inode_generation,
        exact_object_key_id: event.exact_object_key_id,
        composite_atom_id: event.composite_atom_id,
        active_role_id: event.active_role_id,
        process_state_vector_id: event.process_state_vector_id,
        entry_kind: u32::from(event.entry_kind),
        effect_family: u32::from(event.effect_family),
        operation: u32::from(event.operation),
        configured_errno: i32::from(event.configured_errno),
        kernel_result: event.kernel_result,
        reason_code: u32::from(event.reason),
        reason: reason_name(event.reason).to_owned(),
        physical_result_code: u32::from(event.physical_result),
        physical_result: physical_result_name(event.physical_result).to_owned(),
        stage: observation_stage(event.physical_result).to_owned(),
        controller_process_state_id: id_hex(event.controller_process_state_id),
        controller_transition_version: event.controller_transition_version,
        target_task_cookie: event.target_task_cookie,
        target_profile_generation_ref_id: event.target_profile_generation_ref_id,
        target_process_state_id: id_hex(event.target_process_state_id),
        target_transition_version: event.target_transition_version,
        target_role_id: event.target_role_id,
        target_process_state_vector_id: event.target_process_state_vector_id,
        operation_argument: event.operation_argument,
        network_socket_key_id: event.network_socket_key_id,
        network_socket_generation: event.network_socket_generation,
        network_flow_generation: event.network_flow_generation,
        network_destination_policy_handle: event.network_destination_policy_handle,
        network_namespace_address: event.network_namespace.network_namespace_address,
        network_namespace_inode: event.network_namespace.network_namespace_inode,
        network_current_namespace_address: event
            .network_current_namespace
            .network_namespace_address,
        network_current_namespace_inode: event.network_current_namespace.network_namespace_inode,
        network_creator_profile_generation_ref_id: event.network_creator_profile_generation_ref_id,
        network_peer_address: event.network_peer_address.to_vec(),
        network_peer_port: u32::from(event.network_peer_port),
        network_address_family: u32::from(event.network_address_family),
        network_protocol: u32::from(event.network_protocol),
        network_socket_state: u32::from(event.network_socket_state),
        network_response_scope: u32::from(event.network_response_scope),
        network_flow_authorization_id: id_hex(event.network_flow_authorization_id),
        network_creator_destination_policy_handle: event.network_creator_destination_policy_handle,
        network_flow_authorizer_profile_generation_ref_id: event
            .network_flow_authorizer_profile_generation_ref_id,
        network_parent_socket_key_id: event.network_parent_socket_key_id,
        network_parent_socket_generation: event.network_parent_socket_generation,
        io_uring_ring_id: id_hex(event.io_uring_ring_id),
        io_uring_ring_generation: event.io_uring_ring_generation,
        io_uring_submission_sequence: event.io_uring_submission_sequence,
        io_uring_user_data: event.io_uring_user_data,
        io_uring_file_offset: event.io_uring_file_offset,
        io_uring_buffer_address: event.io_uring_buffer_address,
        io_uring_file_cookie: event.io_uring_file_cookie,
        io_uring_executor_pid_tgid: event.io_uring_executor_pid_tgid,
        io_uring_byte_length: event.io_uring_byte_length,
        io_uring_sqe_index: event.io_uring_sqe_index,
        io_uring_request_flags: event.io_uring_request_flags,
        io_uring_rw_flags: event.io_uring_rw_flags,
        io_uring_opcode: u32::from(event.io_uring_opcode),
    }
}

fn id_hex(id: Id128V1) -> String {
    format!("{:016x}{:016x}", id.high, id.low)
}

const fn reason_name(reason: u8) -> &'static str {
    match reason {
        value if value == EffectObservationReasonV1::ExactPolicyAllow as u8 => "EXACT_POLICY_ALLOW",
        value if value == EffectObservationReasonV1::ExactPolicyAuditAllow as u8 => {
            "EXACT_POLICY_AUDIT_ALLOW"
        }
        value if value == EffectObservationReasonV1::WouldDeny as u8 => "WOULD_DENY",
        value if value == EffectObservationReasonV1::PriorLsmDenial as u8 => "PRIOR_LSM_DENIAL",
        value if value == EffectObservationReasonV1::MissingIdentity as u8 => "MISSING_IDENTITY",
        value if value == EffectObservationReasonV1::CorruptIdentityOrGeneration as u8 => {
            "CORRUPT_IDENTITY_OR_GENERATION"
        }
        value if value == EffectObservationReasonV1::UnresolvedObject as u8 => "UNRESOLVED_OBJECT",
        value if value == EffectObservationReasonV1::UnsupportedObject as u8 => {
            "UNSUPPORTED_OBJECT"
        }
        value if value == EffectObservationReasonV1::ExactPolicyDeny as u8 => "EXACT_POLICY_DENY",
        value if value == EffectObservationReasonV1::ExceptionUnavailable as u8 => {
            "EXCEPTION_UNAVAILABLE"
        }
        value if value == EffectObservationReasonV1::PathTreePolicyDeny as u8 => {
            "PATH_TREE_POLICY_DENY"
        }
        value if value == EffectObservationReasonV1::NetworkResponseFence as u8 => {
            "NETWORK_RESPONSE_FENCE"
        }
        _ => "UNKNOWN",
    }
}

const fn physical_result_name(result: u8) -> &'static str {
    match result {
        value if value == EffectPhysicalResultV1::UnknownAfterPreEffect as u8 => {
            "UNKNOWN_AFTER_PRE_EFFECT"
        }
        value if value == EffectPhysicalResultV1::DeniedBeforeEffect as u8 => {
            "DENIED_BEFORE_EFFECT"
        }
        value if value == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u8 => {
            "PACKET_DROPPED_AFTER_REWRITE"
        }
        _ => "UNKNOWN",
    }
}

const fn observation_stage(result: u8) -> &'static str {
    if result == EffectPhysicalResultV1::PacketDroppedAfterRewrite as u8 {
        "FINAL_PACKET_V1"
    } else {
        "LOCAL_PRE_EFFECT_V1"
    }
}

#[cfg(test)]
mod tests {
    use erebor_interceptor_abi::{
        EffectObservationHealthV1, EffectObservationReasonV1, EffectObservationV1,
        EffectPhysicalResultV1, Id128V1, NetworkNamespaceGenerationV1,
    };
    use zerocopy::IntoBytes as _;

    use super::{reason_name, EffectObservationStore};

    #[test]
    fn enforcement_denial_reasons_are_not_downgraded_to_unknown() {
        assert_eq!(
            reason_name(EffectObservationReasonV1::ExactPolicyDeny as u8),
            "EXACT_POLICY_DENY"
        );
        assert_eq!(
            reason_name(EffectObservationReasonV1::ExceptionUnavailable as u8),
            "EXCEPTION_UNAVAILABLE"
        );
    }

    #[test]
    fn records_exact_events_and_bounds_recent_history() {
        let store = EffectObservationStore::new(1);
        for task_cookie in [7, 8] {
            let event = EffectObservationV1 {
                task_cookie,
                process_lineage_id: Id128V1::new(1, 2),
                controller_process_state_id: Id128V1::new(3, 4),
                controller_transition_version: 5,
                target_task_cookie: 6,
                target_profile_generation_ref_id: 7,
                target_process_state_id: Id128V1::new(8, 9),
                target_transition_version: 10,
                target_role_id: 11,
                target_process_state_vector_id: 12,
                operation_argument: 13,
                network_namespace: NetworkNamespaceGenerationV1 {
                    network_namespace_address: 28,
                    network_namespace_inode: 29,
                    reserved: 0,
                },
                network_current_namespace: NetworkNamespaceGenerationV1 {
                    network_namespace_address: 30,
                    network_namespace_inode: 31,
                    reserved: 0,
                },
                io_uring_ring_id: Id128V1::new(14, 15),
                io_uring_ring_generation: 16,
                io_uring_submission_sequence: 17,
                io_uring_user_data: 18,
                io_uring_file_offset: 19,
                io_uring_buffer_address: 20,
                io_uring_file_cookie: 21,
                io_uring_executor_pid_tgid: 22,
                io_uring_byte_length: 23,
                io_uring_sqe_index: 24,
                io_uring_request_flags: 25,
                io_uring_rw_flags: 26,
                io_uring_opcode: 27,
                reason: EffectObservationReasonV1::WouldDeny as u8,
                physical_result: EffectPhysicalResultV1::UnknownAfterPreEffect as u8,
                ..EffectObservationV1::default()
            };
            store.record_bytes(event.as_bytes());
        }
        let recent = store.recent();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].task_cookie, 8);
        assert_eq!(
            recent[0].process_lineage_id,
            "00000000000000010000000000000002"
        );
        assert_eq!(recent[0].reason, "WOULD_DENY");
        assert_eq!(
            recent[0].controller_process_state_id,
            "00000000000000030000000000000004"
        );
        assert_eq!(recent[0].controller_transition_version, 5);
        assert_eq!(recent[0].target_task_cookie, 6);
        assert_eq!(recent[0].target_profile_generation_ref_id, 7);
        assert_eq!(
            recent[0].target_process_state_id,
            "00000000000000080000000000000009"
        );
        assert_eq!(recent[0].target_transition_version, 10);
        assert_eq!(recent[0].target_role_id, 11);
        assert_eq!(recent[0].target_process_state_vector_id, 12);
        assert_eq!(recent[0].operation_argument, 13);
        assert_eq!(recent[0].network_namespace_address, 28);
        assert_eq!(recent[0].network_namespace_inode, 29);
        assert_eq!(recent[0].network_current_namespace_address, 30);
        assert_eq!(recent[0].network_current_namespace_inode, 31);
        assert_eq!(
            recent[0].io_uring_ring_id,
            "000000000000000e000000000000000f"
        );
        assert_eq!(recent[0].io_uring_ring_generation, 16);
        assert_eq!(recent[0].io_uring_submission_sequence, 17);
        assert_eq!(recent[0].io_uring_user_data, 18);
        assert_eq!(recent[0].io_uring_file_offset, 19);
        assert_eq!(recent[0].io_uring_buffer_address, 20);
        assert_eq!(recent[0].io_uring_file_cookie, 21);
        assert_eq!(recent[0].io_uring_executor_pid_tgid, 22);
        assert_eq!(recent[0].io_uring_byte_length, 23);
        assert_eq!(recent[0].io_uring_sqe_index, 24);
        assert_eq!(recent[0].io_uring_request_flags, 25);
        assert_eq!(recent[0].io_uring_rw_flags, 26);
        assert_eq!(recent[0].io_uring_opcode, 27);
    }

    #[test]
    fn cursor_excludes_pre_marker_events_after_recent_history_rolls() {
        let store = EffectObservationStore::new(2);
        let record = |task_cookie| {
            store.record_bytes(
                EffectObservationV1 {
                    task_cookie,
                    ..EffectObservationV1::default()
                }
                .as_bytes(),
            );
        };

        record(1);
        let after_first = store.cursor();
        record(2);
        let after_second = store.cursor();
        record(3);

        assert_eq!(
            store
                .recent_since(after_first)
                .iter()
                .map(|event| event.task_cookie)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert_eq!(
            store
                .recent_since(after_second)
                .iter()
                .map(|event| event.task_cookie)
                .collect::<Vec<_>>(),
            [3]
        );
    }

    #[test]
    fn sums_per_cpu_health_and_counts_decoder_errors() {
        let store = EffectObservationStore::default();
        store.record_bytes(&[1, 2, 3]);
        let first = EffectObservationHealthV1 {
            attempted: 4,
            emitted: 3,
            lost: 1,
            unresolved: 2,
        };
        let second = EffectObservationHealthV1 {
            attempted: 6,
            emitted: 5,
            lost: 1,
            unresolved: 4,
        };
        let bytes = [first.as_bytes(), second.as_bytes()].concat();
        let health = store.health(Some(&bytes));
        assert_eq!(health.attempted, 10);
        assert_eq!(health.emitted, 8);
        assert_eq!(health.lost, 2);
        assert_eq!(health.unresolved, 6);
        assert_eq!(health.decoder_errors, 1);
    }
}
