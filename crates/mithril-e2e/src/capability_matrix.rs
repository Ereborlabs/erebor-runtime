use erebor_interceptor_abi::{CapabilityRecordV1, CapabilityStateV1};

pub const KERNEL_QUALIFICATION_CAPABILITIES: [&str; 19] = [
    "BPF_LSM_ATTACH_READBACK",
    "FILE_OPEN_PRE_EFFECT_DENIAL",
    "TASK_FORK_EXEC_IDENTITY",
    "MOUNT_COMPONENT_GRAPH",
    "TOPOLOGY_MUTATION_DIRTY_ORDERING",
    "EXEC_PRE_EFFECT_DENIAL",
    "FILE_LIFETIME_AND_PERMISSION",
    "MMAP_MPROTECT",
    "IPC_RELATIONSHIP",
    "SOCKET_LIFECYCLE",
    "CGROUP_FINAL_FLOW",
    "DNS_IDENTITY",
    "DEVICE_IOCTL",
    "PROCESS_CONTROL",
    "PRIVILEGE_AND_SELF_PROTECTION",
    "VERIFIER_AND_STACK_BOUNDS",
    "MAP_SATURATION_AND_EVIDENCE_LOSS",
    "AARCH64_PHYSICAL_QUALIFICATION",
    "X86_64_PHYSICAL_QUALIFICATION",
];

pub struct KernelQualificationCapabilityMatrix;

impl KernelQualificationCapabilityMatrix {
    #[must_use]
    pub fn records(physical_evidence_digest: Option<&str>) -> Vec<CapabilityRecordV1> {
        KERNEL_QUALIFICATION_CAPABILITIES
            .into_iter()
            .map(|capability_id| {
                let physically_supported = physical_evidence_digest.is_some()
                    && matches!(
                        capability_id,
                        "BPF_LSM_ATTACH_READBACK"
                            | "FILE_OPEN_PRE_EFFECT_DENIAL"
                            | "X86_64_PHYSICAL_QUALIFICATION"
                    );
                CapabilityRecordV1 {
                    capability_id: capability_id.to_owned(),
                    state: if physically_supported {
                        CapabilityStateV1::Supported
                    } else {
                        CapabilityStateV1::Unsupported
                    },
                    reason_code: if physically_supported {
                        "PHYSICAL_X86_ALLOW_DENY_ALLOW".to_owned()
                    } else if physical_evidence_digest.is_none()
                        && matches!(
                            capability_id,
                            "BPF_LSM_ATTACH_READBACK"
                                | "FILE_OPEN_PRE_EFFECT_DENIAL"
                                | "X86_64_PHYSICAL_QUALIFICATION"
                        )
                    {
                        "CURRENT_ARTIFACT_NOT_PHYSICALLY_RECHECKED".to_owned()
                    } else {
                        "NOT_PHYSICALLY_QUALIFIED".to_owned()
                    },
                    evidence_digest: physically_supported
                        .then(|| physical_evidence_digest.unwrap_or_default().to_owned()),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use erebor_interceptor_abi::CapabilityStateV1;

    use super::{KernelQualificationCapabilityMatrix, KERNEL_QUALIFICATION_CAPABILITIES};

    #[test]
    fn every_allocated_surface_is_supported_or_explicitly_unsupported() {
        let records = KernelQualificationCapabilityMatrix::records(Some(&"a".repeat(64)));
        assert_eq!(records.len(), KERNEL_QUALIFICATION_CAPABILITIES.len());
        assert_eq!(
            records
                .iter()
                .map(|record| record.capability_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            records.len()
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record.state == CapabilityStateV1::Supported)
                .count(),
            3
        );
        assert!(records.iter().all(|record| {
            matches!(
                record.state,
                CapabilityStateV1::Supported | CapabilityStateV1::Unsupported
            )
        }));
    }
}
