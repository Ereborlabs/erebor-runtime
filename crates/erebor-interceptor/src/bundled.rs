use sha2::{Digest as _, Sha256};

pub const BUNDLED_BPF_OBJECT: &[u8] = include_bytes!(env!("EREBOR_INTERCEPTOR_BPF_OBJECT"));

#[must_use]
pub fn bundled_bpf_sha256() -> String {
    format!("{:x}", Sha256::digest(BUNDLED_BPF_OBJECT))
}

#[cfg(test)]
mod tests {
    use libbpf_rs::ObjectBuilder;

    use super::{bundled_bpf_sha256, BUNDLED_BPF_OBJECT};

    fn bpf_immediate(instruction: &[u8]) -> Option<i32> {
        Some(i32::from_le_bytes(instruction.get(4..8)?.try_into().ok()?))
    }

    fn open_object() -> crate::Result<libbpf_rs::OpenObject> {
        ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })
    }

    #[test]
    fn libbpf_cargo_built_object_is_embedded_and_parseable() -> crate::Result<()> {
        assert_eq!(bundled_bpf_sha256().len(), 64);
        let object = open_object()?;
        assert!(object
            .progs()
            .any(|program| program.name().to_string_lossy() == "erebor_task_alloc"));
        let activation_probe = object
            .progs()
            .find(|program| program.name().to_string_lossy() == "erebor_policy_activation_probe");
        assert!(activation_probe.is_some());
        if let Some(activation_probe) = activation_probe {
            assert_eq!(activation_probe.section().to_string_lossy(), "classifier");
        }
        Ok(())
    }

    #[test]
    fn enforcement_hooks_and_map_abis_are_in_the_compiled_object() -> crate::Result<()> {
        use std::collections::BTreeSet;
        use std::mem::size_of;

        use erebor_interceptor_abi::{
            BindingActivationTargetKeyV1, ControllerSignalAuthorityKeyV1,
            ControllerSignalAuthorityV1, EffectObservationHealthV1, ExceptionRuntimeStateKeyV1,
            ExceptionRuntimeStateV1, ExecutionSetBindingStateV1, TaskEffectAttemptStateV1,
        };

        let object = open_object()?;
        let programs = object
            .progs()
            .map(|program| program.name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        for required in crate::host::REQUIRED_IDENTITY_PROGRAMS {
            assert!(programs.contains(required), "missing {required}");
        }
        let exception_map = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "exception_runtime_states")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "bounded exception map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            exception_map.key_size() as usize,
            size_of::<ExceptionRuntimeStateKeyV1>()
        );
        assert_eq!(
            exception_map.value_size() as usize,
            size_of::<ExceptionRuntimeStateV1>()
        );
        let receipt_map = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "exception_use_receipts")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "bounded exception receipt map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            u64::from(receipt_map.max_entries()),
            crate::EXCEPTION_USE_RECEIPT_CAPACITY
        );
        let attempt_map = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "task_effect_attempt_states")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "task effect attempt map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            attempt_map.value_size() as usize,
            size_of::<TaskEffectAttemptStateV1>()
        );
        let activation_map = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "binding_activation_targets")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "binding activation target map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            activation_map.key_size() as usize,
            size_of::<BindingActivationTargetKeyV1>()
        );
        assert_eq!(
            activation_map.value_size() as usize,
            size_of::<ExecutionSetBindingStateV1>()
        );
        assert_eq!(activation_map.max_entries(), 65_536);
        let signal_authority_map = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "controller_signal_authorities")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "controller signal authority map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            signal_authority_map.key_size() as usize,
            size_of::<ControllerSignalAuthorityKeyV1>()
        );
        assert_eq!(
            signal_authority_map.value_size() as usize,
            size_of::<ControllerSignalAuthorityV1>()
        );
        assert_eq!(signal_authority_map.max_entries(), 65_536);
        let health = object
            .maps()
            .find(|map| map.name().to_string_lossy() == "effect_observation_health")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "effect observation health map is missing".to_owned(),
                }
                .build()
            })?;
        assert_eq!(
            health.value_size() as usize,
            size_of::<EffectObservationHealthV1>()
        );
        Ok(())
    }

    #[test]
    fn exception_runtime_map_has_a_kernel_typed_spin_lock() -> crate::Result<()> {
        use std::ffi::OsStr;
        use std::path::Path;

        use libbpf_rs::btf::types::Struct;
        use libbpf_rs::Btf;

        let object_path = Path::new("embedded erebor-interceptor.bpf.o");
        let btf = Btf::from_raw("embedded erebor-interceptor.bpf.o", BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF BTF",
                path: object_path.to_path_buf(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: object_path,
                    reason: "bundled BPF object has no BTF".to_owned(),
                }
                .build()
            })?;
        let state = btf
            .type_by_name::<Struct<'_>>("exception_runtime_state_bpf_v1")
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: object_path,
                    reason: "exception map value has no BPF-specific BTF struct".to_owned(),
                }
                .build()
            })?;
        let lock = state
            .iter()
            .find(|member| member.name == Some(OsStr::new("lock")))
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    path: object_path,
                    reason: "exception map value has no lock field".to_owned(),
                }
                .build()
            })?;
        let lock = btf.type_by_id::<Struct<'_>>(lock.ty).ok_or_else(|| {
            crate::error::InvalidConfigurationSnafu {
                path: object_path,
                reason: "exception lock field is not a struct".to_owned(),
            }
            .build()
        })?;
        assert_eq!(lock.name(), Some(OsStr::new("bpf_spin_lock")));
        Ok(())
    }

    #[test]
    fn syscall_exit_tracepoint_does_not_call_spin_lock() -> crate::Result<()> {
        const BPF_CALL: u8 = 0x85;
        let object = open_object()?;
        let mut found = false;
        for program in object
            .progs()
            .filter(|program| program.name().to_string_lossy() == "erebor_mount_mutation_sys_exit")
        {
            found = true;
            assert!(!program.insns().iter().any(|instruction| {
                instruction.code == BPF_CALL
                    && instruction.imm == libbpf_rs::libbpf_sys::BPF_FUNC_spin_lock as i32
            }));
        }
        assert!(found);
        Ok(())
    }

    #[test]
    fn task_alloc_bounds_the_configured_errno_for_lsm() -> crate::Result<()> {
        use erebor_interceptor_abi::IdentityRuntimeConfigV1;
        use libbpf_rs::libbpf_sys::{
            BPF_ALU64, BPF_ARSH, BPF_JMP, BPF_JSLT, BPF_K, BPF_LDX, BPF_LSH, BPF_MEM, BPF_MOV,
            BPF_W,
        };

        const FIRST_EFFECT_ERRNO_OFFSET: i16 =
            std::mem::offset_of!(IdentityRuntimeConfigV1, first_effect_errno) as i16;
        const MAX_ERRNO: i32 = 4095;
        let object = open_object()?;
        let mut found = false;
        for program in object
            .progs()
            .filter(|program| program.name().to_string_lossy() == "erebor_task_alloc")
        {
            let instructions = program.insns();
            let sign_extends = instructions.windows(3).any(|instructions| {
                let errno_register = instructions[0].dst_reg();
                instructions[0].code == (BPF_LDX | BPF_MEM | BPF_W) as u8
                    && instructions[0].off == FIRST_EFFECT_ERRNO_OFFSET
                    && instructions[1].code == (BPF_ALU64 | BPF_LSH | BPF_K) as u8
                    && instructions[1].dst_reg() == errno_register
                    && instructions[1].imm == 32
                    && instructions[2].code == (BPF_ALU64 | BPF_ARSH | BPF_K) as u8
                    && instructions[2].dst_reg() == errno_register
                    && instructions[2].imm == 32
            });
            let bounds = instructions.windows(3).any(|instructions| {
                let errno_register = instructions[0].dst_reg();
                instructions[0].code == (BPF_JMP | BPF_JSLT | BPF_K) as u8
                    && instructions[0].imm == -MAX_ERRNO
                    && instructions[1].code == (BPF_JMP | BPF_JSLT | BPF_K) as u8
                    && instructions[1].dst_reg() == errno_register
                    && instructions[1].imm == 0
                    && instructions[2].code == (BPF_ALU64 | BPF_MOV | BPF_K) as u8
                    && instructions[2].dst_reg() == errno_register
                    && (-MAX_ERRNO..0).contains(&instructions[2].imm)
            });
            found = sign_extends && bounds;
        }
        assert!(found);
        Ok(())
    }

    #[test]
    fn task_alloc_uses_compiled_task_storage_helpers() -> crate::Result<()> {
        const BPF_CALL: u8 = 0x85;
        let object = open_object()?;
        let mut found = false;
        for program in object
            .progs()
            .filter(|program| program.name().to_string_lossy() == "erebor_task_alloc")
        {
            found = true;
            let calls = program
                .insns()
                .iter()
                .filter(|instruction| {
                    instruction.code == BPF_CALL
                        && instruction.imm
                            == libbpf_rs::libbpf_sys::BPF_FUNC_task_storage_get as i32
                })
                .count();
            assert_eq!(calls, 7);
        }
        assert!(found);
        Ok(())
    }

    #[test]
    fn exec_programs_bound_exact_argv_capture_iterations() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_K, BPF_MOV};

        const BPF_CALL: u8 = 0x85;
        const ARGV_LOOP_BUDGET: i32 = 256;
        let object = open_object()?;
        for program_name in ["erebor_sys_enter_execve", "erebor_sys_enter_execveat"] {
            let mut found = false;
            for program in object
                .progs()
                .filter(|program| program.name().to_string_lossy() == program_name)
            {
                found = true;
                let instructions = program.insns();
                let loop_calls = instructions
                    .iter()
                    .enumerate()
                    .filter(|(_, instruction)| {
                        instruction.code == BPF_CALL
                            && instruction.imm == libbpf_rs::libbpf_sys::BPF_FUNC_loop as i32
                    })
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();
                assert_eq!(loop_calls.len(), 1, "{program_name}");
                let loop_call = loop_calls[0];
                assert!(instructions[loop_call.saturating_sub(8)..loop_call]
                    .iter()
                    .any(|instruction| {
                        instruction.code == (BPF_ALU64 | BPF_MOV | BPF_K) as u8
                            && instruction.dst_reg() == 1
                            && instruction.imm == ARGV_LOOP_BUDGET
                    }));
            }
            assert!(found, "bundled object must contain {program_name}");
        }
        Ok(())
    }

    #[test]
    fn bprm_candidate_store_uses_a_compiled_bounded_index() {
        use std::mem::size_of;

        use erebor_interceptor_abi::ExactExecutableCandidateV1;
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_AND, BPF_K, BPF_MUL};

        let candidate_size = size_of::<ExactExecutableCandidateV1>() as i32;
        let instructions = BUNDLED_BPF_OBJECT.chunks_exact(8).collect::<Vec<_>>();
        assert!(instructions.windows(2).any(|pair| {
            pair[0][0] == (BPF_ALU64 | BPF_AND | BPF_K) as u8
                && bpf_immediate(pair[0]) == Some(7)
                && pair[1][0] == (BPF_ALU64 | BPF_MUL | BPF_K) as u8
                && pair[1][1] & 0x0f == pair[0][1] & 0x0f
                && bpf_immediate(pair[1]) == Some(candidate_size)
        }));
    }

    #[test]
    fn bpf_path_walks_use_compiled_component_and_namespace_budgets() {
        use erebor_interceptor_abi::{
            MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1, MAX_CANONICAL_PATH_COMPONENTS_V1,
        };
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_K, BPF_MOV};

        let path_component_budget = MAX_CANONICAL_PATH_COMPONENTS_V1 as i32;
        let mount_scan_depth = MAX_CANONICAL_MOUNT_SCAN_DEPTH_V1 as i32;
        let path_walk_budget = 4_096 + path_component_budget;
        assert_eq!(mount_scan_depth, path_component_budget);
        let instructions = BUNDLED_BPF_OBJECT.chunks_exact(8).collect::<Vec<_>>();
        for budget in [mount_scan_depth, path_component_budget, path_walk_budget] {
            assert!(instructions.iter().enumerate().any(|(index, instruction)| {
                instruction[0] == 0x85
                    && bpf_immediate(instruction)
                        == Some(libbpf_rs::libbpf_sys::BPF_FUNC_loop as i32)
                    && instructions[index.saturating_sub(8)..index]
                        .iter()
                        .any(|candidate| {
                            candidate[0] == (BPF_ALU64 | BPF_MOV | BPF_K) as u8
                                && candidate[1] & 0x0f == 1
                                && bpf_immediate(candidate) == Some(budget)
                        })
            }));
        }
    }
}
