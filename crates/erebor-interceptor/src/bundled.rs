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

    #[test]
    fn libbpf_cargo_built_object_is_embedded_and_parseable() -> crate::Result<()> {
        assert_eq!(bundled_bpf_sha256().len(), 64);
        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
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
    fn enforcement_local_hooks_and_bounded_exception_map_are_bundled() -> crate::Result<()> {
        use std::collections::BTreeSet;
        use std::mem::size_of;

        use erebor_interceptor_abi::{
            BindingActivationTargetKeyV1, ExceptionRuntimeStateKeyV1, ExceptionRuntimeStateV1,
            ExecutionSetBindingStateV1, TaskEffectAttemptStateV1,
        };

        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        let programs = object
            .progs()
            .map(|program| program.name().to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        for required in crate::host::REQUIRED_IDENTITY_PROGRAMS {
            assert!(programs.contains(required), "missing {required}");
        }
        let exception_map = match object
            .maps()
            .find(|map| map.name().to_string_lossy() == "exception_runtime_states")
        {
            Some(map) => map,
            None => {
                return crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "bounded exception map is missing".to_owned(),
                }
                .fail()
            }
        };
        assert_eq!(
            exception_map.key_size() as usize,
            size_of::<ExceptionRuntimeStateKeyV1>()
        );
        assert_eq!(
            exception_map.value_size() as usize,
            size_of::<ExceptionRuntimeStateV1>()
        );
        let receipt_map = match object
            .maps()
            .find(|map| map.name().to_string_lossy() == "exception_use_receipts")
        {
            Some(map) => map,
            None => {
                return crate::error::InvalidConfigurationSnafu {
                    path: std::path::Path::new("embedded erebor-interceptor.bpf.o"),
                    reason: "bounded exception receipt map is missing".to_owned(),
                }
                .fail()
            }
        };
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
        Ok(())
    }

    #[test]
    fn bounded_exception_denials_do_not_retain_receipts() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let consume = source
            .split("static __always_inline int consume_bounded_exception")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool label_matches_runtime")
                    .next()
            })
            .unwrap_or_default();
        let terminal = consume
            .find("exception->consumed_uses >= exception->maximum_uses")
            .unwrap_or(usize::MAX);
        let idempotent = consume
            .find("return receipt->state == exception_receipt_state_v1_consumed")
            .unwrap_or(usize::MAX);
        let claim = consume.find("BPF_NOEXIST").unwrap_or_default();
        let unlock = consume.rfind("bpf_spin_unlock").unwrap_or(usize::MAX);
        let delete = consume.rfind("bpf_map_delete_elem").unwrap_or_default();

        assert!(idempotent < terminal && terminal < claim);
        assert!(unlock < delete);
        assert!(consume.contains("keep_receipt = true;"));
        assert_eq!(consume.matches("keep_receipt = true;").count(), 1);
    }

    #[test]
    fn bounded_exception_receipt_construction_uses_per_cpu_scratch() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let scratch = source
            .split("struct identity_scratch_v1 {")
            .nth(1)
            .and_then(|source| source.split("};").next())
            .unwrap_or_default();
        let consume = source
            .split("static __always_inline int consume_bounded_exception")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool label_matches_runtime")
                    .next()
            })
            .unwrap_or_default();

        assert!(scratch.contains("exception_use_receipt_key_v1 exception_receipt_key;"));
        assert!(scratch.contains("exception_use_receipt_v1 exception_receipt_draft;"));
        assert!(consume.contains("receipt_key = &scratch->exception_receipt_key;"));
        assert!(consume.contains("claiming = &scratch->exception_receipt_draft;"));
        assert!(consume.contains("__builtin_memset(receipt_key, 0, sizeof(*receipt_key));"));
        assert!(consume.contains("__builtin_memset(claiming, 0, sizeof(*claiming));"));
        assert!(!consume.contains("exception_use_receipt_key_v1 receipt_key = {};"));
        assert!(!consume.contains("exception_use_receipt_v1 claiming = {};"));
    }

    #[test]
    fn bounded_file_open_exceptions_use_exact_attempt_frames() {
        let maps = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let effects =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let exit = include_str!("../../../bpf/erebor-interceptor/programs/identity_exit.bpf.h");
        let file_mode = effects
            .split("static __always_inline int file_mode_effects")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool file_is_socket")
                    .next()
            })
            .unwrap_or_default();
        let read = file_mode
            .split("if (mode & FMODE_READ)")
            .nth(1)
            .and_then(|source| source.split("if (ret)").next())
            .unwrap_or_default();
        let write = file_mode
            .split("if (mode & FMODE_WRITE)")
            .nth(1)
            .unwrap_or_default();
        let open = effects
            .split("SEC(\"lsm/file_open\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_receive\")").next())
            .unwrap_or_default();
        let receive = effects
            .split("SEC(\"lsm/file_receive\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_permission\")").next())
            .unwrap_or_default();

        assert!(maps.contains("__type(value, task_effect_attempt_state_v1);"));
        assert!(maps.contains("attempt->next_effect_attempt_sequence++"));
        assert!(maps.contains("attempt->depth >= MAX_NESTED_EFFECT_ATTEMPTS_V1"));
        assert!(maps.contains("task_effect_attempt_state_kind_v1_overflow_fail_closed"));
        assert!(maps.contains("attempt->depth\n                ? task_effect_attempt_state_kind_v1_overflow_fail_closed"));
        assert!(maps.contains("frame->hook_discriminator != effect_attempt_hook_v1_file_open"));
        assert!(maps.contains("frame->repeated_lsm_pass_count != 1"));
        assert!(maps.contains("frame->operation != operation"));
        assert!(effects.contains("begin_task_effect_syscall(bpf_get_current_task_btf())"));
        assert!(effects.contains("finish_task_effect_syscall(bpf_get_current_task_btf())"));
        assert!(exit.contains("exit_task_effect_attempts(task)"));
        assert!(read.contains("identity_file_open_effect_gate("));
        assert!(read.contains("kernel_effect_operation_v1_open_read"));
        assert!(write.contains("identity_file_open_effect_gate("));
        assert!(write.contains("kernel_effect_operation_v1_open_write"));
        assert!(open.contains("file_mode_effects(file, true, ret)"));
        assert!(receive.contains("file_mode_effects(file, false, ret)"));
    }

    #[test]
    fn exception_runtime_map_has_a_kernel_typed_spin_lock() -> crate::Result<()> {
        use std::ffi::OsStr;
        use std::path::Path;

        use libbpf_rs::btf::types::Struct;
        use libbpf_rs::Btf;

        let object_path = Path::new("embedded erebor-interceptor.bpf.o");
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        assert!(source.contains("__type(value, struct exception_runtime_state_bpf_v1);"));
        let btf = Btf::from_raw("embedded erebor-interceptor.bpf.o", BUNDLED_BPF_OBJECT).map_err(
            |source| crate::Error::Libbpf {
                action: "inspect bundled BPF BTF",
                path: object_path.to_path_buf(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            },
        )?;
        let Some(btf) = btf else {
            return crate::error::InvalidConfigurationSnafu {
                path: object_path,
                reason: "bundled BPF object has no BTF".to_owned(),
            }
            .fail();
        };
        let Some(state) = btf.type_by_name::<Struct<'_>>("exception_runtime_state_bpf_v1") else {
            return crate::error::InvalidConfigurationSnafu {
                path: object_path,
                reason: "exception map value has no BPF-specific BTF struct".to_owned(),
            }
            .fail();
        };
        let Some(lock) = state
            .iter()
            .find(|member| member.name == Some(OsStr::new("lock")))
        else {
            return crate::error::InvalidConfigurationSnafu {
                path: object_path,
                reason: "exception map value has no lock field".to_owned(),
            }
            .fail();
        };
        let Some(lock) = btf.type_by_id::<Struct<'_>>(lock.ty) else {
            return crate::error::InvalidConfigurationSnafu {
                path: object_path,
                reason: "exception lock field is not a struct".to_owned(),
            }
            .fail();
        };

        assert_eq!(lock.name(), Some(OsStr::new("bpf_spin_lock")));
        Ok(())
    }

    #[test]
    fn syscall_exit_tracepoint_does_not_call_spin_lock() -> crate::Result<()> {
        const BPF_CALL: u8 = 0x85;

        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
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
    fn mount_view_is_dirtied_only_after_the_pre_effect_gate_allows() {
        let effect_source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let helper = effect_source
            .split("static __always_inline int mount_mutation_effect")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/sb_mount\")").next())
            .unwrap_or_default();
        let gate = helper.find("identity_effect_gate").unwrap_or(usize::MAX);
        let stop = helper.find("if (ret)").unwrap_or(usize::MAX);
        let dirty = helper.find("begin_mount_mutation").unwrap_or_default();

        assert!(gate < stop && stop < dirty);
        assert!(helper[gate..dirty].contains("ret);"));
        assert_eq!(effect_source.matches("begin_mount_mutation()").count(), 2);

        let path_source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h");
        let begin = path_source
            .split("static __always_inline int begin_mount_mutation")
            .nth(1)
            .and_then(|source| source.split("static __always_inline void").next())
            .unwrap_or_default();
        assert_eq!(begin.matches("return label ? -EACCES : 0;").count(), 3);

        let finish = path_source
            .split("static __always_inline void finish_mount_mutation")
            .nth(1)
            .and_then(|source| source.split("static __always_inline int").next())
            .unwrap_or_default();
        assert_eq!(finish.matches("decrement_nonzero_counter").count(), 2);
        assert!(!finish.contains("__sync_fetch_and_sub"));
        assert!(!finish.contains("view->state"));
        assert!(!finish.contains("view->transition_version"));
        assert!(!finish.contains("bpf_spin_lock"));
        assert!(path_source.contains("mount_global_mutation_epoch"));
        assert!(path_source.contains("mount_global_clean_epoch"));
        assert!(path_source.contains("mount_global_pending_mutations"));
        assert!(!path_source.contains("mount_global_security_view"));
        assert!(!path_source.contains("mount_global_reconciliation_proposal"));
        for syscall in ["open_tree", "fsconfig", "fsmount", "mount_setattr"] {
            assert!(path_source.contains(&format!("MOUNT_SYSCALL_INVALIDATION({syscall})")));
        }
    }

    #[test]
    fn lifecycle_counters_use_the_nonzero_cas_decrement() {
        let maps = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let decrement = maps
            .split("static __always_inline __u64 decrement_nonzero_counter")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int task_cgroup")
                    .next()
            })
            .unwrap_or_default();

        assert!(decrement.contains("for (int attempt = 0; attempt < 8; attempt++)"));
        assert!(decrement.contains("if (!value)"));
        assert!(
            decrement.contains("__sync_val_compare_and_swap(counter, value, value - 1) == value")
        );
        assert!(decrement.contains("health->reconciliation_required++"));

        let lifecycle_sources = [
            include_str!("../../../bpf/erebor-interceptor/programs/identity_exit.bpf.h"),
            include_str!("../../../bpf/erebor-interceptor/programs/identity_task_helpers.h"),
            include_str!("../../../bpf/erebor-interceptor/programs/identity_root_helpers.h"),
            include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h"),
        ];
        assert!(lifecycle_sources
            .iter()
            .all(|source| !source.contains("__sync_fetch_and_sub")));
        assert_eq!(
            lifecycle_sources[0]
                .matches("decrement_nonzero_counter")
                .count(),
            4
        );
        assert_eq!(
            lifecycle_sources[1]
                .matches("decrement_nonzero_counter")
                .count(),
            4
        );
        assert_eq!(
            lifecycle_sources[2]
                .matches("decrement_nonzero_counter")
                .count(),
            3
        );
        assert_eq!(
            lifecycle_sources[3]
                .matches("decrement_nonzero_counter")
                .count(),
            2
        );
        assert!(lifecycle_sources[0]
            .contains("process->state = process_security_state_kind_v1_corrupt"));
        assert!(lifecycle_sources[1]
            .contains("parent_process->state = process_security_state_kind_v1_corrupt"));
    }

    #[test]
    fn file_path_candidate_cannot_install_object_authority() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let lookup = source
            .split("configured_file_object_binding")
            .nth(1)
            .and_then(|source| source.split("static __noinline void").next())
            .unwrap_or_default();

        assert!(lookup.contains("bpf_map_lookup_elem"));
        assert!(!lookup.contains("bpf_map_update_elem"));
        assert!(!lookup.contains("allocate_id"));
        assert!(!source.contains("exact_object_binding_state_v1_active_dynamic"));
    }

    #[test]
    fn exact_file_lookup_uses_the_bpf_selected_oldest_mount() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h");
        let build = source
            .split("static long canonical_mount_cache_build_step")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int global_mount_epoch_snapshot")
                    .next()
            })
            .unwrap_or_default();
        let collect = source
            .split("static __always_inline int collect_mount_components")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int apply_mount")
                    .next()
            })
            .unwrap_or_default();
        let walk = source
            .split("static long canonical_mount_path_walk_step")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int collect_mount_components")
                    .next()
            })
            .unwrap_or_default();

        assert!(build.contains(
            "build->candidate_namespace_address !=\n            build->mount_namespace_address"
        ));
        assert!(build.contains(
            "build->candidate_mount_id_unique <\n            cached->selected_mount_id_unique"
        ));
        assert!(walk.contains("selected_mount_for_root("));
        assert!(walk.contains("walk->selected_mount_address == walk->namespace_root_address"));
        assert!(collect.contains("walk->first_selected_mount_id_unique"));
        assert!(!collect.contains("canonical_mount_roots"));
    }

    #[test]
    fn path_tree_deny_uses_the_live_bpf_mount_path_before_object_lookup() {
        let effects =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let gate = effects
            .split("static __noinline int resolved_identity_effect_gate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int dispatch_identity_effect_gate")
                    .next()
            })
            .unwrap_or_default();
        let exact = gate
            .find("exact_file_object_from_path(")
            .unwrap_or(usize::MAX);
        let name_mount = gate
            .find("scratch->path_mount_namespace_inode;")
            .unwrap_or(usize::MAX);
        let canonical = gate.find("canonical_path_candidate(").unwrap_or(usize::MAX);
        let floor = gate
            .find("path_tree_denies(scratch, scratch->observation.operation)")
            .unwrap_or(usize::MAX);
        let object = gate
            .find("configured_file_object_binding(scratch)")
            .unwrap_or(usize::MAX);

        assert!(
            exact < name_mount && name_mount < canonical && canonical < floor && floor < object
        );

        let path = include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h");
        let candidate = path
            .split("static __always_inline int canonical_path_candidate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("SEC(\"tracepoint/raw_syscalls/sys_exit\")")
                    .next()
            })
            .unwrap_or_default();
        let collect = path
            .split("static __always_inline int collect_mount_components")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int apply_mount")
                    .next()
            })
            .unwrap_or_default();
        let step = path
            .split("static long canonical_path_match_step")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int canonical_path_candidate")
                    .next()
            })
            .unwrap_or_default();
        let walk = path
            .split("static long canonical_mount_path_walk_step")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int collect_mount_components")
                    .next()
            })
            .unwrap_or_default();
        assert!(walk.contains("if (current != mount_root)"));
        assert!(walk.contains("d_parent"));
        assert!(walk.contains("walk->current_dentry_address = walk->next_dentry_address;"));
        assert!(walk.contains("walk->current_mount_address = walk->next_mount_address;"));
        assert!(walk.contains("walk->selected_mount_address == walk->namespace_root_address"));
        assert!(collect.contains("canonical_mount_path_walk_step"));
        assert!(step.contains("raw_index = match->component_count - offset - 1;"));
        assert_eq!(candidate.matches("snapshot_mount_view(").count(), 0);
        assert!(candidate.contains("match->state_id = 0"));
    }

    #[test]
    fn link_and_rename_check_source_before_destination() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let link = source
            .split("int BPF_PROG(erebor_identity_path_link")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/path_rename\")").next())
            .unwrap_or_default();
        let rename = source
            .split("int BPF_PROG(erebor_identity_path_rename")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int mount_mutation_effect")
                    .next()
            })
            .unwrap_or_default();

        let link_source = link.find("new_dir, old_dentry").unwrap_or(usize::MAX);
        let link_stop = link.find("if (ret)").unwrap_or(usize::MAX);
        let link_destination = link.find("new_dir, new_dentry").unwrap_or(usize::MAX);
        assert!(link_source < link_stop && link_stop < link_destination);

        let rename_source = rename.find("old_dir, old_dentry").unwrap_or(usize::MAX);
        let rename_stop = rename.find("if (ret)").unwrap_or(usize::MAX);
        let rename_destination = rename.find("new_dir, new_dentry").unwrap_or(usize::MAX);
        assert!(rename_source < rename_stop && rename_stop < rename_destination);
    }

    #[test]
    fn task_alloc_bounds_the_configured_errno_for_lsm() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{
            BPF_ALU64, BPF_ARSH, BPF_JMP, BPF_JSLT, BPF_K, BPF_LDX, BPF_LSH, BPF_MEM, BPF_MOV,
            BPF_W,
        };

        const MAX_ERRNO: i32 = 4095;

        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
        let mut found = false;
        for program in object
            .progs()
            .filter(|program| program.name().to_string_lossy() == "erebor_task_alloc")
        {
            let instructions = program.insns();
            let sign_extends = instructions.windows(3).any(|instructions| {
                let errno_register = instructions[0].dst_reg();
                instructions[0].code == (BPF_LDX | BPF_MEM | BPF_W) as u8
                    && instructions[0].off == 32
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
    fn task_alloc_only_uses_task_storage_for_trusted_hook_tasks() -> crate::Result<()> {
        const BPF_CALL: u8 = 0x85;

        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
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

            // The hook reads the trusted current creator, claims and installs that
            // creator as an external root, and installs the trusted task_alloc
            // child. It also preallocates the child's fail-closed io_uring state.
            // It never derives a task pointer from a scalar identifier.
            assert_eq!(calls, 7);
        }
        assert!(found);
        Ok(())
    }

    #[test]
    fn socket_storage_uses_the_trusted_socket_member_pointer() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h");
        let helper = source
            .split("static __always_inline struct sock *ipc_socket_sock")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool ipc_is_unix_stream")
                    .next()
            })
            .unwrap_or_default();

        assert!(helper.contains("return socket ? socket->sk : NULL;"));
        assert!(!helper.contains("BPF_CORE_READ"));
    }

    #[test]
    fn ipc_actor_validation_is_not_nested_in_operation_frames() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h");

        assert!(source.contains("static __noinline int ipc_current_actor"));
        for helper in [
            "ipc_socket_post_create_effect",
            "ipc_unix_stream_connect_effect",
            "ipc_connected_effect",
        ] {
            let body = source
                .split(&format!("int {helper}"))
                .nth(1)
                .and_then(|source| source.split("\n}\n").next())
                .unwrap_or_default();
            assert!(!body.contains("ipc_current_actor"), "{helper}");
        }
        assert_eq!(source.matches("SEC(\"lsm/socket_post_create\")").count(), 1);
        assert_eq!(
            source.matches("SEC(\"lsm/unix_stream_connect\")").count(),
            1
        );
        let post_create = source
            .split("SEC(\"lsm/socket_post_create\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/unix_stream_connect\")").next())
            .unwrap_or_default();
        assert!(post_create.contains("if (type != SOCK_STREAM)"));
        assert!(!post_create.contains("BPF_CORE_READ"));
    }

    #[test]
    fn ipc_relationships_require_one_profile_generation() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h");
        let connect = source
            .split("static __noinline int ipc_unix_stream_connect_effect")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __noinline int ipc_unix_stream_connect_dispatch")
                    .next()
            })
            .unwrap_or_default();
        let connected = source
            .split("static __noinline int ipc_connected_effect")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __noinline int ipc_socket_post_create_effect")
                    .next()
            })
            .unwrap_or_default();

        assert!(connect.contains(
            "listener->endpoint_a_profile_generation_ref_id !=\n            scratch->process.active_profile_generation_ref_id"
        ));
        assert!(connected.contains(
            "state->endpoint_a_profile_generation_ref_id !=\n            state->endpoint_b_profile_generation_ref_id"
        ));
    }

    #[test]
    fn transferred_unix_stream_sockets_do_not_transfer_endpoint_authority() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h");
        let connected = source
            .split("static __noinline int ipc_connected_effect")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __noinline int ipc_socket_post_create_effect")
                    .next()
            })
            .unwrap_or_default();
        let connect = source
            .split("static __noinline int ipc_unix_stream_connect_dispatch")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/socket_post_create\")").next())
            .unwrap_or_default();

        assert!(connected.contains("return state ? -EACCES : ret;"));
        assert!(connected.contains("if (ipc_endpoint_a_is_current(state, scratch, binding))"));
        assert!(connected.contains("else if (ipc_endpoint_b_is_current(state, scratch, binding))"));
        assert!(connected.contains("effect_observation_reason_v1_corrupt_identity_or_generation"));
        assert!(connect.contains("return listener ? -EACCES : ret;"));
    }

    #[test]
    fn socket_io_has_one_effect_owner() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let file_permission = source
            .split("SEC(\"lsm/file_permission\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_ioctl\")").next())
            .unwrap_or_default();

        assert!(file_permission.contains("file_is_socket(file)"));
        assert!(file_permission.contains("io_uring_execution_state_kind_v1_inactive"));
        assert!(file_permission.contains("return ret;"));
    }

    #[test]
    fn io_uring_workers_use_exact_retained_submitter_authority() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_io_uring.bpf.h");
        let effects =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let lifecycle =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h");

        assert!(source.contains("IORING_SETUP_MITHRIL_V1"));
        assert!(source.contains("io_uring_exact_restrictions(context)"));
        assert!(source.contains("io_uring_file_mapping_gate("));
        assert!(source.contains("BPF_CORE_READ_INTO(&context, file, private_data)"));
        assert!(source.contains("(flags & MAP_TYPE) != MAP_SHARED"));
        assert!(source.contains("opcode != IORING_OP_READ && opcode != IORING_OP_WRITE"));
        assert!(source.contains("request->actor.profile_generation_ref_id"));
        assert!(source.contains("profile_generation_async_refs"));
        let resolver = source
            .split("static __noinline int resolved_io_uring_effect_gate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("SEC(\"tracepoint/syscalls/sys_enter_io_uring_setup\")")
                    .next()
            })
            .unwrap_or_default();
        let exact = resolver
            .find("bpf_map_lookup_elem(&effect_decisions")
            .unwrap_or(usize::MAX);
        let class = resolver
            .find("bpf_map_lookup_elem(&effect_defaults")
            .unwrap_or_default();
        assert!(exact < class);
        assert!(source.contains("setup->state = io_uring_setup_state_kind_v1_invalid;"));
        let submit = source
            .split("SEC(\"tp_btf/io_uring_submit_req\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"fentry/io_issue_sqe\")").next())
            .unwrap_or_default();
        assert!(submit.contains("generation->state != policy_generation_state_v1_active"));
        assert!(source.contains("SEC(\"fentry/io_issue_sqe\")"));
        assert!(source.contains("SEC(\"fexit/io_issue_sqe\")"));
        let identity = effects
            .split("static __noinline int resolved_identity_effect_gate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int dispatch_identity_effect_gate")
                    .next()
            })
            .unwrap_or_default();
        let dispatch = effects
            .split("static __always_inline int dispatch_identity_effect_gate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int identity_effect_gate")
                    .next()
            })
            .unwrap_or_default();
        assert!(!identity.contains("resolved_io_uring_effect_gate"));
        assert!(dispatch.contains("return resolved_io_uring_effect_gate("));
        assert!(dispatch.contains("return resolved_identity_effect_gate("));
        assert!(effects.contains("return resolved_io_uring_effect_gate("));
        assert!(lifecycle.contains("&io_uring_execution_states, task, 0,"));
    }

    #[test]
    fn received_files_use_the_current_recipient_file_decision() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let receive = source
            .split("SEC(\"lsm/file_receive\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_permission\")").next())
            .unwrap_or_default();
        let qualification =
            include_str!("../../../bpf/erebor-interceptor/qualification/feasibility.bpf.c");

        assert_eq!(source.matches("SEC(\"lsm/file_receive\")").count(), 1);
        assert!(receive.contains("file_is_socket(file)"));
        assert!(receive.contains("return file_mode_effects(file, false, ret);"));
        let decision = source
            .split("static __always_inline int apply_effect_decision")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __noinline int resolved_identity_effect_gate")
                    .next()
            })
            .unwrap_or_default();
        assert!(decision.contains("if (!allow_exception || !file_open_attempt ||"));
        assert_eq!(
            qualification.matches("SEC(\"lsm/file_receive\")").count(),
            1
        );
    }

    #[test]
    fn anonymous_data_memory_is_not_treated_as_a_file_effect() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let mmap = source
            .split("SEC(\"lsm/mmap_file\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_mprotect\")").next())
            .unwrap_or_default();
        let mprotect = source
            .split("SEC(\"lsm/file_mprotect\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/ptrace_access_check\")").next())
            .unwrap_or_default();

        assert!(mmap.contains("if (!file || (flags & MAP_ANONYMOUS))"));
        assert!(mmap.contains("if (!(prot & PROT_EXEC))"));
        assert!(mmap.contains("identity_unqualified_effect_gate"));
        assert!(mmap.contains("kernel_effect_operation_v1_mmap_exec"));
        assert!(mprotect.contains("if (!file)"));
        assert!(mprotect.contains("if (!adds_exec)"));
        assert!(mprotect.contains("kernel_effect_operation_v1_mprotect"));
    }

    #[test]
    fn typed_actor_validation_is_not_nested_in_device_or_process_frames() {
        let effects =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h");

        assert!(effects.contains("static __noinline int identity_effect_actor_gate"));
        for helper in [
            "identity_device_ioctl_effect",
            "identity_process_control_effect",
        ] {
            let body = source
                .split(&format!("int {helper}"))
                .nth(1)
                .and_then(|source| source.split("\n}\n").next())
                .unwrap_or_default();
            assert!(!body.contains("resolved_identity_effect_gate"), "{helper}");
        }
        assert_eq!(source.matches("identity_effect_actor_gate(").count(), 2);
    }

    #[test]
    fn process_control_matches_arguments_and_revalidates_the_live_target() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h");
        let effect = source
            .split("static __noinline int identity_process_control_effect")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int identity_process_control_gate")
                    .next()
            })
            .unwrap_or_default();

        let exact_argument = effect
            .find("operation_argument = operation_argument")
            .unwrap_or(usize::MAX);
        let exact_lookup = effect
            .find("bpf_map_lookup_elem(&process_control_rules")
            .unwrap_or(usize::MAX);
        let wildcard = effect.find("argument_wildcard = 1").unwrap_or_default();
        assert!(exact_argument < exact_lookup && exact_lookup < wildcard);
        assert!(effect.contains("rule->decision != physical_decision_kind_v1_deny"));
        assert!(effect.contains("binding_matches_label(target_binding, target_live_label)"));
        assert!(!effect.contains("target_binding->active_profile_generation_ref_id !="));
        assert!(effect.contains("generation_allows_existing_holder(generation)"));
    }

    #[test]
    fn retiring_generations_allow_existing_holders_but_not_new_roots() {
        let maps = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let holder = maps
            .split("static __always_inline bool generation_allows_existing_holder")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline execution_set_binding_state_v1 *")
                    .next()
            })
            .unwrap_or_default();
        let new_root = maps
            .split("binding_activation_for_new_root")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool consume_initial_root")
                    .next()
            })
            .unwrap_or_default();

        assert!(holder.contains("policy_generation_state_v1_active"));
        assert!(holder.contains("policy_generation_state_v1_retiring"));
        assert!(new_root.contains("descriptor->state != policy_generation_state_v1_active"));
        assert!(!new_root.contains("generation_allows_existing_holder"));
    }

    #[test]
    fn executable_open_and_header_read_keep_exec_authority() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let file_mode = source
            .split("static __always_inline int file_mode_effects")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline bool file_is_socket")
                    .next()
            })
            .unwrap_or_default();

        let executable = file_mode.find("flags & __FMODE_EXEC").unwrap_or(usize::MAX);
        let readable = file_mode.find("mode & FMODE_READ").unwrap_or_default();
        assert!(executable < readable);
        assert!(file_mode.contains("BPF_CORE_READ_INTO(&flags, file, f_flags)"));
        assert!(!file_mode.contains("identity_effect_actor_gate("));
        assert!(file_mode.contains("identity_file_open_effect_gate("));
        assert!(file_mode.contains("kernel_effect_operation_v1_execute"));

        let permission = source
            .split("SEC(\"lsm/file_permission\")")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/file_ioctl\")").next())
            .unwrap_or_default();
        let executable = permission
            .find("flags & __FMODE_EXEC")
            .unwrap_or(usize::MAX);
        let readable = permission.find("mask & MAY_READ").unwrap_or_default();
        assert!(executable < readable);
        assert!(permission.contains("BPF_CORE_READ_INTO(&flags, file, f_flags)"));
        assert!(permission.contains("identity_effect_actor_gate("));
        assert!(permission.contains("initial_exec_open_without_pending()"));
        assert!(permission.contains("identity_effect_gate(file"));

        let initial = source
            .split("static __always_inline bool initial_exec_open_without_pending")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int file_mode_effects")
                    .next()
            })
            .unwrap_or_default();
        assert!(initial.contains("BPF_CORE_READ_BITFIELD_PROBED(task, in_execve)"));
        assert!(initial.contains("bpf_map_lookup_elem(&pending_execs"));
    }

    #[test]
    fn unlinked_dentries_do_not_reuse_path_authority() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_task_helpers.h");
        let helper = source
            .split("static __always_inline bool dentry_unlinked")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline void exact_file_object_from_path")
                    .next()
            })
            .unwrap_or_default();

        assert!(helper.contains("d_hash.pprev"));
        assert!(helper.contains("d_parent"));
        assert!(helper.contains("!previous && parent != dentry"));
        assert_eq!(source.matches("dentry_unlinked(dentry)").count(), 2);
    }

    #[test]
    fn device_inode_generation_matches_the_userspace_identity() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_task_helpers.h");
        let helper = source
            .split("static __always_inline void exact_file_object_from_path")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline void exact_file_object_from_file")
                    .next()
            })
            .unwrap_or_default();

        assert!(helper.contains(concat!(
            "if ((mode & S_IFMT) == S_IFCHR || (mode & S_IFMT) == S_IFBLK)\n",
            "            object->inode_generation = 0;"
        )));
    }

    #[test]
    fn capability_observations_keep_the_numeric_capability() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h");
        let dispatch = source
            .split("static __always_inline int dispatch_identity_effect_gate")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int identity_effect_gate")
                    .next()
            })
            .unwrap_or_default();
        let capable = source
            .split("SEC(\"lsm/capable\")")
            .nth(1)
            .unwrap_or_default();

        assert!(dispatch.contains("scratch->observation.operation_argument ="));
        assert!(dispatch.contains("scratch->effect_gate_operation_argument"));
        assert!(capable.contains("effect_gate_operation_argument = (__u32)cap"));
    }

    #[test]
    fn unrepresentable_exec_candidate_reaches_effect_policy_without_allocating_ids() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h");
        let initial = source
            .split("if (!pending) {")
            .nth(1)
            .and_then(|source| source.split("#pragma unroll").next())
            .unwrap_or_default();

        let candidate = initial.find("candidate_from_bprm").unwrap_or(usize::MAX);
        let unsupported = initial
            .find("config->effect_policy_enabled ? BPRM_OBSERVE_EFFECT_V1")
            .unwrap_or(usize::MAX);
        let allocation = initial.find("allocate_id").unwrap_or_default();
        assert!(candidate < unsupported && unsupported < allocation);
        assert!(initial.contains("release_transition_guard"));
    }

    #[test]
    fn exec_programs_bound_exact_argv_capture_iterations() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_K, BPF_MOV};

        const BPF_CALL: u8 = 0x85;
        const ARGV_LOOP_BUDGET: i32 = 256;

        let object = ObjectBuilder::default()
            .open_memory(BUNDLED_BPF_OBJECT)
            .map_err(|source| crate::Error::Libbpf {
                action: "inspect bundled BPF object",
                path: "embedded erebor-interceptor.bpf.o".into(),
                source,
                location: snafu::Location::new(file!(), line!(), column!()),
            })?;
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
                    .filter(|instruction| {
                        instruction.1.code == BPF_CALL
                            && instruction.1.imm == libbpf_rs::libbpf_sys::BPF_FUNC_loop as i32
                    })
                    .map(|(index, _)| index)
                    .collect::<Vec<_>>();

                assert_eq!(loop_calls.len(), 1, "{program_name}");
                let loop_call = loop_calls[0];
                assert!(
                    instructions[loop_call.saturating_sub(8)..loop_call]
                        .iter()
                        .any(|instruction| {
                            instruction.code == (BPF_ALU64 | BPF_MOV | BPF_K) as u8
                                && instruction.dst_reg() == 1
                                && instruction.imm == ARGV_LOOP_BUDGET
                        }),
                    "{program_name} must cap exact argv capture at {ARGV_LOOP_BUDGET} callbacks"
                );
            }
            assert!(found, "bundled object must contain {program_name}");
        }
        Ok(())
    }

    #[test]
    fn bprm_candidate_store_uses_a_verifier_bounded_index() -> crate::Result<()> {
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
        Ok(())
    }

    #[test]
    fn bpf_path_walks_use_meta_component_and_namespace_budgets() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_K, BPF_MOV};

        const PATH_COMPONENT_BUDGET: i32 = 255;
        const PATH_WALK_BUDGET: i32 = 4_096 + PATH_COMPONENT_BUDGET;
        let maps = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let path = include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h");
        let instructions = BUNDLED_BPF_OBJECT.chunks_exact(8).collect::<Vec<_>>();
        assert!(maps.contains("mount_scan_stack[MAX_CANONICAL_PATH_COMPONENTS_V1 + 1]"));
        assert!(path.contains("build->stack_depth >= MAX_CANONICAL_PATH_COMPONENTS_V1"));
        for budget in [PATH_COMPONENT_BUDGET, PATH_WALK_BUDGET] {
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
        Ok(())
    }

    #[test]
    fn administrative_slot_cancellation_is_an_exact_atomic_control_operation() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity.bpf.c");
        let cancellation = source
            .split("policy_activation_probe_map_kind_v1_administrative_slot_cancel")
            .nth(1)
            .and_then(|source| source.split("default:").next())
            .unwrap_or_default();

        assert!(cancellation.contains("&approved_exec_slots"));
        assert!(cancellation.contains("administrative_slot->proof_id"));
        assert!(cancellation.contains("administrative_slot->claim_slot_id"));
        assert!(cancellation.contains("__sync_val_compare_and_swap"));
        assert!(cancellation.contains("approved_exec_slot_state_v1_armed"));
        assert!(cancellation.contains("approved_exec_slot_state_v1_cancelled"));
    }

    #[test]
    fn network_socket_authority_is_retained_until_kernel_release() {
        let maps = include_str!("../../../bpf/erebor-interceptor/programs/identity_maps.h");
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_network.bpf.h");
        let release = source
            .split("int BPF_PROG(erebor_network_socket_release")
            .nth(1)
            .unwrap_or_default();

        assert!(maps.contains("BPF_F_NO_PREALLOC | BPF_F_CLONE"));
        assert!(source.contains("SEC(\"fexit/inet_csk_accept\")"));
        assert!(source.contains("state->parent_socket_generation"));
        assert!(release.contains("profile_generation_socket_refs"));
        assert!(release.contains("network_response_floors"));
        assert!(release.contains("network_socket_state_kind_v1_tombstoned"));
    }

    #[test]
    fn network_use_intersects_current_and_creator_decisions() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_network.bpf.h");
        let destination = source
            .split("static __noinline int network_apply_destination")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int network_socket_create_result")
                    .next()
            })
            .unwrap_or_default();

        assert!(destination.contains("current_class = network_classify_destination"));
        assert!(destination.contains("creator_class = network_classify_destination"));
        assert!(destination.contains("network_decision_allows(creator, creator_generation)"));
        assert!(destination.contains("network_apply_decision(config, scratch, current_generation"));
        assert!(destination.contains("network_replace_flow_authorizer"));
    }

    #[test]
    fn network_namespace_transfer_keeps_both_namespaces_without_transferring_authority() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_network.bpf.h");
        let validation = source
            .split("static __always_inline int network_validate_socket")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int network_replace_flow_authorizer")
                    .next()
            })
            .unwrap_or_default();

        assert!(validation.contains("scratch->observation.network_current_namespace"));
        assert!(source.contains(
            "scratch->observation.network_namespace =\n        state->socket_network_namespace"
        ));
        assert!(!validation.contains("network_namespace_equal"));
    }

    #[test]
    fn network_control_hooks_leave_unix_sockets_to_the_ipc_owner() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_network.bpf.h");

        assert!(source.contains("static __always_inline bool network_socket_is_inet"));
        assert_eq!(
            source
                .matches("if (!network_socket_is_inet(socket))")
                .count(),
            5
        );
        let create = source
            .split("int BPF_PROG(erebor_identity_socket_create")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/socket_bind\")").next())
            .unwrap_or_default();
        assert!(create.contains("family == AF_UNIX"));
        assert!(create.contains("network_unsupported"));
    }

    #[test]
    fn final_packet_floor_uses_retained_flow_state_without_a_current_actor() {
        let source =
            include_str!("../../../bpf/erebor-interceptor/programs/identity_network.bpf.h");
        let packet = source
            .split("int erebor_network_final_flow")
            .nth(1)
            .and_then(|source| source.split("SEC(\"lsm/socket_create\")").next())
            .unwrap_or_default();

        assert!(packet.contains("bpf_sk_storage_get(&network_socket_states"));
        assert!(packet.contains("state->flow_authorizer_profile_generation_ref_id"));
        assert!(packet.contains("state->creator_profile_generation_ref_id"));
        assert!(packet.contains("network_response_floors"));
        assert!(packet.contains("effect_observation_reason_v1_network_response_fence"));
        assert!(!packet.contains("network_current_actor"));
        assert!(!packet.contains("bpf_get_current_task"));
    }

    #[test]
    fn mount_reconciliation_commits_in_bpf_before_global_clean_publication() {
        let source = include_str!("../../../bpf/erebor-interceptor/programs/identity.bpf.c");
        let command = source
            .split("policy_activation_probe_map_kind_v1_mount_reconciliation")
            .nth(1)
            .and_then(|source| source.split("default:").next())
            .unwrap_or_default();
        let path = include_str!("../../../bpf/erebor-interceptor/programs/identity_path.bpf.h");
        let commit = path
            .split("static __always_inline int commit_mount_reconciliation_proposal")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int snapshot_mount_view")
                    .next()
            })
            .unwrap_or_default();
        let apply = path
            .split("static __always_inline int apply_mount_reconciliation_proposal")
            .nth(1)
            .and_then(|source| {
                source
                    .split("static __always_inline int commit_mount_reconciliation_proposal")
                    .next()
            })
            .unwrap_or_default();

        assert!(command.contains("commit_mount_reconciliation_proposal"));
        assert!(!command.contains("snapshot_mount_view"));
        assert!(command.contains("request->expected"));
        assert!(commit.contains("*global_clean > global_generation"));
        assert!(!commit.contains("*global_clean != global_generation"));
        assert!(commit.contains("*global_pending"));
        assert!(commit.contains("*mutation_epoch != global_generation"));
        assert!(commit.contains("proposal, global_generation, false"));
        assert!(apply.contains("bpf_spin_lock"));
        assert!(apply.contains("mount_topology_state_v1_dirty"));
        assert!(apply.contains("mount_topology_state_v1_clean"));
        assert!(apply.contains("view->topology_generation &&"));
        assert!(apply.contains("view->topology_generation < global_generation"));
        assert!(!apply.contains("(!require_dirty ||"));
        assert!(apply.contains("!view->pending_mutations"));
        assert!(apply.contains("proposal->expected_transition_version"));
        assert!(apply.contains("view->transition_version != ~0ULL"));
    }
}
