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
        let program = object
            .progs()
            .find(|program| program.name().to_string_lossy() == "erebor_task_alloc")
            .expect("bundled object must contain erebor_task_alloc");
        let calls = program
            .insns()
            .iter()
            .filter(|instruction| {
                instruction.code == BPF_CALL
                    && instruction.imm == libbpf_rs::libbpf_sys::BPF_FUNC_task_storage_get as i32
            })
            .count();

        // task_alloc inherits from the trusted current creator and installs the
        // child. Independent roots are established after final placement by the
        // cgroup-attach hook, not inferred from the half-built child task.
        assert_eq!(calls, 2);
        Ok(())
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
            let program = object
                .progs()
                .find(|program| program.name().to_string_lossy() == program_name)
                .unwrap_or_else(|| panic!("bundled object must contain {program_name}"));
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
        Ok(())
    }

    #[test]
    fn bprm_candidate_store_uses_a_verifier_bounded_index() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_AND, BPF_K, BPF_MUL};

        let instructions = BUNDLED_BPF_OBJECT.chunks_exact(8).collect::<Vec<_>>();
        assert!(instructions.windows(2).any(|pair| {
            pair[0][0] == (BPF_ALU64 | BPF_AND | BPF_K) as u8
                && i32::from_le_bytes(pair[0][4..8].try_into().expect("BPF immediate")) == 7
                && pair[1][0] == (BPF_ALU64 | BPF_MUL | BPF_K) as u8
                && pair[1][1] & 0x0f == pair[0][1] & 0x0f
                && i32::from_le_bytes(pair[1][4..8].try_into().expect("BPF immediate")) == 40
        }));
        Ok(())
    }

    #[test]
    fn bprm_path_match_uses_one_bounded_loop_callback() -> crate::Result<()> {
        use libbpf_rs::libbpf_sys::{BPF_ALU64, BPF_K, BPF_MOV};

        const PATH_COMPONENT_BUDGET: i32 = 64;
        let instructions = BUNDLED_BPF_OBJECT.chunks_exact(8).collect::<Vec<_>>();
        assert!(instructions.iter().enumerate().any(|(index, instruction)| {
            instruction[0] == 0x85
                && i32::from_le_bytes(instruction[4..8].try_into().expect("BPF immediate"))
                    == libbpf_rs::libbpf_sys::BPF_FUNC_loop as i32
                && instructions[index.saturating_sub(8)..index]
                    .iter()
                    .any(|candidate| {
                        candidate[0] == (BPF_ALU64 | BPF_MOV | BPF_K) as u8
                            && candidate[1] & 0x0f == 1
                            && i32::from_le_bytes(
                                candidate[4..8].try_into().expect("BPF immediate"),
                            ) == PATH_COMPONENT_BUDGET
                    })
        }));
        Ok(())
    }
}
