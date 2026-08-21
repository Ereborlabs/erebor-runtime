use std::path::Path;

use ed25519_dalek::SigningKey;
use erebor_interceptor_abi::KernelEffectOperationV1;
use mithril_control::{
    AntiRollbackStore, BlastRadiusLimitV1, CompiledOperationV1, CompiledPhysicalResultV1,
    DestinationPolicyRecordV1, DnsPolicyModeV1, EffectFamilyDefaultV1, EffectFamilyV1, EntryKindV1,
    ErrnoV1, ExactExceptionSubjectSelectorV1, ExceptionConsumptionScopeV1, ExceptionV1,
    HardSafetyConditionV1, IpcRelationshipRuleV1, NetworkPolicyV1, NetworkPortRangeV1,
    NetworkProtocolV1, PathPatternPrecedenceV1, PathTreeDenyFloorV1, PermittedAuthorityDeltaV1,
    PolicyCompiler, PolicyDispositionV1, PolicyDocumentV1, PolicySimulator,
    ProfileActivationMetadataV1, ProfileCandidateArtifactV1, ProfileSealRequestV1,
    RegistryDigestsV1, RollbackAuthorizationArtifactV1, RollbackAuthorizationPayloadV1,
    RootClassificationV1, SimulatedDispositionV1,
};

const VALID_POLICY: &str = include_str!("fixtures/policy-v1.yaml");

fn parse(source: &str) -> mithril_control::Result<PolicyDocumentV1> {
    PolicyDocumentV1::parse(Path::new("policy-v1.yaml"), source.as_bytes())
}

#[test]
fn checked_policy_is_closed_and_compiles_deterministically() -> mithril_control::Result<()> {
    let document = parse(VALID_POLICY)?;
    let first = PolicyCompiler.compile(&document)?;
    let second = PolicyCompiler.compile(&document)?;
    assert_eq!(first, second);
    assert_eq!(first.compiled_cells.len(), 1);
    Ok(())
}

#[test]
fn path_pattern_precedence_is_signed_policy_input() -> mithril_control::Result<()> {
    let document = parse(VALID_POLICY)?;
    let wildcard_wins = PolicyCompiler.compile(&document)?;
    let mut exact_wins = document;
    exact_wins.path_pattern_precedence = PathPatternPrecedenceV1::ExactWins;
    let exact_wins = PolicyCompiler.compile(&exact_wins)?;

    assert_ne!(wildcard_wins.canonical_policy, exact_wins.canonical_policy);
    assert_ne!(
        wildcard_wins.source_policy_digest,
        exact_wins.source_policy_digest
    );
    Ok(())
}

#[test]
fn child_owned_policy_values_validate_before_document_relationships() -> mithril_control::Result<()>
{
    let mut document = parse(VALID_POLICY)?;
    document.roles[0].role_id = "INVALID_ROLE".to_owned();
    assert!(PolicyCompiler
        .compile(&document)
        .is_err_and(|error| error.to_string().contains("CFG_LOCAL_ID")));
    Ok(())
}

#[test]
fn administrative_entry_requires_the_exact_approval_contract() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    document
        .protected_universe
        .entry_kind_ids
        .push(EntryKindV1::ApprovedAdministrativeExec);
    document.roles[0]
        .permitted_entry_kinds
        .push(EntryKindV1::ApprovedAdministrativeExec);
    let mut administrative = document.entry_role_assignments[0].clone();
    administrative.assignment_id = "approved-administrative-exec".to_owned();
    administrative.entry_kinds = vec![EntryKindV1::ApprovedAdministrativeExec];
    administrative.accepted_classifications =
        vec![RootClassificationV1::ApprovedAdministrativeNextMatch];
    administrative.required_administrative_exec_approval = true;
    administrative.unknown_restricted_role_id = None;
    document.entry_role_assignments.push(administrative);
    assert!(PolicyCompiler.compile(&document).is_ok());

    let mutations: [fn(&mut mithril_control::EntryRoleAssignmentV1); 3] = [
        |entry: &mut mithril_control::EntryRoleAssignmentV1| {
            entry.required_administrative_exec_approval = false;
        },
        |entry: &mut mithril_control::EntryRoleAssignmentV1| {
            entry.entry_kinds = vec![EntryKindV1::ContainerStart];
        },
        |entry: &mut mithril_control::EntryRoleAssignmentV1| {
            entry.accepted_classifications = vec![RootClassificationV1::ExactInitial];
        },
    ];
    let administrative_index = document.entry_role_assignments.len() - 1;
    for mutate in mutations {
        let mut invalid = document.clone();
        mutate(&mut invalid.entry_role_assignments[administrative_index]);
        assert!(PolicyCompiler.compile(&invalid).is_err());
    }
    Ok(())
}

#[test]
fn protect_mode_compiles_the_same_denial_as_a_physical_deny() -> mithril_control::Result<()> {
    let source = VALID_POLICY.replacen(
        "desired_profile_mode: OBSERVE",
        "desired_profile_mode: PROTECT",
        1,
    );
    let compiled = PolicyCompiler.compile(&parse(&source)?)?;
    assert_eq!(
        compiled.compiled_cells[0].physical_result,
        CompiledPhysicalResultV1::DenyEffect
    );
    let outcome =
        PolicySimulator::new(&compiled).simulate(compiled.compiled_cells[0].key.clone(), None);
    assert_eq!(outcome.disposition, SimulatedDispositionV1::Deny);
    assert_eq!(outcome.configured_errno, Some(-13));
    Ok(())
}

#[test]
fn path_tree_rules_are_signed_denial_floors_only() -> mithril_control::Result<()> {
    let mut document = parse(&VALID_POLICY.replacen(
        "desired_profile_mode: OBSERVE",
        "desired_profile_mode: PROTECT",
        1,
    ))?;
    document.path_tree_deny_floors.push(PathTreeDenyFloorV1 {
        schema_version: 1,
        rule_id: "deny-secret-tree".to_owned(),
        canonical_path: "/tmp/secret-dir".to_owned(),
        recursive: true,
        effect_families: vec![EffectFamilyV1::File],
        operation_ids: ["CREATE", "OPEN_READ", "RENAME"]
            .map(str::to_owned)
            .to_vec(),
        requested_disposition: PolicyDispositionV1::Deny,
        exception_ids: Vec::new(),
    });
    assert!(PolicyCompiler.compile(&document).is_ok());

    let mut allow = document.clone();
    allow.path_tree_deny_floors[0].requested_disposition = PolicyDispositionV1::Allow;
    assert!(PolicyCompiler
        .compile(&allow)
        .is_err_and(|error| error.to_string().contains("CFG_PATH_TREE_DENY")));

    let mut non_recursive = document.clone();
    non_recursive.path_tree_deny_floors[0].recursive = false;
    assert!(PolicyCompiler
        .compile(&non_recursive)
        .is_err_and(|error| error.to_string().contains("CFG_PATH_TREE_DENY")));

    let mut excepted = document;
    excepted.path_tree_deny_floors[0]
        .exception_ids
        .push("not-a-positive-path-exception".to_owned());
    assert!(PolicyCompiler
        .compile(&excepted)
        .is_err_and(|error| error.to_string().contains("CFG_PATH_TREE_DENY")));
    Ok(())
}

#[test]
fn protect_mode_closes_open_read_and_mmap_as_separate_cells() -> mithril_control::Result<()> {
    let source = VALID_POLICY.replacen(
        "desired_profile_mode: OBSERVE",
        "desired_profile_mode: PROTECT",
        1,
    );
    let mut document = parse(&source)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.operation_ids = ["MMAP_READ", "OPEN_READ", "READ"]
        .map(str::to_owned)
        .to_vec();
    let compiled = PolicyCompiler.compile(&document)?;

    assert_eq!(compiled.compiled_cells.len(), 3);
    assert!(compiled
        .compiled_cells
        .iter()
        .all(|cell| cell.physical_result == CompiledPhysicalResultV1::DenyEffect));
    assert_eq!(
        compiled
            .compiled_cells
            .iter()
            .map(|cell| cell.key.operation_id.as_str())
            .collect::<Vec<_>>(),
        ["MMAP_READ", "OPEN_READ", "READ"]
    );
    Ok(())
}

#[test]
fn unix_stream_relationship_dispositions_have_closed_errno_rules() -> mithril_control::Result<()> {
    for (disposition, errno, accepted) in [
        (PolicyDispositionV1::Allow, None, true),
        (PolicyDispositionV1::Alert, None, true),
        (PolicyDispositionV1::Deny, Some(ErrnoV1::Eacces), true),
        (PolicyDispositionV1::Allow, Some(ErrnoV1::Eacces), false),
        (PolicyDispositionV1::Alert, Some(ErrnoV1::Eacces), false),
        (PolicyDispositionV1::Deny, None, false),
        (PolicyDispositionV1::Reject, None, false),
    ] {
        let mut document = parse(VALID_POLICY)?;
        document.ipc_relationship_rules.push(IpcRelationshipRuleV1 {
            relationship_rule_id: "converter-runtime-stream".to_owned(),
            source_role_ids: vec!["converter".to_owned()],
            peer_role_ids: vec!["runtime-external".to_owned()],
            channel_class_ids: vec!["UNIX_STREAM".to_owned()],
            operations: vec!["IPC_ACCESS".to_owned()],
            requested_disposition: disposition,
            errno,
        });

        assert_eq!(PolicyCompiler.compile(&document).is_ok(), accepted);
    }
    Ok(())
}

#[test]
fn unix_stream_relationships_reject_one_conflicting_role_pair() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    document.ipc_relationship_rules = [
        (
            "allow",
            "converter",
            "runtime-external",
            PolicyDispositionV1::Allow,
            None,
        ),
        (
            "deny-reversed",
            "runtime-external",
            "converter",
            PolicyDispositionV1::Deny,
            Some(ErrnoV1::Eacces),
        ),
    ]
    .map(
        |(id, source, peer, disposition, errno)| IpcRelationshipRuleV1 {
            relationship_rule_id: id.to_owned(),
            source_role_ids: vec![source.to_owned()],
            peer_role_ids: vec![peer.to_owned()],
            channel_class_ids: vec!["UNIX_STREAM".to_owned()],
            operations: vec!["IPC_ACCESS".to_owned()],
            requested_disposition: disposition,
            errno,
        },
    )
    .to_vec();

    assert!(PolicyCompiler.compile(&document).is_err());
    Ok(())
}

#[test]
fn process_control_requires_exact_positive_arguments_and_target_roles(
) -> Result<(), Box<dyn std::error::Error>> {
    for (operation, expected_family, expected_argument) in [
        ("SIGNAL_15", KernelEffectOperationV1::Signal, 15),
        ("PTRACE_ACCESS_18", KernelEffectOperationV1::Ptrace, 18),
    ] {
        let mut document = process_control_policy(operation, PolicyDispositionV1::Allow)?;
        let compiled = PolicyCompiler.compile(&document)?;
        assert_eq!(compiled.compiled_cells.len(), 1);
        assert_eq!(compiled.compiled_cells[0].key.operation_id, operation);
        let compiled_operation = CompiledOperationV1::try_from(operation)?
            .process_control()
            .ok_or("fixture operation must be process control")?;
        assert_eq!(compiled_operation.kernel_id, expected_family);
        assert_eq!(compiled_operation.argument, expected_argument);
        assert!(!compiled_operation.argument_wildcard);

        document.rules[0].requested_disposition = PolicyDispositionV1::Deny;
        document.rules[0].errno = Some(ErrnoV1::Eacces);
        assert!(PolicyCompiler.compile(&document).is_ok());
    }

    let mut wildcard = process_control_policy("SIGNAL", PolicyDispositionV1::Allow)?;
    assert!(PolicyCompiler.compile(&wildcard).is_err());
    wildcard.rules[0].requested_disposition = PolicyDispositionV1::Deny;
    wildcard.rules[0].errno = Some(ErrnoV1::Eacces);
    assert!(PolicyCompiler.compile(&wildcard).is_ok());

    for operation in ["SIGNAL_01", "SIGNAL_", "PTRACE_ACCESS_4294967296"] {
        assert!(PolicyCompiler
            .compile(&process_control_policy(
                operation,
                PolicyDispositionV1::Allow
            )?)
            .is_err());
    }
    let mut unknown_target = process_control_policy("SIGNAL_15", PolicyDispositionV1::Allow)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut unknown_target.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.object = mithril_control::LocalObjectSelectorV1::SecurityObjects {
        security_object_ids: vec!["PROCESS".to_owned()],
        target_selector_ids: vec!["unknown-role".to_owned()],
    };
    assert!(PolicyCompiler.compile(&unknown_target).is_err());
    Ok(())
}

#[test]
fn generic_privilege_local_rules_are_denial_only() -> mithril_control::Result<()> {
    for operation in ["BPF", "CAPABILITY"] {
        let mut deny = parse(VALID_POLICY)?;
        let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut deny.rules[0].rule_match
        else {
            unreachable!("fixture has a local effect rule")
        };
        effect.effect_families = vec![EffectFamilyV1::Privilege];
        effect.operation_ids = vec![operation.to_owned()];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut invalid = deny.clone();
            invalid.rules[0].requested_disposition = disposition;
            invalid.rules[0].errno = None;
            assert!(PolicyCompiler
                .compile(&invalid)
                .is_err_and(|error| error.to_string().contains("CFG_PRIVILEGE_WILDCARD")));
        }
    }
    Ok(())
}

#[test]
fn io_uring_operations_have_closed_authority_rules() -> mithril_control::Result<()> {
    for (operation, expected) in [
        ("IO_URING_SETUP", KernelEffectOperationV1::IoUringSetup),
        (
            "IO_URING_REGISTER",
            KernelEffectOperationV1::IoUringRegister,
        ),
        ("IO_URING_SQPOLL", KernelEffectOperationV1::IoUringSqpoll),
        (
            "IO_URING_OVERRIDE_CREDS",
            KernelEffectOperationV1::IoUringOverrideCreds,
        ),
        ("IO_URING_COMMAND", KernelEffectOperationV1::IoUringCommand),
    ] {
        assert_eq!(
            CompiledOperationV1::try_from(operation).map(|operation| operation.kernel_id),
            Ok(expected)
        );

        let mut deny = parse(VALID_POLICY)?;
        let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut deny.rules[0].rule_match
        else {
            unreachable!("fixture has a local effect rule")
        };
        effect.effect_families = vec![EffectFamilyV1::Privilege];
        effect.operation_ids = vec![operation.to_owned()];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        let mut allow = deny;
        allow.rules[0].requested_disposition = PolicyDispositionV1::Allow;
        allow.rules[0].errno = None;
        if operation == "IO_URING_SETUP" {
            assert!(PolicyCompiler.compile(&allow).is_ok());
        } else {
            assert!(PolicyCompiler.compile(&allow).is_err_and(|error| error
                .to_string()
                .contains("CFG_IO_URING_UNQUALIFIED_AUTHORITY")));
        }
    }
    Ok(())
}

#[test]
fn positive_device_ioctl_rules_require_exact_commands() -> mithril_control::Result<()> {
    let mut deny = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut deny.rules[0].rule_match else {
        unreachable!("fixture has a local effect rule")
    };
    effect.effect_families = vec![EffectFamilyV1::Device];
    effect.operation_ids = vec!["IOCTL".to_owned()];
    effect.object = mithril_control::LocalObjectSelectorV1::Devices {
        device_class_ids: vec!["PROJECTED_TOKEN".to_owned()],
        ioctl_command_ids: Vec::new(),
    };
    assert!(PolicyCompiler.compile(&deny).is_ok());

    for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
        let mut wildcard = deny.clone();
        wildcard.rules[0].requested_disposition = disposition;
        wildcard.rules[0].errno = None;
        assert!(PolicyCompiler
            .compile(&wildcard)
            .is_err_and(|error| error.to_string().contains("CFG_DEVICE_IOCTL_WILDCARD")));

        let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
            &mut wildcard.rules[0].rule_match
        else {
            unreachable!("fixture has a local effect rule")
        };
        let mithril_control::LocalObjectSelectorV1::Devices {
            ioctl_command_ids, ..
        } = &mut effect.object
        else {
            unreachable!("fixture has a device selector")
        };
        ioctl_command_ids.push(21_531);
        assert!(PolicyCompiler.compile(&wildcard).is_ok());
    }
    Ok(())
}

#[test]
fn file_namespace_operations_compile_to_closed_kernel_ids() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.operation_ids = ["CREATE", "LINK", "MMAP_READ", "RENAME", "SETATTR", "UNLINK"]
        .map(str::to_owned)
        .to_vec();

    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(compiled.compiled_cells.len(), 6);
    assert_eq!(
        compiled
            .compiled_cells
            .iter()
            .map(|cell| {
                CompiledOperationV1::try_from(cell.key.operation_id.as_str())
                    .map(|operation| operation.kernel_id)
                    .ok()
            })
            .collect::<Vec<_>>(),
        [
            KernelEffectOperationV1::Create,
            KernelEffectOperationV1::Link,
            KernelEffectOperationV1::MmapRead,
            KernelEffectOperationV1::Rename,
            KernelEffectOperationV1::Setattr,
            KernelEffectOperationV1::Unlink,
        ]
        .map(Some)
    );
    Ok(())
}

#[test]
fn bounded_exception_binds_one_exact_allow_cell() -> mithril_control::Result<()> {
    let source = VALID_POLICY.replacen(
        "desired_profile_mode: OBSERVE",
        "desired_profile_mode: PROTECT",
        1,
    );
    let mut document = parse(&source)?;
    document.rules[0].requested_disposition = PolicyDispositionV1::Allow;
    document.rules[0].errno = None;
    document.rules[0].exception_ids.clear();
    let cell = PolicyCompiler.compile(&document)?.compiled_cells.remove(0);
    let mut write_document = document.clone();
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut write_document.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.operation_ids = vec!["OPEN_WRITE".to_owned()];
    let write_cell = PolicyCompiler.compile(&write_document)?;
    assert_eq!(
        write_cell.compiled_cells[0]
            .key
            .digest(document.profile_id())?,
        "501b6f332e0cb9d64d878fd1269a51d792a1c2769a04fe5c6d8e1178ba5e7438"
    );
    document.exceptions.push(ExceptionV1 {
        exception_id: "one-token-open".to_owned(),
        exception_instance_id: "88888888-8888-4888-8888-888888888888".to_owned(),
        changed_rule_ids: vec![document.rules[0].rule_id.clone()],
        exact_subject: ExactExceptionSubjectSelectorV1 {
            protected_scope_ids: vec![document.protected_universe.protected_scope_ids[0].clone()],
            execution_set_ids: vec![document.protected_universe.execution_set_ids[0].clone()],
            entry_kind_ids: vec![mithril_control::EntryKindV1::ContainerStart],
            role_ids: vec!["converter".to_owned()],
            immutable_definition_digests: vec![],
            exact_compiled_key_digests: vec!["0".repeat(64)],
        },
        authority_delta: PermittedAuthorityDeltaV1 {
            from_physical_result: "DENY_ERRNO".to_owned(),
            to_physical_result: "ALLOW_EFFECT".to_owned(),
            added_or_removed_operation_cells: vec![],
            added_or_removed_transition_cells: vec![],
            maximum_blast_radius: BlastRadiusLimitV1::Local {
                permitted_target_selector_ids: vec![],
                process_count: 1,
                execution_set_count: 1,
                socket_count: 1,
                node_count: 1,
            },
        },
        approver_principal_id: "99999999-9999-4999-8999-999999999999".to_owned(),
        approval_proof_digest: "a".repeat(64),
        closed_reason_code: "ONE_TOKEN_OPEN".to_owned(),
        valid_from_utc_ns: 1,
        valid_until_utc_ns: i64::MAX,
        consumption_scope: ExceptionConsumptionScopeV1::PerTargetNode,
        maximum_uses: 1,
        maximum_lifetime_ns: 1_000_000_000,
    });
    document.exceptions[0]
        .exact_subject
        .exact_compiled_key_digests = vec![cell.key.digest(document.profile_id())?];
    document.exceptions[0]
        .authority_delta
        .added_or_removed_operation_cells = document.exceptions[0]
        .exact_subject
        .exact_compiled_key_digests
        .clone();
    document.rules[0]
        .exception_ids
        .push("one-token-open".to_owned());

    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(
        compiled.compiled_cells[0].consuming_exception_id.as_deref(),
        Some("one-token-open")
    );
    let exact = document.clone();
    let mut multiple_cells = exact.clone();
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut multiple_cells.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.operation_ids = ["OPEN_READ", "OPEN_WRITE"].map(str::to_owned).to_vec();
    multiple_cells.rules[0].exception_ids.clear();
    multiple_cells.exceptions.clear();
    let preliminary = PolicyCompiler.compile(&multiple_cells)?;
    multiple_cells = exact.clone();
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut multiple_cells.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.operation_ids = ["OPEN_READ", "OPEN_WRITE"].map(str::to_owned).to_vec();
    multiple_cells.exceptions[0]
        .exact_subject
        .exact_compiled_key_digests = preliminary
        .compiled_cells
        .iter()
        .map(|cell| cell.key.digest(multiple_cells.profile_id()))
        .collect::<mithril_control::Result<Vec<_>>>()?;
    multiple_cells.exceptions[0]
        .authority_delta
        .added_or_removed_operation_cells = multiple_cells.exceptions[0]
        .exact_subject
        .exact_compiled_key_digests
        .clone();
    assert!(PolicyCompiler.compile(&multiple_cells).is_err());
    document.rules[0].exception_ids.clear();
    assert!(PolicyCompiler.compile(&document).is_err());
    document = exact.clone();
    document.exceptions[0]
        .exact_subject
        .role_ids
        .push("runtime-external".to_owned());
    assert!(PolicyCompiler.compile(&document).is_err());
    document = exact.clone();
    document.exceptions[0].authority_delta.from_physical_result = "ALLOW_EFFECT".to_owned();
    assert!(PolicyCompiler.compile(&document).is_err());
    document = exact;
    document.exceptions[0]
        .exact_subject
        .exact_compiled_key_digests = vec!["f".repeat(64)];
    assert!(PolicyCompiler.compile(&document).is_err());
    let exception = document.exceptions[0].clone();
    document.exceptions = vec![exception; 4_097];
    assert!(PolicyCompiler.compile(&document).is_err());
    Ok(())
}

#[test]
fn restricted_yaml_rejects_ambiguous_or_open_input() {
    let cases = [
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: ProtectionPolicy\nkind: ProtectionPolicy",
            1,
        ),
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: ProtectionPolicy\nunknown: true",
            1,
        ),
        VALID_POLICY.replacen("kind: ProtectionPolicy", "kind: &kind ProtectionPolicy", 1),
        VALID_POLICY.replacen(
            "kind: ProtectionPolicy",
            "kind: !custom ProtectionPolicy",
            1,
        ),
        format!("{VALID_POLICY}\n---\n{VALID_POLICY}"),
        VALID_POLICY.replacen(
            "desired_profile_mode: OBSERVE",
            "desired_profile_mode: UNKNOWN",
            1,
        ),
    ];
    for source in cases {
        assert!(parse(&source).is_err());
    }
}

#[test]
fn comments_do_not_change_canonical_policy() -> mithril_control::Result<()> {
    let plain = PolicyCompiler.compile(&parse(VALID_POLICY)?)?;
    let commented = PolicyCompiler.compile(&parse(&format!("# ignored\n{VALID_POLICY}"))?)?;
    assert_eq!(plain.canonical_policy, commented.canonical_policy);
    assert_eq!(plain.source_policy_digest, commented.source_policy_digest);
    Ok(())
}

#[test]
fn compiler_rejects_unknown_or_ambiguous_kernel_dimensions() -> mithril_control::Result<()> {
    let mut unknown_role = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut unknown_role.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.subject.role_ids = vec!["unknown-role".to_owned()];
    assert!(PolicyCompiler.compile(&unknown_role).is_err());

    let mut duplicate_object = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
        &mut duplicate_object.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.object = mithril_control::LocalObjectSelectorV1::ExactObjectKeys {
        exact_object_key_ids: vec![7, 7],
    };
    assert!(PolicyCompiler.compile(&duplicate_object).is_err());
    Ok(())
}

#[test]
fn unequal_exact_overlap_requires_one_explicit_override() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    let mut allow = document.rules[0].clone();
    allow.rule_id = "allow-projected-token-open".to_owned();
    allow.requested_disposition = PolicyDispositionV1::Allow;
    allow.errno = None;
    document.rules.push(allow);
    assert!(PolicyCompiler.compile(&document).is_err());

    document.rules[1]
        .overrides_rule_ids
        .push("deny-projected-token-open".to_owned());
    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(compiled.compiled_cells.len(), 1);
    assert_eq!(
        compiled.compiled_cells[0].physical_result,
        CompiledPhysicalResultV1::AllowEffect
    );
    Ok(())
}

#[test]
fn equal_errno_with_unequal_actions_is_still_an_exact_conflict() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    let mut unequal = document.rules[0].clone();
    unequal.rule_id = "different-finding-same-denial".to_owned();
    assert!(unequal.finding.is_some());
    if let Some(finding) = unequal.finding.as_mut() {
        finding.reason_code = "DIFFERENT_REASON".to_owned();
    }
    document.rules.push(unequal);
    assert!(PolicyCompiler.compile(&document).is_err());

    document.rules[1]
        .overrides_rule_ids
        .push("deny-projected-token-open".to_owned());
    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(
        compiled.compiled_cells[0].source_rule_ids,
        ["different-finding-same-denial"]
    );
    Ok(())
}

#[test]
fn effect_family_default_fills_only_unmatched_exact_cells() -> mithril_control::Result<()> {
    let mut document = parse(VALID_POLICY)?;
    document.rules[0].enabled = false;
    document.effect_family_defaults = vec![EffectFamilyDefaultV1 {
        role_ids: vec!["converter".to_owned()],
        effect_family: EffectFamilyV1::File,
        operations: vec!["OPEN_READ".to_owned()],
        requested_disposition: PolicyDispositionV1::Deny,
        errno: Some(ErrnoV1::Eacces),
        finding: document.rules[0].finding.clone(),
    }];
    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(compiled.compiled_cells.len(), 5);
    assert!(compiled
        .compiled_cells
        .iter()
        .all(|cell| cell.source_rule_ids.is_empty()
            && cell.key.object_selector == "DEFAULT"
            && cell.physical_result == CompiledPhysicalResultV1::SimulatablePolicyDeny));
    Ok(())
}

#[test]
fn generic_privilege_effect_defaults_are_denial_only() -> mithril_control::Result<()> {
    for operation in ["BPF", "CAPABILITY"] {
        let mut deny = parse(VALID_POLICY)?;
        deny.rules[0].enabled = false;
        deny.effect_family_defaults = vec![EffectFamilyDefaultV1 {
            role_ids: vec!["converter".to_owned()],
            effect_family: EffectFamilyV1::Privilege,
            operations: vec![operation.to_owned()],
            requested_disposition: PolicyDispositionV1::Deny,
            errno: Some(ErrnoV1::Eacces),
            finding: deny.rules[0].finding.clone(),
        }];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut invalid = deny.clone();
            invalid.effect_family_defaults[0].requested_disposition = disposition;
            invalid.effect_family_defaults[0].errno = None;
            assert!(PolicyCompiler
                .compile(&invalid)
                .is_err_and(|error| error.to_string().contains("CFG_PRIVILEGE_WILDCARD")));
        }
    }
    Ok(())
}

#[test]
fn network_effect_defaults_are_denial_only() -> mithril_control::Result<()> {
    for operation in ["CONNECT", "SEND"] {
        let mut deny = parse(VALID_POLICY)?;
        deny.rules[0].enabled = false;
        deny.effect_family_defaults = vec![EffectFamilyDefaultV1 {
            role_ids: vec!["converter".to_owned()],
            effect_family: EffectFamilyV1::Network,
            operations: vec![operation.to_owned()],
            requested_disposition: PolicyDispositionV1::Deny,
            errno: Some(ErrnoV1::Eacces),
            finding: deny.rules[0].finding.clone(),
        }];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut invalid = deny.clone();
            invalid.effect_family_defaults[0].requested_disposition = disposition;
            invalid.effect_family_defaults[0].errno = None;
            assert!(PolicyCompiler
                .compile(&invalid)
                .is_err_and(|error| error.to_string().contains("CFG_NETWORK_DEFAULT_AUTHORITY")));
        }
    }
    Ok(())
}

#[test]
fn safe_network_controls_may_use_a_positive_role_default() -> mithril_control::Result<()> {
    for operation in [
        "SOCKET_CREATE",
        "LISTEN",
        "ACCEPT",
        "SHUTDOWN",
        "SETSOCKOPT",
    ] {
        let mut document = parse(VALID_POLICY)?;
        document.rules[0].enabled = false;
        document.effect_family_defaults = vec![EffectFamilyDefaultV1 {
            role_ids: vec!["converter".to_owned()],
            effect_family: EffectFamilyV1::Network,
            operations: vec![operation.to_owned()],
            requested_disposition: PolicyDispositionV1::Allow,
            errno: None,
            finding: None,
        }];
        assert!(PolicyCompiler.compile(&document).is_ok());
    }
    Ok(())
}

#[test]
fn destination_policy_compiles_only_canonical_bounded_network_rules() -> mithril_control::Result<()>
{
    let mut document = parse(VALID_POLICY)?;
    document.network_policy = Some(NetworkPolicyV1 {
        dns_mode: DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses,
        destination_policies: vec![DestinationPolicyRecordV1 {
            destination_policy_id: "result-service".to_owned(),
            protocols: vec![NetworkProtocolV1::Tcp, NetworkProtocolV1::Udp],
            ipv4_prefixes: vec!["127.0.0.0/8".to_owned()],
            ipv6_prefixes: vec!["::1/128".to_owned()],
            port_ranges: vec![NetworkPortRangeV1 {
                first: 8_443,
                last: 8_443,
            }],
            required_network_namespace_ids: Vec::new(),
            service_identities: Vec::new(),
            final_address_required: true,
        }],
    });
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.effect_families = vec![EffectFamilyV1::Network];
    effect.operation_ids = vec!["CONNECT".to_owned()];
    effect.object = mithril_control::LocalObjectSelectorV1::Destinations {
        destination_policy_ids: vec!["result-service".to_owned()],
    };
    document.rules[0].requested_disposition = PolicyDispositionV1::Allow;
    document.rules[0].errno = None;

    let compiled = PolicyCompiler.compile(&document)?;
    assert_eq!(compiled.compiled_cells.len(), 1);
    assert_eq!(
        compiled.compiled_cells[0].key.object_selector,
        "DESTINATION:result-service"
    );

    let mut invalid = document.clone();
    let Some(network) = invalid.network_policy.as_mut() else {
        unreachable!("fixture has a network policy")
    };
    network.destination_policies[0].ipv4_prefixes = vec!["127.0.0.1/8".to_owned()];
    assert!(PolicyCompiler
        .compile(&invalid)
        .is_err_and(|error| error.to_string().contains("CFG_NETWORK_PREFIX")));

    let mut no_final_address = document.clone();
    let Some(network) = no_final_address.network_policy.as_mut() else {
        unreachable!("fixture has a network policy")
    };
    network.destination_policies[0].final_address_required = false;
    assert!(PolicyCompiler
        .compile(&no_final_address)
        .is_err_and(|error| error.to_string().contains("CFG_NETWORK_FINAL_ADDRESS")));

    let mut dns = document;
    let Some(network) = dns.network_policy.as_mut() else {
        unreachable!("fixture has a network policy")
    };
    network.destination_policies[0].port_ranges = vec![NetworkPortRangeV1 {
        first: 53,
        last: 53,
    }];
    assert!(PolicyCompiler
        .compile(&dns)
        .is_err_and(|error| error.to_string().contains("CFG_NETWORK_DNS_MODE")));
    Ok(())
}

#[test]
fn mount_effect_defaults_are_denial_only() -> mithril_control::Result<()> {
    for operation in ["MOUNT", "UNMOUNT", "PIVOT_ROOT", "MOVE_MOUNT"] {
        let mut deny = parse(VALID_POLICY)?;
        deny.rules[0].enabled = false;
        deny.effect_family_defaults = vec![EffectFamilyDefaultV1 {
            role_ids: vec!["converter".to_owned()],
            effect_family: EffectFamilyV1::Mount,
            operations: vec![operation.to_owned()],
            requested_disposition: PolicyDispositionV1::Deny,
            errno: Some(ErrnoV1::Eacces),
            finding: deny.rules[0].finding.clone(),
        }];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut invalid = deny.clone();
            invalid.effect_family_defaults[0].requested_disposition = disposition;
            invalid.effect_family_defaults[0].errno = None;
            assert!(PolicyCompiler
                .compile(&invalid)
                .is_err_and(|error| error.to_string().contains("CFG_MOUNT_DEFAULT_AUTHORITY")));
        }
    }
    Ok(())
}

#[test]
fn executable_memory_rules_require_exact_objects_for_authority() -> mithril_control::Result<()> {
    for operation in ["MMAP_EXEC", "MPROTECT"] {
        let mut exact = parse(VALID_POLICY)?;
        let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut exact.rules[0].rule_match
        else {
            unreachable!("fixture has a local effect rule")
        };
        effect.effect_families = vec![EffectFamilyV1::Exec];
        effect.operation_ids = vec![operation.to_owned()];
        effect.object = mithril_control::LocalObjectSelectorV1::ExactObjectKeys {
            exact_object_key_ids: vec![7],
        };
        exact.rules[0].requested_disposition = PolicyDispositionV1::Allow;
        exact.rules[0].errno = None;
        assert!(PolicyCompiler.compile(&exact).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut unqualified = exact.clone();
            let mithril_control::RuleMatchV1::LocalPreEffect(effect) =
                &mut unqualified.rules[0].rule_match
            else {
                unreachable!("fixture has a local effect rule")
            };
            effect.object = mithril_control::LocalObjectSelectorV1::ObjectClasses {
                object_class_ids: vec!["PROJECTED_TOKEN".to_owned()],
            };
            unqualified.rules[0].requested_disposition = disposition;
            assert!(PolicyCompiler
                .compile(&unqualified)
                .is_err_and(|error| error
                    .to_string()
                    .contains("CFG_EXECUTABLE_MEMORY_AUTHORITY")));
        }

        let mut deny = exact;
        let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut deny.rules[0].rule_match
        else {
            unreachable!("fixture has a local effect rule")
        };
        effect.object = mithril_control::LocalObjectSelectorV1::ObjectClasses {
            object_class_ids: vec!["PROJECTED_TOKEN".to_owned()],
        };
        deny.rules[0].requested_disposition = PolicyDispositionV1::Deny;
        deny.rules[0].errno = Some(ErrnoV1::Eacces);
        assert!(PolicyCompiler.compile(&deny).is_ok());
    }
    Ok(())
}

#[test]
fn unqualified_executable_authority_defaults_are_denial_only() -> mithril_control::Result<()> {
    for operation in ["EXECUTE", "MMAP_EXEC", "MPROTECT"] {
        let mut deny = parse(VALID_POLICY)?;
        deny.rules[0].enabled = false;
        deny.effect_family_defaults = vec![EffectFamilyDefaultV1 {
            role_ids: vec!["converter".to_owned()],
            effect_family: EffectFamilyV1::Exec,
            operations: vec![operation.to_owned()],
            requested_disposition: PolicyDispositionV1::Deny,
            errno: Some(ErrnoV1::Eacces),
            finding: deny.rules[0].finding.clone(),
        }];
        assert!(PolicyCompiler.compile(&deny).is_ok());

        for disposition in [PolicyDispositionV1::Allow, PolicyDispositionV1::Alert] {
            let mut invalid = deny.clone();
            invalid.effect_family_defaults[0].requested_disposition = disposition;
            invalid.effect_family_defaults[0].errno = None;
            assert!(PolicyCompiler.compile(&invalid).is_err_and(|error| error
                .to_string()
                .contains("CFG_EXECUTABLE_MEMORY_AUTHORITY")));
        }
    }
    Ok(())
}

#[test]
fn signature_binds_source_and_recomputed_compiler_output() -> mithril_control::Result<()> {
    let document = parse(VALID_POLICY)?;
    let compiled = PolicyCompiler.compile(&document)?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let artifact =
        ProfileCandidateArtifactV1::sign(&document, compiled, seal_request(1, 1, None), &key)?;
    artifact.verify(&key.verifying_key())?;
    artifact.verify_at(&key.verifying_key(), 1_800_000_000_000_000_000)?;
    assert!(artifact
        .verify_at(&key.verifying_key(), 2_000_000_000_000_000_000)
        .is_err());

    let mut changed_cells = artifact.clone();
    changed_cells.compiled_profile.compiled_cells[0].physical_result =
        CompiledPhysicalResultV1::AllowEffect;
    assert!(changed_cells.verify(&key.verifying_key()).is_err());

    let mut changed_source = artifact;
    changed_source.policy_document.metadata.profile_version = 2;
    assert!(changed_source.verify(&key.verifying_key()).is_err());
    Ok(())
}

#[test]
fn semantic_uuid_aliases_cannot_split_anti_rollback_identity() -> mithril_control::Result<()> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let document = parse(VALID_POLICY)?;
    let compiled = PolicyCompiler.compile(&document)?;
    let mut request = seal_request(1, 1, None);
    request.issuer_id.make_ascii_uppercase();
    let aliased_issuer =
        ProfileCandidateArtifactV1::sign(&document, compiled.clone(), request, &key)?;
    assert!(aliased_issuer.verify(&key.verifying_key()).is_err());

    let mut canonical = document.clone();
    canonical.metadata.profile_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned();
    assert!(PolicyCompiler.compile(&canonical).is_ok());
    for profile_id in [
        canonical.metadata.profile_id.to_ascii_uppercase(),
        canonical.metadata.profile_id.replace('-', ""),
        format!("{{{}}}", canonical.metadata.profile_id),
    ] {
        let mut aliased = canonical.clone();
        aliased.metadata.profile_id = profile_id;
        assert!(PolicyCompiler.compile(&aliased).is_err());
    }
    Ok(())
}

#[test]
fn observe_never_converts_hard_safety_failures_to_allow() -> mithril_control::Result<()> {
    let compiled = PolicyCompiler.compile(&parse(VALID_POLICY)?)?;
    let key = compiled.compiled_cells[0].key.clone();
    let simulator = PolicySimulator::new(&compiled);
    assert_eq!(
        simulator.simulate(key.clone(), None).disposition,
        SimulatedDispositionV1::WouldDeny
    );
    for condition in [
        HardSafetyConditionV1::PriorLsmDenial,
        HardSafetyConditionV1::MissingTaskIdentity,
        HardSafetyConditionV1::CorruptGeneration,
        HardSafetyConditionV1::EmergencyRestriction,
        HardSafetyConditionV1::AmbiguousTopology,
        HardSafetyConditionV1::UnsupportedPhysicalBoundary,
    ] {
        assert_eq!(
            simulator.simulate(key.clone(), Some(condition)).disposition,
            SimulatedDispositionV1::HardDeny
        );
    }
    Ok(())
}

#[test]
fn rollback_is_exact_signed_and_one_use() -> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut version_two = parse(VALID_POLICY)?;
    version_two.metadata.profile_version = 2;
    let current = signed(&version_two, seal_request(1, 2, None), &key)?;
    let target_document = parse(VALID_POLICY)?;
    let authorization_id = "88888888-8888-4888-8888-888888888888";
    let target = signed(
        &target_document,
        seal_request(1, 1, Some(authorization_id)),
        &key,
    )?;
    let platform = "ab".repeat(32);
    let rollback = RollbackAuthorizationArtifactV1::sign(
        "test-key".to_owned(),
        RollbackAuthorizationPayloadV1 {
            authorization_id: authorization_id.to_owned(),
            trust_domain_id: target.header.trust_domain_id.clone(),
            issuer_id: target.header.issuer_id.clone(),
            approver_principal_id: "99999999-9999-4999-8999-999999999999".to_owned(),
            sequence_epoch: 1,
            issuer_sequence: 3,
            profile_id: target.header.profile_id.clone(),
            current_digest: current.header.policy_document_digest.clone(),
            current_version: 2,
            exact_older_target_digest: target.header.policy_document_digest.clone(),
            exact_older_target_version: 1,
            closed_reason_code: 1,
            human_reason_artifact_digest: None,
            exact_platform_scope_digest: platform.clone(),
            issued_at_utc_ns: 10,
            expires_at_utc_ns: 30,
        },
        &key,
    )?;
    let directory = tempfile::tempdir()?;
    let mut store = AntiRollbackStore::load(directory.path().join("rollback.json"))?;
    let accepted = store.validate(&current, None, &platform, 20)?;
    let pending = store.prepare_activation(&accepted, activation(2), None)?;
    store.finalize_pending(&pending)?;
    assert!(store.validate(&target, None, &platform, 20).is_err());
    assert!(store
        .validate(
            &target,
            Some((&rollback, &key.verifying_key())),
            "wrong-platform",
            20,
        )
        .is_err());
    let accepted = store.validate(
        &target,
        Some((&rollback, &key.verifying_key())),
        &platform,
        20,
    )?;
    let pending = store.prepare_activation(&accepted, activation(1), Some(2))?;
    let mut recovered = AntiRollbackStore::load(directory.path().join("rollback.json"))?;
    assert_eq!(recovered.pending_activations(), vec![pending.clone()]);
    assert!(recovered.validate(&target, None, &platform, 100).is_ok());
    assert!(recovered.validate(&current, None, &platform, 100).is_ok());
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.path().join("rollback.json"))?)?;
    assert_eq!(
        state["consumed_rollback_authorization_ids"],
        serde_json::json!([])
    );
    assert_eq!(
        state["high_water"]
            .as_object()
            .and_then(|rows| rows.values().next())
            .and_then(|row| row["current_profile_version"].as_u64()),
        Some(2)
    );
    recovered.finalize_pending(&pending)?;
    store = recovered;

    let mut version_three = parse(VALID_POLICY)?;
    version_three.metadata.profile_version = 3;
    let next = signed(&version_three, seal_request(1, 4, None), &key)?;
    let accepted = store.validate(&next, None, &platform, 20)?;
    let pending = store.prepare_activation(&accepted, activation(3), Some(1))?;
    store.finalize_pending(&pending)?;
    assert!(store
        .validate(
            &target,
            Some((&rollback, &key.verifying_key())),
            &platform,
            20,
        )
        .is_err());
    Ok(())
}

#[test]
fn anti_rollback_validation_is_non_mutating_and_legacy_state_is_conservative(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut version_two = parse(VALID_POLICY)?;
    version_two.metadata.profile_version = 2;
    let current = signed(&version_two, seal_request(1, 2, None), &key)?;
    let mut version_three = parse(VALID_POLICY)?;
    version_three.metadata.profile_version = 3;
    let next = signed(&version_three, seal_request(1, 3, None), &key)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rollback.json");
    let platform = "cd".repeat(32);
    let mut store = AntiRollbackStore::load(&path)?;
    let accepted = store.validate(&current, None, &platform, 20)?;
    let pending = store.prepare_activation(&accepted, activation(2), None)?;
    store.finalize_pending(&pending)?;
    let before = std::fs::read(&path)?;

    let accepted = store.validate(&next, None, &platform, 20)?;
    assert_eq!(std::fs::read(&path)?, before);
    let pending = store.prepare_activation(&accepted, activation(3), Some(2))?;
    let pending_state: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let pending_row = pending_state["high_water"]
        .as_object()
        .and_then(|rows| rows.values().next())
        .ok_or("pending anti-rollback state has no profile")?;
    assert_eq!(pending_row["greatest_profile_version"], 3);
    assert_eq!(pending_row["current_profile_version"], 2);
    let mut recovered = AntiRollbackStore::load(&path)?;
    assert!(recovered.validate(&current, None, &platform, 20).is_ok());
    assert!(recovered.validate(&next, None, &platform, 20).is_ok());
    assert_eq!(recovered.pending_activations(), vec![pending.clone()]);
    recovered.clear_old_epoch_pending(&pending)?;
    assert!(recovered.pending_activations().is_empty());
    assert!(recovered.validate(&current, None, &platform, 20).is_ok());

    let mut state: serde_json::Value = serde_json::from_slice(&before)?;
    let row = state["high_water"]
        .as_object_mut()
        .and_then(|rows| rows.values_mut().next())
        .ok_or("anti-rollback test state has no profile")?;
    let row = row
        .as_object_mut()
        .ok_or("anti-rollback test profile is not an object")?;
    row.remove("greatest_policy_digest");
    row.remove("current_activation");
    row.remove("pending_activation");
    std::fs::write(&path, serde_json::to_vec(&state)?)?;
    let mut legacy = AntiRollbackStore::load(&path)?;
    let legacy_current = legacy.validate(&current, None, &platform, 20)?;
    assert!(!legacy.is_current_activation(&legacy_current, &activation(2)));
    let pending = legacy.prepare_activation(&legacy_current, activation(2), Some(2))?;
    legacy.finalize_pending(&pending)?;
    assert!(legacy.is_current_activation(&legacy_current, &activation(2)));

    let mut conflict = version_two;
    conflict.rules[0].priority += 1;
    let conflict = signed(&conflict, seal_request(1, 2, None), &key)?;
    assert!(legacy.validate(&conflict, None, &platform, 20).is_err());
    Ok(())
}

fn activation(profile_generation_ref_id: u64) -> ProfileActivationMetadataV1 {
    ProfileActivationMetadataV1 {
        profile_generation_ref_id,
        node_boot_id: [1; 16],
        label_epoch: 1,
        descriptor_sha256: [profile_generation_ref_id as u8; 32],
    }
}

fn signed(
    document: &PolicyDocumentV1,
    request: ProfileSealRequestV1,
    key: &SigningKey,
) -> mithril_control::Result<ProfileCandidateArtifactV1> {
    ProfileCandidateArtifactV1::sign(document, PolicyCompiler.compile(document)?, request, key)
}

fn process_control_policy(
    operation: &str,
    disposition: PolicyDispositionV1,
) -> mithril_control::Result<PolicyDocumentV1> {
    let mut document = parse(VALID_POLICY)?;
    let mithril_control::RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match
    else {
        unreachable!("fixture has a local effect rule")
    };
    effect.effect_families = vec![EffectFamilyV1::Privilege];
    effect.operation_ids = vec![operation.to_owned()];
    effect.object = mithril_control::LocalObjectSelectorV1::SecurityObjects {
        security_object_ids: vec!["PROCESS".to_owned()],
        target_selector_ids: vec!["runtime-external".to_owned()],
    };
    document.rules[0].requested_disposition = disposition;
    document.rules[0].errno = (disposition == PolicyDispositionV1::Deny).then_some(ErrnoV1::Eacces);
    Ok(document)
}

fn seal_request(
    sequence_epoch: u64,
    issuer_sequence: u64,
    rollback_authorization_id: Option<&str>,
) -> ProfileSealRequestV1 {
    let digest = "00".repeat(32);
    ProfileSealRequestV1 {
        signing_key_id: "test-key".to_owned(),
        issuer_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_owned(),
        sequence_epoch,
        issuer_sequence,
        rollback_authorization_id: rollback_authorization_id.map(str::to_owned),
        registry_digests: RegistryDigestsV1 {
            provider_numeric_registry_bundle_digest: digest.clone(),
            required_capability_schema_digest: digest.clone(),
            source_selector_registry_digest: digest.clone(),
            object_classifier_registry_digest: digest.clone(),
            reason_code_registry_digest: digest.clone(),
            correlation_package_registry_digest: digest.clone(),
            provider_vocabulary_registry_digest: digest,
        },
    }
}
