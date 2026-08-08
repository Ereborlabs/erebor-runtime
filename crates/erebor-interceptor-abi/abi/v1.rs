pub struct EnumVariant {
    pub name: &'static str,
    pub value: u8,
}

pub struct EnumSpec {
    pub name: &'static str,
    pub variants: &'static [EnumVariant],
}

pub struct FieldSpec {
    pub name: &'static str,
    pub ty: &'static str,
}

pub struct StructSpec {
    pub name: &'static str,
    pub fields: &'static [FieldSpec],
}

pub const ENUMS: &[EnumSpec] = &[
    EnumSpec {
        name: "BindingLifecycleStateV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "PREPARING", value: 1 },
            EnumVariant { name: "ACTIVE", value: 2 },
            EnumVariant { name: "DRAINING", value: 3 },
            EnumVariant { name: "TERMINATING", value: 4 },
            EnumVariant { name: "TOMBSTONED", value: 5 },
        ],
    },
    EnumSpec {
        name: "PhysicalDecisionKindV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "ALLOW", value: 1 },
            EnumVariant { name: "AUDIT_ALLOW", value: 2 },
            EnumVariant { name: "DENY", value: 3 },
        ],
    },
    EnumSpec {
        name: "NegativeDecisionKindV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "NO_ADDITIONAL_RESTRICTION", value: 1 },
            EnumVariant { name: "AUDIT_ALLOW", value: 2 },
            EnumVariant { name: "DENY", value: 3 },
        ],
    },
    EnumSpec {
        name: "InstalledStateV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "PREPARING", value: 1 },
            EnumVariant { name: "ACTIVE", value: 2 },
            EnumVariant { name: "RETIRING", value: 3 },
        ],
    },
    EnumSpec {
        name: "MembershipStateV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "ACTIVE", value: 1 },
            EnumVariant { name: "RETIRING", value: 2 },
        ],
    },
    EnumSpec {
        name: "FloorRequirementKindV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "EXPLICIT_NEUTRAL", value: 1 },
            EnumVariant { name: "DYNAMIC_REQUIRED", value: 2 },
        ],
    },
    EnumSpec {
        name: "TransitionKindV1",
        variants: &[
            EnumVariant { name: "UNKNOWN", value: 0 },
            EnumVariant { name: "NONE", value: 1 },
            EnumVariant { name: "PROCESS_ONLY", value: 2 },
            EnumVariant { name: "NATIVE_AUTHORITY_ONLY", value: 3 },
        ],
    },
];

pub const STRUCTS: &[StructSpec] = &[
    StructSpec {
        name: "TaskPlacementExpectationV1",
        fields: &[
            FieldSpec { name: "protected_root_binding_id", ty: "Id128" },
            FieldSpec { name: "protected_root_binding_nonce", ty: "Id128" },
            FieldSpec { name: "allowed_descendant_policy_id", ty: "u32" },
        ],
    },
    StructSpec {
        name: "ProfileGenerationRefV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "node_boot_id", ty: "Id128" },
            FieldSpec { name: "label_epoch", ty: "u64" },
            FieldSpec { name: "profile_id", ty: "Id128" },
            FieldSpec { name: "owner_generation", ty: "u64" },
            FieldSpec { name: "compiled_artifact_digest_id", ty: "u64" },
            FieldSpec { name: "state", ty: "InstalledStateV1" },
        ],
    },
    StructSpec {
        name: "EffectDecisionKeyV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "active_role_id", ty: "u32" },
            FieldSpec { name: "entry_kind", ty: "u16" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
            FieldSpec { name: "exact_object_key_id", ty: "u64" },
            FieldSpec { name: "process_state_vector_id", ty: "u32" },
            FieldSpec { name: "binding_lifecycle_state", ty: "BindingLifecycleStateV1" },
        ],
    },
    StructSpec {
        name: "EffectDefaultKeyV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "active_role_id", ty: "u32" },
            FieldSpec { name: "entry_kind", ty: "u16" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
            FieldSpec { name: "process_state_vector_id", ty: "u32" },
            FieldSpec { name: "binding_lifecycle_state", ty: "BindingLifecycleStateV1" },
        ],
    },
    StructSpec {
        name: "PhysicalDecisionV1",
        fields: &[
            FieldSpec { name: "decision", ty: "PhysicalDecisionKindV1" },
            FieldSpec { name: "errno", ty: "i16" },
            FieldSpec { name: "evidence_class_id", ty: "u32" },
            FieldSpec { name: "transition_id", ty: "u32" },
            FieldSpec { name: "exception_numeric_handle", ty: "u32" },
        ],
    },
    StructSpec {
        name: "RestrictionDecisionKeyV1",
        fields: &[
            FieldSpec { name: "restriction_set_ref_id", ty: "u64" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
            FieldSpec { name: "exact_object_key_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "RestrictionDefaultKeyV1",
        fields: &[
            FieldSpec { name: "restriction_set_ref_id", ty: "u64" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "RestrictionDecisionV1",
        fields: &[
            FieldSpec { name: "result", ty: "NegativeDecisionKindV1" },
            FieldSpec { name: "errno", ty: "i16" },
            FieldSpec { name: "restriction_reason_bits", ty: "u64" },
        ],
    },
    StructSpec {
        name: "ResponseDecisionKeyV1",
        fields: &[
            FieldSpec { name: "response_set_ref_id", ty: "u64" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
            FieldSpec { name: "exact_object_key_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "ResponseDefaultKeyV1",
        fields: &[
            FieldSpec { name: "response_set_ref_id", ty: "u64" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "ResponseDecisionV1",
        fields: &[
            FieldSpec { name: "result", ty: "NegativeDecisionKindV1" },
            FieldSpec { name: "errno", ty: "i16" },
            FieldSpec { name: "response_plan_set_digest_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "RestrictionSetDescriptorV1",
        fields: &[
            FieldSpec { name: "restriction_set_ref_id", ty: "u64" },
            FieldSpec { name: "set_epoch", ty: "u64" },
            FieldSpec { name: "covered_generation_set_ref_id", ty: "u64" },
            FieldSpec { name: "row_count", ty: "u32" },
            FieldSpec { name: "table_digest_id", ty: "u64" },
            FieldSpec { name: "declared_default_digest_id", ty: "u64" },
            FieldSpec { name: "state", ty: "InstalledStateV1" },
        ],
    },
    StructSpec {
        name: "ResponseSetDescriptorV1",
        fields: &[
            FieldSpec { name: "response_set_ref_id", ty: "u64" },
            FieldSpec { name: "set_epoch", ty: "u64" },
            FieldSpec { name: "covered_generation_set_ref_id", ty: "u64" },
            FieldSpec { name: "row_count", ty: "u32" },
            FieldSpec { name: "table_digest_id", ty: "u64" },
            FieldSpec { name: "declared_default_digest_id", ty: "u64" },
            FieldSpec { name: "response_plan_set_digest_id", ty: "u64" },
            FieldSpec { name: "state", ty: "InstalledStateV1" },
        ],
    },
    StructSpec {
        name: "GenerationSetDescriptorV1",
        fields: &[
            FieldSpec { name: "retained_generation_set_ref_id", ty: "u64" },
            FieldSpec { name: "membership_count", ty: "u32" },
            FieldSpec { name: "membership_digest_id", ty: "u64" },
            FieldSpec { name: "state", ty: "InstalledStateV1" },
        ],
    },
    StructSpec {
        name: "GenerationMembershipKeyV1",
        fields: &[
            FieldSpec { name: "retained_generation_set_ref_id", ty: "u64" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "GenerationMembershipValueV1",
        fields: &[
            FieldSpec { name: "state", ty: "MembershipStateV1" },
            FieldSpec { name: "generation_artifact_digest_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "FloorRequirementKeyV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "active_role_id", ty: "u32" },
            FieldSpec { name: "entry_kind", ty: "u16" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
            FieldSpec { name: "composite_atom_id", ty: "u64" },
            FieldSpec { name: "process_state_vector_id", ty: "u32" },
            FieldSpec { name: "binding_lifecycle_state", ty: "BindingLifecycleStateV1" },
        ],
    },
    StructSpec {
        name: "FloorRequirementValueV1",
        fields: &[
            FieldSpec { name: "kind", ty: "FloorRequirementKindV1" },
            FieldSpec { name: "template_id", ty: "u64" },
            FieldSpec { name: "required_provenance_bits", ty: "u64" },
            FieldSpec { name: "required_reference_classes", ty: "u64" },
        ],
    },
    StructSpec {
        name: "RestrictionFloorV1",
        fields: &[
            FieldSpec { name: "result", ty: "NegativeDecisionKindV1" },
            FieldSpec { name: "errno", ty: "i16" },
            FieldSpec { name: "reason_bits", ty: "u64" },
        ],
    },
    StructSpec {
        name: "ExactObjectFloorKeyV1",
        fields: &[
            FieldSpec { name: "exact_object_key_id", ty: "u64" },
            FieldSpec { name: "exact_object_generation", ty: "u64" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
        ],
    },
    StructSpec {
        name: "ExactSocketOrChannelFloorKeyV1",
        fields: &[
            FieldSpec { name: "exact_socket_or_channel_key_id", ty: "u64" },
            FieldSpec { name: "exact_socket_or_channel_generation", ty: "u64" },
            FieldSpec { name: "current_actor_authority_domain_id", ty: "Id128" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
        ],
    },
    StructSpec {
        name: "BindingLifetimeFloorKeyV1",
        fields: &[
            FieldSpec { name: "binding_id", ty: "Id128" },
            FieldSpec { name: "binding_nonce", ty: "Id128" },
            FieldSpec { name: "lifecycle_state", ty: "BindingLifecycleStateV1" },
            FieldSpec { name: "effect_family", ty: "u16" },
            FieldSpec { name: "operation", ty: "u16" },
        ],
    },
    StructSpec {
        name: "TransitionDescriptorV1",
        fields: &[
            FieldSpec { name: "transition_id", ty: "u32" },
            FieldSpec { name: "node_boot_id", ty: "Id128" },
            FieldSpec { name: "label_epoch", ty: "u64" },
            FieldSpec { name: "transition_kind", ty: "TransitionKindV1" },
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "exception_numeric_handle", ty: "u32" },
            FieldSpec { name: "transition_artifact_digest_id", ty: "u64" },
            FieldSpec { name: "state", ty: "InstalledStateV1" },
        ],
    },
    StructSpec {
        name: "ProcessTransitionKeyV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "transition_id", ty: "u32" },
            FieldSpec { name: "current_role_id", ty: "u32" },
            FieldSpec { name: "current_process_state_vector_id", ty: "u32" },
            FieldSpec { name: "current_process_response_set_ref_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "ProcessTransitionValueV1",
        fields: &[
            FieldSpec { name: "next_role_id", ty: "u32" },
            FieldSpec { name: "next_process_state_vector_id", ty: "u32" },
            FieldSpec { name: "next_process_response_set_ref_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "NativeAuthorityTransitionKeyV1",
        fields: &[
            FieldSpec { name: "profile_generation_ref_id", ty: "u64" },
            FieldSpec { name: "transition_id", ty: "u32" },
            FieldSpec { name: "current_potential_sensitive_bits", ty: "u64" },
            FieldSpec { name: "current_observed_sensitive_bits", ty: "u64" },
            FieldSpec { name: "current_restriction_set_ref_id", ty: "u64" },
            FieldSpec { name: "current_domain_response_set_ref_id", ty: "u64" },
        ],
    },
    StructSpec {
        name: "NativeAuthorityTransitionValueV1",
        fields: &[
            FieldSpec { name: "next_potential_sensitive_bits", ty: "u64" },
            FieldSpec { name: "next_observed_sensitive_bits", ty: "u64" },
            FieldSpec { name: "next_restriction_set_ref_id", ty: "u64" },
            FieldSpec { name: "next_domain_response_set_ref_id", ty: "u64" },
        ],
    },
];
