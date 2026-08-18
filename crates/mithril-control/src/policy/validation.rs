use super::compiler::{compiled_key_digest, object_cells, process_control_operation, CompiledDecisionCellV1, CompiledPhysicalResultV1};
use super::{path::canonical_path_components, source::*, source_proof::ProofQualityPredicateV1, source_response::*};
use crate::error::PolicyValidationSnafu;
use crate::Result;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use {
    time::{format_description::well_known::Rfc3339, OffsetDateTime},
    uuid::Uuid,
};
const MAX_EXCEPTION_STATES: usize = 4_096;
type ValidationResult = std::result::Result<(), ValidationIssue>;
pub(super) trait Validate {
    fn validate(&self) -> ValidationResult;
}
pub(super) struct ValidationIssue {
    code: &'static str,
    reason: String,
}
impl ValidationIssue {
    pub(super) fn for_policy(self, policy_id: &str) -> crate::Error {
        PolicyValidationSnafu { policy_id, code: self.code, reason: self.reason }.build()
    }
}
macro_rules! require {
    ($condition:expr, $code:expr, $reason:expr) => {
        if !$condition {
            return Err(ValidationIssue { code: $code, reason: ($reason).into() });
        }
    };
}
macro_rules! validate_each {
    ($document:expr; $($field:ident),+ $(,)?) => {$({
        for value in &$document.$field { value.validate()?; } })+};
}
macro_rules! local_id_only {
    ($($type:ty => $field:ident),+ $(,)?) => {$ (
        impl Validate for $type { fn validate(&self) -> ValidationResult {
            PolicyValue::LocalId(&self.$field).validate() }}
    )+};
}
macro_rules! string_set {
    ($values:expr) => {
        $values.iter().map(String::as_str).collect::<BTreeSet<_>>()
    };
}
macro_rules! ordered {
    ($($values:expr),+ $(,)?) => { $(ordered_unique($values))&&+ };
}
macro_rules! all_in {
    ($values:expr, $set:expr) => {
        $values.iter().all(|value| $set.contains(value.as_str()))
    };
}
macro_rules! bounded {
    ($ids:expr; $($count:expr),+ $(,)?) => {
        ordered_unique($ids) && [$($count),+].into_iter().all(|count| *count > 0)
    };
}
macro_rules! authority_rule {
    ($id:expr, $accounts:expr, $principals:expr, $operations:expr, $resources:expr, $proof:expr, $disposition:expr, $finding:expr, $responses:expr, $budgets:expr, $legal:expr) => {{
        PolicyValue::LocalId($id).validate()?;
        $proof.validate()?;
        let exact = $legal
            && ordered!($accounts, $principals)
            && !$operations.is_empty()
            && ordered!($operations, $resources, $responses)
            && $budgets.rate_limits.is_empty()
            && $budgets.concurrency_limits.is_empty()
            && $budgets.maximum_lifetime.is_none()
            && $budgets.automatic_response_limit.is_none()
            && ($finding.is_some()
                || ($responses.is_empty() && *$disposition != PolicyDispositionV1::Alert));
        require!(exact, "CFG_AUTHORITY_RULE", format!("authority behavior rule `{}` is invalid", $id));
        if let Some(finding) = $finding {
            finding.validate()?;
        }
        Ok(())
    }};
}
enum PolicyValue<'a> {
    LocalId(&'a str),
    RegistrySymbol(&'a str),
    CanonicalUuid(&'a str),
    Uuid(&'a str),
    Digest(&'a str),
    Duration(&'a str, bool),
}
impl Validate for PolicyValue<'_> {
    fn validate(&self) -> ValidationResult {
        let (valid, code, reason) = match *self {
            Self::LocalId(value) => (
                (1..=128).contains(&value.len())
                    && value.as_bytes()[0].is_ascii_lowercase()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'.' | b'-')
                    }),
                "CFG_LOCAL_ID",
                format!("`{value}` is not a PolicyLocalIdV1"),
            ),
            Self::RegistrySymbol(value) => (
                (1..=128).contains(&value.len())
                    && value.as_bytes()[0].is_ascii_uppercase()
                    && value.bytes().all(|byte| {
                        byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                    }),
                "CFG_REGISTRY_SYMBOL",
                format!("`{value}` is not an uppercase registry symbol"),
            ),
            Self::CanonicalUuid(value) => (Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value), "CFG_ID128", "value must be a canonical lowercase hyphenated Id128 UUID".to_owned()),
            Self::Uuid(value) => (Uuid::parse_str(value).is_ok(), "CFG_ID128", "value must be a UUID".to_owned()),
            Self::Digest(value) => (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()), "CFG_DIGEST", "value must be a 64-character hexadecimal digest".to_owned()),
            Self::Duration(value, zero_allowed) => {
                let suffix = if value.ends_with("ns") || value.ends_with("us") || value.ends_with("ms") {
                    2
                } else if value.ends_with('s') || value.ends_with('m') || value.ends_with('h') {
                    1
                } else {
                    0
                };
                let valid = suffix > 0 && value[..value.len() - suffix].parse::<u64>().is_ok_and(|duration| zero_allowed || duration > 0);
                (valid, "CFG_DURATION", "value must be a bounded duration".to_owned())
            }
        };
        require!(valid, code, reason);
        Ok(())
    }
}
impl Validate for PolicyMetadataV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::CanonicalUuid(&self.profile_id).validate()?;
        PolicyValue::CanonicalUuid(&self.trust_domain_id).validate()?;
        let parse = |value: &str| OffsetDateTime::parse(value, &Rfc3339).ok().filter(|time| time.offset().is_utc()).and_then(|time| i64::try_from(time.unix_timestamp_nanos()).ok());
        let from = parse(&self.valid_from_utc);
        require!(from.is_some(), "CFG_TIMESTAMP", "valid_from_utc must be a UTC timestamp");
        require!(self.valid_until_utc.as_deref().is_none_or(|until| parse(until).is_some_and(|until| Some(until) > from)), "CFG_VALIDITY_WINDOW", "valid_until_utc must be a later UTC timestamp");
        Ok(())
    }
}
impl Validate for ProtectedUniverseV1 {
    fn validate(&self) -> ValidationResult {
        for id in self.workload_selector_ids.iter().chain(&self.role_ids) {
            PolicyValue::LocalId(id).validate()?;
        }
        for id in &self.object_class_ids {
            PolicyValue::RegistrySymbol(id).validate()?;
        }
        Ok(())
    }
}
local_id_only! { WorkloadSelectorV1 => workload_selector_id, ObjectClassifierBindingV1 => classifier_binding_id, RoleDefinitionV1 => role_id, NativeRoleTransitionRuleV1 => transition_rule_id }
impl Validate for EntryRoleAssignmentV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.assignment_id).validate()?;
        let administrative_kind = self.entry_kinds.contains(&EntryKindV1::ApprovedAdministrativeExec);
        let administrative_classification = self.accepted_classifications.contains(&RootClassificationV1::ApprovedAdministrativeNextMatch);
        let complete = !self.workload_selector_ids.is_empty() && !self.entry_kinds.is_empty() && !self.container_kinds.is_empty() && !self.accepted_classifications.is_empty();
        let ordered = ordered!(&self.workload_selector_ids, &self.entry_kinds, &self.container_kinds, &self.immutable_definition_digests, &self.accepted_classifications);
        require!(complete && ordered, "CFG_ENTRY_ASSIGNMENT", format!("entry `{}` has empty or unordered selectors", self.assignment_id));
        let exact_administrative_binding = self.entry_kinds
            == [EntryKindV1::ApprovedAdministrativeExec]
            && self.accepted_classifications
                == [RootClassificationV1::ApprovedAdministrativeNextMatch]
            && self.required_administrative_exec_approval
            && self.required_purpose_source_capability_id.is_none()
            && self.unknown_restricted_role_id.is_none();
        require!(
            !(self.required_administrative_exec_approval
                || administrative_kind
                || administrative_classification)
                || exact_administrative_binding,
            "CFG_ADMINISTRATIVE_ENTRY",
            format!("entry `{}` has an invalid administrative binding", self.assignment_id)
        );
        Ok(())
    }
}
impl Validate for StateBitDefinitionV1 {
    fn validate(&self) -> ValidationResult {
        require!(self.bit_index < 64 && self.monotonic, "CFG_STATE_BIT", "state bits must be in 0..63 and monotonic");
        Ok(())
    }
}
impl Validate for ProcessStateDefinitionV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.process_state_id).validate()?;
        require!(ordered_unique(&self.state_bits), "CFG_STATE_ORDER", "process state bits must be sorted and unique");
        Ok(())
    }
}
impl Validate for IpcRelationshipRuleV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.relationship_rule_id).validate()?;
        let roles = !self.source_role_ids.is_empty() && !self.peer_role_ids.is_empty() && ordered!(&self.source_role_ids, &self.peer_role_ids);
        let operation = self.channel_class_ids == ["UNIX_STREAM"] && self.operations == ["IPC_ACCESS"];
        let decision = self.requested_disposition != PolicyDispositionV1::Reject && (self.requested_disposition == PolicyDispositionV1::Deny) == self.errno.is_some();
        require!(roles && operation && decision, "CFG_IPC_RELATIONSHIP", format!("IPC relationship `{}` is invalid", self.relationship_rule_id));
        Ok(())
    }
}
impl EffectFamilyV1 {
    fn accepts(self, operation: &str) -> bool {
        match self {
            Self::Exec => matches!(operation, "EXECUTE" | "MMAP_EXEC" | "MPROTECT"),
            Self::File => matches!(operation, "OPEN_READ" | "OPEN_WRITE" | "READ" | "WRITE" | "MMAP_READ" | "MMAP_WRITE" | "MPROTECT" | "CREATE" | "SETATTR" | "UNLINK" | "LINK" | "RENAME"),
            Self::Network => matches!(operation, "CONNECT" | "SEND"),
            Self::Device => operation == "IOCTL",
            Self::Privilege => matches!(operation, "CAPABILITY" | "BPF" | "IO_URING_SETUP" | "IO_URING_REGISTER" | "IO_URING_SQPOLL" | "IO_URING_OVERRIDE_CREDS" | "IO_URING_COMMAND") || process_control_operation(operation).is_some(),
            Self::Ipc => operation == "IPC_ACCESS",
            Self::Mount => matches!(operation, "MOUNT" | "UNMOUNT" | "PIVOT_ROOT" | "MOVE_MOUNT"),
        }
    }
}
impl Validate for ProofQualityPredicateV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            ordered!(
                &self.source_authority,
                &self.local_subject_binding,
                &self.remote_subject_binding,
                &self.operation_result_authority,
                &self.temporal_coverage,
                &self.integrity
            ),
            "CFG_PROOF_ORDER",
            "proof predicates must be sorted and unique"
        );
        Ok(())
    }
}
impl Validate for FindingSpecV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::RegistrySymbol(&self.reason_code).validate()?;
        if let Some(id) = &self.title_template_id {
            PolicyValue::LocalId(id).validate()?;
        }
        require!(ordered_unique(&self.route_ids), "CFG_FINDING", "finding routes must be sorted and unique");
        Ok(())
    }
}
impl Validate for PathTreeDenyFloorV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.rule_id).validate()?;
        canonical_path_components("<validation>", &self.canonical_path).map_err(|error| ValidationIssue { code: "CFG_PATH_TREE_DENY", reason: error.to_string() })?;
        let shape = self.schema_version == 1 && self.recursive && self.requested_disposition == PolicyDispositionV1::Deny && self.exception_ids.is_empty() && self.effect_families == [EffectFamilyV1::File];
        let operations = !self.operation_ids.is_empty() && ordered_unique(&self.operation_ids) && self.operation_ids.iter().all(|operation| EffectFamilyV1::File.accepts(operation));
        require!(shape && operations, "CFG_PATH_TREE_DENY", format!("path-tree rule `{}` is not an exact recursive FILE DENY", self.rule_id));
        Ok(())
    }
}
impl Validate for NotificationRouteV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.route_id).validate()?;
        PolicyValue::LocalId(&self.sink_binding_id).validate()?;
        PolicyValue::Duration(&self.dedupe_window, true).validate()?;
        require!(
            !self.grouping_fields.is_empty()
                && !self.allowed_evidence_fields.is_empty()
                && ordered!(&self.grouping_fields, &self.allowed_evidence_fields),
            "CFG_NOTIFICATION_ROUTE",
            format!("notification route `{}` is invalid", self.route_id)
        );
        Ok(())
    }
}
impl Validate for BlastRadiusLimitV1 {
    fn validate(&self) -> ValidationResult {
        let valid = match self {
            Self::Local { permitted_target_selector_ids: ids, process_count: a, execution_set_count: b, socket_count: c, node_count: d } => bounded!(ids; a, b, c, d),
            Self::Kubernetes { permitted_namespace_uids: ids, object_count: a, controller_count: b, node_count: c } => bounded!(ids; a, b, c),
            Self::Credential { permitted_provider_account_ids: ids, session_count: a, principal_count: b, role_count: c, account_count: d } => bounded!(ids; a, b, c, d),
            Self::Mesh { permitted_tailnet_or_tenant_ids: ids, device_count: a, route_count: b, auth_key_count: c } => bounded!(ids; a, b, c),
            Self::SourceControl { permitted_organization_ids: ids, installation_count: a, repository_count: b, ref_or_pr_count: c } => bounded!(ids; a, b, c),
            Self::Artifact { permitted_store_ids: ids, artifact_count: a, consumer_count: b } => ordered_unique(ids) && *a > 0 && *b > 0,
            Self::ProviderResources { permitted_provider_account_ids: a, permitted_resource_selector_ids: b, resource_count: c, principal_count: d } => ordered_unique(a) && ordered_unique(b) && *c > 0 && *d > 0,
        };
        require!(valid, "CFG_BLAST_RADIUS", "blast radius must be ordered and bounded");
        Ok(())
    }
}
impl Validate for ResponseBindingV1 {
    fn validate(&self) -> ValidationResult {
        use BlastRadiusLimitV1 as Blast;
        use PhysicalPostconditionV1 as Post;
        use ResponseActionSpecV1 as Action;
        use TargetRevalidationV1 as Target;
        PolicyValue::LocalId(&self.binding_id).validate()?;
        self.required_proof.validate()?;
        self.maximum_blast_radius.validate()?;
        PolicyValue::Duration(&self.watch_interval, false).validate()?;
        let contract = (&self.action_spec, self.target_revalidation, self.physical_postcondition, &self.maximum_blast_radius);
        let compatible = matches!(
            contract,
            (Action::RestrictLineage, Target::LineageRootAndCompleteEffectiveResponseSet, Post::ResponseSetInstalledAndDescendantsReconciled, Blast::Local { .. })
                | (Action::FenceSockets, Target::SocketCookieProvenanceAndLiveBinding, Post::SocketSetFencedAndExistingFlowOraclePassed, Blast::Local { .. })
                | (Action::FreezeCgroup, Target::CgroupFdNonceAndMemberSet, Post::CgroupFrozenAndPacketFenceActive, Blast::Local { .. })
                | (Action::TerminateProcessPidfd, Target::ProcessPidfdTaskCookieStarttimeCgroupBinding, Post::ProcessStoppedViaPidfd, Blast::Local { .. })
                | (Action::RejectKubernetesReplacement { .. }, Target::KubernetesUidResourceVersion, Post::ReplacementRejectedThroughWatchWatermark, Blast::Kubernetes { .. })
                | (Action::RevokeCredential { .. }, Target::ProviderStableIdRevisionAndAuthority, Post::ProviderCredentialActionReadBack, Blast::Credential { .. })
                | (Action::DisableMeshDevice { .. }, Target::ProviderStableIdRevisionAndAuthority, Post::MeshDeviceDisabledAndHandshakeRejected, Blast::Mesh { .. })
                | (Action::QuarantineArtifact { .. }, Target::ArtifactImmutableDigestAndStoreRevision, Post::ArtifactQuarantinedAndConsumerLoadRejected, Blast::Artifact { .. })
                | (Action::SuspendInstallation { .. }, Target::ProviderStableIdRevisionAndAuthority, Post::ProviderOperationSpecificPostcondition, Blast::SourceControl { .. })
                | (Action::ProviderSpecific { .. }, Target::ProviderStableIdRevisionAndAuthority, Post::ProviderOperationSpecificPostcondition, Blast::ProviderResources { .. })
        );
        require!(compatible, "CFG_RESPONSE_BINDING", format!("response binding `{}` has an incompatible exact contract", self.binding_id));
        Ok(())
    }
}
impl Validate for EffectFamilyDefaultV1 {
    fn validate(&self) -> ValidationResult {
        let io_uring_denial_only = |operation: &str| matches!(operation, "IO_URING_REGISTER" | "IO_URING_SQPOLL" | "IO_URING_OVERRIDE_CREDS" | "IO_URING_COMMAND");
        let dimensions = !self.role_ids.is_empty() && !self.operations.is_empty() && ordered!(&self.role_ids, &self.operations) && self.operations.iter().all(|operation| self.effect_family.accepts(operation));
        let decision = matches!(self.requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Deny)
            && (self.requested_disposition == PolicyDispositionV1::Deny) == self.errno.is_some()
            && (self.requested_disposition != PolicyDispositionV1::Alert || self.finding.is_some());
        require!(dimensions && decision, "CFG_EFFECT_DEFAULT", "effect-family default is not an exact local decision");
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self
                    .operations
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "CAPABILITY" | "BPF")),
            "CFG_PRIVILEGE_WILDCARD",
            "generic CAPABILITY and BPF defaults are denial-only"
        );
        require!(self.requested_disposition == PolicyDispositionV1::Deny || self.operations.iter().all(|operation| !io_uring_denial_only(operation)), "CFG_IO_URING_UNQUALIFIED_AUTHORITY", "unqualified io_uring defaults are denial-only");
        require!(self.requested_disposition == PolicyDispositionV1::Deny || self.effect_family != EffectFamilyV1::Network, "CFG_NETWORK_DEFAULT_AUTHORITY", "NETWORK defaults are denial-only");
        require!(self.requested_disposition == PolicyDispositionV1::Deny || self.effect_family != EffectFamilyV1::Mount, "CFG_MOUNT_DEFAULT_AUTHORITY", "MOUNT defaults are denial-only");
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self.effect_family != EffectFamilyV1::Exec
                || self
                    .operations
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "EXECUTE" | "MMAP_EXEC" | "MPROTECT")),
            "CFG_EXECUTABLE_MEMORY_AUTHORITY",
            "unqualified executable defaults are denial-only"
        );
        if let Some(finding) = &self.finding {
            finding.validate()?;
        }
        Ok(())
    }
}
impl Validate for DefaultPostureActionV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            self.requested_disposition != PolicyDispositionV1::Allow
                && (self.requested_disposition != PolicyDispositionV1::Alert
                    || self.unknown_restricted_role_id.is_some()),
            "CFG_DEFAULT_POSTURE",
            "an alerting default posture needs a restricted role"
        );
        self.finding.validate()
    }
}
impl Validate for CommonSubjectMatchV1 {
    fn validate(&self) -> ValidationResult {
        let required = self.required_process_state_ids.iter().collect::<BTreeSet<_>>();
        let dimensions = ordered!(&self.workload_selector_ids, &self.protected_scope_ids, &self.execution_set_ids, &self.entry_kind_ids, &self.role_ids);
        let states = ordered!(&self.required_process_state_ids, &self.forbidden_process_state_ids) && self.forbidden_process_state_ids.iter().all(|id| !required.contains(id));
        require!(dimensions && states, "CFG_SUBJECT_REFERENCE", "subject dimensions must be sorted, unique, and disjoint");
        Ok(())
    }
}
impl Validate for RuleMatchV1 {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::LocalPreEffect(effect) => {
                effect.subject.validate()?;
                effect.required_proof.validate()?;
                let complete = !effect.effect_families.is_empty() && !effect.operation_ids.is_empty() && !object_cells(&effect.object).is_empty();
                let ordered = ordered!(&effect.effect_families, &effect.operation_ids, &effect.binding_lifecycle_states);
                let registered = effect.effect_families.iter().all(|family| effect.operation_ids.iter().all(|operation| family.accepts(operation)));
                require!(complete && ordered && registered, "CFG_EMPTY_REQUIRED_SELECTOR", "local selector is empty, unordered, or unsupported");
            }
            Self::NativeTransition(value) => {
                value.subject.validate()?;
                require!(!value.operations.is_empty() && ordered!(&value.operations, &value.executable_object_ids, &value.source_role_ids, &value.target_role_ids), "CFG_NATIVE_TRANSITION_MATCH", "native-transition selector is invalid");
            }
            Self::EntryAdmission(value) => {
                value.subject.validate()?;
                let complete = !value.runtime_operations.is_empty() && !value.root_classifications.is_empty();
                let ordered = ordered!(&value.runtime_operations, &value.root_classifications, &value.source_proof_qualities, &value.required_purpose_source_capability_ids, &value.immutable_definition_digests);
                require!(complete && ordered, "CFG_ENTRY_ADMISSION_MATCH", "entry selector is invalid");
            }
            Self::RemotePreAdmission(value) => {
                value.subject.validate()?;
                value.required_proof.validate()?;
                let complete = !value.gate_capability_ids.is_empty() && !value.providers.is_empty() && !value.operation_ids.is_empty();
                let ordered = ordered!(&value.gate_capability_ids, &value.providers, &value.provider_account_ids, &value.operation_ids, &value.resources, &value.required_lease_permission_ids);
                require!(complete && ordered, "CFG_REMOTE_ADMISSION_MATCH", "remote selector is invalid");
            }
            Self::PostEffect(value) => value.validate()?,
        }
        Ok(())
    }
}
impl Validate for PostEffectMatchV1 {
    fn validate(&self) -> ValidationResult {
        let valid = match self {
            Self::LocalCompletion { subject, effect_families, operation_ids, authoritative_results, required_proof } => {
                subject.validate()?;
                required_proof.validate()?;
                !effect_families.is_empty()
                    && !operation_ids.is_empty()
                    && !authoritative_results.is_empty()
                    && ordered!(effect_families, operation_ids, authoritative_results)
                    && effect_families.iter().all(|family| {
                        operation_ids.iter().all(|operation| family.accepts(operation))
                    })
            }
            Self::ProviderResult { providers, provider_account_ids, operation_ids, resources, authoritative_results, required_proof } => {
                required_proof.validate()?;
                !providers.is_empty() && !operation_ids.is_empty() && !authoritative_results.is_empty() && ordered!(providers, provider_account_ids, operation_ids, resources, authoritative_results)
            }
            Self::CorrelationFinding { package_ids, reason_codes, finding_states, required_proof } => {
                required_proof.validate()?;
                !package_ids.is_empty() && !finding_states.is_empty() && ordered!(package_ids, reason_codes, finding_states)
            }
        };
        require!(valid, "CFG_POST_EFFECT_MATCH", "post-effect selector is invalid");
        Ok(())
    }
}
impl Validate for DetectionDispositionRuleV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.rule_id).validate()?;
        self.rule_match.validate()?;
        let stage = match self.rule_match {
            RuleMatchV1::EntryAdmission(_) => EvaluationStageV1::EntryAdmission,
            RuleMatchV1::LocalPreEffect(_) => EvaluationStageV1::LocalPreEffect,
            RuleMatchV1::NativeTransition(_) => EvaluationStageV1::NativeTransition,
            RuleMatchV1::RemotePreAdmission(_) => EvaluationStageV1::RemotePreAdmission,
            RuleMatchV1::PostEffect(_) => EvaluationStageV1::PostEffect,
        };
        let legal = match self.evaluation_stage {
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(self.requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Reject),
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(self.requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Deny),
            EvaluationStageV1::PostEffect => matches!(self.requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert),
        };
        require!(self.schema_version == 1, "CFG_RULE_SCHEMA", format!("rule `{}` schema_version must be 1", self.rule_id));
        require!(self.evaluation_stage == stage, "CFG_STAGE_MATCH", format!("rule `{}` match kind disagrees with its stage", self.rule_id));
        require!(legal, "CFG_STAGE_DISPOSITION", format!("rule `{}` has an illegal disposition", self.rule_id));
        require!((self.requested_disposition == PolicyDispositionV1::Deny) == self.errno.is_some(), "CFG_ERRNO_PRESENCE", format!("rule `{}` has incorrect errno presence", self.rule_id));
        require!(
            ordered!(&self.response_binding_ids, &self.exception_ids)
                && self.exception_ids.len() <= 1
                && (self.exception_ids.is_empty() || (self.evaluation_stage == EvaluationStageV1::LocalPreEffect && self.requested_disposition == PolicyDispositionV1::Allow))
                && ordered_unique(&self.overrides_rule_ids)
                && self.budgets.rate_limits.is_empty()
                && self.budgets.concurrency_limits.is_empty()
                && self.budgets.maximum_lifetime.is_none()
                && self.budgets.automatic_response_limit.is_none()
                && (self.finding.is_some() || (self.response_binding_ids.is_empty() && self.requested_disposition != PolicyDispositionV1::Alert))
                && match (self.valid_from_utc_ns, self.valid_until_utc_ns) {
                    (Some(from), Some(until)) => until > from,
                    _ => true,
                },
            "CFG_RULE_ACTION",
            format!("rule `{}` has an invalid action plan", self.rule_id)
        );
        if let Some(finding) = &self.finding {
            finding.validate()?;
        }
        let conditions = self.fallback_by_condition.iter().map(|fallback| fallback.condition).collect::<Vec<_>>();
        require!(ordered_unique(&conditions), "CFG_FALLBACK_ORDER", format!("rule `{}` fallbacks are unordered", self.rule_id));
        for fallback in &self.fallback_by_condition {
            fallback.validate_for(self.evaluation_stage)?;
        }
        if let RuleMatchV1::LocalPreEffect(effect) = &self.rule_match {
            self.validate_local_authority(effect)?;
        }
        Ok(())
    }
}
impl DetectionDispositionRuleV1 {
    fn validate_local_authority(&self, effect: &LocalEffectMatchV1) -> ValidationResult {
        let io_uring_denial_only = |operation: &str| matches!(operation, "IO_URING_REGISTER" | "IO_URING_SQPOLL" | "IO_URING_OVERRIDE_CREDS" | "IO_URING_COMMAND");
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || effect
                    .operation_ids
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "CAPABILITY" | "BPF")),
            "CFG_PRIVILEGE_WILDCARD",
            format!("rule `{}` uses generic privilege authority", self.rule_id)
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || effect
                    .operation_ids
                    .iter()
                    .all(|operation| !io_uring_denial_only(operation)),
            "CFG_IO_URING_UNQUALIFIED_AUTHORITY",
            format!("rule `{}` uses unqualified io_uring authority", self.rule_id)
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || !effect.effect_families.contains(&EffectFamilyV1::Exec)
                || effect
                    .operation_ids
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "MMAP_EXEC" | "MPROTECT"))
                || matches!(effect.object, LocalObjectSelectorV1::ExactObjectKeys { .. }),
            "CFG_EXECUTABLE_MEMORY_AUTHORITY",
            format!("rule `{}` must use exact executable-memory objects", self.rule_id)
        );
        match &effect.object {
            LocalObjectSelectorV1::ExactObjectKeys { exact_object_key_ids } => require!(
                ordered_unique(exact_object_key_ids)
                    && exact_object_key_ids.iter().all(|id| *id > 0),
                "CFG_EXACT_OBJECT_SELECTOR",
                format!("rule `{}` has invalid exact object IDs", self.rule_id)
            ),
            LocalObjectSelectorV1::Devices { ioctl_command_ids, .. } => require!(
                self.requested_disposition == PolicyDispositionV1::Deny
                    || !ioctl_command_ids.is_empty(),
                "CFG_DEVICE_IOCTL_WILDCARD",
                format!("rule `{}` must name ioctl commands", self.rule_id)
            ),
            LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                target_selector_ids,
            } if security_object_ids.iter().any(|object| object == "PROCESS") => require!(
                security_object_ids.as_slice() == ["PROCESS"]
                    && target_selector_ids.len() == 1
                    && effect.effect_families.as_slice() == [EffectFamilyV1::Privilege]
                    && effect.operation_ids.iter().all(|operation| {
                        process_control_operation(operation).is_some_and(|(_, _, wildcard)| {
                            !wildcard || self.requested_disposition == PolicyDispositionV1::Deny
                        })
                    }),
                "CFG_PROCESS_CONTROL_KEY",
                format!("rule `{}` has an invalid process-control key", self.rule_id)
            ),
            _ => {}
        }
        Ok(())
    }
}
impl FallbackV1 {
    fn validate_for(&self, stage: EvaluationStageV1) -> ValidationResult {
        let legal = match stage {
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(self.requested_disposition, PolicyDispositionV1::Alert | PolicyDispositionV1::Reject),
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(self.requested_disposition, PolicyDispositionV1::Alert | PolicyDispositionV1::Deny),
            EvaluationStageV1::PostEffect => self.requested_disposition == PolicyDispositionV1::Alert,
        };
        require!(
            legal
                && (self.requested_disposition == PolicyDispositionV1::Deny)
                    == self.errno.is_some()
                && (self.requested_disposition != PolicyDispositionV1::Alert
                    || self.unknown_restricted_role_id.is_some()),
            "CFG_FALLBACK_STAGE",
            "rule has an unsafe fallback"
        );
        self.finding.validate()
    }
}
impl Validate for ExceptionV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.exception_id).validate()?;
        PolicyValue::Uuid(&self.exception_instance_id).validate()?;
        PolicyValue::Uuid(&self.approver_principal_id).validate()?;
        PolicyValue::Digest(&self.approval_proof_digest).validate()?;
        PolicyValue::RegistrySymbol(&self.closed_reason_code).validate()?;
        let digests = self
            .exact_subject
            .immutable_definition_digests
            .iter()
            .chain(&self.exact_subject.exact_compiled_key_digests)
            .chain(&self.authority_delta.added_or_removed_operation_cells)
            .chain(&self.authority_delta.added_or_removed_transition_cells);
        for digest in digests {
            PolicyValue::Digest(digest).validate()?;
        }
        self.authority_delta.maximum_blast_radius.validate()?;
        let subject = &self.exact_subject;
        let delta = &self.authority_delta;
        let bounded = self.valid_until_utc_ns > self.valid_from_utc_ns
            && self.maximum_uses > 0
            && self.maximum_lifetime_ns > 0
            && !self.changed_rule_ids.is_empty()
            && ordered_unique(&self.changed_rule_ids);
        let exact_subject = !subject.protected_scope_ids.is_empty()
            && !subject.execution_set_ids.is_empty()
            && !subject.entry_kind_ids.is_empty()
            && !subject.role_ids.is_empty()
            && !subject.exact_compiled_key_digests.is_empty()
            && ordered!(
                &subject.protected_scope_ids,
                &subject.execution_set_ids,
                &subject.entry_kind_ids,
                &subject.role_ids,
                &subject.immutable_definition_digests,
                &subject.exact_compiled_key_digests
            );
        let exact_delta = delta.from_physical_result == "DENY_ERRNO" && delta.to_physical_result == "ALLOW_EFFECT" && ordered!(&delta.added_or_removed_operation_cells, &delta.added_or_removed_transition_cells);
        require!(bounded && exact_subject && exact_delta, "CFG_EXCEPTION", format!("exception `{}` is not a bounded exact authority delta", self.exception_id));
        Ok(())
    }
}
impl Validate for AuthorityBehaviorRuleV1 {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::RemoteAdmission {
                rule_id,
                authorization_interface_capability_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                ..
            } => authority_rule!(
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                PolicyValue::LocalId(authorization_interface_capability_id)
                    .validate()
                    .is_ok()
                    && matches!(requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Reject)
            ),
            Self::PostEffectResult {
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                authoritative_results,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                ..
            } => authority_rule!(
                rule_id,
                provider_accounts,
                principal_or_lease_selectors,
                operations,
                resources,
                required_proof,
                requested_disposition,
                finding,
                response_binding_ids,
                budgets,
                !authoritative_results.is_empty()
                    && ordered_unique(authoritative_results)
                    && matches!(requested_disposition, PolicyDispositionV1::Allow | PolicyDispositionV1::Alert)
            ),
        }
    }
}
impl Validate for SourceCoverageHealthRuleV1 {
    fn validate(&self) -> ValidationResult {
        PolicyValue::LocalId(&self.health_rule_id).validate()?;
        PolicyValue::LocalId(&self.required_source_id).validate()?;
        if let Some(id) = &self.independent_admission_interface_binding_id {
            PolicyValue::LocalId(id).validate()?;
        }
        if let Some(id) = &self.independent_admission_capability_id {
            PolicyValue::LocalId(id).validate()?;
        }
        PolicyValue::Duration(&self.maximum_gap, false).validate()?;
        let independent = match self.on_gap {
            CoverageGapActionV1::Alert => self.independent_admission_interface_binding_id.is_none() && self.independent_admission_capability_id.is_none() && self.independent_response_binding_ids.is_empty(),
            CoverageGapActionV1::RejectNewAdmission => self.independent_admission_interface_binding_id.is_some() && self.independent_admission_capability_id.is_some(),
            CoverageGapActionV1::InstallIndependentFence => !self.independent_response_binding_ids.is_empty(),
        };
        require!(
            !self.protected_scope_ids.is_empty()
                && ordered!(&self.protected_scope_ids, &self.independent_response_binding_ids)
                && independent,
            "CFG_COVERAGE_RULE",
            format!("coverage rule `{}` lacks an independent fallback", self.health_rule_id)
        );
        self.finding.validate()
    }
}
impl Validate for RolloutV1 {
    fn validate(&self) -> ValidationResult {
        require!(ordered_unique(&self.selected_bucket_ids), "CFG_ROLLOUT_ORDER", "selected buckets must be sorted and unique");
        require!(self.selector_hash_modulus > 0 && self.selected_bucket_ids.iter().all(|bucket| *bucket < self.selector_hash_modulus), "CFG_ROLLOUT_BUCKET", "rollout buckets must be below a nonzero modulus");
        Ok(())
    }
}
impl Validate for PolicyDocumentV1 {
    fn validate(&self) -> ValidationResult {
        require!(self.api_version == "mithril.erebor.dev/v1" && self.kind == "ProtectionPolicy", "CFG_SCHEMA_VERSION", "api_version and kind must be the Version 1 values");
        require!(self.metadata.profile_version > 0 && self.rollout.rollout_generation > 0, "CFG_ZERO_GENERATION", "profile and rollout generations must be nonzero");
        require!(self.exceptions.len() <= MAX_EXCEPTION_STATES, "CFG_MAP_CAPACITY", "exception states exceed kernel map capacity");
        require!(self.exceptions.is_empty() || self.rollout.desired_profile_mode == ProfileModeV1::Protect, "CFG_EXCEPTION_MODE", "exceptions require PROTECT mode");
        require!(self.path_tree_deny_floors.is_empty() || self.rollout.desired_profile_mode == ProfileModeV1::Protect, "CFG_PATH_TREE_DENY", "path-tree denial requires PROTECT mode");
        self.metadata.validate()?;
        self.protected_universe.validate()?;
        self.rollout.validate()?;
        for id in &self.required_capability_ids {
            PolicyValue::RegistrySymbol(id).validate()?;
        }
        validate_each!(self;
            workload_selectors, classifier_bindings, roles, entry_role_assignments,
            native_transition_rules, state_bit_definitions, process_state_definitions,
            ipc_relationship_rules, effect_family_defaults, path_tree_deny_floors,
            notification_routes, response_bindings, exceptions, rules,
            authority_behavior_rules, source_coverage_health_rules
        );
        for posture in [&self.default_postures.missing_task_identity, &self.default_postures.required_classifier_unknown, &self.default_postures.unresolved_or_external_root] {
            posture.validate()?;
        }
        self.validate_relationships()?;
        self.validate_role_reachability()
    }
}
impl PolicyDocumentV1 {
    fn validate_relationships(&self) -> ValidationResult {
        let roles = self.roles.iter().map(|value| value.role_id.as_str()).collect::<BTreeSet<_>>();
        let selectors = self.workload_selectors.iter().map(|value| value.workload_selector_id.as_str()).collect::<BTreeSet<_>>();
        let states = self.process_state_definitions.iter().map(|value| value.process_state_id.as_str()).collect::<BTreeSet<_>>();
        let routes = self.notification_routes.iter().map(|value| value.route_id.as_str()).collect::<BTreeSet<_>>();
        let responses = self.response_bindings.iter().map(|value| value.binding_id.as_str()).collect::<BTreeSet<_>>();
        let exceptions = self.exceptions.iter().map(|value| value.exception_id.as_str()).collect::<BTreeSet<_>>();
        let ipc_ids = self.ipc_relationship_rules.iter().map(|value| value.relationship_rule_id.as_str()).collect::<BTreeSet<_>>();
        let authority_ids = self
            .authority_behavior_rules
            .iter()
            .map(|value| match value {
                AuthorityBehaviorRuleV1::RemoteAdmission { rule_id, .. } | AuthorityBehaviorRuleV1::PostEffectResult { rule_id, .. } => rule_id.as_str(),
            })
            .collect::<BTreeSet<_>>();
        let coverage_ids = self.source_coverage_health_rules.iter().map(|value| value.health_rule_id.as_str()).collect::<BTreeSet<_>>();
        let scopes = string_set!(&self.protected_universe.protected_scope_ids);
        let execution_sets = string_set!(&self.protected_universe.execution_set_ids);
        let object_classes = string_set!(&self.protected_universe.object_class_ids);
        let rule_ids = self.rules.iter().map(|value| value.rule_id.as_str()).chain(self.path_tree_deny_floors.iter().map(|value| value.rule_id.as_str())).collect::<BTreeSet<_>>();
        require!(roles == string_set!(&self.protected_universe.role_ids), "CFG_ROLE_REGISTRY", "role registry must equal defined roles");
        require!(selectors == string_set!(&self.protected_universe.workload_selector_ids), "CFG_SELECTOR_REGISTRY", "selector registry must equal defined selectors");
        let unique_ids = roles.len() == self.roles.len()
            && routes.len() == self.notification_routes.len()
            && responses.len() == self.response_bindings.len()
            && exceptions.len() == self.exceptions.len()
            && ipc_ids.len() == self.ipc_relationship_rules.len()
            && authority_ids.len() == self.authority_behavior_rules.len()
            && coverage_ids.len() == self.source_coverage_health_rules.len()
            && rule_ids.len() == self.rules.len() + self.path_tree_deny_floors.len();
        require!(unique_ids, "CFG_DUPLICATE_ID", "policy IDs must be unique by kind");
        for role in &self.roles {
            require!(states.contains(role.default_process_state_id.as_str()), "CFG_STATE_REFERENCE", format!("role `{}` references a missing state", role.role_id));
        }
        for entry in &self.entry_role_assignments {
            require!(roles.contains(entry.resulting_role_id.as_str()) && all_in!(&entry.workload_selector_ids, selectors), "CFG_ROLE_REFERENCE", format!("entry `{}` has an unknown role or selector", entry.assignment_id));
            let permitted = self
                .roles
                .iter()
                .find(|role| role.role_id == entry.resulting_role_id)
                .is_some_and(|role| {
                    entry
                        .entry_kinds
                        .iter()
                        .all(|kind| role.permitted_entry_kinds.contains(kind))
                });
            require!(permitted, "CFG_ENTRY_ASSIGNMENT", format!("entry `{}` uses an entry kind forbidden by its role", entry.assignment_id));
        }
        let process_bits = self.state_bit_definitions.iter().filter(|bit| bit.scope == StateBitScopeV1::Process).map(|bit| bit.bit_index).collect::<BTreeSet<_>>();
        let mut bit_keys = BTreeSet::new();
        let mut semantics = BTreeSet::new();
        for bit in &self.state_bit_definitions {
            require!(bit_keys.insert((bit.scope, bit.bit_index)) && semantics.insert((bit.scope, bit.semantic_id.as_str())), "CFG_DUPLICATE_STATE_BIT", "state bit indices and semantics must be unique per scope");
        }
        for state in &self.process_state_definitions {
            require!(state.state_bits.iter().all(|bit| process_bits.contains(bit)), "CFG_STATE_REFERENCE", format!("state `{}` references an undefined process bit", state.process_state_id));
        }
        let mut ipc = BTreeMap::new();
        for relation in &self.ipc_relationship_rules {
            require!(relation.source_role_ids.iter().chain(&relation.peer_role_ids).all(|id| roles.contains(id.as_str())), "CFG_IPC_RELATIONSHIP", format!("IPC relationship `{}` references an unknown role", relation.relationship_rule_id));
            for source in &relation.source_role_ids {
                for peer in &relation.peer_role_ids {
                    let pair = if source <= peer { (source.as_str(), peer.as_str()) } else { (peer.as_str(), source.as_str()) };
                    let decision = (relation.requested_disposition, relation.errno);
                    require!(ipc.insert(pair, decision).is_none_or(|old| old == decision), "CFG_IPC_RELATIONSHIP_CONFLICT", format!("IPC relationship `{}` conflicts", relation.relationship_rule_id));
                }
            }
        }
        require!(self.unmatched_ipc_disposition != PolicyDispositionV1::Reject, "CFG_IPC_UNMATCHED", "unmatched IPC cannot REJECT at a local hook");
        for default in &self.effect_family_defaults {
            require!(all_in!(&default.role_ids, roles), "CFG_ROLE_REFERENCE", "effect default references an unknown role");
            if let Some(finding) = &default.finding {
                require!(all_in!(&finding.route_ids, routes), "CFG_FINDING", "finding references an unknown route");
            }
        }
        for posture in [&self.default_postures.missing_task_identity, &self.default_postures.required_classifier_unknown, &self.default_postures.unresolved_or_external_root] {
            require!(posture.unknown_restricted_role_id.as_ref().is_none_or(|id| roles.contains(id.as_str())) && all_in!(&posture.finding.route_ids, routes), "CFG_DEFAULT_POSTURE", "default posture references an unknown role or route");
        }
        for rule in &self.rules {
            require!(rule.overrides_rule_ids.iter().all(|id| id != &rule.rule_id && rule_ids.contains(id.as_str())), "CFG_OVERRIDE_REFERENCE", format!("rule `{}` has an invalid override", rule.rule_id));
            let known_actions = all_in!(&rule.response_binding_ids, responses) && all_in!(&rule.exception_ids, exceptions);
            let known_finding = rule.finding.as_ref().is_none_or(|finding| all_in!(&finding.route_ids, routes));
            let known_fallbacks = rule.fallback_by_condition.iter().all(|fallback| {
                all_in!(&fallback.finding.route_ids, routes)
                    && fallback
                        .unknown_restricted_role_id
                        .as_ref()
                        .is_none_or(|id| roles.contains(id.as_str()))
            });
            require!(known_actions && known_finding && known_fallbacks, "CFG_RULE_ACTION", format!("rule `{}` references an unknown action", rule.rule_id));
            let subject = match &rule.rule_match {
                RuleMatchV1::EntryAdmission(value) => Some(&value.subject),
                RuleMatchV1::LocalPreEffect(value) => Some(&value.subject),
                RuleMatchV1::NativeTransition(value) => Some(&value.subject),
                RuleMatchV1::RemotePreAdmission(value) => Some(&value.subject),
                RuleMatchV1::PostEffect(PostEffectMatchV1::LocalCompletion { subject, .. }) => Some(subject),
                RuleMatchV1::PostEffect(_) => None,
            };
            if let Some(subject) = subject {
                let known_dimensions = all_in!(&subject.workload_selector_ids, selectors)
                    && all_in!(&subject.protected_scope_ids, scopes)
                    && all_in!(&subject.execution_set_ids, execution_sets)
                    && subject
                        .entry_kind_ids
                        .iter()
                        .all(|id| self.protected_universe.entry_kind_ids.contains(id))
                    && all_in!(&subject.role_ids, roles);
                let known_states = subject.required_process_state_ids.iter().chain(&subject.forbidden_process_state_ids).all(|id| states.contains(id.as_str()));
                require!(known_dimensions && known_states, "CFG_SUBJECT_REFERENCE", format!("rule `{}` subject references values outside its policy", rule.rule_id));
            }
            if let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match {
                if let LocalObjectSelectorV1::ObjectClasses { object_class_ids } = &effect.object {
                    require!(ordered_unique(object_class_ids) && object_class_ids.iter().all(|id| object_classes.contains(id.as_str())), "CFG_OBJECT_CLASS_REFERENCE", format!("rule `{}` has unknown object classes", rule.rule_id));
                }
                if let LocalObjectSelectorV1::SecurityObjects { security_object_ids, target_selector_ids } = &effect.object {
                    if security_object_ids.iter().any(|id| id == "PROCESS") {
                        require!(roles.contains(target_selector_ids[0].as_str()), "CFG_PROCESS_CONTROL_KEY", format!("rule `{}` has an unknown target role", rule.rule_id));
                    }
                }
            }
            if let RuleMatchV1::NativeTransition(value) = &rule.rule_match {
                require!(value.source_role_ids.iter().chain(&value.target_role_ids).all(|id| roles.contains(id.as_str())), "CFG_NATIVE_TRANSITION_MATCH", format!("rule `{}` has an unknown transition role", rule.rule_id));
            }
        }
        let base_rule_ids = self.rules.iter().map(|rule| rule.rule_id.as_str()).collect::<BTreeSet<_>>();
        for exception in &self.exceptions {
            let subject = &exception.exact_subject;
            let known_rules = all_in!(&exception.changed_rule_ids, base_rule_ids);
            let known_subject = all_in!(&subject.protected_scope_ids, scopes) && all_in!(&subject.execution_set_ids, execution_sets) && all_in!(&subject.role_ids, roles);
            require!(known_rules && known_subject, "CFG_EXCEPTION", format!("exception `{}` references values outside its policy", exception.exception_id));
        }
        for rule in &self.authority_behavior_rules {
            let (responses_used, finding) = match rule {
                AuthorityBehaviorRuleV1::RemoteAdmission { response_binding_ids, finding, .. } | AuthorityBehaviorRuleV1::PostEffectResult { response_binding_ids, finding, .. } => (response_binding_ids, finding),
            };
            require!(all_in!(responses_used, responses) && finding.as_ref().is_none_or(|value| all_in!(&value.route_ids, routes)), "CFG_AUTHORITY_RULE", "authority rule references an unknown route or response");
        }
        for rule in &self.source_coverage_health_rules {
            require!(
                all_in!(&rule.protected_scope_ids, scopes)
                    && all_in!(&rule.independent_response_binding_ids, responses)
                    && all_in!(&rule.finding.route_ids, routes),
                "CFG_COVERAGE_RULE",
                format!("coverage rule `{}` references values outside its policy", rule.health_rule_id)
            );
        }
        Ok(())
    }
    fn validate_role_reachability(&self) -> ValidationResult {
        let mut reachable = self.entry_role_assignments.iter().map(|entry| entry.resulting_role_id.as_str()).collect::<BTreeSet<_>>();
        let mut pending = VecDeque::from_iter(&self.native_transition_rules);
        let mut progress = true;
        while progress {
            progress = false;
            pending.retain(|transition| {
                if transition.source_role_ids.iter().any(|role| reachable.contains(role.as_str())) {
                    progress |= reachable.insert(&transition.resulting_role_id);
                    false
                } else {
                    true
                }
            });
        }
        let missing = self.roles.iter().filter(|role| !reachable.contains(role.role_id.as_str())).map(|role| role.role_id.clone()).collect::<Vec<_>>();
        require!(missing.is_empty(), "CFG_UNREACHABLE_ROLE", format!("unreachable roles: {missing:?}"));
        Ok(())
    }
    pub(super) fn validate_compiled_exceptions(&self, cells: &[CompiledDecisionCellV1]) -> Result<()> {
        for exception in &self.exceptions {
            let bound = cells.iter().filter(|cell| cell.consuming_exception_id.as_deref() == Some(&exception.exception_id)).collect::<Vec<_>>();
            let subject = &exception.exact_subject;
            let digests = bound.iter().map(|cell| compiled_key_digest(self.profile_id(), &cell.key)).collect::<Result<BTreeSet<_>>>()?;
            let scopes = bound.iter().map(|cell| cell.key.protected_scope_id.as_str()).collect::<BTreeSet<_>>();
            let sets = bound.iter().map(|cell| cell.key.execution_set_id.as_str()).collect::<BTreeSet<_>>();
            let kinds = bound.iter().map(|cell| cell.key.entry_kind).collect::<BTreeSet<_>>();
            let roles = bound.iter().map(|cell| cell.key.role_id.as_str()).collect::<BTreeSet<_>>();
            let rules = bound.iter().flat_map(|cell| cell.source_rule_ids.iter().map(String::as_str)).collect::<BTreeSet<_>>();
            let cell = bound.len() == 1 && matches!(bound[0].key.operation_id.as_str(), "OPEN_READ" | "OPEN_WRITE") && bound[0].physical_result == CompiledPhysicalResultV1::AllowEffect;
            let dimensions = scopes
                == subject.protected_scope_ids.iter().map(String::as_str).collect()
                && sets == subject.execution_set_ids.iter().map(String::as_str).collect()
                && kinds == subject.entry_kind_ids.iter().copied().collect()
                && roles == subject.role_ids.iter().map(String::as_str).collect();
            let authority = digests
                == subject.exact_compiled_key_digests.iter().cloned().collect()
                && digests
                    == exception
                        .authority_delta
                        .added_or_removed_operation_cells
                        .iter()
                        .cloned()
                        .collect()
                && exception
                    .authority_delta
                    .added_or_removed_transition_cells
                    .is_empty()
                && rules == exception.changed_rule_ids.iter().map(String::as_str).collect();
            let valid = cell && dimensions && authority;
            if !valid {
                return PolicyValidationSnafu { policy_id: self.profile_id(), code: "CFG_EXCEPTION_CELL", reason: format!("exception `{}` does not bind one qualified file-open allow cell", exception.exception_id) }.fail();
            }
        }
        Ok(())
    }
}
