use std::collections::BTreeSet;

use super::super::compiler::CompiledOperationV1;
use super::super::source::*;
use super::value::PolicyValue;
use super::{Validate, ValidationResult};

// Effect rules validate match shape, local authority, and fallback behavior.

impl Validate for EffectFamilyDefaultV1 {
    fn validate(&self) -> ValidationResult {
        let io_uring_denial_only = |operation: &str| {
            matches!(
                operation,
                "IO_URING_REGISTER"
                    | "IO_URING_SQPOLL"
                    | "IO_URING_OVERRIDE_CREDS"
                    | "IO_URING_COMMAND"
            )
        };
        let dimensions = !self.role_ids.is_empty()
            && !self.operations.is_empty()
            && ordered!(&self.role_ids, &self.operations)
            && self
                .operations
                .iter()
                .all(|operation| self.effect_family.accepts(operation));
        let decision = matches!(
            self.requested_disposition,
            PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Deny
        ) && (self.requested_disposition == PolicyDispositionV1::Deny)
            == self.errno.is_some()
            && (self.requested_disposition != PolicyDispositionV1::Alert || self.finding.is_some());
        require!(
            dimensions && decision,
            "CFG_EFFECT_DEFAULT",
            "effect-family default is not an exact local decision"
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self
                    .operations
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "CAPABILITY" | "BPF")),
            "CFG_PRIVILEGE_WILDCARD",
            "generic CAPABILITY and BPF defaults are denial-only"
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self
                    .operations
                    .iter()
                    .all(|operation| !io_uring_denial_only(operation)),
            "CFG_IO_URING_UNQUALIFIED_AUTHORITY",
            "unqualified io_uring defaults are denial-only"
        );
        let positive_network_control = self.operations.iter().all(|operation| {
            matches!(
                operation.as_str(),
                "SOCKET_CREATE" | "LISTEN" | "ACCEPT" | "SHUTDOWN" | "SETSOCKOPT"
            )
        });
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self.effect_family != EffectFamilyV1::Network
                || positive_network_control,
            "CFG_NETWORK_DEFAULT_AUTHORITY",
            "positive NETWORK defaults are limited to socket controls"
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self.effect_family != EffectFamilyV1::Mount,
            "CFG_MOUNT_DEFAULT_AUTHORITY",
            "MOUNT defaults are denial-only"
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || self.effect_family != EffectFamilyV1::Exec
                || self.operations.iter().all(|operation| !matches!(
                    operation.as_str(),
                    "EXECUTE" | "MMAP_EXEC" | "MPROTECT"
                )),
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
        let required = self
            .required_process_state_ids
            .iter()
            .collect::<BTreeSet<_>>();
        let dimensions = ordered!(
            &self.workload_selector_ids,
            &self.protected_scope_ids,
            &self.execution_set_ids,
            &self.entry_kind_ids,
            &self.role_ids
        );
        let states = ordered!(
            &self.required_process_state_ids,
            &self.forbidden_process_state_ids
        ) && self
            .forbidden_process_state_ids
            .iter()
            .all(|id| !required.contains(id));
        require!(
            dimensions && states,
            "CFG_SUBJECT_REFERENCE",
            "subject dimensions must be sorted, unique, and disjoint"
        );
        Ok(())
    }
}

impl Validate for RuleMatchV1 {
    fn validate(&self) -> ValidationResult {
        match self {
            Self::LocalPreEffect(effect) => {
                effect.subject.validate()?;
                effect.required_proof.validate()?;
                let complete = !effect.effect_families.is_empty()
                    && !effect.operation_ids.is_empty()
                    && !Vec::<String>::from(&effect.object).is_empty();
                let ordered = ordered!(
                    &effect.effect_families,
                    &effect.operation_ids,
                    &effect.binding_lifecycle_states
                );
                let registered = effect.effect_families.iter().all(|family| {
                    effect
                        .operation_ids
                        .iter()
                        .all(|operation| family.accepts(operation))
                });
                require!(
                    complete && ordered && registered,
                    "CFG_EMPTY_REQUIRED_SELECTOR",
                    "local selector is empty, unordered, or unsupported"
                );
            }
            Self::NativeTransition(value) => {
                value.subject.validate()?;
                require!(
                    !value.operations.is_empty()
                        && ordered!(
                            &value.operations,
                            &value.executable_path_selector_ids,
                            &value.source_role_ids,
                            &value.target_role_ids
                        ),
                    "CFG_NATIVE_TRANSITION_MATCH",
                    "native-transition selector is invalid"
                );
            }
            Self::EntryAdmission(value) => {
                value.subject.validate()?;
                let complete =
                    !value.runtime_operations.is_empty() && !value.root_classifications.is_empty();
                let ordered = ordered!(
                    &value.runtime_operations,
                    &value.root_classifications,
                    &value.source_proof_qualities,
                    &value.required_purpose_source_capability_ids,
                    &value.immutable_definition_digests
                );
                require!(
                    complete && ordered,
                    "CFG_ENTRY_ADMISSION_MATCH",
                    "entry selector is invalid"
                );
            }
            Self::RemotePreAdmission(value) => {
                value.subject.validate()?;
                value.required_proof.validate()?;
                let complete = !value.gate_capability_ids.is_empty()
                    && !value.providers.is_empty()
                    && !value.operation_ids.is_empty();
                let ordered = ordered!(
                    &value.gate_capability_ids,
                    &value.providers,
                    &value.provider_account_ids,
                    &value.operation_ids,
                    &value.resources,
                    &value.required_lease_permission_ids
                );
                require!(
                    complete && ordered,
                    "CFG_REMOTE_ADMISSION_MATCH",
                    "remote selector is invalid"
                );
            }
            Self::PostEffect(value) => value.validate()?,
        }
        Ok(())
    }
}

impl Validate for PostEffectMatchV1 {
    fn validate(&self) -> ValidationResult {
        let valid = match self {
            Self::LocalCompletion {
                subject,
                effect_families,
                operation_ids,
                authoritative_results,
                required_proof,
            } => {
                subject.validate()?;
                required_proof.validate()?;
                !effect_families.is_empty()
                    && !operation_ids.is_empty()
                    && !authoritative_results.is_empty()
                    && ordered!(effect_families, operation_ids, authoritative_results)
                    && effect_families.iter().all(|family| {
                        operation_ids
                            .iter()
                            .all(|operation| family.accepts(operation))
                    })
            }
            Self::ProviderResult {
                providers,
                provider_account_ids,
                operation_ids,
                resources,
                authoritative_results,
                required_proof,
            } => {
                required_proof.validate()?;
                !providers.is_empty()
                    && !operation_ids.is_empty()
                    && !authoritative_results.is_empty()
                    && ordered!(
                        providers,
                        provider_account_ids,
                        operation_ids,
                        resources,
                        authoritative_results
                    )
            }
            Self::CorrelationFinding {
                package_ids,
                reason_codes,
                finding_states,
                required_proof,
            } => {
                required_proof.validate()?;
                !package_ids.is_empty()
                    && !finding_states.is_empty()
                    && ordered!(package_ids, reason_codes, finding_states)
            }
        };
        require!(
            valid,
            "CFG_POST_EFFECT_MATCH",
            "post-effect selector is invalid"
        );
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
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(
                self.requested_disposition,
                PolicyDispositionV1::Allow
                    | PolicyDispositionV1::Alert
                    | PolicyDispositionV1::Reject
            ),
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(
                self.requested_disposition,
                PolicyDispositionV1::Allow | PolicyDispositionV1::Alert | PolicyDispositionV1::Deny
            ),
            EvaluationStageV1::PostEffect => matches!(
                self.requested_disposition,
                PolicyDispositionV1::Allow | PolicyDispositionV1::Alert
            ),
        };
        require!(
            self.schema_version == 1,
            "CFG_RULE_SCHEMA",
            format!("rule `{}` schema_version must be 1", self.rule_id)
        );
        require!(
            self.evaluation_stage == stage,
            "CFG_STAGE_MATCH",
            format!(
                "rule `{}` match kind disagrees with its stage",
                self.rule_id
            )
        );
        require!(
            legal,
            "CFG_STAGE_DISPOSITION",
            format!("rule `{}` has an illegal disposition", self.rule_id)
        );
        require!(
            (self.requested_disposition == PolicyDispositionV1::Deny) == self.errno.is_some(),
            "CFG_ERRNO_PRESENCE",
            format!("rule `{}` has incorrect errno presence", self.rule_id)
        );
        require!(
            ordered!(&self.response_binding_ids, &self.exception_ids)
                && self.exception_ids.len() <= 1
                && (self.exception_ids.is_empty()
                    || (self.evaluation_stage == EvaluationStageV1::LocalPreEffect
                        && self.requested_disposition == PolicyDispositionV1::Allow))
                && ordered_unique(&self.overrides_rule_ids)
                && self.budgets.rate_limits.is_empty()
                && self.budgets.concurrency_limits.is_empty()
                && self.budgets.maximum_lifetime.is_none()
                && self.budgets.automatic_response_limit.is_none()
                && (self.finding.is_some()
                    || (self.response_binding_ids.is_empty()
                        && self.requested_disposition != PolicyDispositionV1::Alert))
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
        let conditions = self
            .fallback_by_condition
            .iter()
            .map(|fallback| fallback.condition)
            .collect::<Vec<_>>();
        require!(
            ordered_unique(&conditions),
            "CFG_FALLBACK_ORDER",
            format!("rule `{}` fallbacks are unordered", self.rule_id)
        );
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
        let io_uring_denial_only = |operation: &str| {
            matches!(
                operation,
                "IO_URING_REGISTER"
                    | "IO_URING_SQPOLL"
                    | "IO_URING_OVERRIDE_CREDS"
                    | "IO_URING_COMMAND"
            )
        };
        let exact_linux_capability = matches!(
            &effect.object,
            LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                target_selector_ids,
            } if security_object_ids.as_slice() == ["LINUX_CAPABILITY"]
                && !target_selector_ids.is_empty()
                && ordered_unique(target_selector_ids)
                && target_selector_ids.iter().all(|target| {
                    target.parse::<u32>().is_ok_and(|capability| capability <= 40)
                })
                && effect.effect_families.as_slice() == [EffectFamilyV1::Privilege]
                && effect.operation_ids.as_slice() == ["CAPABILITY"]
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || effect
                    .operation_ids
                    .iter()
                    .all(|operation| match operation.as_str() {
                        "CAPABILITY" => exact_linux_capability,
                        "BPF" => false,
                        _ => true,
                    }),
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
            format!(
                "rule `{}` uses unqualified io_uring authority",
                self.rule_id
            )
        );
        require!(
            self.requested_disposition == PolicyDispositionV1::Deny
                || !effect.effect_families.contains(&EffectFamilyV1::Exec)
                || effect
                    .operation_ids
                    .iter()
                    .all(|operation| !matches!(operation.as_str(), "MMAP_EXEC" | "MPROTECT"))
                || matches!(effect.object, LocalObjectSelectorV1::PathSelectors { .. }),
            "CFG_EXECUTABLE_MEMORY_AUTHORITY",
            format!(
                "rule `{}` must use exact executable-memory objects",
                self.rule_id
            )
        );
        match &effect.object {
            LocalObjectSelectorV1::PathSelectors { path_selector_ids } => require!(
                ordered_unique(path_selector_ids),
                "CFG_PATH_SELECTOR",
                format!("rule `{}` has invalid path selector IDs", self.rule_id)
            ),
            LocalObjectSelectorV1::Devices {
                ioctl_command_ids, ..
            } => require!(
                self.requested_disposition == PolicyDispositionV1::Deny
                    || !ioctl_command_ids.is_empty(),
                "CFG_DEVICE_IOCTL_WILDCARD",
                format!("rule `{}` must name ioctl commands", self.rule_id)
            ),
            LocalObjectSelectorV1::Destinations { .. } => require!(
                effect.effect_families.as_slice() == [EffectFamilyV1::Network]
                    && effect.operation_ids.iter().all(|operation| matches!(
                        operation.as_str(),
                        "BIND" | "ACCEPT" | "CONNECT" | "SEND" | "RECEIVE"
                    )),
                "CFG_NETWORK_DESTINATION_AUTHORITY",
                format!(
                    "rule `{}` must use destination-aware network operations",
                    self.rule_id
                )
            ),
            LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                target_selector_ids,
            } if security_object_ids.iter().any(|object| object == "PROCESS") => require!(
                security_object_ids.as_slice() == ["PROCESS"]
                    && target_selector_ids.len() == 1
                    && effect.effect_families.as_slice() == [EffectFamilyV1::Privilege]
                    && effect.operation_ids.iter().all(|operation| {
                        CompiledOperationV1::try_from(operation.as_str())
                            .ok()
                            .and_then(CompiledOperationV1::process_control)
                            .is_some_and(|operation| {
                                !operation.argument_wildcard
                                    || self.requested_disposition == PolicyDispositionV1::Deny
                            })
                    }),
                "CFG_PROCESS_CONTROL_KEY",
                format!("rule `{}` has an invalid process-control key", self.rule_id)
            ),
            LocalObjectSelectorV1::SecurityObjects {
                security_object_ids,
                ..
            } if security_object_ids
                .iter()
                .any(|object| object == "LINUX_CAPABILITY") =>
            {
                require!(
                    exact_linux_capability,
                    "CFG_LINUX_CAPABILITY_KEY",
                    format!(
                        "rule `{}` has an invalid Linux capability key",
                        self.rule_id
                    )
                )
            }
            _ => {}
        }
        Ok(())
    }
}

impl FallbackV1 {
    fn validate_for(&self, stage: EvaluationStageV1) -> ValidationResult {
        let legal = match stage {
            EvaluationStageV1::EntryAdmission | EvaluationStageV1::RemotePreAdmission => matches!(
                self.requested_disposition,
                PolicyDispositionV1::Alert | PolicyDispositionV1::Reject
            ),
            EvaluationStageV1::NativeTransition | EvaluationStageV1::LocalPreEffect => matches!(
                self.requested_disposition,
                PolicyDispositionV1::Alert | PolicyDispositionV1::Deny
            ),
            EvaluationStageV1::PostEffect => {
                self.requested_disposition == PolicyDispositionV1::Alert
            }
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
