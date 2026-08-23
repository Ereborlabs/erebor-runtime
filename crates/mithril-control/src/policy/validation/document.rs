use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::super::compiler::{CompiledDecisionCellV1, CompiledPhysicalResultV1};
use super::super::source::*;
use super::value::PolicyValue;
use super::{Validate, ValidationResult};
use crate::error::PolicyValidationSnafu;
use crate::Result;

// The document validates child records before it checks cross-record relationships.

const MAX_EXCEPTION_STATES: usize = 4_096;
impl Validate for PolicyDocumentV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            self.api_version == "mithril.erebor.dev/v1" && self.kind == "ProtectionPolicy",
            "CFG_SCHEMA_VERSION",
            "api_version and kind must be the Version 1 values"
        );
        require!(
            self.metadata.profile_version > 0 && self.rollout.rollout_generation > 0,
            "CFG_ZERO_GENERATION",
            "profile and rollout generations must be nonzero"
        );
        require!(
            self.exceptions.len() <= MAX_EXCEPTION_STATES,
            "CFG_MAP_CAPACITY",
            "exception states exceed kernel map capacity"
        );
        require!(
            (self.exceptions.is_empty() && self.file_exception_grants.is_empty())
                || self.rollout.desired_profile_mode == ProfileModeV1::Protect,
            "CFG_EXCEPTION_MODE",
            "exceptions and exception grants require PROTECT mode"
        );
        require!(
            self.path_tree_deny_floors.is_empty()
                || self.rollout.desired_profile_mode == ProfileModeV1::Protect,
            "CFG_PATH_TREE_DENY",
            "path-tree denial requires PROTECT mode"
        );
        self.metadata.validate()?;
        self.protected_universe.validate()?;
        self.rollout.validate()?;
        for id in &self.required_capability_ids {
            PolicyValue::RegistrySymbol(id).validate()?;
        }
        validate_each!(self;
            workload_selectors, classifier_bindings, path_selectors, roles, entry_role_assignments,
            native_transition_rules, state_bit_definitions, process_state_definitions,
            ipc_relationship_rules, effect_family_defaults, path_tree_deny_floors,
            notification_routes, response_bindings, file_exception_grants, exceptions, rules,
            authority_behavior_rules, source_coverage_health_rules
        );
        if let Some(network_policy) = &self.network_policy {
            network_policy.validate()?;
        }
        for posture in [
            &self.default_postures.missing_task_identity,
            &self.default_postures.required_classifier_unknown,
            &self.default_postures.unresolved_or_external_root,
        ] {
            posture.validate()?;
        }
        self.validate_relationships()?;
        self.validate_role_reachability()
    }
}

// The document owns checks that compare IDs or relationships across records.
impl PolicyDocumentV1 {
    fn validate_relationships(&self) -> ValidationResult {
        let roles = self
            .roles
            .iter()
            .map(|value| value.role_id.as_str())
            .collect::<BTreeSet<_>>();
        let selectors = self
            .workload_selectors
            .iter()
            .map(|value| value.workload_selector_id.as_str())
            .collect::<BTreeSet<_>>();
        let states = self
            .process_state_definitions
            .iter()
            .map(|value| value.process_state_id.as_str())
            .collect::<BTreeSet<_>>();
        let routes = self
            .notification_routes
            .iter()
            .map(|value| value.route_id.as_str())
            .collect::<BTreeSet<_>>();
        let responses = self
            .response_bindings
            .iter()
            .map(|value| value.binding_id.as_str())
            .collect::<BTreeSet<_>>();
        let exceptions = self
            .exceptions
            .iter()
            .map(|value| value.exception_id.as_str())
            .collect::<BTreeSet<_>>();
        let exception_grants = self
            .file_exception_grants
            .iter()
            .map(|value| value.grant_id.as_str())
            .collect::<BTreeSet<_>>();
        let ipc_ids = self
            .ipc_relationship_rules
            .iter()
            .map(|value| value.relationship_rule_id.as_str())
            .collect::<BTreeSet<_>>();
        let authority_ids = self
            .authority_behavior_rules
            .iter()
            .map(|value| match value {
                AuthorityBehaviorRuleV1::RemoteAdmission { rule_id, .. }
                | AuthorityBehaviorRuleV1::PostEffectResult { rule_id, .. } => rule_id.as_str(),
            })
            .collect::<BTreeSet<_>>();
        let destination_ids = self
            .network_policy
            .iter()
            .flat_map(|policy| &policy.destination_policies)
            .map(|policy| policy.destination_policy_id.as_str())
            .collect::<BTreeSet<_>>();
        let coverage_ids = self
            .source_coverage_health_rules
            .iter()
            .map(|value| value.health_rule_id.as_str())
            .collect::<BTreeSet<_>>();
        let scopes = string_set!(&self.protected_universe.protected_scope_ids);
        let execution_sets = string_set!(&self.protected_universe.execution_set_ids);
        let object_classes = string_set!(&self.protected_universe.object_class_ids);
        let mut path_selectors = BTreeMap::new();
        let mut path_selector_handles = BTreeSet::new();
        let mut path_selector_targets = BTreeSet::new();
        let mut valid_path_selector_references = true;
        let mut exact_path_selector_count = 0;
        for selector in &self.path_selectors {
            valid_path_selector_references &= object_classes
                .contains(selector.object_class_id.as_str())
                && self.classifier_bindings.iter().any(|binding| {
                    binding.object_class_id == selector.object_class_id
                        && match (&selector.device_class_id, &binding.selector) {
                            (
                                Some(device_class_id),
                                ObjectClassifierSelectorV1::Device { device_class_ids },
                            ) => device_class_ids.contains(device_class_id),
                            (None, ObjectClassifierSelectorV1::Device { .. }) => false,
                            (None, _) => true,
                            (Some(_), _) => false,
                        }
                });
            path_selectors.insert(selector.path_selector_id.as_str(), selector);
            path_selector_targets.insert(&selector.target);
            if selector.requires_exact_object() {
                exact_path_selector_count += 1;
                path_selector_handles.insert(selector.kernel_handle());
            }
        }
        let rule_ids = self
            .rules
            .iter()
            .map(|value| value.rule_id.as_str())
            .chain(
                self.path_tree_deny_floors
                    .iter()
                    .map(|value| value.rule_id.as_str()),
            )
            .collect::<BTreeSet<_>>();
        require!(
            roles == string_set!(&self.protected_universe.role_ids),
            "CFG_ROLE_REGISTRY",
            "role registry must equal defined roles"
        );
        require!(
            selectors == string_set!(&self.protected_universe.workload_selector_ids),
            "CFG_SELECTOR_REGISTRY",
            "selector registry must equal defined selectors"
        );
        let unique_ids = roles.len() == self.roles.len()
            && routes.len() == self.notification_routes.len()
            && responses.len() == self.response_bindings.len()
            && exceptions.len() == self.exceptions.len()
            && exception_grants.len() == self.file_exception_grants.len()
            && ipc_ids.len() == self.ipc_relationship_rules.len()
            && destination_ids.len()
                == self
                    .network_policy
                    .as_ref()
                    .map_or(0, |policy| policy.destination_policies.len())
            && authority_ids.len() == self.authority_behavior_rules.len()
            && coverage_ids.len() == self.source_coverage_health_rules.len()
            && path_selectors.len() == self.path_selectors.len()
            && path_selector_handles.len() == exact_path_selector_count
            && path_selector_targets.len() == self.path_selectors.len()
            && rule_ids.len() == self.rules.len() + self.path_tree_deny_floors.len();
        require!(
            unique_ids,
            "CFG_DUPLICATE_ID",
            "policy IDs must be unique by kind"
        );
        require!(
            valid_path_selector_references,
            "CFG_PATH_SELECTOR_REFERENCE",
            "path selectors need unique path kinds and signed object classes"
        );
        for role in &self.roles {
            require!(
                states.contains(role.default_process_state_id.as_str()),
                "CFG_STATE_REFERENCE",
                format!("role `{}` references a missing state", role.role_id)
            );
        }
        for entry in &self.entry_role_assignments {
            require!(
                roles.contains(entry.resulting_role_id.as_str())
                    && all_in!(&entry.workload_selector_ids, selectors),
                "CFG_ROLE_REFERENCE",
                format!(
                    "entry `{}` has an unknown role or selector",
                    entry.assignment_id
                )
            );
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
            require!(
                permitted,
                "CFG_ENTRY_ASSIGNMENT",
                format!(
                    "entry `{}` uses an entry kind forbidden by its role",
                    entry.assignment_id
                )
            );
        }
        let process_bits = self
            .state_bit_definitions
            .iter()
            .filter(|bit| bit.scope == StateBitScopeV1::Process)
            .map(|bit| bit.bit_index)
            .collect::<BTreeSet<_>>();
        let mut bit_keys = BTreeSet::new();
        let mut semantics = BTreeSet::new();
        for bit in &self.state_bit_definitions {
            require!(
                bit_keys.insert((bit.scope, bit.bit_index))
                    && semantics.insert((bit.scope, bit.semantic_id.as_str())),
                "CFG_DUPLICATE_STATE_BIT",
                "state bit indices and semantics must be unique per scope"
            );
        }
        for state in &self.process_state_definitions {
            require!(
                state
                    .state_bits
                    .iter()
                    .all(|bit| process_bits.contains(bit)),
                "CFG_STATE_REFERENCE",
                format!(
                    "state `{}` references an undefined process bit",
                    state.process_state_id
                )
            );
        }
        let mut ipc = BTreeMap::new();
        for relation in &self.ipc_relationship_rules {
            require!(
                relation
                    .source_role_ids
                    .iter()
                    .chain(&relation.peer_role_ids)
                    .all(|id| roles.contains(id.as_str())),
                "CFG_IPC_RELATIONSHIP",
                format!(
                    "IPC relationship `{}` references an unknown role",
                    relation.relationship_rule_id
                )
            );
            for source in &relation.source_role_ids {
                for peer in &relation.peer_role_ids {
                    let pair = if source <= peer {
                        (source.as_str(), peer.as_str())
                    } else {
                        (peer.as_str(), source.as_str())
                    };
                    let decision = (relation.requested_disposition, relation.errno);
                    require!(
                        ipc.insert(pair, decision).is_none_or(|old| old == decision),
                        "CFG_IPC_RELATIONSHIP_CONFLICT",
                        format!(
                            "IPC relationship `{}` conflicts",
                            relation.relationship_rule_id
                        )
                    );
                }
            }
        }
        require!(
            self.unmatched_ipc_disposition != PolicyDispositionV1::Reject,
            "CFG_IPC_UNMATCHED",
            "unmatched IPC cannot REJECT at a local hook"
        );
        for default in &self.effect_family_defaults {
            require!(
                all_in!(&default.role_ids, roles),
                "CFG_ROLE_REFERENCE",
                "effect default references an unknown role"
            );
            if let Some(finding) = &default.finding {
                require!(
                    all_in!(&finding.route_ids, routes),
                    "CFG_FINDING",
                    "finding references an unknown route"
                );
            }
        }
        for posture in [
            &self.default_postures.missing_task_identity,
            &self.default_postures.required_classifier_unknown,
            &self.default_postures.unresolved_or_external_root,
        ] {
            require!(
                posture
                    .unknown_restricted_role_id
                    .as_ref()
                    .is_none_or(|id| roles.contains(id.as_str()))
                    && all_in!(&posture.finding.route_ids, routes),
                "CFG_DEFAULT_POSTURE",
                "default posture references an unknown role or route"
            );
        }
        for rule in &self.rules {
            require!(
                rule.overrides_rule_ids
                    .iter()
                    .all(|id| id != &rule.rule_id && rule_ids.contains(id.as_str())),
                "CFG_OVERRIDE_REFERENCE",
                format!("rule `{}` has an invalid override", rule.rule_id)
            );
            let known_actions = all_in!(&rule.response_binding_ids, responses)
                && all_in!(&rule.exception_ids, exceptions);
            let known_finding = rule
                .finding
                .as_ref()
                .is_none_or(|finding| all_in!(&finding.route_ids, routes));
            let known_fallbacks = rule.fallback_by_condition.iter().all(|fallback| {
                all_in!(&fallback.finding.route_ids, routes)
                    && fallback
                        .unknown_restricted_role_id
                        .as_ref()
                        .is_none_or(|id| roles.contains(id.as_str()))
            });
            require!(
                known_actions && known_finding && known_fallbacks,
                "CFG_RULE_ACTION",
                format!("rule `{}` references an unknown action", rule.rule_id)
            );
            let subject = match &rule.rule_match {
                RuleMatchV1::EntryAdmission(value) => Some(&value.subject),
                RuleMatchV1::LocalPreEffect(value) => Some(&value.subject),
                RuleMatchV1::NativeTransition(value) => Some(&value.subject),
                RuleMatchV1::RemotePreAdmission(value) => Some(&value.subject),
                RuleMatchV1::PostEffect(PostEffectMatchV1::LocalCompletion { subject, .. }) => {
                    Some(subject)
                }
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
                let known_states = subject
                    .required_process_state_ids
                    .iter()
                    .chain(&subject.forbidden_process_state_ids)
                    .all(|id| states.contains(id.as_str()));
                require!(
                    known_dimensions && known_states,
                    "CFG_SUBJECT_REFERENCE",
                    format!(
                        "rule `{}` subject references values outside its policy",
                        rule.rule_id
                    )
                );
            }
            if let RuleMatchV1::LocalPreEffect(effect) = &rule.rule_match {
                if let LocalObjectSelectorV1::PathSelectors { path_selector_ids } = &effect.object {
                    require!(
                        ordered_unique(path_selector_ids)
                            && path_selector_ids
                                .iter()
                                .all(|id| path_selectors.contains_key(id.as_str())),
                        "CFG_PATH_SELECTOR_REFERENCE",
                        format!("rule `{}` has an invalid path selector", rule.rule_id)
                    );
                }
                if let LocalObjectSelectorV1::Destinations {
                    destination_policy_ids,
                } = &effect.object
                {
                    require!(
                        ordered_unique(destination_policy_ids)
                            && destination_policy_ids
                                .iter()
                                .all(|id| destination_ids.contains(id.as_str())),
                        "CFG_NETWORK_DESTINATION_REFERENCE",
                        format!("rule `{}` has unknown network destinations", rule.rule_id)
                    );
                }
                if let LocalObjectSelectorV1::ObjectClasses { object_class_ids } = &effect.object {
                    require!(
                        ordered_unique(object_class_ids)
                            && object_class_ids
                                .iter()
                                .all(|id| object_classes.contains(id.as_str())),
                        "CFG_OBJECT_CLASS_REFERENCE",
                        format!("rule `{}` has unknown object classes", rule.rule_id)
                    );
                }
                if let LocalObjectSelectorV1::SecurityObjects {
                    security_object_ids,
                    target_selector_ids,
                } = &effect.object
                {
                    if security_object_ids.iter().any(|id| id == "PROCESS") {
                        require!(
                            roles.contains(target_selector_ids[0].as_str()),
                            "CFG_PROCESS_CONTROL_KEY",
                            format!("rule `{}` has an unknown target role", rule.rule_id)
                        );
                    }
                }
            }
            if let RuleMatchV1::NativeTransition(value) = &rule.rule_match {
                require!(
                    value
                        .source_role_ids
                        .iter()
                        .chain(&value.target_role_ids)
                        .all(|id| roles.contains(id.as_str()))
                        && value.executable_path_selector_ids.iter().all(|id| {
                            path_selectors
                                .get(id.as_str())
                                .is_some_and(|selector| selector.requires_exact_object())
                        }),
                    "CFG_NATIVE_TRANSITION_MATCH",
                    format!(
                        "rule `{}` has an unknown role or non-exact executable selector",
                        rule.rule_id
                    )
                );
            }
        }
        let base_rule_ids = self
            .rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        for grant in &self.file_exception_grants {
            require!(
                grant
                    .denied_file_rule_ids
                    .iter()
                    .all(|id| base_rule_ids.contains(id.as_str())
                        && self.rules.iter().any(|rule| {
                            rule.rule_id == *id
                                && rule.requested_disposition == PolicyDispositionV1::Deny
                                && matches!(
                                    &rule.rule_match,
                                    RuleMatchV1::LocalPreEffect(effect)
                                        if effect.effect_families == [EffectFamilyV1::File]
                                )
                        })),
                "CFG_EXCEPTION_GRANT",
                format!(
                    "exception grant `{}` must reference denied file rules",
                    grant.grant_id
                )
            );
        }
        let granted_rules = self
            .file_exception_grants
            .iter()
            .flat_map(|grant| grant.denied_file_rule_ids.iter())
            .collect::<Vec<_>>();
        require!(
            granted_rules.iter().collect::<BTreeSet<_>>().len() == granted_rules.len(),
            "CFG_EXCEPTION_GRANT_OVERLAP",
            "one denied file rule cannot belong to multiple exception grants"
        );
        for exception in &self.exceptions {
            let subject = &exception.exact_subject;
            let known_rules = all_in!(&exception.changed_rule_ids, base_rule_ids);
            let known_subject = all_in!(&subject.protected_scope_ids, scopes)
                && all_in!(&subject.execution_set_ids, execution_sets)
                && all_in!(&subject.role_ids, roles);
            require!(
                known_rules && known_subject,
                "CFG_EXCEPTION",
                format!(
                    "exception `{}` references values outside its policy",
                    exception.exception_id
                )
            );
        }
        for rule in &self.authority_behavior_rules {
            let (responses_used, finding) = match rule {
                AuthorityBehaviorRuleV1::RemoteAdmission {
                    response_binding_ids,
                    finding,
                    ..
                }
                | AuthorityBehaviorRuleV1::PostEffectResult {
                    response_binding_ids,
                    finding,
                    ..
                } => (response_binding_ids, finding),
            };
            require!(
                all_in!(responses_used, responses)
                    && finding
                        .as_ref()
                        .is_none_or(|value| all_in!(&value.route_ids, routes)),
                "CFG_AUTHORITY_RULE",
                "authority rule references an unknown route or response"
            );
        }
        for rule in &self.source_coverage_health_rules {
            require!(
                all_in!(&rule.protected_scope_ids, scopes)
                    && all_in!(&rule.independent_response_binding_ids, responses)
                    && all_in!(&rule.finding.route_ids, routes),
                "CFG_COVERAGE_RULE",
                format!(
                    "coverage rule `{}` references values outside its policy",
                    rule.health_rule_id
                )
            );
        }
        Ok(())
    }
    fn validate_role_reachability(&self) -> ValidationResult {
        let mut reachable = self
            .entry_role_assignments
            .iter()
            .map(|entry| entry.resulting_role_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut pending = VecDeque::from_iter(&self.native_transition_rules);
        let mut progress = true;
        while progress {
            progress = false;
            pending.retain(|transition| {
                if transition
                    .source_role_ids
                    .iter()
                    .any(|role| reachable.contains(role.as_str()))
                {
                    progress |= reachable.insert(&transition.resulting_role_id);
                    false
                } else {
                    true
                }
            });
        }
        let missing = self
            .roles
            .iter()
            .filter(|role| !reachable.contains(role.role_id.as_str()))
            .map(|role| role.role_id.clone())
            .collect::<Vec<_>>();
        require!(
            missing.is_empty(),
            "CFG_UNREACHABLE_ROLE",
            format!("unreachable roles: {missing:?}")
        );
        Ok(())
    }
    pub(in crate::policy) fn validate_compiled_exceptions(
        &self,
        cells: &[CompiledDecisionCellV1],
    ) -> Result<()> {
        for grant in &self.file_exception_grants {
            let bound = cells
                .iter()
                .filter(|cell| cell.consuming_exception_id.as_deref() == Some(&grant.grant_id))
                .collect::<Vec<_>>();
            let source_rules = bound
                .iter()
                .flat_map(|cell| cell.source_rule_ids.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();
            let valid = !bound.is_empty()
                && bound.iter().all(|cell| {
                    matches!(
                        cell.key.operation_id.as_str(),
                        "OPEN_READ" | "OPEN_WRITE"
                    ) && cell.key.effect_family == EffectFamilyV1::File
                        && cell.physical_result == CompiledPhysicalResultV1::AllowEffect
                        && cell.errno.is_none()
                })
                && source_rules
                    == grant
                        .denied_file_rule_ids
                        .iter()
                        .map(String::as_str)
                        .collect();
            if !valid {
                return PolicyValidationSnafu {
                    policy_id: self.profile_id(),
                    code: "CFG_EXCEPTION_GRANT_CELL",
                    reason: format!(
                        "exception grant `{}` does not bind only qualified file-open cells",
                        grant.grant_id
                    ),
                }
                .fail();
            }
        }
        for exception in &self.exceptions {
            let bound = cells
                .iter()
                .filter(|cell| {
                    cell.consuming_exception_id.as_deref() == Some(&exception.exception_id)
                })
                .collect::<Vec<_>>();
            let subject = &exception.exact_subject;
            let digests = bound
                .iter()
                .map(|cell| cell.key.digest(self.profile_id()))
                .collect::<Result<BTreeSet<_>>>()?;
            let scopes = bound
                .iter()
                .map(|cell| cell.key.protected_scope_id.as_str())
                .collect::<BTreeSet<_>>();
            let sets = bound
                .iter()
                .map(|cell| cell.key.execution_set_id.as_str())
                .collect::<BTreeSet<_>>();
            let kinds = bound
                .iter()
                .map(|cell| cell.key.entry_kind)
                .collect::<BTreeSet<_>>();
            let roles = bound
                .iter()
                .map(|cell| cell.key.role_id.as_str())
                .collect::<BTreeSet<_>>();
            let rules = bound
                .iter()
                .flat_map(|cell| cell.source_rule_ids.iter().map(String::as_str))
                .collect::<BTreeSet<_>>();
            let cell = bound.len() == 1
                && matches!(
                    bound[0].key.operation_id.as_str(),
                    "OPEN_READ" | "OPEN_WRITE"
                )
                && bound[0].physical_result == CompiledPhysicalResultV1::AllowEffect;
            let dimensions = scopes
                == subject
                    .protected_scope_ids
                    .iter()
                    .map(String::as_str)
                    .collect()
                && sets
                    == subject
                        .execution_set_ids
                        .iter()
                        .map(String::as_str)
                        .collect()
                && kinds == subject.entry_kind_ids.iter().copied().collect()
                && roles == subject.role_ids.iter().map(String::as_str).collect();
            let authority = digests == subject.exact_compiled_key_digests.iter().cloned().collect()
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
                && rules
                    == exception
                        .changed_rule_ids
                        .iter()
                        .map(String::as_str)
                        .collect();
            let valid = cell && dimensions && authority;
            if !valid {
                return PolicyValidationSnafu {
                    policy_id: self.profile_id(),
                    code: "CFG_EXCEPTION_CELL",
                    reason: format!(
                        "exception `{}` does not bind one qualified file-open allow cell",
                        exception.exception_id
                    ),
                }
                .fail();
            }
        }
        Ok(())
    }
}
