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
            .map(|value| (value.role_id.as_str(), value))
            .collect::<BTreeMap<_, _>>();
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
        let destinations = self
            .network_policy
            .iter()
            .flat_map(|policy| &policy.destination_policies)
            .map(|policy| (policy.destination_policy_id.as_str(), policy))
            .collect::<BTreeMap<_, _>>();
        let dns = self.network_policy.as_ref().is_some_and(|policy| {
            policy.dns_mode == DnsPolicyModeV1::DenyDnsAndUsePolicyResolvedAddresses
        });
        let scopes = string_set!(&self.protected_universe.protected_scope_ids);
        let execution_sets = string_set!(&self.protected_universe.execution_set_ids);
        let object_classes = string_set!(&self.protected_universe.object_class_ids);
        let path_selectors = self
            .path_selectors
            .iter()
            .map(|selector| (selector.path_selector_id.as_str(), selector))
            .collect::<BTreeMap<_, _>>();
        let rules = self
            .rules
            .iter()
            .map(|value| (value.rule_id.as_str(), value))
            .collect::<BTreeMap<_, _>>();
        let rule_ids = rules
            .keys()
            .copied()
            .chain(
                self.path_tree_deny_floors
                    .iter()
                    .map(|value| value.rule_id.as_str()),
            )
            .collect::<BTreeSet<_>>();
        require!(
            roles
                .keys()
                .copied()
                .eq(string_set!(&self.protected_universe.role_ids)),
            "CFG_ROLE_REGISTRY",
            "role registry must equal defined roles"
        );
        require!(
            self.path_tree_deny_floors
                .iter()
                .all(|floor| roles.contains_key(floor.role_id.as_str())),
            "CFG_ROLE_REFERENCE",
            "path-tree denial references an unknown role"
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
            && Self::unique_values(
                self.file_exception_grants
                    .iter()
                    .map(|grant| &grant.grant_id),
            )
            && Self::unique_values(
                self.ipc_relationship_rules
                    .iter()
                    .map(|rule| &rule.relationship_rule_id),
            )
            && destinations.len()
                == self
                    .network_policy
                    .as_ref()
                    .map_or(0, |policy| policy.destination_policies.len())
            && Self::unique_values(
                self.authority_behavior_rules
                    .iter()
                    .map(|rule| rule.references().0),
            )
            && Self::unique_values(
                self.source_coverage_health_rules
                    .iter()
                    .map(|rule| &rule.health_rule_id),
            )
            && path_selectors.len() == self.path_selectors.len()
            && Self::unique_values(
                self.path_selectors
                    .iter()
                    .filter(|selector| selector.requires_exact_object())
                    .map(PathSelectorV1::kernel_handle),
            )
            && Self::unique_values(self.path_selectors.iter().map(|selector| &selector.target))
            && rule_ids.len() == self.rules.len() + self.path_tree_deny_floors.len();
        require!(
            unique_ids,
            "CFG_DUPLICATE_ID",
            "policy IDs must be unique by kind"
        );
        require!(
            self.path_selectors.iter().all(|selector| {
                object_classes.contains(selector.object_class_id.as_str())
                    && self.classifier_bindings.iter().any(|binding| {
                        binding.object_class_id == selector.object_class_id
                            && match (&selector.device_class_id, &binding.selector) {
                                (
                                    Some(id),
                                    ObjectClassifierSelectorV1::Device { device_class_ids },
                                ) => device_class_ids.contains(id),
                                (None, ObjectClassifierSelectorV1::Device { .. })
                                | (Some(_), _) => false,
                                (None, _) => true,
                            }
                    })
            }),
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
            let role = roles.get(entry.resulting_role_id.as_str());
            require!(
                role.is_some() && all_in!(&entry.workload_selector_ids, selectors),
                "CFG_ROLE_REFERENCE",
                format!(
                    "entry `{}` has an unknown role or selector",
                    entry.assignment_id
                )
            );
            let permitted = role.is_some_and(|role| {
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
            let valid_admission_rule = entry.admission_execution_rule_id.as_ref().is_none_or(
                |rule_id| {
                    rules.get(rule_id.as_str()).is_some_and(|rule| {
                        rule.enabled
                            && rule.requested_disposition == PolicyDispositionV1::Allow
                            && matches!(
                                &rule.rule_match,
                                RuleMatchV1::LocalPreEffect(value)
                                    if value.effect_families == [EffectFamilyV1::Exec]
                                        && value.operation_ids.iter().any(|operation| operation == "EXECUTE")
                                        && value.subject.role_ids == [entry.resulting_role_id.as_str()]
                                        && entry.entry_kinds.iter().all(|kind| {
                                            value.subject.entry_kind_ids.contains(kind)
                                        })
                                        && matches!(
                                            &value.object,
                                            LocalObjectSelectorV1::PathSelectors { .. }
                                        )
                            )
                    })
                },
            );
            require!(
                valid_admission_rule,
                "CFG_ENTRY_EXECUTION_RULE",
                format!(
                    "entry `{}` has an invalid admission execution rule",
                    entry.assignment_id
                )
            );
        }
        let bits = self
            .state_bit_definitions
            .iter()
            .map(|bit| (bit.scope, bit.bit_index))
            .collect::<BTreeSet<_>>();
        require!(
            bits.len() == self.state_bit_definitions.len()
                && Self::unique_values(
                    self.state_bit_definitions
                        .iter()
                        .map(|bit| (bit.scope, &bit.semantic_id))
                ),
            "CFG_DUPLICATE_STATE_BIT",
            "state bit indices and semantics must be unique per scope"
        );
        for state in &self.process_state_definitions {
            require!(
                state
                    .state_bits
                    .iter()
                    .all(|bit| bits.contains(&(StateBitScopeV1::Process, *bit))),
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
                    .all(|id| roles.contains_key(id.as_str())),
                "CFG_IPC_RELATIONSHIP",
                format!(
                    "IPC relationship `{}` references an unknown role",
                    relation.relationship_rule_id
                )
            );
            for source in &relation.source_role_ids {
                for peer in &relation.peer_role_ids {
                    let mut pair = [source.as_str(), peer.as_str()];
                    pair.sort();
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
                all_in!(&default.role_ids, keys roles),
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
                    .is_none_or(|id| roles.contains_key(id.as_str()))
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
            require!(
                all_in!(&rule.response_binding_ids, responses)
                    && all_in!(&rule.exception_ids, exceptions)
                    && rule
                        .finding
                        .iter()
                        .map(|finding| (finding, None))
                        .chain(rule.fallback_by_condition.iter().map(|fallback| (
                            &fallback.finding,
                            fallback.unknown_restricted_role_id.as_ref()
                        )))
                        .all(|(finding, role)| all_in!(&finding.route_ids, routes)
                            && role.is_none_or(|id| roles.contains_key(id.as_str()))),
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
                    && all_in!(&subject.role_ids, keys roles);
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
                let (valid, code, reason) = match &effect.object {
                    LocalObjectSelectorV1::PathSelectors { path_selector_ids } => (
                        all_in!(path_selector_ids, keys path_selectors),
                        "CFG_PATH_SELECTOR_REFERENCE",
                        "an invalid path selector",
                    ),
                    LocalObjectSelectorV1::Destinations {
                        destination_policy_ids,
                    } => (
                        ordered_unique(destination_policy_ids)
                            && all_in!(destination_policy_ids, keys destinations),
                        "CFG_NETWORK_DESTINATION_REFERENCE",
                        "unknown network destinations",
                    ),
                    LocalObjectSelectorV1::ObjectClasses { object_class_ids } => (
                        ordered_unique(object_class_ids)
                            && all_in!(object_class_ids, object_classes),
                        "CFG_OBJECT_CLASS_REFERENCE",
                        "unknown object classes",
                    ),
                    _ => (true, "", ""),
                };
                require!(valid, code, format!("rule `{}` has {reason}", rule.rule_id));
                if let LocalObjectSelectorV1::Destinations {
                    destination_policy_ids,
                } = &effect.object
                {
                    require!(
                        rule.requested_disposition == PolicyDispositionV1::Deny
                            || !dns
                            || destination_policy_ids.iter().all(|id| {
                                destinations[id.as_str()]
                                    .port_ranges
                                    .iter()
                                    .all(|range| !(range.first..=range.last).contains(&53))
                            }),
                        "CFG_NETWORK_DNS_MODE",
                        "policy-resolved address mode cannot authorize DNS port 53"
                    );
                }
                if let LocalObjectSelectorV1::SecurityObjects {
                    security_object_ids,
                    target_selector_ids,
                } = &effect.object
                {
                    if security_object_ids.iter().any(|id| id == "PROCESS") {
                        require!(
                            roles.contains_key(target_selector_ids[0].as_str()),
                            "CFG_PROCESS_CONTROL_KEY",
                            format!("rule `{}` has an unknown target role", rule.rule_id)
                        );
                    }
                }
            }
            if let RuleMatchV1::NativeTransition(value) = &rule.rule_match {
                require!(
                    [&value.source_role_ids, &value.target_role_ids]
                        .into_iter()
                        .all(|ids| all_in!(ids, keys roles))
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
        for grant in &self.file_exception_grants {
            require!(
                grant
                    .denied_file_rule_ids
                    .iter()
                    .all(|id| rules.get(id.as_str()).is_some_and(|rule| {
                        rule.requested_disposition == PolicyDispositionV1::Deny
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
        require!(
            Self::unique_values(
                self.file_exception_grants
                    .iter()
                    .flat_map(|grant| &grant.denied_file_rule_ids)
            ),
            "CFG_EXCEPTION_GRANT_OVERLAP",
            "one denied file rule cannot belong to multiple exception grants"
        );
        for exception in &self.exceptions {
            let subject = &exception.exact_subject;
            let known_rules = all_in!(&exception.changed_rule_ids, keys rules);
            let known_subject = all_in!(&subject.protected_scope_ids, scopes)
                && all_in!(&subject.execution_set_ids, execution_sets)
                && all_in!(&subject.role_ids, keys roles);
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
            let (_, bindings, finding) = rule.references();
            require!(
                all_in!(bindings, responses)
                    && finding.is_none_or(|value| all_in!(&value.route_ids, routes)),
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
    fn unique_values<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
        let mut seen = BTreeSet::new();
        values.into_iter().all(|value| seen.insert(value))
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
                    matches!(cell.key.operation_id.as_str(), "OPEN_READ" | "OPEN_WRITE")
                        && cell.key.effect_family == EffectFamilyV1::File
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
