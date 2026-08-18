use super::super::source::*;
use super::value::PolicyValue;
use super::{Validate, ValidationResult};

// Exceptions and authority rules validate bounded changes to signed authority.

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
        require!(
            exact,
            "CFG_AUTHORITY_RULE",
            format!("authority behavior rule `{}` is invalid", $id)
        );
        if let Some(finding) = $finding {
            finding.validate()?;
        }
        Ok(())
    }};
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
        let exact_delta = delta.from_physical_result == "DENY_ERRNO"
            && delta.to_physical_result == "ALLOW_EFFECT"
            && ordered!(
                &delta.added_or_removed_operation_cells,
                &delta.added_or_removed_transition_cells
            );
        require!(
            bounded && exact_subject && exact_delta,
            "CFG_EXCEPTION",
            format!(
                "exception `{}` is not a bounded exact authority delta",
                self.exception_id
            )
        );
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
                    && matches!(
                        requested_disposition,
                        PolicyDispositionV1::Allow
                            | PolicyDispositionV1::Alert
                            | PolicyDispositionV1::Reject
                    )
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
                    && matches!(
                        requested_disposition,
                        PolicyDispositionV1::Allow | PolicyDispositionV1::Alert
                    )
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
            CoverageGapActionV1::Alert => {
                self.independent_admission_interface_binding_id.is_none()
                    && self.independent_admission_capability_id.is_none()
                    && self.independent_response_binding_ids.is_empty()
            }
            CoverageGapActionV1::RejectNewAdmission => {
                self.independent_admission_interface_binding_id.is_some()
                    && self.independent_admission_capability_id.is_some()
            }
            CoverageGapActionV1::InstallIndependentFence => {
                !self.independent_response_binding_ids.is_empty()
            }
        };
        require!(
            !self.protected_scope_ids.is_empty()
                && ordered!(
                    &self.protected_scope_ids,
                    &self.independent_response_binding_ids
                )
                && independent,
            "CFG_COVERAGE_RULE",
            format!(
                "coverage rule `{}` lacks an independent fallback",
                self.health_rule_id
            )
        );
        self.finding.validate()
    }
}

impl Validate for RolloutV1 {
    fn validate(&self) -> ValidationResult {
        require!(
            ordered_unique(&self.selected_bucket_ids),
            "CFG_ROLLOUT_ORDER",
            "selected buckets must be sorted and unique"
        );
        require!(
            self.selector_hash_modulus > 0
                && self
                    .selected_bucket_ids
                    .iter()
                    .all(|bucket| *bucket < self.selector_hash_modulus),
            "CFG_ROLLOUT_BUCKET",
            "rollout buckets must be below a nonzero modulus"
        );
        Ok(())
    }
}
