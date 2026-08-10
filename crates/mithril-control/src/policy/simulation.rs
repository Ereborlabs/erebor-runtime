use serde::{Deserialize, Serialize};

use super::{
    CompiledDecisionCellV1, CompiledPhysicalResultV1, StaticDecisionKeyV1, StaticExpandedProfileV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HardSafetyConditionV1 {
    PriorLsmDenial,
    MissingTaskIdentity,
    CorruptGeneration,
    EmergencyRestriction,
    AmbiguousTopology,
    UnsupportedPhysicalBoundary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulatedDispositionV1 {
    Allow,
    AuditAllow,
    WouldDeny,
    HardDeny,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulatedPhysicalResultV1 {
    NotAttempted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectSimulationV1 {
    pub actor_and_object: StaticDecisionKeyV1,
    pub evaluation_stage: String,
    pub disposition: SimulatedDispositionV1,
    pub configured_errno: Option<i16>,
    pub physical_result: SimulatedPhysicalResultV1,
    pub source_rule_ids: Vec<String>,
    pub explanation_code: String,
}

pub struct PolicySimulator<'a> {
    profile: &'a StaticExpandedProfileV1,
}

impl<'a> PolicySimulator<'a> {
    #[must_use]
    pub const fn new(profile: &'a StaticExpandedProfileV1) -> Self {
        Self { profile }
    }

    #[must_use]
    pub fn simulate(
        &self,
        key: StaticDecisionKeyV1,
        hard_safety_condition: Option<HardSafetyConditionV1>,
    ) -> EffectSimulationV1 {
        if let Some(condition) = hard_safety_condition {
            return EffectSimulationV1 {
                actor_and_object: key,
                evaluation_stage: "LOCAL_PRE_EFFECT".to_owned(),
                disposition: SimulatedDispositionV1::HardDeny,
                configured_errno: Some(-13),
                physical_result: SimulatedPhysicalResultV1::NotAttempted,
                source_rule_ids: Vec::new(),
                explanation_code: format!("HARD_SAFETY_{condition:?}").to_uppercase(),
            };
        }
        match self
            .profile
            .compiled_cells
            .binary_search_by(|cell| cell.key.cmp(&key))
        {
            Ok(index) => decision(&self.profile.compiled_cells[index]),
            Err(_) => EffectSimulationV1 {
                actor_and_object: key,
                evaluation_stage: "LOCAL_PRE_EFFECT".to_owned(),
                disposition: SimulatedDispositionV1::Unresolved,
                configured_errno: None,
                physical_result: SimulatedPhysicalResultV1::Unknown,
                source_rule_ids: Vec::new(),
                explanation_code: "NO_EXACT_COMPILED_CELL".to_owned(),
            },
        }
    }
}

fn decision(cell: &CompiledDecisionCellV1) -> EffectSimulationV1 {
    let (disposition, physical_result, explanation_code) = match cell.physical_result {
        CompiledPhysicalResultV1::AllowEffect => (
            SimulatedDispositionV1::Allow,
            SimulatedPhysicalResultV1::NotAttempted,
            "EXACT_POLICY_ALLOW",
        ),
        CompiledPhysicalResultV1::AuditAllowEffect => (
            SimulatedDispositionV1::AuditAllow,
            SimulatedPhysicalResultV1::NotAttempted,
            "EXACT_POLICY_AUDIT_ALLOW",
        ),
        CompiledPhysicalResultV1::SimulatablePolicyDeny => (
            SimulatedDispositionV1::WouldDeny,
            SimulatedPhysicalResultV1::NotAttempted,
            "SIMULATABLE_POLICY_DENY_ALLOWED_IN_OBSERVE",
        ),
    };
    EffectSimulationV1 {
        actor_and_object: cell.key.clone(),
        evaluation_stage: "LOCAL_PRE_EFFECT".to_owned(),
        disposition,
        configured_errno: cell.errno,
        physical_result,
        source_rule_ids: cell.source_rule_ids.clone(),
        explanation_code: explanation_code.to_owned(),
    }
}
