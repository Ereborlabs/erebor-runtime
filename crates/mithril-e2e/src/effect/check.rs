use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use erebor_runtime_ipc::v1::MithrilEffectObservation;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{Platform, Task, TestResult};

pub(crate) struct EffectCheck {
    task: Task,
    seen: BTreeSet<(u32, u64)>,
}

impl EffectCheck {
    pub(crate) fn new<P: Platform>(env: &P, task: Task) -> TestResult<Self> {
        let seen = env
            .snapshot()?
            .recent_effects
            .into_iter()
            .map(|event| (event.source_cpu_id, event.source_sequence))
            .collect();
        Ok(Self { task, seen })
    }

    fn fresh(&self, event: &MithrilEffectObservation) -> bool {
        !self
            .seen
            .contains(&(event.source_cpu_id, event.source_sequence))
    }

    pub(crate) fn wait<P: Platform>(
        &self,
        env: &P,
        reason: &str,
        family: KernelEffectFamilyV1,
        operation: KernelEffectOperationV1,
        result: i32,
        name: &str,
    ) -> TestResult<MithrilEffectObservation> {
        Ok(self
            .wait_many(env, reason, (family, operation), result, 1, name)?
            .remove(0))
    }

    pub(super) fn wait_many<P: Platform>(
        &self,
        env: &P,
        reason: &str,
        effect: (KernelEffectFamilyV1, KernelEffectOperationV1),
        result: i32,
        count: usize,
        name: &str,
    ) -> TestResult<Vec<MithrilEffectObservation>> {
        self.wait_where(env, count, name, |event| {
            self.task
                .matches_effect(event, reason, effect.0, effect.1, result)
        })
    }

    pub(crate) fn wait_match<P: Platform>(
        &self,
        env: &P,
        name: &str,
        check: impl Fn(&MithrilEffectObservation) -> bool,
    ) -> TestResult<MithrilEffectObservation> {
        Ok(self.wait_where(env, 1, name, check)?.remove(0))
    }

    fn wait_where<P: Platform>(
        &self,
        env: &P,
        count: usize,
        name: &str,
        check: impl Fn(&MithrilEffectObservation) -> bool,
    ) -> TestResult<Vec<MithrilEffectObservation>> {
        assert!(count > 0);
        let path = env.maps().0.to_owned();
        let last = RefCell::new(Vec::new());
        Ok(wait_for(
            &path,
            name,
            Duration::from_secs(30),
            || {
                let snapshot = env.snapshot().map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                let fresh = snapshot
                    .recent_effects
                    .into_iter()
                    .filter(|event| self.fresh(event))
                    .collect::<Vec<_>>();
                *last.borrow_mut() = fresh
                    .iter()
                    .rev()
                    .take(8)
                    .map(|event| {
                        (
                            event.reason.clone(),
                            event.effect_family,
                            event.operation,
                            event.kernel_result,
                            event.task_cookie,
                            event.active_role_id,
                            event.admitted_entry_rule_id,
                            event.profile_generation_ref_id,
                            event.composite_atom_id,
                            event.exact_object_key_id,
                        )
                    })
                    .collect();
                let matched = fresh
                    .into_iter()
                    .filter(|event| check(event))
                    .collect::<Vec<_>>();
                Ok((matched.len() >= count).then_some(matched))
            },
            || format!("last new effects: {:?}", last.borrow()),
        )?)
    }
}
