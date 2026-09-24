use std::{cell::RefCell, collections::BTreeSet, time::Duration};

use erebor_interceptor_abi::{KernelEffectFamilyV1, KernelEffectOperationV1};
use erebor_runtime_ipc::v1::MithrilEffectObservation;

use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::platform::{Platform, Task, TestResult};

pub(super) struct EffectCheck {
    task: Task,
    seen: BTreeSet<(u32, u64)>,
}

impl EffectCheck {
    pub(super) fn new<P: Platform>(env: &P, task: Task) -> TestResult<Self> {
        let seen = env
            .snapshot()?
            .recent_effects
            .into_iter()
            .map(|event| (event.source_cpu_id, event.source_sequence))
            .collect();
        Ok(Self { task, seen })
    }

    pub(super) fn wait<P: Platform>(
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
                    .filter(|event| {
                        !self
                            .seen
                            .contains(&(event.source_cpu_id, event.source_sequence))
                    })
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
                            event.profile_generation_ref_id,
                            event.composite_atom_id,
                            event.exact_object_key_id,
                        )
                    })
                    .collect();
                let matched = fresh
                    .into_iter()
                    .filter(|event| {
                        self.task
                            .matches_effect(event, reason, effect.0, effect.1, result)
                    })
                    .collect::<Vec<_>>();
                Ok((matched.len() >= count).then_some(matched))
            },
            || format!("last new effects: {:?}", last.borrow()),
        )?)
    }
}
