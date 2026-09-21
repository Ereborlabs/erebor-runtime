use std::{cell::RefCell, path::Path, time::Duration};

use erebor_interceptor::KernelStateReader;
use erebor_interceptor_abi::{
    BindingActivationTargetKeyV1, ExecutionSetBindingStateV1, Id128V1, PendingExecStateV1,
    PendingExecV1, PolicyGenerationStateV1, ProfileGenerationDescriptorV1,
};
use snafu::ResultExt as _;
use zerocopy::{IntoBytes as _, KnownLayout, TryFromBytes};

use crate::error::{InterceptorSnafu, InvalidInputSnafu};
use crate::physical::wait_for;
use crate::platform::Platform;
use crate::Result;

#[derive(Debug)]
pub(crate) struct GenerationState {
    pub(crate) active: Option<u64>,
    pub(crate) descriptor: Option<ProfileGenerationDescriptorV1>,
    pub(crate) targets: usize,
    pub(crate) bindings: usize,
    pub(crate) pending: Option<PendingExecV1>,
}

impl GenerationState {
    pub(crate) fn descriptor<P: Platform>(
        env: &P,
        generation: u64,
    ) -> Result<ProfileGenerationDescriptorV1> {
        Self::value(
            env.maps().1,
            "profile_generation_descriptors",
            &generation.to_ne_bytes(),
            env.maps().0,
        )?
        .ok_or_else(|| {
            InvalidInputSnafu {
                path: env.maps().0,
                reason: "the profile generation descriptor is missing",
            }
            .build()
        })
    }

    pub(crate) fn read<P: Platform>(
        env: &P,
        profile: Id128V1,
        generation: u64,
        task: u64,
    ) -> Result<Self> {
        let (path, reader) = env.maps();
        let active = Self::value(
            reader,
            "active_profile_generations",
            profile.as_bytes(),
            path,
        )?;
        let descriptor = Self::value(
            reader,
            "profile_generation_descriptors",
            &generation.to_ne_bytes(),
            path,
        )?;
        let mut targets = 0;
        for bytes in reader
            .keys("binding_activation_targets")
            .context(InterceptorSnafu)?
        {
            let key =
                BindingActivationTargetKeyV1::try_read_from_bytes(&bytes).map_err(|source| {
                    InvalidInputSnafu {
                        path,
                        reason: format!("binding activation target key is invalid: {source}"),
                    }
                    .build()
                })?;
            targets += usize::from(key.profile_generation_ref_id == generation);
        }
        let mut bindings = 0;
        for key in reader
            .keys("execution_set_bindings")
            .context(InterceptorSnafu)?
        {
            let Some(value) = Self::value::<ExecutionSetBindingStateV1>(
                reader,
                "execution_set_bindings",
                &key,
                path,
            )?
            else {
                continue;
            };
            bindings += usize::from(value.active_profile_generation_ref_id == generation);
        }
        let pending = Self::value(reader, "pending_execs", &task.to_ne_bytes(), path)?;
        Ok(Self {
            active,
            descriptor,
            targets,
            bindings,
            pending,
        })
    }

    pub(crate) fn wait_fatal<P: Platform>(env: &P) -> Result<PendingExecV1> {
        let path = env.maps().0.to_owned();
        let last = RefCell::new(String::from("<none>"));
        wait_for(
            &path,
            "terminal pending exec",
            Duration::from_secs(30),
            || {
                for key in env
                    .maps()
                    .1
                    .keys("pending_execs")
                    .context(InterceptorSnafu)?
                {
                    let Some(pending) =
                        Self::value::<PendingExecV1>(env.maps().1, "pending_execs", &key, &path)?
                    else {
                        continue;
                    };
                    *last.borrow_mut() = format!("{pending:?}");
                    if pending.state == PendingExecStateV1::PostPonrFatal {
                        return Ok(Some(pending));
                    }
                }
                Ok(None)
            },
            || format!("last pending exec: {}", last.borrow()),
        )
    }

    pub(crate) fn wait_retiring<P: Platform>(
        env: &P,
        profile: Id128V1,
        generation: u64,
        task: u64,
    ) -> Result<Self> {
        Self::wait(
            env,
            profile,
            generation,
            task,
            "generation retirement",
            |state| {
                state.active != Some(generation)
                    && state
                        .descriptor
                        .as_ref()
                        .is_some_and(|value| value.state == PolicyGenerationStateV1::Retiring)
            },
        )
    }

    pub(crate) fn wait_absent<P: Platform>(
        env: &P,
        profile: Id128V1,
        generation: u64,
        task: u64,
    ) -> Result<Self> {
        Self::wait(
            env,
            profile,
            generation,
            task,
            "generation removal",
            |state| state.descriptor.is_none() && state.targets == 0 && state.bindings == 0,
        )
    }

    fn wait<P: Platform>(
        env: &P,
        profile: Id128V1,
        generation: u64,
        task: u64,
        operation: &str,
        ready: impl Fn(&Self) -> bool,
    ) -> Result<Self> {
        let path = env.maps().0.to_owned();
        let last = RefCell::new(String::from("<none>"));
        wait_for(
            &path,
            operation,
            Duration::from_secs(30),
            || {
                let state = Self::read(env, profile, generation, task)?;
                *last.borrow_mut() = format!("{state:?}");
                Ok(ready(&state).then_some(state))
            },
            || format!("last generation state: {}", last.borrow()),
        )
    }

    fn value<T: KnownLayout + TryFromBytes>(
        reader: &KernelStateReader,
        map: &str,
        key: &[u8],
        path: &Path,
    ) -> Result<Option<T>> {
        reader
            .lookup(map, key)
            .context(InterceptorSnafu)?
            .map(|bytes| {
                T::try_read_from_bytes(&bytes).map_err(|source| {
                    InvalidInputSnafu {
                        path,
                        reason: format!("{map} value is invalid: {source}"),
                    }
                    .build()
                })
            })
            .transpose()
    }
}
