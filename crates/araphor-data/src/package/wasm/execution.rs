use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Mutex,
};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use snafu::{IntoError as _, ResultExt as _};
use wasmtime::{Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline};

use crate::{AnalysisReadControl, Result};

use super::{
    bindings::{self, araphor::analysis::types, AnalysisPackagePre},
    Code, MAX_LIFT_BYTES,
};

const MAX_EVALUATIONS: usize = 4;
const MAX_HOST_CALLS: usize = 4096;
const MAX_FUEL: u64 = 100_000_000;

#[cfg(test)]
pub(super) struct GuestEntry {
    pub(super) entered: mpsc::Sender<()>,
    pub(super) release: Option<mpsc::Receiver<()>>,
}

pub(super) struct GuestState {
    limits: StoreLimits,
    control: AnalysisReadControl,
    host_calls: usize,
    limited: bool,
    #[cfg(test)]
    entered: Option<GuestEntry>,
}

impl GuestState {
    fn new(control: AnalysisReadControl) -> Self {
        Self {
            limits: StoreLimitsBuilder::new()
                .memory_size(256 * 1024 * 1024)
                .memories(1)
                .table_elements(16_384)
                .tables(4)
                .instances(16)
                .trap_on_grow_failure(true)
                .build(),
            control,
            host_calls: 0,
            limited: false,
            #[cfg(test)]
            entered: None,
        }
    }
}

impl types::Host for GuestState {}

impl ResourceLimiter for GuestState {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.limits.memory_growing(current, desired, maximum);
        self.limited |= !matches!(result, Ok(true));
        result
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let result = self.limits.table_growing(current, desired, maximum);
        self.limited |= !matches!(result, Ok(true));
        result
    }

    fn instances(&self) -> usize {
        self.limits.instances()
    }
    fn memories(&self) -> usize {
        self.limits.memories()
    }
    fn tables(&self) -> usize {
        self.limits.tables()
    }
}

impl bindings::araphor::analysis::host::Host for GuestState {
    fn cancelled(&mut self) -> wasmtime::Result<bool> {
        #[cfg(test)]
        if let Some(entered) = self.entered.take() {
            entered.entered.send(()).map_err(wasmtime::Error::new)?;
            if let Some(release) = entered.release {
                release
                    .recv_timeout(self.control.remaining().map_err(wasmtime::Error::new)?)
                    .map_err(wasmtime::Error::new)?;
            }
        }
        self.host_calls += 1;
        if self.host_calls > MAX_HOST_CALLS {
            self.limited = true;
            return Err(wasmtime::Error::msg("analysis host call limit"));
        }
        Ok(self.control.check().is_err())
    }
}

pub(super) struct EpochTicker {
    engine: Engine,
    worker: Mutex<Option<EpochWorker>>,
}

struct EpochWorker {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EpochTicker {
    pub(super) fn new(engine: Engine) -> Self {
        Self {
            engine,
            worker: Mutex::new(None),
        }
    }

    fn start(&self) -> Result<()> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| Code::Incomplete.error("component epoch worker lock"))?;
        if worker.as_ref().is_some_and(|worker| {
            worker
                .thread
                .as_ref()
                .is_some_and(|thread| thread.is_finished())
        }) {
            return Err(Code::Incomplete.error("component epoch worker stopped"));
        }
        if worker.is_none() {
            let engine = self.engine.clone();
            let (stop, stopped) = mpsc::channel::<()>();
            let thread = std::thread::Builder::new()
                .name("analysis-wasm-epoch".into())
                .spawn(move || {
                    while matches!(
                        stopped.recv_timeout(Duration::from_millis(5)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ) {
                        engine.increment_epoch();
                    }
                })
                .map_err(wasmtime::Error::new)
                .context(crate::PackageWasmSnafu {
                    code: Code::Incomplete,
                    operation: "component epoch worker",
                })?;
            *worker = Some(EpochWorker {
                stop: Some(stop),
                thread: Some(thread),
            });
        }
        Ok(())
    }
}

impl Drop for EpochWorker {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) struct EvaluationPermit<'a>(&'a AtomicUsize);

impl<'a> EvaluationPermit<'a> {
    pub(super) fn acquire(running: &'a AtomicUsize) -> Result<Self> {
        running
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_EVALUATIONS).then_some(count + 1)
            })
            .map_err(|_| {
                crate::AnalysisBusySnafu {
                    resource: "component evaluations",
                }
                .build()
            })?;
        Ok(Self(running))
    }
}

impl Drop for EvaluationPermit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl super::WasmExecution {
    pub(super) fn invoke(
        &self,
        component: &AnalysisPackagePre<GuestState>,
        input: types::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<types::Output> {
        let control = control.within(Duration::from_secs(5))?;
        self.epoch.start()?;
        let mut store = Store::new(&self.engine, GuestState::new(control));
        #[cfg(test)]
        {
            store.data_mut().entered = self
                .entered
                .lock()
                .map_err(|_| Code::Incomplete.error("component test gate"))?
                .take();
        }
        store.limiter(|state| state);
        store.set_fuel(MAX_FUEL).context(crate::PackageWasmSnafu {
            code: Code::Incomplete,
            operation: "component fuel",
        })?;
        store.set_hostcall_fuel(MAX_LIFT_BYTES);
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|store| {
            if store.data().control.check().is_err() {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let result = component.instantiate(&mut store).and_then(|instance| {
            instance
                .araphor_analysis_analysis()
                .call_evaluate(&mut store, &input)
        });
        let result = result.map_err(|source| {
            let code = if store.data().limited
                || matches!(
                    source.downcast_ref::<wasmtime::Trap>(),
                    Some(wasmtime::Trap::OutOfFuel | wasmtime::Trap::StackOverflow)
                )
                // Wasmtime 49 keeps this lifting limit error type private.
                || source.root_cause().to_string()
                    == concat!(
                        "too much data is being copied between the host and the guest: ",
                        "fuel allocated for hostcalls has been exhausted"
                    ) {
                Code::Limit
            } else {
                Code::Incomplete
            };
            crate::PackageWasmSnafu {
                code,
                operation: "component evaluation",
            }
            .into_error(source)
        });
        store.data().control.check()?;
        result?.map_err(|error| {
            let wire = sdk::wire::EvaluationError::from(error);
            if wire.field.len() > 1024 {
                return Code::Limit.error("component error field");
            }
            crate::AnalysisContractSnafu.into_error(sdk::Error::contract(wire.code, wire.field))
        })
    }
}
