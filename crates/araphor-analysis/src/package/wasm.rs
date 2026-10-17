use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, TryLockError,
};

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;
use tokio::sync::watch;
use wasmtime::{component::Linker, Config, Engine, OptLevel};

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::PackageErrorCodeV1 as Code;

mod admission;
mod bindings;
mod cache;
mod compiler;
mod execution;

#[cfg(any(test, feature = "test-fixtures"))]
mod fixtures;

#[cfg(test)]
mod tests;

pub(crate) struct WasmExecution {
    limits: WasmLimits,
    engine: Engine,
    linker: Linker<execution::GuestState>,
    epoch: Arc<execution::EpochTicker>,
    cache: Mutex<cache::CodeCache>,
    compiler: Mutex<bool>,
    running: AtomicUsize,
    capacity: watch::Sender<()>,
    #[cfg(test)]
    entered: Mutex<Option<execution::GuestEntry>>,
}

#[derive(Clone)]
pub(super) struct PreparedComponent {
    entry: Arc<cache::CacheEntry>,
    _release: CapacityRelease,
}

#[derive(Clone)]
struct CapacityRelease(watch::Sender<()>);

impl Drop for CapacityRelease {
    fn drop(&mut self) {
        self.0.send_replace(());
    }
}

impl PreparedComponent {
    fn component(&self) -> &bindings::AnalysisPackagePre<execution::GuestState> {
        &self.entry.prepared
    }

    fn instance_pre(&self) -> &wasmtime::component::InstancePre<execution::GuestState> {
        self.component().instance_pre()
    }
}

impl WasmExecution {
    pub(in crate::package) async fn wait_capacity(
        &self,
        resource: &str,
        requested: usize,
    ) -> Result<()> {
        let mut changes = self.capacity.subscribe();
        loop {
            changes.borrow_and_update();
            let ready = match resource {
                "component evaluations" => {
                    self.running.load(Ordering::Acquire) < execution::MAX_EVALUATIONS
                }
                "component compiler" => match self.compiler.try_lock() {
                    Ok(compiler) => {
                        if *compiler {
                            return Err(Code::Incomplete
                                .error("component compiler recovery")
                                .into());
                        }
                        true
                    }
                    Err(TryLockError::WouldBlock) => false,
                    Err(TryLockError::Poisoned(_)) => {
                        return Err(Code::Incomplete.error("component compiler lock").into())
                    }
                },
                "component cache capacity" => self
                    .cache
                    .lock()
                    .map_err(|_| Code::Incomplete.error("component cache lock"))?
                    .available(requested),
                _ => return Err(Code::Invalid.error("component capacity resource").into()),
            };
            if ready {
                return Ok(());
            }
            changes
                .changed()
                .await
                .map_err(|_| Code::Incomplete.error("component capacity watch"))?;
        }
    }

    pub(crate) fn limits(limits: sdk::Limits, quota: &WasmLimits) -> sdk::Limits {
        sdk::Limits {
            max_batches: limits.max_batches.min(1024),
            max_rows: limits.max_rows.min(1_000_000),
            max_bytes: quota
                .data_bytes
                .map_or(limits.max_bytes, |maximum| limits.max_bytes.min(maximum)),
            max_checkpoint_bytes: limits.max_checkpoint_bytes.min(16 * 1024 * 1024),
        }
    }

    pub(crate) fn new(limits: WasmLimits) -> Result<Self> {
        let engine = Self::new_engine(limits.fuel.is_some())?;
        let mut linker = Linker::new(&engine);
        bindings::AnalysisPackage::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |state| state,
        )
        .context(crate::PackageWasmSnafu {
            code: Code::Unsupported,
            operation: "analysis host bindings",
        })?;
        let capacity = watch::channel(()).0;
        Ok(Self {
            limits,
            epoch: Arc::new(execution::EpochTicker::new(engine.clone())),
            engine,
            linker,
            cache: Mutex::new(cache::CodeCache::new(capacity.clone())),
            compiler: Mutex::new(false),
            running: AtomicUsize::new(0),
            capacity,
            #[cfg(test)]
            entered: Mutex::new(None),
        })
    }

    fn new_engine(fuel: bool) -> Result<Engine> {
        let mut config = Config::new();
        config
            .consume_fuel(fuel)
            .epoch_interruption(true)
            .cranelift_opt_level(OptLevel::None)
            .cranelift_nan_canonicalization(true)
            .max_wasm_stack(512 * 1024)
            .memory_reservation(256 * 1024 * 1024)
            .memory_reservation_for_growth(0)
            .memory_guard_size(64 * 1024)
            .wasm_component_model(true)
            .wasm_memory64(false)
            .wasm_multi_memory(false)
            .wasm_relaxed_simd(false)
            .wasm_gc(false)
            .wasm_component_model_error_context(false)
            .wasm_component_model_gc(false)
            .wasm_component_model_map(false)
            .wasm_component_model_memory64(false)
            .wasm_component_model_fixed_length_lists(false)
            .wasm_component_model_implements(false);
        Engine::new(&config).context(crate::PackageWasmSnafu {
            code: Code::Unsupported,
            operation: "engine configuration",
        })
    }

    pub(crate) fn admit(&self, bytes: &[u8], control: &AnalysisReadControl) -> Result<()> {
        self.prepare(bytes, control).map(|_| ())
    }

    pub(super) fn prepare(
        &self,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<PreparedComponent> {
        self.compiled(bytes, control)
    }

    #[cfg(test)]
    pub(crate) fn evaluate(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        use std::borrow::Cow;

        control.check()?;
        let prepared = self.prepare(bytes, control)?;
        descriptor
            .validate_evaluation(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let evaluation =
            if Self::limits(evaluation.context.limits, &self.limits) == evaluation.context.limits {
                Cow::Borrowed(evaluation)
            } else {
                let mut evaluation = evaluation.clone();
                evaluation.context.limits = Self::limits(evaluation.context.limits, &self.limits);
                Cow::Owned(evaluation)
            };
        let input = descriptor
            .check_evaluation(&evaluation)
            .and_then(|checked| checked.encode())
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        let output = self.invoke(&prepared, input.into(), control)?;
        let decoded = sdk::wire::Output::from(output)
            .decode(descriptor, &evaluation)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        Ok(decoded)
    }
}
