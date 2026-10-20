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
mod execution;

#[cfg(any(test, feature = "test-fixtures"))]
mod fixtures;

#[cfg(test)]
mod tests;

pub struct WasmExecution {
    pub(crate) limits: WasmLimits,
    engine: Engine,
    linker: Linker<execution::GuestState>,
    cache: Mutex<cache::CodeCache>,
    compiler: Mutex<()>,
    running: AtomicUsize,
    capacity: watch::Sender<()>,
    #[cfg(any(test, feature = "test-fixtures"))]
    entered: Mutex<Option<execution::GuestEntry>>,
}

#[derive(Clone)]
pub struct PreparedComponent {
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
    pub async fn wait_capacity(&self, resource: &str, requested: usize) -> Result<()> {
        let mut changes = self.capacity.subscribe();
        loop {
            changes.borrow_and_update();
            let ready = match resource {
                "component evaluations" => self
                    .limits
                    .evaluations
                    .is_none_or(|maximum| self.running.load(Ordering::Acquire) < maximum),
                "component compiler" => match self.compiler.try_lock() {
                    Ok(_compiler) => true,
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

    pub fn limits(limits: sdk::Limits, quota: &WasmLimits) -> sdk::Limits {
        sdk::Limits {
            max_bytes: quota
                .data_bytes
                .map_or(limits.max_bytes, |maximum| limits.max_bytes.min(maximum)),
            max_checkpoint_bytes: quota
                .data_bytes
                .map_or(limits.max_checkpoint_bytes, |maximum| {
                    limits.max_checkpoint_bytes.min(maximum)
                }),
            ..limits
        }
    }

    pub fn new(limits: WasmLimits) -> Result<Self> {
        if limits.compiler_bytes.is_some() {
            return Err(Code::Unsupported
                .error("in-process compiler memory limit")
                .into());
        }
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
            engine,
            linker,
            cache: Mutex::new(cache::CodeCache::new(capacity.clone(), limits)),
            compiler: Mutex::new(()),
            running: AtomicUsize::new(0),
            capacity,
            #[cfg(any(test, feature = "test-fixtures"))]
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

    pub fn admit(&self, bytes: &[u8], control: &AnalysisReadControl) -> Result<()> {
        self.prepare(bytes, control).map(|_| ())
    }

    pub fn prepare(
        &self,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<PreparedComponent> {
        self.compiled(bytes, control)
    }

    pub fn evaluate(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        self.evaluate_reserved(descriptor, evaluation, bytes, control, None)
    }

    pub(crate) fn evaluate_reserved(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        control: &AnalysisReadControl,
        copy_bytes: Option<usize>,
    ) -> Result<sdk::Output> {
        control.check()?;
        let prepared = self.prepare(bytes, control)?;
        self.evaluate_prepared(descriptor, evaluation, &prepared, control, copy_bytes)
    }

    pub(crate) fn evaluate_prepared(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        prepared: &PreparedComponent,
        control: &AnalysisReadControl,
        copy_bytes: Option<usize>,
    ) -> Result<sdk::Output> {
        use std::borrow::Cow;

        control.check()?;
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
        let output = self.invoke_reserved(prepared, input.into(), control, copy_bytes)?;
        let decoded = sdk::wire::Output::from(output)
            .decode(descriptor, &evaluation)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        Ok(decoded)
    }
}
