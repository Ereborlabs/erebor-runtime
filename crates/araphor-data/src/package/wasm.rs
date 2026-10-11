use std::{
    borrow::Cow,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;
use wasmtime::{component::Linker, Config, Engine, OptLevel};

use crate::{AnalysisReadControl, Result};

use super::PackageErrorCodeV1 as Code;

mod admission;
mod bindings;
mod cache;
mod compiler;
mod execution;

#[cfg(any(test, feature = "test-fixtures"))]
mod fixtures;

const MAX_LIFT_BYTES: usize = 32 * 1024 * 1024;
const MAX_DATA_BYTES: u64 = 32 * 1024 * 1024;

#[cfg(test)]
mod tests;

pub(crate) struct WasmExecution {
    engine: Engine,
    linker: Linker<execution::GuestState>,
    epoch: Arc<execution::EpochTicker>,
    cache: Mutex<cache::CodeCache>,
    compiler: Mutex<bool>,
    running: AtomicUsize,
    #[cfg(test)]
    entered: Mutex<Option<execution::GuestEntry>>,
}

impl WasmExecution {
    pub(crate) fn limits(limits: sdk::Limits) -> sdk::Limits {
        sdk::Limits {
            max_batches: limits.max_batches.min(1024),
            max_rows: limits.max_rows.min(1_000_000),
            max_bytes: limits.max_bytes.min(MAX_DATA_BYTES),
            max_checkpoint_bytes: limits.max_checkpoint_bytes.min(16 * 1024 * 1024),
        }
    }

    pub(crate) fn new() -> Result<Self> {
        let engine = Self::new_engine()?;
        let mut linker = Linker::new(&engine);
        bindings::AnalysisPackage::add_to_linker::<_, wasmtime::component::HasSelf<_>>(
            &mut linker,
            |state| state,
        )
        .context(crate::PackageWasmSnafu {
            code: Code::Unsupported,
            operation: "analysis host bindings",
        })?;
        Ok(Self {
            epoch: Arc::new(execution::EpochTicker::new(engine.clone())),
            engine,
            linker,
            cache: Mutex::new(cache::CodeCache::default()),
            compiler: Mutex::new(false),
            running: AtomicUsize::new(0),
            #[cfg(test)]
            entered: Mutex::new(None),
        })
    }

    fn new_engine() -> Result<Engine> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
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
        self.compiled(bytes, control).map(|_| ())
    }

    #[cfg(test)]
    pub(crate) fn evaluate(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        self.evaluate_input(descriptor, evaluation, bytes, None, control)
    }

    pub(crate) fn evaluate_encoded(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        input: sdk::wire::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        self.evaluate_input(descriptor, evaluation, bytes, Some(input), control)
    }

    fn evaluate_input(
        &self,
        descriptor: &sdk::Package,
        evaluation: &sdk::Evaluation,
        bytes: &[u8],
        input: Option<sdk::wire::Evaluation>,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Output> {
        control.check()?;
        let _permit = execution::EvaluationPermit::acquire(&self.running)?;
        let component = self.compiled(bytes, control)?;
        descriptor
            .validate_evaluation(evaluation)
            .context(crate::AnalysisContractSnafu)?;
        let evaluation = if Self::limits(evaluation.context.limits) == evaluation.context.limits {
            Cow::Borrowed(evaluation)
        } else {
            let mut evaluation = evaluation.clone();
            evaluation.context.limits = Self::limits(evaluation.context.limits);
            Cow::Owned(evaluation)
        };
        let input = match input {
            Some(input) => input,
            None => sdk::wire::Evaluation::encode(descriptor, &evaluation)
                .context(crate::AnalysisContractSnafu)?,
        };
        control.check()?;
        let output = self.invoke(&component, input.into(), control)?;
        let decoded = sdk::wire::Output::from(output)
            .decode(descriptor, &evaluation)
            .context(crate::AnalysisContractSnafu)?;
        control.check()?;
        Ok(decoded)
    }
}
