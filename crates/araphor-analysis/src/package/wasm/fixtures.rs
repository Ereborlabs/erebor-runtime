use std::sync::{atomic::AtomicUsize, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{AnalysisPackageOwner, AnalysisReadControl, Result, WasmLimits};

use super::{Code, WasmExecution};

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component fixture cache charges: {charges:?}"))]
struct FixtureBudgetError {
    charges: [usize; 5],
}

impl AnalysisPackageOwner {
    #[cfg(test)]
    pub fn observe_guest(&self) -> Result<std::sync::mpsc::Receiver<()>> {
        let (entered, receiver) = std::sync::mpsc::channel();
        *self
            .wasm
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? =
            Some(super::execution::GuestEntry {
                entered,
                release: None,
            });
        Ok(receiver)
    }

    /// Reuse compiled fixture code and keep each evaluation store separate.
    /// This method is available for tests and the test-fixtures feature.
    pub fn prepare_test_code(&mut self) -> Result<()> {
        self.wasm = WasmExecution::fixture_code(self.wasm.limits)?;
        Ok(())
    }
}

impl WasmExecution {
    pub(super) fn fixture_code(limits: WasmLimits) -> Result<Self> {
        static FIXTURES: Mutex<[Option<WasmExecution>; 2]> = Mutex::new([None, None]);
        let mut fixtures = FIXTURES
            .lock()
            .map_err(|_| Code::Incomplete.error("component fixture code lock"))?;
        let fixture = &mut fixtures[usize::from(limits.fuel.is_some())];
        if fixture.is_none() {
            let prepared = Self::new(WasmLimits {
                fuel: limits.fuel,
                ..WasmLimits::default()
            })?;
            let sources = Self::fixture_sources();
            let mut charges = [0; 5];
            for (index, (_, source)) in sources.iter().enumerate() {
                prepared.admit(
                    source,
                    &AnalysisReadControl::with_timeout(Duration::from_secs(45))?,
                )?;
                charges[index] = prepared
                    .cache
                    .lock()
                    .map_err(|_| Code::Incomplete.error("component fixture cache lock"))?
                    .charge(&Sha256::digest(source).into())
                    .ok_or_else(|| Code::Incomplete.error("component fixture cache entry"))?;
            }
            for (_, source) in sources {
                if prepared.cached(&Sha256::digest(source).into())?.is_none() {
                    return Err(wasmtime::Error::new(FixtureBudgetError { charges })).context(
                        crate::PackageWasmSnafu {
                            code: Code::Limit,
                            operation: "component fixture cache bytes",
                        },
                    );
                }
            }
            *fixture = Some(prepared);
        }
        let prepared = fixture
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("component fixture code"))?;
        let cache = prepared
            .cache
            .lock()
            .map_err(|_| Code::Incomplete.error("component fixture cache lock"))?
            .clone();
        Ok(Self {
            limits,
            engine: prepared.engine.clone(),
            linker: prepared.linker.clone(),
            epoch: prepared.epoch.clone(),
            cache: Mutex::new(cache),
            compiler: Mutex::new(false),
            running: AtomicUsize::new(0),
            capacity: prepared.capacity.clone(),
            #[cfg(test)]
            entered: Mutex::new(None),
        })
    }

    fn fixture_sources() -> [(&'static str, &'static [u8]); 5] {
        [
            (
                "discovery",
                araphor_analysis_builtins::components::DISCOVERY,
            ),
            ("process", araphor_analysis_builtins::components::PROCESS),
            (
                "credentials",
                araphor_analysis_builtins::components::CREDENTIALS,
            ),
            (
                "kubernetes",
                araphor_analysis_builtins::components::KUBERNETES,
            ),
            ("runtime", araphor_analysis_builtins::components::RUNTIME),
        ]
    }
}

#[cfg(test)]
mod tests;
