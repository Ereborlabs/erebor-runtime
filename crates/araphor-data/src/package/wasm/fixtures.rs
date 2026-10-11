use std::sync::{atomic::AtomicUsize, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{AnalysisPackageOwner, AnalysisReadControl, Result};

use super::{Code, WasmExecution};

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component fixture cache charges: {charges:?}"))]
struct FixtureBudgetError {
    charges: [usize; 5],
}

impl AnalysisPackageOwner {
    /// Reuse compiled fixture code and keep each evaluation store separate.
    /// This method is available for tests and the test-fixtures feature.
    pub fn prepare_test_code(&mut self) -> Result<()> {
        self.wasm = WasmExecution::fixture_code()?;
        Ok(())
    }
}

impl WasmExecution {
    pub(super) fn fixture_code() -> Result<Self> {
        static FIXTURES: Mutex<Option<WasmExecution>> = Mutex::new(None);
        let mut fixtures = FIXTURES
            .lock()
            .map_err(|_| Code::Incomplete.error("component fixture code lock"))?;
        if fixtures.is_none() {
            let prepared = Self::new()?;
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
            *fixtures = Some(prepared);
        }
        let prepared = fixtures
            .as_ref()
            .ok_or_else(|| Code::Incomplete.error("component fixture code"))?;
        let cache = prepared
            .cache
            .lock()
            .map_err(|_| Code::Incomplete.error("component fixture cache lock"))?
            .clone();
        Ok(Self {
            engine: prepared.engine.clone(),
            linker: prepared.linker.clone(),
            epoch: prepared.epoch.clone(),
            cache: Mutex::new(cache),
            compiler: Mutex::new(false),
            running: AtomicUsize::new(0),
            #[cfg(test)]
            entered: Mutex::new(None),
        })
    }

    fn fixture_sources() -> [(&'static str, &'static [u8]); 5] {
        [
            (
                "discovery",
                include_bytes!("../../../../araphor-analysis-builtins/artifacts/discovery.wasm"),
            ),
            (
                "process",
                include_bytes!("../../../../araphor-analysis-builtins/artifacts/process.wasm"),
            ),
            (
                "credentials",
                include_bytes!("../../../../araphor-analysis-builtins/artifacts/credentials.wasm"),
            ),
            (
                "kubernetes",
                include_bytes!("../../../../araphor-analysis-builtins/artifacts/kubernetes.wasm"),
            ),
            (
                "runtime",
                include_bytes!("../../../../araphor-analysis-sdk/tests/artifacts/runtime.wasm"),
            ),
        ]
    }
}

#[cfg(test)]
mod tests;
