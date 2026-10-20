use std::sync::{atomic::AtomicUsize, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::{Code, WasmExecution};

#[derive(Debug, snafu::Snafu)]
#[snafu(display("component fixture cache charges: {charges:?}"))]
struct FixtureBudgetError {
    charges: [usize; 5],
}

impl WasmExecution {
    pub fn guest_entry(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Result<()> {
        *self
            .entered
            .lock()
            .map_err(|_| Code::Incomplete.error("component test gate"))? =
            Some(super::execution::GuestEntry { entered, release });
        Ok(())
    }
    pub fn observe_guest(&self) -> Result<std::sync::mpsc::Receiver<()>> {
        let (entered, receiver) = std::sync::mpsc::channel();
        self.guest_entry(entered, None)?;
        Ok(receiver)
    }
    pub fn fixture_code(limits: WasmLimits) -> Result<Self> {
        if limits.cache_bytes.is_some()
            || limits.cache_entries.is_some()
            || limits.compiler_bytes.is_some()
            || limits.image_bytes.is_some()
        {
            return Self::new(limits);
        }
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
            cache: Mutex::new(cache),
            compiler: Mutex::new(()),
            running: AtomicUsize::new(0),
            capacity: prepared.capacity.clone(),
            #[cfg(any(test, feature = "test-fixtures"))]
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
