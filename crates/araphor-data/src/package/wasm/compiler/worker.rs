use std::io::Read as _;

use snafu::ResultExt as _;

use crate::{AnalysisPackageOwner, AnalysisReadControl, Result};

use super::super::{admission::CompileBudget, admission::MAX_SOURCE_BYTES, cache::MAX_IMAGE_BYTES};
use super::{image::CompilerImage, Code, WasmExecution, WORKER_ARG};

impl AnalysisPackageOwner {
    /// Run the compiler child before application setup.
    /// Call this method at the start of the synchronous executable entry point.
    pub fn run_worker_if_requested() -> Result<bool> {
        let mut arguments = std::env::args_os().skip(1);
        if arguments.next().as_deref() != Some(std::ffi::OsStr::new(WORKER_ARG)) {
            return Ok(false);
        }
        if arguments.next().is_some() {
            return Err(Code::Invalid.error("component compiler arguments"));
        }
        Self::run_compiler_worker()?;
        Ok(true)
    }

    /// Run a compiler child with the required process limits.
    /// A test executable calls this method from its ignored compiler test.
    pub fn run_compiler_worker() -> Result<()> {
        WasmExecution::worker_limits()?;
        let result = WasmExecution::worker_image();
        CompilerImage::write(&result, std::io::stderr().lock())
    }
}

impl WasmExecution {
    #[cfg(unix)]
    pub(super) fn worker_limits() -> Result<()> {
        use rustix::process::{getrlimit, Resource};

        for (resource, maximum) in [
            (Resource::As, super::MAX_ADDRESS_BYTES),
            (Resource::Cpu, super::MAX_CPU_SECONDS),
            (Resource::Core, 0),
        ] {
            let limits = getrlimit(resource);
            if limits.current.is_none_or(|value| value > maximum)
                || limits.maximum.is_none_or(|value| value > maximum)
            {
                return Err(Code::Unsupported.error("component compiler process limits"));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn worker_limits() -> Result<()> {
        Err(Code::Unsupported.error("component compiler process limits"))
    }

    fn worker_image() -> Result<Vec<u8>> {
        let mut source = Vec::new();
        source
            .try_reserve_exact(MAX_SOURCE_BYTES + 1)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Limit,
                operation: "component compiler source allocation",
            })?;
        std::io::stdin()
            .lock()
            .take((MAX_SOURCE_BYTES + 1) as u64)
            .read_to_end(&mut source)
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component compiler source read",
            })?;
        let control = AnalysisReadControl::with_timeout(super::MAX_WALL_TIME)?;
        CompileBudget::check(&source, &control)?;
        let engine = Self::new_engine()?;
        let image = engine
            .precompile_component(&source)
            .context(crate::PackageWasmSnafu {
                code: Code::Invalid,
                operation: "component compilation",
            })?;
        if image.len() > MAX_IMAGE_BYTES {
            return Err(Code::Limit.error("component compiled image"));
        }
        Ok(image)
    }
}
