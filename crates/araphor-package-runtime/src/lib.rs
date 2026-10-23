use std::sync::{Arc, Mutex, Weak};

use araphor_analysis_sdk as sdk;
use araphor_package::{PackageBundleV1, PackageImplementationV1, PackageRefV1};
use snafu::ResultExt as _;

pub use araphor_data::{AnalysisReadControl, PackageErrorCodeV1};
pub use tokio_util::task::task_tracker::{TaskTracker, TaskTrackerToken};

mod error;
mod limits;
pub mod native;
pub mod wasm;

pub(crate) use error::{
    AnalysisBusySnafu, AnalysisContractSnafu, IoSnafu, PackageNativeSnafu, PackageWasmSnafu,
};
pub use error::{Error, Result};
pub use limits::{Limits, WasmLimits};

pub struct Runtime {
    limits: Limits,
    wasm: Mutex<Option<Arc<wasm::WasmExecution>>>,
    #[cfg(any(test, feature = "test-fixtures"))]
    preparing: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}

#[derive(Clone)]
pub struct Prepared {
    runtime: Weak<Runtime>,
    bundle: Arc<PackageBundleV1>,
    package: PackageRefV1,
    export: String,
    component: wasm::PreparedComponent,
}

struct Pending {
    control: AnalysisReadControl,
    complete: bool,
}

impl Drop for Pending {
    fn drop(&mut self) {
        if !self.complete {
            let _cancelled = self.control.cancel();
        }
    }
}

impl Prepared {
    pub async fn acquire_evaluation(
        &self,
        control: &AnalysisReadControl,
    ) -> Result<Option<wasm::EvaluationPermit>> {
        let runtime = self
            .runtime
            .upgrade()
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("prepared runtime is closed"))?;
        runtime.wasm()?.acquire_evaluation(control).await
    }
}

impl Runtime {
    pub fn new(limits: Limits) -> Result<Arc<Self>> {
        if limits.native.memory_bytes == Some(0) || limits.native.cpu_seconds == Some(0) {
            limits.native.validate()?;
        }
        Ok(Arc::new(Self {
            limits,
            wasm: Mutex::new(None),
            #[cfg(any(test, feature = "test-fixtures"))]
            preparing: Mutex::new(None),
        }))
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn guest_entry(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: Option<std::sync::mpsc::Receiver<()>>,
    ) -> Result<()> {
        self.wasm()?.guest_entry(entered, release)
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn guest_cached(&self, bytes: &[u8]) -> Result<bool> {
        use sha2::Digest as _;

        Ok(self
            .wasm()?
            .cached(&sha2::Sha256::digest(bytes).into())?
            .is_some())
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn preparation_entry(
        &self,
        entered: std::sync::mpsc::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    ) -> Result<()> {
        *self
            .preparing
            .lock()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("preparation test gate"))? =
            Some((entered, release));
        Ok(())
    }

    pub fn prepare(
        self: &Arc<Self>,
        bundle: Arc<PackageBundleV1>,
        package: PackageRefV1,
        export: String,
        control: &AnalysisReadControl,
    ) -> Result<Option<Prepared>> {
        control.check()?;
        let artifact = bundle.artifact(&package)?;
        match artifact.implementation(&export)? {
            PackageImplementationV1::Wasm {
                artifact: bytes, ..
            } => {
                #[cfg(any(test, feature = "test-fixtures"))]
                {
                    let preparing = self
                        .preparing
                        .lock()
                        .map_err(|_| PackageErrorCodeV1::Incomplete.error("preparation test gate"))?
                        .take();
                    if let Some((entered, release)) = preparing {
                        entered.send(()).map_err(|_| {
                            PackageErrorCodeV1::Incomplete.error("preparation test entry")
                        })?;
                        if let Some(timeout) = control.remaining()? {
                            release.recv_timeout(timeout).map_err(|_| {
                                PackageErrorCodeV1::Incomplete.error("preparation test release")
                            })?;
                        } else {
                            release.recv().map_err(|_| {
                                PackageErrorCodeV1::Incomplete.error("preparation test release")
                            })?;
                        }
                    }
                }
                let component = self.wasm()?.prepare(bytes, control)?;
                Ok(Some(Prepared {
                    runtime: Arc::downgrade(self),
                    bundle,
                    package,
                    export,
                    component,
                }))
            }
            PackageImplementationV1::Native { .. } => {
                self.limits.native.validate()?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    pub async fn wait_capacity(&self, resource: &str, requested: usize) -> Result<()> {
        self.wasm()?.wait_capacity(resource, requested).await
    }

    fn wasm(&self) -> Result<Arc<wasm::WasmExecution>> {
        let mut runtime = self
            .wasm
            .lock()
            .map_err(|_| PackageErrorCodeV1::Incomplete.error("Wasm runtime lock"))?;
        if runtime.is_none() {
            *runtime = Some(Arc::new(wasm::WasmExecution::new(self.limits.wasm)?));
        }
        runtime
            .as_ref()
            .cloned()
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("Wasm runtime").into())
    }

    pub async fn evaluate(
        self: &Arc<Self>,
        bundle: Arc<PackageBundleV1>,
        package: PackageRefV1,
        evaluation: sdk::Evaluation,
        control: AnalysisReadControl,
        workers: &TaskTracker,
    ) -> Result<(sdk::Evaluation, sdk::Output)> {
        self.evaluate_reserved(
            bundle,
            package,
            evaluation,
            control,
            workers,
            None,
            None,
            None,
            (),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate_reserved(
        self: &Arc<Self>,
        bundle: Arc<PackageBundleV1>,
        package: PackageRefV1,
        evaluation: sdk::Evaluation,
        control: AnalysisReadControl,
        workers: &TaskTracker,
        copy_bytes: Option<usize>,
        prepared: Option<Prepared>,
        admission: Option<wasm::EvaluationPermit>,
        lease: impl Send + 'static,
    ) -> Result<(sdk::Evaluation, sdk::Output)> {
        let worker_token = workers.token();
        if workers.is_closed() {
            return Err(PackageErrorCodeV1::Incomplete
                .error("runtime scope is closed")
                .into());
        }
        control.check()?;
        if prepared.as_ref().is_some_and(|prepared| {
            !prepared.runtime.ptr_eq(&Arc::downgrade(self))
                || !Arc::ptr_eq(&prepared.bundle, &bundle)
                || prepared.package != package
                || prepared.export != evaluation.export
        }) {
            return Err(PackageErrorCodeV1::Invalid
                .error("prepared package binding")
                .into());
        }
        let artifact = bundle.artifact(&package)?;
        let wasm = match artifact.implementation(&evaluation.export)? {
            PackageImplementationV1::Wasm { .. } => Some(self.wasm()?),
            PackageImplementationV1::Native { .. } => {
                self.limits.native.validate()?;
                None
            }
            _ => {
                return Err(PackageErrorCodeV1::Unsupported
                    .error("runtime target")
                    .into())
            }
        };
        if wasm.is_none() && admission.is_some() {
            return Err(PackageErrorCodeV1::Invalid
                .error("component evaluation admission")
                .into());
        }
        let stage = control.within(None)?;
        let mut pending = Pending {
            control: stage.within(None)?,
            complete: false,
        };
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut worker = tokio::task::spawn_blocking(move || {
            let _worker_token = worker_token;
            // Keep the slot until the worker releases its exchange memory.
            let _admission = admission.as_ref().map(wasm::EvaluationPermit::retain);
            let _lease = lease;
            let result: Result<_> = (move || {
                let artifact = bundle.artifact(&package)?;
                let implementation = artifact.implementation(&evaluation.export)?;
                if let Some(runtime) = wasm {
                    let PackageImplementationV1::Wasm {
                        artifact: bytes, ..
                    } = implementation
                    else {
                        return Err(PackageErrorCodeV1::Invalid.error("runtime target").into());
                    };
                    let prepared = match prepared {
                        Some(prepared) => prepared.component,
                        None => runtime.prepare(bytes, &stage)?,
                    };
                    let output = runtime.evaluate_prepared(
                        &artifact.descriptor,
                        &evaluation,
                        &prepared,
                        &stage,
                        copy_bytes,
                        admission,
                    )?;
                    Ok((evaluation, output))
                } else {
                    let PackageImplementationV1::Native {
                        artifact: bytes,
                        qualification: Some(qualification),
                        ..
                    } = implementation
                    else {
                        return Err(PackageErrorCodeV1::Unsupported
                            .error("native qualification")
                            .into());
                    };
                    let checked = artifact
                        .descriptor
                        .check_evaluation(&evaluation)
                        .context(AnalysisContractSnafu)?;
                    let library = native::NativeLibrary::load(bytes, qualification, &stage)?;
                    let output = library.call(&checked, copy_bytes, &stage)?;
                    checked
                        .validate_output(&output)
                        .context(AnalysisContractSnafu)?;
                    stage.check()?;
                    Ok((evaluation, output))
                }
            })();
            drop(send.send(result));
        });
        let result = tokio::select! {
            result = &mut worker => {
                result.context(error::WorkerSnafu)?;
                receive.await.context(error::WorkerResultSnafu)?
            }
            () = control.cancelled() => {
                let _cancelled = pending.control.cancel();
                let _finished = worker.await;
                control.check()?;
                return Err(PackageErrorCodeV1::Incomplete.error("runtime cancellation").into());
            }
            () = control.expired() => {
                let expired = control.check();
                let _cancelled = pending.control.cancel();
                let _finished = worker.await;
                expired?;
                return Err(PackageErrorCodeV1::Incomplete.error("runtime deadline").into());
            }
        };
        pending.complete = true;
        control.check()?;
        result
    }
}
