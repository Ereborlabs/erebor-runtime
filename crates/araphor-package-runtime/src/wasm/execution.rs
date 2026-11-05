use std::sync::Arc;

#[cfg(any(test, feature = "test-fixtures"))]
use std::sync::mpsc;

use araphor_analysis_sdk as sdk;
use snafu::{IntoError as _, ResultExt as _};
use wasmtime::component::{Resource, ResourceTable};
use wasmtime::{Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline};

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::{
    bindings::{self, araphor::analysis::types},
    Code, EvaluationPermit, PreparedComponent,
};

#[derive(snafu::Snafu)]
#[snafu(display("{source}"))]
struct EvaluationFailure {
    // Drop the trap source before the code pin.
    #[snafu(source(from(wasmtime::Error, wasmtime::Error::into_boxed_dyn_error)))]
    source: Box<dyn std::error::Error + Send + Sync>,
    _pin: PreparedComponent,
}

impl std::fmt::Debug for EvaluationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvaluationFailure")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
pub(super) struct GuestEntry {
    pub(super) entered: mpsc::Sender<()>,
    pub(super) release: Option<mpsc::Receiver<()>>,
}

pub(super) struct GuestState {
    table: ResourceTable,
    transfer: Option<sdk::Transfer>,
    limits: StoreLimits,
    control: AnalysisReadControl,
    host_calls: usize,
    host_limit: Option<usize>,
    limited: bool,
    #[cfg(any(test, feature = "test-fixtures"))]
    entered: Option<GuestEntry>,
}

pub struct HostTransaction(pub(crate) Arc<dyn sdk::InvocationService + Send + Sync>);

impl GuestState {
    fn new(control: AnalysisReadControl, quota: &WasmLimits) -> Self {
        let mut limits = StoreLimitsBuilder::new()
            .memories(quota.memories.unwrap_or(usize::MAX))
            .tables(quota.tables.unwrap_or(usize::MAX))
            .instances(quota.instances.unwrap_or(usize::MAX))
            .trap_on_grow_failure(true);
        if let Some(elements) = quota.table_elements {
            limits = limits.table_elements(elements);
        }
        if let Some(bytes) = quota.memory_bytes {
            limits = limits.memory_size(bytes);
        }
        Self {
            table: ResourceTable::new(),
            transfer: None,
            limits: limits.build(),
            control,
            host_calls: 0,
            host_limit: quota.host_calls,
            limited: false,
            #[cfg(any(test, feature = "test-fixtures"))]
            entered: None,
        }
    }
}

impl types::Host for GuestState {}

impl bindings::araphor::analysis::graph::Host for GuestState {}

impl bindings::araphor::analysis::graph::HostTransaction for GuestState {
    fn read(
        &mut self,
        resource: Resource<HostTransaction>,
        name: String,
        arguments: types::Dataset,
    ) -> wasmtime::Result<std::result::Result<types::Input, types::EvaluationError>> {
        self.check_host()?;
        self.transfer.take();
        let host = &self.table.get(&resource)?.0;
        let result = (|| {
            let arguments = sdk::wire::Dataset::from(arguments);
            let schema = host.argument_schema(&name)?;
            let transfer = host.reserve_transfer()?;
            let lifted = arguments
                .arrow_ipc
                .capacity()
                .checked_add(arguments.name.capacity())
                .and_then(|bytes| bytes.checked_add(name.capacity()))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sdk::wire::Dataset>()))
                .ok_or_else(|| {
                    sdk::Error::contract(sdk::ErrorCode::Limit, "Graph lifted arguments")
                })?;
            let available = transfer
                .bytes
                .map(|bytes| {
                    bytes.checked_sub(lifted).ok_or_else(|| {
                        sdk::Error::contract(sdk::ErrorCode::Limit, "Graph lifted arguments")
                    })
                })
                .transpose()?;
            let arguments = sdk::wire::Dataset::decode_ipc_bounded(
                &arguments.name,
                &arguments.arrow_ipc,
                Some(&schema),
                available,
            )?;
            let input = host.read(&name, &arguments)?;
            let schema = input
                .data
                .batches
                .first()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "Graph read schema"))?
                .schema();
            let scratch = input.data.batches.iter().try_fold(0usize, |bytes, batch| {
                Ok::<_, sdk::Error>(bytes.max(sdk::wire::Dataset::encoding_scratch(batch)?))
            })?;
            let retained = arguments
                .allocated_bytes()
                .checked_add(scratch)
                .and_then(|bytes| bytes.checked_add(input.allocated_bytes()))
                .and_then(|bytes| bytes.checked_add(lifted))
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "Graph transfer"))?;
            let remaining = transfer.bytes.map(|bytes| bytes.saturating_sub(retained));
            let result = sdk::wire::Input {
                data: sdk::wire::Dataset::encode_bounded(&input.data, &schema, remaining)?,
                revision: input.revision,
                coverage: input.coverage,
            }
            .into();
            Ok::<_, sdk::Error>((result, transfer))
        })();
        self.control.check().map_err(wasmtime::Error::new)?;
        Ok(match result {
            Ok((result, transfer)) => {
                self.transfer = Some(transfer);
                Ok(result)
            }
            Err(error) => Err(sdk::wire::EvaluationError::from(error).into()),
        })
    }

    fn stage(
        &mut self,
        resource: Resource<HostTransaction>,
        commands: types::Dataset,
    ) -> wasmtime::Result<std::result::Result<(), types::EvaluationError>> {
        self.check_host()?;
        self.transfer.take();
        let host = &self.table.get(&resource)?.0;
        let result = (|| {
            let commands = sdk::wire::Dataset::from(commands);
            let schema = host.command_schema(&commands.name)?;
            let transfer = host.reserve_transfer()?;
            let lifted = commands
                .arrow_ipc
                .capacity()
                .checked_add(commands.name.capacity())
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sdk::wire::Dataset>()))
                .ok_or_else(|| {
                    sdk::Error::contract(sdk::ErrorCode::Limit, "Graph lifted commands")
                })?;
            let available = transfer
                .bytes
                .map(|bytes| {
                    bytes.checked_sub(lifted).ok_or_else(|| {
                        sdk::Error::contract(sdk::ErrorCode::Limit, "Graph lifted commands")
                    })
                })
                .transpose()?;
            let commands = sdk::wire::Dataset::decode_ipc_bounded(
                &commands.name,
                &commands.arrow_ipc,
                Some(&schema),
                available,
            )?;
            host.stage(&commands)
        })();
        self.control.check().map_err(wasmtime::Error::new)?;
        Ok(result.map_err(|error| sdk::wire::EvaluationError::from(error).into()))
    }

    fn drop(&mut self, resource: Resource<HostTransaction>) -> wasmtime::Result<()> {
        self.table.delete(resource)?;
        Ok(())
    }
}

impl GuestState {
    fn charge_host(&mut self) -> wasmtime::Result<()> {
        if self
            .host_limit
            .is_some_and(|maximum| self.host_calls >= maximum)
        {
            self.limited = true;
            return Err(wasmtime::Error::msg("analysis host call limit"));
        }
        self.host_calls = self.host_calls.saturating_add(1);
        Ok(())
    }

    fn check_host(&mut self) -> wasmtime::Result<()> {
        self.charge_host()?;
        self.control.check().map_err(wasmtime::Error::new)
    }
}

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
        #[cfg(any(test, feature = "test-fixtures"))]
        if let Some(entered) = self.entered.take() {
            entered.entered.send(()).map_err(wasmtime::Error::new)?;
            if let Some(release) = entered.release {
                match self.control.remaining().map_err(wasmtime::Error::new)? {
                    Some(timeout) => release.recv_timeout(timeout).map_err(wasmtime::Error::new),
                    None => release.recv().map_err(wasmtime::Error::new),
                }?;
            }
        }
        self.charge_host()?;
        Ok(self.control.check().is_err())
    }
}

struct EpochWatch {
    done: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl EpochWatch {
    fn new(engine: Engine, control: AnalysisReadControl) -> Result<Self> {
        let (done, completed) = tokio::sync::oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("analysis-wasm-interrupt".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                if let Ok(runtime) = runtime {
                    runtime.block_on(async move {
                        tokio::select! {
                            _ = completed => {},
                            () = control.cancelled() => engine.increment_epoch(),
                            () = control.expired() => engine.increment_epoch(),
                        }
                    });
                } else {
                    let _cancelled = control.cancel();
                    engine.increment_epoch();
                }
            })
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component interrupt worker",
            })?;
        Ok(Self {
            done: Some(done),
            worker: Some(worker),
        })
    }
}
impl Drop for EpochWatch {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _sent = done.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _joined = worker.join();
        }
    }
}

impl super::WasmExecution {
    pub fn invoke(
        &self,
        prepared: &PreparedComponent,
        input: types::Evaluation,
        control: &AnalysisReadControl,
    ) -> Result<types::Output> {
        self.invoke_reserved(prepared, input, control, None, None, None)
    }

    pub(super) fn invoke_reserved(
        &self,
        prepared: &PreparedComponent,
        input: types::Evaluation,
        control: &AnalysisReadControl,
        copy_bytes: Option<usize>,
        admission: Option<EvaluationPermit>,
        host: Option<Arc<dyn sdk::InvocationService + Send + Sync>>,
    ) -> Result<types::Output> {
        control.check()?;
        let _permit = match (admission, &self.evaluations) {
            (Some(permit), Some(capacity)) if Arc::ptr_eq(permit.0.semaphore(), capacity) => {
                Some(permit)
            }
            (Some(_), _) => {
                return Err(Code::Invalid.error("component evaluation admission").into())
            }
            (None, _) => self.try_acquire_evaluation()?,
        };
        if !Engine::same(&self.engine, prepared.component().engine()) {
            return Err(Code::Unsupported.error("component engine").into());
        }
        let control = match self.limits.timeout {
            Some(timeout) => control.within(timeout)?,
            None => control.within(control.remaining()?)?,
        };
        let watched = control.within(None)?;
        let mut store = Store::new(&self.engine, GuestState::new(control, &self.limits));
        let graph = host
            .map(|host| store.data_mut().table.push(HostTransaction(host)))
            .transpose()
            .map_err(wasmtime::Error::new)
            .context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "Graph transaction resource",
            })?;
        #[cfg(any(test, feature = "test-fixtures"))]
        {
            store.data_mut().entered = self
                .entered
                .lock()
                .map_err(|_| Code::Incomplete.error("component test gate"))?
                .take();
        }
        store.limiter(|state| state);
        if let Some(fuel) = self.limits.fuel {
            store.set_fuel(fuel).context(crate::PackageWasmSnafu {
                code: Code::Incomplete,
                operation: "component fuel",
            })?;
        }
        store.set_hostcall_fuel(
            self.limits
                .allocation_bytes
                .into_iter()
                .chain(copy_bytes)
                .min()
                .unwrap_or(usize::MAX),
        );
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|store| {
            if store.data().control.check().is_err() {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let _watch = EpochWatch::new(self.engine.clone(), watched)?;
        let result = prepared
            .component()
            .instantiate(&mut store)
            .and_then(|instance| {
                instance.araphor_analysis_analysis().call_evaluate(
                    &mut store,
                    &input,
                    graph
                        .as_ref()
                        .map(|resource| Resource::new_borrow(resource.rep())),
                )
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
            .into_error(wasmtime::Error::new(
                EvaluationFailureSnafu {
                    _pin: prepared.clone(),
                }
                .into_error(source),
            ))
        });
        store.data().control.check()?;
        result?.map_err(|error| {
            let wire = sdk::wire::EvaluationError::from(error);
            crate::AnalysisContractSnafu.into_error(sdk::Error::contract(wire.code, wire.field))
        })
    }
}
