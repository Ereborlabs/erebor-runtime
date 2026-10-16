use std::cell::Cell;
use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{Error, ErrorCode, Evaluation, Output, Package, Result, CONTRACT_VERSION};

mod abi;
mod decode;
mod exchange;
mod streams;
pub use abi::*;
use decode::Decoder;
use exchange::Exchange;

const MAX_ERROR_BYTES: u64 = 1024;

type Cancellation = (unsafe extern "C" fn(*mut c_void) -> i32, *mut c_void);
thread_local! { static CANCELLATION: Cell<Option<Cancellation>> = const { Cell::new(None) }; }

pub fn cancelled() -> bool {
    CANCELLATION.with(|current| {
        current
            .get()
            .is_some_and(|(call, context)| unsafe { call(context) != 0 })
    })
}

struct CancellationScope(Option<Cancellation>);

impl Drop for CancellationScope {
    fn drop(&mut self) {
        CANCELLATION.with(|current| current.set(self.0));
    }
}

pub struct Invocation<'a, F: Fn() -> bool> {
    package: &'a Package,
    evaluation: &'a Evaluation,
    cancelled: Box<F>,
    exchange: Exchange,
}

impl<'a, F: Fn() -> bool> Invocation<'a, F> {
    pub fn new(package: &'a Package, evaluation: &'a Evaluation, cancelled: F) -> Result<Self> {
        Ok(Self {
            package,
            evaluation,
            cancelled: Box::new(cancelled),
            exchange: Exchange::evaluation(package, evaluation)?,
        })
    }

    /// Call the native table and copy all returned storage into the host.
    ///
    /// # Safety
    /// The table and callbacks must be valid until this call returns.
    /// The producer must obey the v1 pointer and ownership contract.
    pub unsafe fn call(mut self, api: &Api, output_limits: crate::Limits) -> Result<Output> {
        api.validate()?;
        output_limits.validate()?;
        if !self.evaluation.context.limits.permits(&output_limits) {
            return Err(Error::contract(ErrorCode::Limit, "native output limits"));
        }
        if (self.cancelled)() {
            return Err(Error::contract(ErrorCode::Incomplete, "cancelled"));
        }
        let request = self.request();
        let context = &self.evaluation.context;
        let mut response = Response::default();
        let guard = ResponseGuard {
            api,
            response: &mut response,
        };
        let evaluate = api
            .evaluate
            .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "native evaluate"))?;
        let status = unsafe { evaluate(&request, guard.response) };
        if (self.cancelled)() {
            return Err(Error::contract(ErrorCode::Incomplete, "cancelled"));
        }
        if status != guard.response.error.code {
            return Err(Error::contract(ErrorCode::Invalid, "native error status"));
        }
        if status != 0 {
            let code = match status {
                1 => ErrorCode::Invalid,
                2 => ErrorCode::Incompatible,
                3 => ErrorCode::Unauthorized,
                4 => ErrorCode::Incomplete,
                5 => ErrorCode::Failed,
                6 => ErrorCode::Limit,
                _ => return Err(Error::contract(ErrorCode::Invalid, "native error code")),
            };
            let field = guard.response.error.field;
            if field.size > MAX_ERROR_BYTES || field.size > context.limits.max_bytes {
                return Err(Error::contract(ErrorCode::Limit, "native error field"));
            }
            if field.size > 0 && field.data.is_null() {
                return Err(Error::contract(ErrorCode::Invalid, "native error field"));
            }
            let bytes = if field.size == 0 {
                &[][..]
            } else {
                unsafe { std::slice::from_raw_parts(field.data, field.size as usize) }
            };
            let field = std::str::from_utf8(bytes)
                .map_err(|_| Error::contract(ErrorCode::Invalid, "native error UTF-8"))?;
            return Err(Error::contract(code, field));
        }
        catch_unwind(AssertUnwindSafe(|| unsafe {
            Decoder::output(self.package, self.evaluation, guard.response, output_limits)
        }))
        .map_err(|_| Error::contract(ErrorCode::Invalid, "native output"))?
    }

    fn request(&mut self) -> Request {
        let context = &self.evaluation.context;
        Request {
            export_name: Bytes::new(self.evaluation.export.as_bytes()),
            inputs: self.exchange.inputs.as_ptr(),
            input_count: self.exchange.inputs.len() as u64,
            parameters: self.exchange.parameters,
            context: Context {
                id: Bytes::new(context.id.as_bytes()),
                time_utc_ns: context.time_utc_ns,
                seed: context.seed.unwrap_or_default(),
                has_seed: u8::from(context.seed.is_some()),
                limits: context.limits,
            },
            checkpoint: self.exchange.checkpoint_ptr(),
            cancelled: Some(cancel_callback::<F>),
            cancel_context: (&mut *self.cancelled as *mut F).cast(),
        }
    }
}

struct ResponseGuard<'a> {
    api: &'a Api,
    response: &'a mut Response,
}

impl Drop for ResponseGuard<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.api.release {
            unsafe { release(self.response) };
        }
    }
}

unsafe extern "C" fn cancel_callback<F: Fn() -> bool>(context: *mut c_void) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        i32::from((&*context.cast::<F>())())
    }))
    .unwrap_or(1)
}

struct OwnedResponse {
    _output: Option<Box<Output>>,
    exchange: Option<Exchange>,
    field: String,
}

impl Api {
    pub const fn for_guest<G: crate::Guest>() -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            struct_size: std::mem::size_of::<Self>() as u64,
            evaluate: Some(evaluate::<G>),
            release: Some(release),
        }
    }
}

unsafe extern "C" fn evaluate<G: crate::Guest>(
    request: *const Request,
    response: *mut Response,
) -> u32 {
    if response.is_null() || !(response as usize).is_multiple_of(std::mem::align_of::<Response>()) {
        return ErrorCode::Invalid as u32;
    }
    unsafe {
        *response = Response::default();
    }
    let result = catch_unwind(AssertUnwindSafe(|| unsafe { evaluate_guest::<G>(request) }))
        .unwrap_or_else(|_| Err(Error::contract(ErrorCode::Failed, "native panic")));
    let (code, mut owned) = match result {
        Ok(owned) => (0, owned),
        Err(error) => {
            let mut error = crate::wire::EvaluationError::from(error);
            if error.field.len() as u64 > MAX_ERROR_BYTES {
                error.code = ErrorCode::Limit;
                error.field = "native error field".into();
            }
            (
                error.code as u32,
                Box::new(OwnedResponse {
                    _output: None,
                    exchange: None,
                    field: error.field,
                }),
            )
        }
    };
    let target = unsafe { &mut *response };
    if let Some(frame) = &mut owned.exchange {
        target.datasets = frame.datasets.as_ptr();
        target.dataset_count = frame.datasets.len() as u64;
        target.evidence = frame.evidence.as_ptr();
        target.evidence_count = frame.evidence.len() as u64;
        target.reasons = frame.reasons.as_ptr();
        target.reason_count = frame.reasons.len() as u64;
        target.checkpoint = frame.checkpoint_ptr();
    }
    target.error = NativeError {
        code,
        field: Bytes::new(owned.field.as_bytes()),
    };
    target.private_data = Box::into_raw(owned).cast();
    code
}

unsafe fn evaluate_guest<G: crate::Guest>(request: *const Request) -> Result<Box<OwnedResponse>> {
    if request.is_null() || !(request as usize).is_multiple_of(std::mem::align_of::<Request>()) {
        return Err(Error::contract(ErrorCode::Invalid, "native request"));
    }
    let request = unsafe { &*request };
    let cancellation = request.cancelled.map(|call| (call, request.cancel_context));
    let _scope = CancellationScope(CANCELLATION.with(|current| current.replace(cancellation)));
    if cancelled() {
        return Err(Error::contract(ErrorCode::Incomplete, "cancelled"));
    }
    let package = G::package();
    let (evaluation, model) = unsafe { Decoder::evaluation(&package, request)? };
    let checked = crate::CheckedEvaluation::new(&package, model, &evaluation);
    let output = G::compute(&checked)?;
    if cancelled() {
        return Err(Error::contract(ErrorCode::Incomplete, "cancelled"));
    }
    checked.validate_output(&output)?;
    let output = Box::new(output);
    let exchange = Exchange::output(checked.model(), &output)?;
    Ok(Box::new(OwnedResponse {
        _output: Some(output),
        exchange: Some(exchange),
        field: String::new(),
    }))
}

unsafe extern "C" fn release(response: *mut Response) {
    let _result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if response.is_null() {
            return;
        }
        let private = (*response).private_data;
        *response = Response::default();
        if !private.is_null() {
            drop(Box::from_raw(private.cast::<OwnedResponse>()));
        }
    }));
}

/// Export a Rust guest through the native v1 table.
#[macro_export]
macro_rules! export_native {
    ($guest:ty) => {
        #[allow(unsafe_code)]
        #[no_mangle]
        pub extern "C" fn araphor_analysis_get_api_v1() -> *const $crate::native::Api {
            static API: $crate::native::Api = $crate::native::Api::for_guest::<$guest>();
            &API
        }
    };
}

#[cfg(test)]
mod tests;
