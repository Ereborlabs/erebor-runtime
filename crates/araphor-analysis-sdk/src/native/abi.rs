use std::ffi::c_void;

use arrow_array::ffi_stream::FFI_ArrowArrayStream;

use crate::{Error, ErrorCode, Limits, Result, CONTRACT_VERSION};

pub const ACCESSOR_SYMBOL: &[u8] = b"araphor_analysis_get_api_v1\0";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub data: *const u8,
    pub size: u64,
}

impl Bytes {
    pub(super) fn new(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            size: bytes.len() as u64,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Context {
    pub id: Bytes,
    pub time_utc_ns: i64,
    pub seed: u64,
    pub has_seed: u8,
    pub limits: NativeLimits,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NativeLimits {
    pub max_batches: u32,
    pub max_rows: u64,
    pub max_bytes: u64,
    pub max_checkpoint_bytes: u64,
}

impl From<Limits> for NativeLimits {
    fn from(value: Limits) -> Self {
        Self {
            max_batches: value.max_batches,
            max_rows: value.max_rows,
            max_bytes: value.max_bytes,
            max_checkpoint_bytes: value.max_checkpoint_bytes,
        }
    }
}

impl From<NativeLimits> for Limits {
    fn from(value: NativeLimits) -> Self {
        Self {
            max_batches: value.max_batches,
            max_rows: value.max_rows,
            max_bytes: value.max_bytes,
            max_checkpoint_bytes: value.max_checkpoint_bytes,
        }
    }
}

#[repr(C)]
pub struct Window {
    pub source: Bytes,
    pub start_utc_ns: i64,
    pub end_utc_ns: i64,
}

#[repr(C)]
pub struct Revision {
    pub owner: Bytes,
    pub id: Bytes,
    pub window: *const Window,
}

#[repr(C)]
pub struct Coverage {
    pub state: u32,
    pub limits: *const Bytes,
    pub limit_count: u64,
}

#[repr(C)]
pub struct Dataset {
    pub name: Bytes,
    pub batches: *mut FFI_ArrowArrayStream,
}

#[repr(C)]
pub struct Input {
    pub data: Dataset,
    pub revision: Revision,
    pub coverage: Coverage,
}

#[repr(C)]
pub struct Checkpoint {
    pub version: u32,
    pub datasets: *const Dataset,
    pub dataset_count: u64,
}

#[repr(C)]
pub struct RowRef {
    pub dataset: Bytes,
    pub row: u64,
}

#[repr(C)]
pub struct Evidence {
    pub output: RowRef,
    pub input: RowRef,
}

#[repr(C)]
pub struct Reason {
    pub output: RowRef,
    pub code: Bytes,
    pub details: *mut FFI_ArrowArrayStream,
}

#[repr(C)]
pub struct NativeError {
    pub code: u32,
    pub field: Bytes,
}

#[repr(C)]
pub struct Request {
    pub export_name: Bytes,
    pub inputs: *const Input,
    pub input_count: u64,
    pub parameters: *mut FFI_ArrowArrayStream,
    pub context: Context,
    pub checkpoint: *const Checkpoint,
    pub cancelled: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub cancel_context: *mut c_void,
}

#[repr(C)]
pub struct Response {
    pub datasets: *const Dataset,
    pub dataset_count: u64,
    pub evidence: *const Evidence,
    pub evidence_count: u64,
    pub reasons: *const Reason,
    pub reason_count: u64,
    pub checkpoint: *const Checkpoint,
    pub error: NativeError,
    pub private_data: *mut c_void,
}

impl Default for Response {
    fn default() -> Self {
        Self {
            datasets: std::ptr::null(),
            dataset_count: 0,
            evidence: std::ptr::null(),
            evidence_count: 0,
            reasons: std::ptr::null(),
            reason_count: 0,
            checkpoint: std::ptr::null(),
            error: NativeError {
                code: 0,
                field: Bytes::new(&[]),
            },
            private_data: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct Api {
    pub contract_version: u32,
    pub struct_size: u64,
    pub evaluate: Option<unsafe extern "C" fn(*const Request, *mut Response) -> u32>,
    pub release: Option<unsafe extern "C" fn(*mut Response)>,
}

impl Api {
    pub fn validate(&self) -> Result<()> {
        if self.contract_version != CONTRACT_VERSION
            || self.struct_size != std::mem::size_of::<Self>() as u64
            || self.evaluate.is_none()
            || self.release.is_none()
        {
            return Err(Error::contract(ErrorCode::Incompatible, "native table"));
        }
        Ok(())
    }
}
