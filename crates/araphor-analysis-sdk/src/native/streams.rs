use std::ffi::{c_char, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use arrow_array::ffi_stream::{ArrowArrayStreamReader, FFI_ArrowArrayStream};
use arrow_array::{RecordBatchIterator, RecordBatchReader};
use arrow_data::ffi::FFI_ArrowArray;
use arrow_schema::ffi::FFI_ArrowSchema;

use crate::{Error, ErrorCode, Limits, RecordBatch, Result, Schema};

pub(super) struct Streams {
    // The boxes keep published addresses stable when this vector grows.
    #[allow(clippy::vec_box)]
    values: Vec<Box<FFI_ArrowArrayStream>>,
}

impl Streams {
    pub(super) fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub(super) fn add(
        &mut self,
        batches: Vec<RecordBatch>,
        schema: &Schema,
    ) -> *mut FFI_ArrowArrayStream {
        let reader =
            RecordBatchIterator::new(batches.into_iter().map(Ok), Arc::new(schema.clone()));
        let inner = Box::new(FFI_ArrowArrayStream::new(Box::new(reader)));
        let mut stream = Box::new(FFI_ArrowArrayStream {
            get_schema: Some(get_schema),
            get_next: Some(get_next),
            get_last_error: Some(last_error),
            release: Some(release),
            private_data: Box::into_raw(inner).cast(),
        });
        let pointer = &mut *stream as *mut _;
        self.values.push(stream);
        pointer
    }
}

unsafe extern "C" fn get_schema(
    stream: *mut FFI_ArrowArrayStream,
    out: *mut FFI_ArrowSchema,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let inner = (*stream).private_data.cast::<FFI_ArrowArrayStream>();
        (*inner).get_schema.map_or(22, |call| call(inner, out))
    }))
    .unwrap_or(22)
}

unsafe extern "C" fn get_next(stream: *mut FFI_ArrowArrayStream, out: *mut FFI_ArrowArray) -> i32 {
    catch_unwind(AssertUnwindSafe(|| unsafe {
        let inner = (*stream).private_data.cast::<FFI_ArrowArrayStream>();
        (*inner).get_next.map_or(22, |call| call(inner, out))
    }))
    .unwrap_or(22)
}

unsafe extern "C" fn last_error(_stream: *mut FFI_ArrowArrayStream) -> *const c_char {
    c"native Arrow stream failed".as_ptr()
}

unsafe extern "C" fn release(stream: *mut FFI_ArrowArrayStream) {
    let _result = catch_unwind(AssertUnwindSafe(|| unsafe {
        if stream.is_null() || (*stream).release.is_none() {
            return;
        }
        (*stream).release = None;
        let private = std::mem::replace(&mut (*stream).private_data, std::ptr::null_mut());
        drop(Box::from_raw(private.cast::<FFI_ArrowArrayStream>()));
    }));
}

unsafe extern "C" fn borrow_schema(
    stream: *mut FFI_ArrowArrayStream,
    out: *mut FFI_ArrowSchema,
) -> i32 {
    let source = unsafe { (*stream).private_data.cast::<FFI_ArrowArrayStream>() };
    unsafe { (*source).get_schema.map_or(22, |call| call(source, out)) }
}

unsafe extern "C" fn borrow_next(
    stream: *mut FFI_ArrowArrayStream,
    out: *mut FFI_ArrowArray,
) -> i32 {
    let source = unsafe { (*stream).private_data.cast::<FFI_ArrowArrayStream>() };
    unsafe { (*source).get_next.map_or(22, |call| call(source, out)) }
}

unsafe extern "C" fn borrow_release(_stream: *mut FFI_ArrowArrayStream) {}

pub(super) unsafe fn read(
    pointer: *mut FFI_ArrowArrayStream,
    schema: &Schema,
    limits: Limits,
) -> Result<Vec<RecordBatch>> {
    if pointer.is_null()
        || unsafe {
            (*pointer).release.is_none()
                || (*pointer).get_schema.is_none()
                || (*pointer).get_next.is_none()
        }
    {
        return Err(Error::contract(ErrorCode::Invalid, "native stream"));
    }
    let borrowed = FFI_ArrowArrayStream {
        get_schema: Some(borrow_schema),
        get_next: Some(borrow_next),
        get_last_error: Some(last_error),
        release: Some(borrow_release),
        private_data: pointer.cast::<c_void>(),
    };
    let reader = ArrowArrayStreamReader::try_new(borrowed)?;
    if reader.schema().as_ref() != schema {
        return Err(Error::contract(ErrorCode::Invalid, "native stream schema"));
    }
    let mut batches = Vec::new();
    let mut bytes = 0_u64;
    let mut rows = 0_u64;
    for batch in reader {
        let batch = batch?;
        bytes = bytes.saturating_add(batch.get_array_memory_size() as u64);
        rows = rows.saturating_add(batch.num_rows() as u64);
        if bytes > limits.max_bytes
            || rows > limits.max_rows
            || batches.len() >= limits.max_batches as usize
        {
            return Err(Error::contract(ErrorCode::Limit, "native stream data"));
        }
        for array in batch.columns() {
            array.to_data().validate_full()?;
        }
        batches.push(batch);
    }
    Ok(batches)
}
