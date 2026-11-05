use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use super::{abi, decode::Decoder, exchange::Exchange, streams, ABI_VERSION};
use crate::{Dataset, Error, ErrorCode, Input, InvocationHost, InvocationService, Result};

pub(super) struct HostContext<'a>(pub &'a dyn InvocationService);

struct HostFrame {
    _transfer: Option<crate::Transfer>,
    _input: Option<Box<Input>>,
    exchange: Exchange,
    field: String,
}

impl HostContext<'_> {
    pub(super) fn table(&mut self) -> abi::HostApi {
        abi::HostApi {
            abi_version: ABI_VERSION,
            struct_size: std::mem::size_of::<abi::HostApi>() as u64,
            context: (self as *mut Self).cast(),
            read: Some(Self::read),
            stage: Some(Self::stage),
            release: Some(Self::release),
        }
    }

    unsafe extern "C" fn read(
        context: *mut c_void,
        name: abi::Bytes,
        arguments: *const abi::Dataset,
        response: *mut abi::HostResponse,
    ) -> u32 {
        unsafe {
            Self::respond(response, || {
                let mut decoder = Decoder::new(None);
                let scope = decoder.one(context.cast::<HostContext<'_>>())?;
                let transfer = scope.0.reserve_transfer()?;
                let mut decoder = Decoder::new(transfer.bytes);
                let name = decoder.text(name)?;
                let schema = scope.0.argument_schema(&name)?;
                let arguments = decoder.one(arguments)?;
                let arguments = Dataset {
                    name: decoder.text(arguments.name)?,
                    batches: streams::read(arguments.batches, &schema, decoder.remaining())?,
                };
                let input = scope.0.read(&name, &arguments)?;
                Ok((Some(input), transfer))
            })
        }
    }

    unsafe extern "C" fn stage(
        context: *mut c_void,
        commands: *const abi::Dataset,
        response: *mut abi::HostResponse,
    ) -> u32 {
        unsafe {
            Self::respond(response, || {
                let mut decoder = Decoder::new(None);
                let scope = decoder.one(context.cast::<HostContext<'_>>())?;
                let transfer = scope.0.reserve_transfer()?;
                let mut decoder = Decoder::new(transfer.bytes);
                let commands = decoder.one(commands)?;
                let name = decoder.text(commands.name)?;
                let schema = scope.0.command_schema(&name)?;
                scope.0.stage(&Dataset {
                    name,
                    batches: streams::read(commands.batches, &schema, decoder.remaining())?,
                })?;
                Ok((None, transfer))
            })
        }
    }

    unsafe fn respond(
        response: *mut abi::HostResponse,
        call: impl FnOnce() -> Result<(Option<Input>, crate::Transfer)>,
    ) -> u32 {
        if response.is_null()
            || !(response as usize).is_multiple_of(std::mem::align_of::<abi::HostResponse>())
        {
            return ErrorCode::Invalid as u32;
        }
        unsafe { *response = abi::HostResponse::default() };
        let result = catch_unwind(AssertUnwindSafe(|| {
            let (input, transfer) = call()?;
            let input = input.map(Box::new);
            if transfer.bytes.is_some_and(|bytes| {
                input
                    .as_ref()
                    .is_some_and(|input| input.allocated_bytes() > bytes)
            }) {
                return Err(Error::contract(ErrorCode::Limit, "Graph read bytes"));
            }
            let mut exchange = Exchange::new();
            if let Some(input) = &input {
                let schema = input
                    .data
                    .batches
                    .first()
                    .ok_or_else(|| Error::contract(ErrorCode::Invalid, "Graph result schema"))?
                    .schema();
                let data = exchange.input(input, &schema)?;
                exchange.inputs.push(data);
            }
            Ok::<_, Error>(HostFrame {
                _transfer: Some(transfer),
                _input: input,
                exchange,
                field: String::new(),
            })
        }))
        .unwrap_or_else(|_| Err(Error::contract(ErrorCode::Failed, "Graph host panic")));
        let (code, frame) = match result {
            Ok(frame) => (0, Box::new(frame)),
            Err(error) => {
                let error = crate::wire::EvaluationError::from(error);
                (
                    error.code as u32,
                    Box::new(HostFrame {
                        _transfer: None,
                        _input: None,
                        exchange: Exchange::new(),
                        field: error.field,
                    }),
                )
            }
        };
        let target = unsafe { &mut *response };
        target.copy_limit = frame
            ._transfer
            .as_ref()
            .and_then(|transfer| transfer.bytes)
            .map_or(u64::MAX, |bytes| bytes as u64);
        target.input = frame
            .exchange
            .inputs
            .first()
            .map_or(std::ptr::null(), |input| input);
        target.error = abi::NativeError {
            code,
            field: abi::Bytes::new(frame.field.as_bytes()),
        };
        target.private_data = Box::into_raw(frame).cast();
        code
    }

    unsafe extern "C" fn release(response: *mut abi::HostResponse) {
        let _result = catch_unwind(AssertUnwindSafe(|| unsafe {
            if response.is_null() {
                return;
            }
            let frame = (*response).private_data;
            *response = abi::HostResponse::default();
            if !frame.is_null() {
                drop(Box::from_raw(frame.cast::<HostFrame>()));
            }
        }));
    }
}

pub(super) struct HostProxy<'a>(pub &'a abi::HostApi);

struct HostGuard<'a> {
    api: &'a abi::HostApi,
    response: abi::HostResponse,
}

impl Drop for HostGuard<'_> {
    fn drop(&mut self) {
        if let Some(release) = self.api.release {
            unsafe { release(&mut self.response) };
        }
    }
}

impl HostProxy<'_> {
    fn invoke(&self, name: Option<&str>, data: &Dataset) -> Result<Option<Input>> {
        self.0.validate()?;
        let schema = data
            .batches
            .first()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "Graph dataset"))?
            .schema();
        let port = crate::Port::new(&data.name, schema.as_ref().clone());
        let mut frame = Exchange::new();
        let data = frame.dataset(data, std::slice::from_ref(&port))?;
        let mut guard = HostGuard {
            api: self.0,
            response: abi::HostResponse::default(),
        };
        let status = match name {
            Some(name) => unsafe {
                self.0
                    .read
                    .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "Graph read"))?(
                    self.0.context,
                    abi::Bytes::new(name.as_bytes()),
                    &data,
                    &mut guard.response,
                )
            },
            None => unsafe {
                self.0
                    .stage
                    .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "Graph stage"))?(
                    self.0.context,
                    &data,
                    &mut guard.response,
                )
            },
        };
        if status != guard.response.error.code {
            return Err(Error::contract(ErrorCode::Invalid, "Graph host status"));
        }
        let mut decoder = Decoder::new(
            (guard.response.copy_limit != u64::MAX)
                .then(|| usize::try_from(guard.response.copy_limit))
                .transpose()
                .map_err(|_| Error::contract(ErrorCode::Limit, "Graph read limit"))?,
        );
        if status != 0 {
            let code = match status {
                1 => ErrorCode::Invalid,
                2 => ErrorCode::Incompatible,
                3 => ErrorCode::Unauthorized,
                4 => ErrorCode::Incomplete,
                5 => ErrorCode::Failed,
                6 => ErrorCode::Limit,
                _ => return Err(Error::contract(ErrorCode::Invalid, "Graph host error")),
            };
            return Err(Error::contract(code, unsafe {
                decoder.text(guard.response.error.field)?
            }));
        }
        match name {
            Some(_) => {
                let input = unsafe { decoder.one(guard.response.input)? };
                unsafe { decoder.input(input, None) }.map(Some)
            }
            None if guard.response.input.is_null() => Ok(None),
            None => Err(Error::contract(ErrorCode::Invalid, "Graph stage response")),
        }
    }
}

impl InvocationHost for HostProxy<'_> {
    fn read(&self, name: &str, arguments: &Dataset) -> Result<Input> {
        self.invoke(Some(name), arguments)?
            .ok_or_else(|| Error::contract(ErrorCode::Incomplete, "Graph read result"))
    }

    fn stage(&self, commands: &Dataset) -> Result<()> {
        self.invoke(None, commands).map(|_| ())
    }
}
