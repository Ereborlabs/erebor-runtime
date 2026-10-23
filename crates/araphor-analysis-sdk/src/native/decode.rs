use super::{abi, streams};
use crate::{Error, ErrorCode, Evaluation, Model, Output, Package, Result};

pub(super) struct Decoder {
    copy_bytes: Option<usize>,
    bytes: usize,
}

impl Decoder {
    fn new(copy_bytes: Option<usize>) -> Self {
        Self {
            copy_bytes,
            bytes: 0,
        }
    }

    pub(super) unsafe fn evaluation<'a>(
        package: &'a Package,
        request: &abi::Request,
    ) -> Result<(Evaluation, &'a crate::Model)> {
        let mut decoder = Self::new(None);
        let export = unsafe { decoder.text(request.export_name)? };
        let model = package.wire_validator(&export)?;
        if request.context.has_seed > 1 {
            return Err(Error::contract(ErrorCode::Invalid, "native seed flag"));
        }
        let mut inputs = decoder.vector(request.input_count)?;
        for input in unsafe { decoder.slice(request.inputs, request.input_count)? } {
            let data = unsafe {
                decoder.dataset(&input.data, model.inputs.iter().map(|input| &input.port))?
            };
            let window = if input.revision.window.is_null() {
                None
            } else {
                let window = unsafe { decoder.one(input.revision.window)? };
                Some(crate::SourceWindow {
                    source: unsafe { decoder.bytes(window.source)? }.to_vec(),
                    start_utc_ns: window.start_utc_ns,
                    end_utc_ns: window.end_utc_ns,
                })
            };
            let state = match input.coverage.state {
                0 => crate::CoverageState::Complete,
                1 => crate::CoverageState::Gapped,
                2 => crate::CoverageState::Unknown,
                _ => return Err(Error::contract(ErrorCode::Invalid, "native coverage")),
            };
            let mut reasons = decoder.vector(input.coverage.limit_count)?;
            for reason in
                unsafe { decoder.slice(input.coverage.limits, input.coverage.limit_count)? }
            {
                reasons.push(unsafe { decoder.text(*reason)? });
            }
            inputs.push(crate::Input {
                data,
                revision: crate::Revision {
                    owner: unsafe { decoder.text(input.revision.owner)? },
                    id: unsafe { decoder.text(input.revision.id)? },
                    window,
                },
                coverage: crate::Coverage {
                    state,
                    limits: reasons,
                },
            });
        }
        let parameters = if request.parameters.is_null() {
            None
        } else {
            Some(unsafe { decoder.single(request.parameters, &model.parameters)? })
        };
        let evaluation = Evaluation {
            export,
            inputs,
            parameters,
            context: crate::EvaluationContext {
                id: unsafe { decoder.text(request.context.id)? },
                time_utc_ns: request.context.time_utc_ns,
                seed: (request.context.has_seed == 1).then_some(request.context.seed),
            },
            checkpoint: unsafe { decoder.checkpoint(request.checkpoint, model)? },
        };
        model.input(&evaluation)?;
        Ok((evaluation, model))
    }

    pub(super) unsafe fn output(
        checked: &crate::CheckedEvaluation<'_>,
        response: &abi::Response,
        copy_bytes: Option<usize>,
    ) -> Result<Output> {
        let model = checked.model();
        let mut decoder = Self::new(copy_bytes);
        let mut datasets = decoder.vector(response.dataset_count)?;
        for data in unsafe { decoder.slice(response.datasets, response.dataset_count)? } {
            datasets.push(unsafe { decoder.dataset(data, &model.outputs)? });
        }
        let mut evidence = decoder.vector(response.evidence_count)?;
        for link in unsafe { decoder.slice(response.evidence, response.evidence_count)? } {
            evidence.push(crate::EvidenceLink {
                output: unsafe { decoder.reference(&link.output)? },
                input: unsafe { decoder.reference(&link.input)? },
            });
        }
        let mut reasons = decoder.vector(response.reason_count)?;
        for reason in unsafe { decoder.slice(response.reasons, response.reason_count)? } {
            let code = unsafe { decoder.text(reason.code)? };
            let spec = model
                .reasons
                .iter()
                .find(|reason| reason.code == code)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "native reason"))?;
            reasons.push(crate::ReasonValue {
                output: unsafe { decoder.reference(&reason.output)? },
                code,
                details: unsafe { decoder.single(reason.details, &spec.details)? },
            });
        }
        let output = Output {
            datasets,
            evidence,
            reasons,
            checkpoint: unsafe { decoder.checkpoint(response.checkpoint, model)? },
        };
        checked.validate_output(&output)?;
        if copy_bytes.is_some_and(|limit| output.allocated_bytes() > limit) {
            return Err(Error::contract(ErrorCode::Limit, "native output bytes"));
        }
        Ok(output)
    }

    unsafe fn dataset<'p>(
        &mut self,
        value: &abi::Dataset,
        ports: impl IntoIterator<Item = &'p crate::Port>,
    ) -> Result<crate::Dataset> {
        let name = unsafe { self.text(value.name)? };
        let port = ports
            .into_iter()
            .find(|port| port.name == name)
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "native dataset"))?;
        let batches = unsafe { streams::read(value.batches, &port.schema, self.remaining())? };
        self.account(&batches)?;
        Ok(crate::Dataset { name, batches })
    }

    unsafe fn single(
        &mut self,
        stream: *mut arrow_array::ffi_stream::FFI_ArrowArrayStream,
        schema: &crate::Schema,
    ) -> Result<crate::RecordBatch> {
        let mut batches = unsafe { streams::read(stream, schema, self.remaining())? };
        self.account(&batches)?;
        if batches.len() != 1 || batches[0].num_rows() != 1 {
            return Err(Error::contract(ErrorCode::Invalid, "native single row"));
        }
        self.bytes = self
            .bytes
            .saturating_sub(batches.capacity() * std::mem::size_of::<crate::RecordBatch>());
        Ok(batches.remove(0))
    }

    unsafe fn checkpoint(
        &mut self,
        pointer: *const abi::Checkpoint,
        model: &Model,
    ) -> Result<Option<crate::Checkpoint>> {
        if pointer.is_null() {
            return Ok(None);
        }
        let value = unsafe { self.one(pointer)? };
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Incompatible, "native checkpoint"))?;
        if value.version != spec.version {
            return Err(Error::contract(
                ErrorCode::Incompatible,
                "native checkpoint version",
            ));
        }
        let mut datasets = self.vector(value.dataset_count)?;
        for data in unsafe { self.slice(value.datasets, value.dataset_count)? } {
            datasets.push(unsafe { self.dataset(data, &spec.datasets)? });
        }
        Ok(Some(crate::Checkpoint {
            version: value.version,
            datasets,
        }))
    }

    unsafe fn reference(&mut self, value: &abi::RowRef) -> Result<crate::RowRef> {
        Ok(crate::RowRef {
            dataset: unsafe { self.text(value.dataset)? },
            row: value.row,
        })
    }

    unsafe fn text(&mut self, value: abi::Bytes) -> Result<String> {
        std::str::from_utf8(unsafe { self.bytes(value)? })
            .map(str::to_owned)
            .map_err(|_| Error::contract(ErrorCode::Invalid, "native UTF-8"))
    }

    unsafe fn bytes<'a>(&mut self, value: abi::Bytes) -> Result<&'a [u8]> {
        self.charge(value.size)?;
        unsafe { self.slice(value.data, value.size) }
    }

    pub(super) unsafe fn one<'a, T>(&mut self, pointer: *const T) -> Result<&'a T> {
        unsafe { self.slice(pointer, 1) }.map(|values| &values[0])
    }

    unsafe fn slice<'a, T>(&mut self, pointer: *const T, count: u64) -> Result<&'a [T]> {
        let count = usize::try_from(count)
            .map_err(|_| Error::contract(ErrorCode::Limit, "native count"))?;
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "native count"))?;
        if self.copy_bytes.is_some_and(|limit| bytes > limit) {
            return Err(Error::contract(ErrorCode::Limit, "native count"));
        }
        if count == 0 {
            return Ok(&[]);
        }
        if pointer.is_null() || !(pointer as usize).is_multiple_of(std::mem::align_of::<T>()) {
            return Err(Error::contract(ErrorCode::Invalid, "native pointer"));
        }
        Ok(unsafe { std::slice::from_raw_parts(pointer, count) })
    }

    fn remaining(&self) -> Option<usize> {
        self.copy_bytes
            .map(|limit| limit.saturating_sub(self.bytes))
    }

    fn charge(&mut self, bytes: u64) -> Result<()> {
        let bytes = usize::try_from(bytes)
            .map_err(|_| Error::contract(ErrorCode::Limit, "native bytes"))?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "native bytes"))?;
        if self.copy_bytes.is_some_and(|limit| self.bytes > limit) {
            return Err(Error::contract(ErrorCode::Limit, "native bytes"));
        }
        Ok(())
    }

    fn vector<T>(&mut self, count: u64) -> Result<Vec<T>> {
        let count = usize::try_from(count)
            .map_err(|_| Error::contract(ErrorCode::Limit, "native count"))?;
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or_else(|| Error::contract(ErrorCode::Limit, "native count"))?;
        self.charge(bytes as u64)?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| Error::contract(ErrorCode::Limit, "native allocation"))?;
        Ok(values)
    }

    fn account(&mut self, batches: &Vec<crate::RecordBatch>) -> Result<()> {
        let bytes = batches.iter().try_fold(
            batches
                .capacity()
                .checked_mul(std::mem::size_of::<crate::RecordBatch>())
                .ok_or_else(|| Error::contract(ErrorCode::Limit, "native bytes"))?,
            |bytes, batch| {
                bytes
                    .checked_add(crate::Dataset::batch_allocation(batch))
                    .ok_or_else(|| Error::contract(ErrorCode::Limit, "native bytes"))
            },
        )?;
        self.charge(bytes as u64)
    }
}
