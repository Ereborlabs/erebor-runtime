use super::{abi, streams::Streams};
use crate::{Error, ErrorCode, Evaluation, Model, Output, Package, Result};

pub(super) struct Exchange {
    streams: Streams,
    // The boxes keep published addresses stable when this vector grows.
    #[allow(clippy::vec_box)]
    windows: Vec<Box<abi::Window>>,
    coverage: Vec<Box<[abi::Bytes]>>,
    pub(super) inputs: Vec<abi::Input>,
    pub(super) datasets: Vec<abi::Dataset>,
    pub(super) evidence: Vec<abi::Evidence>,
    pub(super) reasons: Vec<abi::Reason>,
    checkpoint_data: Vec<abi::Dataset>,
    pub(super) checkpoint: Option<Box<abi::Checkpoint>>,
    pub(super) parameters: *mut arrow_array::ffi_stream::FFI_ArrowArrayStream,
}

impl Exchange {
    fn new() -> Self {
        Self {
            streams: Streams::new(),
            windows: Vec::new(),
            coverage: Vec::new(),
            inputs: Vec::new(),
            datasets: Vec::new(),
            evidence: Vec::new(),
            reasons: Vec::new(),
            checkpoint_data: Vec::new(),
            checkpoint: None,
            parameters: std::ptr::null_mut(),
        }
    }

    pub(super) fn evaluation(package: &Package, value: &Evaluation) -> Result<Self> {
        let model = package.validator(value)?;
        model.input(value)?;
        let mut frame = Self::new();
        for input in &value.inputs {
            let data = frame.dataset(&input.data, model.inputs.iter().map(|input| &input.port))?;
            let window = input
                .revision
                .window
                .as_ref()
                .map(|value| {
                    let item = Box::new(abi::Window {
                        source: abi::Bytes::new(&value.source),
                        start_utc_ns: value.start_utc_ns,
                        end_utc_ns: value.end_utc_ns,
                    });
                    let pointer = &*item as *const _;
                    frame.windows.push(item);
                    pointer
                })
                .unwrap_or(std::ptr::null());
            let limits: Box<[_]> = input
                .coverage
                .limits
                .iter()
                .map(|value| abi::Bytes::new(value.as_bytes()))
                .collect();
            let coverage = abi::Coverage {
                state: input.coverage.state as u32,
                limits: limits.as_ptr(),
                limit_count: limits.len() as u64,
            };
            frame.coverage.push(limits);
            frame.inputs.push(abi::Input {
                data,
                revision: abi::Revision {
                    owner: abi::Bytes::new(input.revision.owner.as_bytes()),
                    id: abi::Bytes::new(input.revision.id.as_bytes()),
                    window,
                },
                coverage,
            });
        }
        if let Some(batch) = &value.parameters {
            frame.parameters = frame.streams.add(vec![batch.clone()], &model.parameters);
        }
        frame.set_checkpoint(value.checkpoint.as_ref(), model)?;
        Ok(frame)
    }

    pub(super) fn output(model: &Model, value: &Output) -> Result<Self> {
        let mut frame = Self::new();
        for data in &value.datasets {
            let data = frame.dataset(data, &model.outputs)?;
            frame.datasets.push(data);
        }
        frame.evidence = value
            .evidence
            .iter()
            .map(|link| abi::Evidence {
                output: Self::reference(&link.output),
                input: Self::reference(&link.input),
            })
            .collect();
        for reason in &value.reasons {
            let spec = model
                .reasons
                .iter()
                .find(|spec| spec.code == reason.code)
                .ok_or_else(|| Error::contract(ErrorCode::Invalid, "native reason"))?;
            let details = frame
                .streams
                .add(vec![reason.details.clone()], &spec.details);
            frame.reasons.push(abi::Reason {
                output: Self::reference(&reason.output),
                code: abi::Bytes::new(reason.code.as_bytes()),
                details,
            });
        }
        frame.set_checkpoint(value.checkpoint.as_ref(), model)?;
        Ok(frame)
    }

    fn dataset<'p>(
        &mut self,
        data: &crate::Dataset,
        ports: impl IntoIterator<Item = &'p crate::Port>,
    ) -> Result<abi::Dataset> {
        let port = ports
            .into_iter()
            .find(|port| port.name == data.name)
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "native dataset"))?;
        Ok(abi::Dataset {
            name: abi::Bytes::new(data.name.as_bytes()),
            batches: self.streams.add(data.batches.clone(), &port.schema),
        })
    }

    fn set_checkpoint(&mut self, value: Option<&crate::Checkpoint>, model: &Model) -> Result<()> {
        let Some(value) = value else { return Ok(()) };
        let spec = model
            .checkpoint
            .as_ref()
            .ok_or_else(|| Error::contract(ErrorCode::Invalid, "native checkpoint"))?;
        for data in &value.datasets {
            let data = self.dataset(data, &spec.datasets)?;
            self.checkpoint_data.push(data);
        }
        self.checkpoint = Some(Box::new(abi::Checkpoint {
            version: value.version,
            datasets: self.checkpoint_data.as_ptr(),
            dataset_count: self.checkpoint_data.len() as u64,
        }));
        Ok(())
    }

    pub(super) fn checkpoint_ptr(&self) -> *const abi::Checkpoint {
        self.checkpoint
            .as_deref()
            .map_or(std::ptr::null(), |value| value)
    }

    fn reference(value: &crate::RowRef) -> abi::RowRef {
        abi::RowRef {
            dataset: abi::Bytes::new(value.dataset.as_bytes()),
            row: value.row,
        }
    }
}
