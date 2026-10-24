use serde::{Deserialize, Serialize};

use crate::{Error, ErrorCode, RecordBatch, Result};

#[derive(Clone, Debug)]
pub struct Dataset {
    pub name: String,
    pub batches: Vec<RecordBatch>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceWindow {
    pub source: Vec<u8>,
    pub start_utc_ns: i64,
    pub end_utc_ns: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub owner: String,
    pub id: String,
    pub window: Option<SourceWindow>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum CoverageState {
    Complete = 0,
    Gapped = 1,
    Unknown = 2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub state: CoverageState,
    pub limits: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Input {
    pub data: Dataset,
    pub revision: Revision,
    pub coverage: Coverage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationContext {
    pub id: String,
    pub time_utc_ns: i64,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Evaluation {
    pub export: String,
    pub inputs: Vec<Input>,
    pub parameters: Option<RecordBatch>,
    pub context: EvaluationContext,
    pub checkpoint: Option<Checkpoint>,
}

impl Evaluation {
    pub fn encoding_scratch_bytes(&self) -> Result<usize> {
        self.inputs
            .iter()
            .flat_map(|input| &input.data.batches)
            .chain(self.parameters.iter())
            .chain(
                self.checkpoint.iter().flat_map(|checkpoint| {
                    checkpoint.datasets.iter().flat_map(|data| &data.batches)
                }),
            )
            .try_fold(0_usize, |bytes, batch| {
                crate::wire::Dataset::encoding_scratch(batch)
                    .map(|scratch| bytes.saturating_add(scratch))
            })
    }

    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self
            .export
            .capacity()
            .saturating_add(self.context.id.capacity())
            .saturating_add(
                self.inputs
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Input>()),
            );
        for input in &self.inputs {
            bytes = bytes
                .saturating_add(input.data.allocated_bytes())
                .saturating_add(crate::memory::Memory::input_metadata(
                    &input.revision,
                    &input.coverage,
                ));
        }
        if let Some(parameters) = &self.parameters {
            bytes = bytes.saturating_add(Dataset::batch_allocation(parameters));
        }
        if let Some(checkpoint) = &self.checkpoint {
            bytes = bytes.saturating_add(Dataset::allocation(&checkpoint.datasets));
        }
        bytes
    }

    pub fn input(&self, name: &str) -> Result<&Input> {
        self.inputs
            .iter()
            .find(|input| input.data.name == name)
            .ok_or_else(|| Error::contract(ErrorCode::Incomplete, format!("input {name}")))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RowRef {
    pub dataset: String,
    pub row: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLink {
    pub output: RowRef,
    pub input: RowRef,
}

#[derive(Clone, Debug)]
pub struct ReasonValue {
    pub output: RowRef,
    pub code: String,
    pub details: RecordBatch,
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub version: u32,
    pub datasets: Vec<Dataset>,
}

#[derive(Clone, Debug, Default)]
pub struct Output {
    pub datasets: Vec<Dataset>,
    pub evidence: Vec<EvidenceLink>,
    pub reasons: Vec<ReasonValue>,
    pub checkpoint: Option<Checkpoint>,
}

impl Output {
    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = Dataset::allocation(&self.datasets);
        bytes = bytes.saturating_add(
            self.evidence
                .capacity()
                .saturating_mul(std::mem::size_of::<EvidenceLink>()),
        );
        for link in &self.evidence {
            bytes = bytes
                .saturating_add(link.input.dataset.capacity())
                .saturating_add(link.output.dataset.capacity());
        }
        bytes = bytes.saturating_add(
            self.reasons
                .capacity()
                .saturating_mul(std::mem::size_of::<ReasonValue>()),
        );
        for reason in &self.reasons {
            bytes = bytes
                .saturating_add(reason.output.dataset.capacity())
                .saturating_add(reason.code.capacity())
                .saturating_add(Dataset::batch_allocation(&reason.details));
        }
        if let Some(checkpoint) = &self.checkpoint {
            bytes = bytes.saturating_add(Dataset::allocation(&checkpoint.datasets));
        }
        bytes
    }
}

impl Coverage {
    pub fn metadata_bytes(&self) -> usize {
        self.limits.iter().fold(
            self.limits
                .capacity()
                .saturating_mul(std::mem::size_of::<String>()),
            |bytes, limit| bytes.saturating_add(limit.capacity()),
        )
    }
}

impl Input {
    pub fn metadata_bytes(&self) -> usize {
        self.data
            .metadata_bytes()
            .saturating_add(crate::memory::Memory::input_metadata(
                &self.revision,
                &self.coverage,
            ))
    }
}

impl Dataset {
    pub fn metadata_bytes(&self) -> usize {
        self.allocated_bytes().saturating_sub(
            self.batches
                .iter()
                .flat_map(RecordBatch::columns)
                .fold(0usize, |bytes, array| {
                    bytes.saturating_add(array.get_buffer_memory_size())
                }),
        )
    }

    fn allocation(datasets: &Vec<Self>) -> usize {
        let mut bytes = datasets
            .capacity()
            .saturating_mul(std::mem::size_of::<Self>());
        for data in datasets {
            bytes = bytes.saturating_add(data.allocated_bytes());
        }
        bytes
    }

    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self.name.capacity().saturating_add(
            self.batches
                .capacity()
                .saturating_mul(std::mem::size_of::<RecordBatch>()),
        );
        for batch in &self.batches {
            bytes = bytes.saturating_add(Self::batch_allocation(batch));
        }
        bytes
    }

    pub(crate) fn batch_allocation(batch: &RecordBatch) -> usize {
        batch
            .get_array_memory_size()
            .saturating_add(
                batch
                    .num_columns()
                    .saturating_mul(std::mem::size_of::<arrow_array::ArrayRef>()),
            )
            .saturating_add(std::mem::size_of::<crate::Schema>())
            .saturating_add(std::mem::size_of::<[usize; 2]>())
            .saturating_add(crate::memory::Memory::schema_heap(batch.schema_ref()))
    }
}
