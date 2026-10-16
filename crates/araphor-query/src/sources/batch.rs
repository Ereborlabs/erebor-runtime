use std::sync::Arc;

use araphor_data::{ProjectionSink, Result};
use datafusion::arrow::array::{builder::*, ArrayRef, RecordBatch, RecordBatchOptions};
use datafusion::arrow::datatypes::{DataType, SchemaRef};
use datafusion::common::ScalarValue;

pub(super) struct ArrowBatch {
    pub(super) schema: SchemaRef,
    pub(super) indices: Vec<usize>,
    pub(super) batches: Vec<RecordBatch>,
    builders: Vec<Box<dyn ArrayBuilder>>,
    byte_capacity: Vec<usize>,
    scratch: Vec<ScalarValue>,
    capacity: usize,
    rows: usize,
    pub(super) total_rows: usize,
}

impl ArrowBatch {
    pub(super) fn new(
        schema: SchemaRef,
        indices: Vec<usize>,
        sink: &mut ProjectionSink<'_>,
    ) -> Result<Self> {
        sink.charge(
            std::mem::size_of::<Self>()
                + schema.fields().len() * (std::mem::size_of::<ScalarValue>() + 256),
        )?;
        Ok(Self {
            scratch: Vec::with_capacity(schema.fields().len()),
            schema,
            indices,
            batches: Vec::new(),
            builders: Vec::new(),
            byte_capacity: Vec::new(),
            capacity: 0,
            rows: 0,
            total_rows: 0,
        })
    }

    pub(super) fn append(
        &mut self,
        sink: &mut ProjectionSink<'_>,
        mut value: impl FnMut(&str, &DataType, &mut ProjectionSink<'_>) -> Result<ScalarValue>,
    ) -> Result<bool> {
        self.scratch.clear();
        for field in self.schema.fields() {
            let cell = value(field.name(), field.data_type(), sink)?;
            if cell.data_type() != *field.data_type() || (!field.is_nullable() && cell.is_null()) {
                return Err(Self::invalid(
                    "a projected source value differs from its native Arrow field",
                ));
            }
            self.scratch.push(cell);
        }
        let row_bytes = self.scratch.iter().fold(0usize, |bytes, value| {
            bytes.saturating_add(Self::value_bytes(value))
        });
        if !sink.admit(row_bytes.max(1))? {
            return Ok(false);
        }
        if self.rows == self.capacity || !self.fits() {
            self.finish(sink)?;
            self.allocate(sink, row_bytes)?;
        }
        for (builder, value) in self.builders.iter_mut().zip(&self.scratch) {
            match value {
                ScalarValue::Binary(value) => {
                    Self::builder::<BinaryBuilder>(builder)?.append_option(value.as_deref())
                }
                ScalarValue::Utf8(value) => {
                    Self::builder::<StringBuilder>(builder)?.append_option(value.as_deref())
                }
                ScalarValue::UInt64(value) => {
                    Self::builder::<UInt64Builder>(builder)?.append_option(*value)
                }
                ScalarValue::UInt32(value) => {
                    Self::builder::<UInt32Builder>(builder)?.append_option(*value)
                }
                ScalarValue::Int64(value) => {
                    Self::builder::<Int64Builder>(builder)?.append_option(*value)
                }
                ScalarValue::Int32(value) => {
                    Self::builder::<Int32Builder>(builder)?.append_option(*value)
                }
                ScalarValue::Boolean(value) => {
                    Self::builder::<BooleanBuilder>(builder)?.append_option(*value)
                }
                ScalarValue::TimestampMicrosecond(value, None) => {
                    Self::builder::<TimestampMicrosecondBuilder>(builder)?.append_option(*value)
                }
                _ => {
                    return Err(Self::invalid(
                        "the source field has no native Arrow builder",
                    ));
                }
            }
        }
        self.rows += 1;
        self.total_rows += 1;
        sink.projected(row_bytes);
        self.scratch.clear();
        Ok(true)
    }

    fn value_bytes(value: &ScalarValue) -> usize {
        match value {
            ScalarValue::Binary(value) => 5 + value.as_ref().map_or(0, Vec::len),
            ScalarValue::Utf8(value) => 5 + value.as_ref().map_or(0, String::len),
            _ => value.data_type().primitive_width().unwrap_or(1) + 1,
        }
    }

    fn fits(&self) -> bool {
        self.builders
            .iter()
            .zip(&self.scratch)
            .zip(&self.byte_capacity)
            .all(|((builder, value), capacity)| {
                let used = if let Some(builder) = builder.as_any().downcast_ref::<BinaryBuilder>() {
                    builder.values_slice().len()
                } else if let Some(builder) = builder.as_any().downcast_ref::<StringBuilder>() {
                    builder.values_slice().len()
                } else {
                    return true;
                };
                used.checked_add(Self::value_bytes(value).saturating_sub(5))
                    .is_some_and(|bytes| bytes <= *capacity)
            })
    }

    fn allocate(&mut self, sink: &mut ProjectionSink<'_>, row_bytes: usize) -> Result<()> {
        let width = row_bytes
            .saturating_add(self.schema.fields().len() * 16)
            .max(1);
        let capacity = 32usize
            .min(sink.page_rows())
            .min((sink.remaining_bytes() / width).max(1));
        let mut bytes = std::mem::size_of::<RecordBatch>() + self.schema.fields().len() * 512;
        for value in &self.scratch {
            bytes = bytes
                .checked_add(
                    Self::value_bytes(value)
                        .checked_mul(capacity)
                        .ok_or_else(Self::overflow)?,
                )
                .ok_or_else(Self::overflow)?;
        }
        sink.charge(bytes)?;
        self.builders.clear();
        self.byte_capacity.clear();
        for (field, value) in self.schema.fields().iter().zip(&self.scratch) {
            let variable = Self::value_bytes(value)
                .saturating_sub(5)
                .checked_mul(capacity)
                .ok_or_else(Self::overflow)?;
            if variable > i32::MAX as usize {
                return Err(Self::overflow());
            }
            let builder: Box<dyn ArrayBuilder> = match field.data_type() {
                DataType::Binary => Box::new(BinaryBuilder::with_capacity(capacity, variable)),
                DataType::Utf8 => Box::new(StringBuilder::with_capacity(capacity, variable)),
                kind => make_builder(kind, capacity),
            };
            self.builders.push(builder);
            self.byte_capacity.push(variable);
        }
        self.capacity = capacity;
        Ok(())
    }

    pub(super) fn finish(&mut self, sink: &mut ProjectionSink<'_>) -> Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        sink.grow(&mut self.batches)?;
        let columns: Vec<ArrayRef> = self
            .builders
            .iter_mut()
            .map(|builder| builder.finish())
            .collect();
        let batch = RecordBatch::try_new_with_options(
            Arc::clone(&self.schema),
            columns,
            &RecordBatchOptions::new().with_row_count(Some(self.rows)),
        )
        .map_err(Self::arrow_error)?;
        self.batches.push(batch);
        self.rows = 0;
        self.capacity = 0;
        self.builders.clear();
        Ok(())
    }

    pub(super) fn select_rows(
        &mut self,
        selected: &std::collections::BTreeSet<usize>,
        sink: &mut ProjectionSink<'_>,
    ) -> Result<()> {
        self.finish(sink)?;
        let mut batches = Vec::new();
        let mut offset = 0;
        for batch in &self.batches {
            let mut start = None;
            for index in 0..=batch.num_rows() {
                let keep = index < batch.num_rows() && selected.contains(&(offset + index));
                match (start, keep) {
                    (None, true) => start = Some(index),
                    (Some(first), false) => {
                        sink.grow(&mut batches)?;
                        sink.charge(
                            std::mem::size_of::<RecordBatch>() + batch.num_columns() * 256,
                        )?;
                        batches.push(batch.slice(first, index - first));
                        start = None;
                    }
                    _ => {}
                }
            }
            offset += batch.num_rows();
        }
        self.batches = batches;
        Ok(())
    }

    pub(super) fn traversal(
        &mut self,
        max_hops: u32,
        boundary: bool,
        sink: &mut ProjectionSink<'_>,
    ) -> Result<()> {
        for batch in &mut self.batches {
            sink.charge(
                std::mem::size_of::<RecordBatch>()
                    + batch.num_columns() * std::mem::size_of::<ArrayRef>()
                    + batch.num_rows() * 5
                    + 256,
            )?;
            let mut columns = batch.columns().to_vec();
            if let Ok(index) = self.schema.index_of("max_hops") {
                columns[index] = Arc::new(datafusion::arrow::array::UInt32Array::from_iter_values(
                    std::iter::repeat_n(max_hops, batch.num_rows()),
                ));
            }
            if let Ok(index) = self.schema.index_of("hop_boundary") {
                columns[index] = Arc::new(datafusion::arrow::array::BooleanArray::from_iter(
                    std::iter::repeat_n(Some(boundary), batch.num_rows()),
                ));
            }
            *batch = RecordBatch::try_new_with_options(
                Arc::clone(&self.schema),
                columns,
                &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
            )
            .map_err(Self::arrow_error)?;
        }
        Ok(())
    }

    fn builder<B: ArrayBuilder + 'static>(builder: &mut Box<dyn ArrayBuilder>) -> Result<&mut B> {
        builder
            .as_any_mut()
            .downcast_mut()
            .ok_or_else(|| Self::invalid("the native source builder differs from its field"))
    }

    pub(super) fn invalid(reason: &'static str) -> araphor_data::Error {
        araphor_data::Error::AnalysisState {
            path: "<query source>".into(),
            reason: reason.into(),
            location: snafu::location!(),
        }
    }

    pub(super) fn overflow() -> araphor_data::Error {
        araphor_data::Error::AnalysisInputTooLarge {
            resource: "native source Arrow allocation",
            location: snafu::location!(),
        }
    }

    pub(super) fn arrow_error(source: datafusion::arrow::error::ArrowError) -> araphor_data::Error {
        araphor_data::Error::AnalysisContract {
            source: source.into(),
            location: snafu::location!(),
        }
    }
}
