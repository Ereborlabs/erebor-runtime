use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{builder::*, ArrayRef, RecordBatch, RecordBatchOptions};

use super::{arrow_error, invalid, overflow, ReadBudget, Result};

pub(super) struct Table {
    pub(super) schema: Arc<sdk::Schema>,
    pub(super) batches: Vec<RecordBatch>,
    pub(super) total_rows: usize,
    pub(super) names: &'static [&'static str],
    pub(super) mapping: Vec<Option<usize>>,
    builders: Vec<Box<dyn ArrayBuilder>>,
    variable: Vec<usize>,
    used: Vec<usize>,
    lengths: Vec<usize>,
    capacity: usize,
    rows: usize,
}

impl Table {
    pub(super) fn new(
        schema: Arc<sdk::Schema>,
        names: &'static [&'static str],
        budget: &mut ReadBudget<'_>,
    ) -> Result<Self> {
        let columns = schema.fields().len();
        budget.charge(
            size_of::<Self>()
                + columns * (size_of::<Box<dyn ArrayBuilder>>() + 3 * size_of::<usize>()),
        )?;
        budget.charge(
            names
                .len()
                .checked_mul(size_of::<Option<usize>>())
                .ok_or_else(overflow)?,
        )?;
        let mut mapping = vec![None; names.len()];
        for (index, field) in schema.fields().iter().enumerate() {
            let slot = names
                .iter()
                .position(|name| *name == field.name())
                .ok_or_else(|| invalid("a requested native field has no table mapping"))?;
            mapping[slot] = Some(index);
        }
        Ok(Self {
            schema,
            names,
            mapping,
            batches: Vec::new(),
            total_rows: 0,
            builders: Vec::with_capacity(columns),
            variable: vec![0; columns],
            used: vec![0; columns],
            lengths: vec![0; columns],
            capacity: 0,
            rows: 0,
        })
    }

    pub(super) fn cell(
        &mut self,
        index: usize,
        kind: &sdk::DataType,
        null: bool,
        length: usize,
    ) -> Result<()> {
        let field = self.schema.field(index);
        if field.data_type() != kind || (null && !field.is_nullable()) {
            return Err(invalid(
                "the table value differs from its native Arrow field",
            ));
        }
        self.lengths[index] = length;
        Ok(())
    }

    pub(super) fn admit(&mut self, budget: &mut ReadBudget<'_>, bytes: usize) -> Result<bool> {
        if !budget.admit(bytes.max(1))? {
            return Ok(false);
        }
        if self.rows == self.capacity
            || self.lengths.iter().enumerate().any(|(index, length)| {
                self.used[index]
                    .checked_add(*length)
                    .is_none_or(|used| used > self.variable[index])
            })
        {
            self.finish(budget)?;
            let width = bytes.saturating_add(self.schema.fields().len() * 16).max(1);
            let capacity = 32usize
                .min(budget.page_rows())
                .min((budget.remaining_bytes() / width).max(1));
            let mut charge = size_of::<RecordBatch>()
                + self.schema.fields().len() * (size_of::<ArrayRef>() + 512);
            for (index, field) in self.schema.fields().iter().enumerate() {
                let variable = self.lengths[index]
                    .checked_mul(capacity)
                    .ok_or_else(overflow)?;
                if variable > i32::MAX as usize {
                    return Err(overflow());
                }
                self.variable[index] = variable;
                let payload = match field.data_type() {
                    sdk::DataType::Binary | sdk::DataType::Utf8 => variable
                        .checked_add((capacity + 1) * size_of::<i32>())
                        .ok_or_else(overflow)?,
                    sdk::DataType::Boolean => 64,
                    kind => kind
                        .primitive_width()
                        .ok_or_else(|| invalid("the source field has no native builder"))?
                        .checked_mul(capacity)
                        .ok_or_else(overflow)?,
                };
                charge = charge
                    .checked_add(payload)
                    .and_then(|value| value.checked_add(if field.is_nullable() { 64 } else { 0 }))
                    .ok_or_else(overflow)?;
            }
            budget.charge(charge)?;
            self.builders.clear();
            for (index, field) in self.schema.fields().iter().enumerate() {
                self.builders.push(match field.data_type() {
                    sdk::DataType::Binary => {
                        Box::new(BinaryBuilder::with_capacity(capacity, self.variable[index]))
                    }
                    sdk::DataType::Utf8 => {
                        Box::new(StringBuilder::with_capacity(capacity, self.variable[index]))
                    }
                    kind => make_builder(kind, capacity),
                });
            }
            self.capacity = capacity;
            self.used.fill(0);
        }
        Ok(true)
    }

    pub(super) fn builder<B: ArrayBuilder + 'static>(&mut self, index: usize) -> Result<&mut B> {
        self.builders[index]
            .as_any_mut()
            .downcast_mut()
            .ok_or_else(|| invalid("the source builder differs from its field"))
    }

    pub(super) fn appended(&mut self, budget: &mut ReadBudget<'_>, bytes: usize) {
        for (used, length) in self.used.iter_mut().zip(&self.lengths) {
            *used += length;
        }
        self.rows += 1;
        self.total_rows += 1;
        budget.projected(bytes);
    }

    pub(super) fn finish(&mut self, budget: &mut ReadBudget<'_>) -> Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        budget.grow(&mut self.batches)?;
        let columns = self
            .builders
            .iter_mut()
            .map(|builder| builder.finish())
            .collect();
        self.batches.push(
            RecordBatch::try_new_with_options(
                Arc::clone(&self.schema),
                columns,
                &RecordBatchOptions::new().with_row_count(Some(self.rows)),
            )
            .map_err(arrow_error)?,
        );
        self.rows = 0;
        self.capacity = 0;
        self.builders.clear();
        Ok(())
    }

    pub(super) fn select_rows(
        &mut self,
        selected: &[usize],
        budget: &mut ReadBudget<'_>,
    ) -> Result<()> {
        self.finish(budget)?;
        let mut batches = Vec::new();
        let mut offset = 0;
        for batch in &self.batches {
            let mut start = None;
            for index in 0..=batch.num_rows() {
                let keep =
                    index < batch.num_rows() && selected.binary_search(&(offset + index)).is_ok();
                match (start, keep) {
                    (None, true) => start = Some(index),
                    (Some(first), false) => {
                        budget.grow(&mut batches)?;
                        budget.charge(
                            size_of::<RecordBatch>() + batch.num_columns() * size_of::<ArrayRef>(),
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
        budget: &mut ReadBudget<'_>,
    ) -> Result<()> {
        self.finish(budget)?;
        for batch in &mut self.batches {
            budget.charge(
                size_of::<RecordBatch>()
                    + batch.num_columns() * size_of::<ArrayRef>()
                    + batch.num_rows() * size_of::<u32>()
                    + 64,
            )?;
            let mut columns = batch.columns().to_vec();
            if let Ok(index) = self.schema.index_of("max_hops") {
                columns[index] = Arc::new(sdk::arrow_array::UInt32Array::from_iter_values(
                    std::iter::repeat_n(max_hops, batch.num_rows()),
                ));
            }
            if let Ok(index) = self.schema.index_of("hop_boundary") {
                columns[index] = Arc::new(sdk::arrow_array::BooleanArray::from_iter(
                    std::iter::repeat_n(Some(boundary), batch.num_rows()),
                ));
            }
            *batch = RecordBatch::try_new_with_options(
                Arc::clone(&self.schema),
                columns,
                &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
            )
            .map_err(arrow_error)?;
        }
        Ok(())
    }
}

macro_rules! table_row {
    (
        $(#[$attr:meta])*
        $vis:vis fn $append:ident($($args:tt)*);
        schema $schema:ident;
        $(prefix $prefix:ident {
            $( $common:ident => $common_kind:ident($common_nullable:literal): $common_value:expr ),* $(,)?
        })?
        row($capture:ident, $relation:expr, $budget:ident);
        setup { $($setup:tt)* }
        fields {
            $( $name:ident => $kind:ident($nullable:literal): $value:expr ),* $(,)?
        }
        $(then { $($tail:tt)* })?
    ) => {
        pub(super) fn $schema() -> Vec<sdk::Field> {
            table_row!(@fields;
                $($( $common => $common_kind($common_nullable), )*)?
                $( $name => $kind($nullable), )*
            )
        }
        $(pub(super) fn $prefix() -> Vec<sdk::Field> {
            table_row!(@fields; $( $common => $common_kind($common_nullable), )*)
        })?
        $(#[$attr])*
        $vis fn $append($($args)*) -> crate::Result<bool> {
            $($setup)*
            table_row!(@finish
                table_row!($capture, $relation, $budget;
                    $($( $common => $common_kind: $common_value, )*)?
                    $( $name => $kind: $value, )*
                );
                $(then { $($tail)* })?
            )
        }
    };
    (@fields; $( $name:ident => $kind:ident($nullable:literal) ),* $(,)?) => {
        vec![$(sdk::Field::new(stringify!($name), table_row!(@type $kind), $nullable)),*]
    };
    (@finish $row:expr; then { $($tail:tt)* }) => {
        {
            if !$row? { return Ok(false); }
            $($tail)*
        }
    };
    (@finish $row:expr;) => { $row };
    ($capture:expr, $relation:expr, $budget:expr; $( $name:ident => $kind:ident : $value:expr ),* $(,)?) => {{
        let capture = &mut *$capture;
        (|| -> crate::Result<bool> {
            if capture.read.projected($relation).is_none() { return Ok(true); }
            const NAMES: &[&str] = &[$(stringify!($name)),*];
            let mut mapping = {
                let table = capture.table($relation, NAMES, &mut *$budget)?;
                let mut indices = [None; NAMES.len()];
                indices.copy_from_slice(&table.mapping);
                indices.into_iter()
            };
            let ($( $name, )*) = ($( if let Some(index) = mapping.next().flatten() {
                Some((index, table_row!(@prepare $kind, $value, &mut *$budget)))
            } else { None }, )*);
            let budget = &mut *$budget;
            let table = capture.table($relation, NAMES, budget)?;
            let mut bytes = 0usize;
            $(if let Some((index, value)) = &$name {
                let length = table_row!(@length $kind, value);
                table.cell(*index, &table_row!(@type $kind), value.is_none(), length)?;
                bytes = bytes.checked_add(table_row!(@logical $kind, length)).ok_or_else(super::overflow)?;
            })*
            if !table.admit(budget, bytes)? { return Ok(false); }
            $(if let Some((index, value)) = $name {
                table_row!(@append table, index, $kind, value);
            })*
            table.appended(budget, bytes);
            Ok(true)
        })()
    }};
    (@prepare Binary, $value:expr, $budget:expr) => {{ let value: Option<&[u8]> = $value; value }};
    (@prepare Utf8, $value:expr, $budget:expr) => {{ let value = $value; value }};
    (@prepare Json, $value:expr, $budget:expr) => { super::json($value, $budget)? };
    (@prepare $kind:ident, $value:expr, $budget:expr) => { $value };
    (@length Binary, $value:expr) => { $value.as_ref().map_or(0, |value| value.len()) };
    (@length Utf8, $value:expr) => { $value.as_ref().map_or(0, |value| value.len()) };
    (@length Json, $value:expr) => { $value.as_ref().map_or(0, |value| value.len()) };
    (@length $kind:ident, $value:expr) => { 0usize };
    (@logical Binary, $length:expr) => { 5usize.saturating_add($length) };
    (@logical Utf8, $length:expr) => { 5usize.saturating_add($length) };
    (@logical Json, $length:expr) => { 5usize.saturating_add($length) };
    (@logical UInt64, $length:expr) => { 9usize };
    (@logical Int64, $length:expr) => { 9usize };
    (@logical TimestampMicrosecond, $length:expr) => { 9usize };
    (@logical UInt32, $length:expr) => { 5usize };
    (@logical Int32, $length:expr) => { 5usize };
    (@logical Boolean, $length:expr) => { 2usize };
    (@type Json) => { sdk::DataType::Binary };
    (@type TimestampMicrosecond) => { sdk::DataType::Timestamp(sdk::TimeUnit::Microsecond, None) };
    (@type $kind:ident) => { sdk::DataType::$kind };
    (@append $table:expr, $name:expr, Binary, $value:expr) => { $table.builder::<sdk::arrow_array::builder::BinaryBuilder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, Utf8, $value:expr) => { $table.builder::<sdk::arrow_array::builder::StringBuilder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, Json, $value:expr) => { $table.builder::<sdk::arrow_array::builder::BinaryBuilder>($name)?.append_option($value.as_deref()) };
    (@append $table:expr, $name:expr, UInt64, $value:expr) => { $table.builder::<sdk::arrow_array::builder::UInt64Builder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, Int64, $value:expr) => { $table.builder::<sdk::arrow_array::builder::Int64Builder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, UInt32, $value:expr) => { $table.builder::<sdk::arrow_array::builder::UInt32Builder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, Int32, $value:expr) => { $table.builder::<sdk::arrow_array::builder::Int32Builder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, Boolean, $value:expr) => { $table.builder::<sdk::arrow_array::builder::BooleanBuilder>($name)?.append_option($value) };
    (@append $table:expr, $name:expr, TimestampMicrosecond, $value:expr) => { $table.builder::<sdk::arrow_array::builder::TimestampMicrosecondBuilder>($name)?.append_option($value) };
}

pub(super) use table_row;
