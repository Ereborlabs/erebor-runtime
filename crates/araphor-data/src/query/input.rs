use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::mem::{size_of, take};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use prost::Message as _;
use sdk::arrow_array::{
    builder::*, Array as _, ArrayRef, BinaryArray, RecordBatchOptions, StringArray, UInt64Array,
};
use snafu::{IntoError as _, ResultExt as _};

use super::discovery::{BEHAVIORS, CONTEXT};
use super::graph::{BRANCHES, FINDINGS, PACKAGES, POLICY, RELATIONSHIPS, SUBJECTS};
use super::notification::NOTIFICATIONS;
use super::{budget::QueryLease, QueryTemplate};
use crate::analysis::ProjectionSink;
use crate::{
    AnalysisContextVersionV1, AnalysisExtractionV1, AnalysisGapV1, AnalysisInputV1,
    AnalysisSourceSnapshotV1, CoverageInterval, CoverageReport, EvidenceIntakeIdentityV1, Result,
    TraceRecipeManifestV1, TraceRecipeV1,
};

macro_rules! column {
    (@type TimestampMicrosecond) => {
        araphor_analysis_sdk::DataType::Timestamp(araphor_analysis_sdk::TimeUnit::Microsecond, None)
    };
    (@type $kind:ident) => {
        araphor_analysis_sdk::DataType::$kind
    };
    (@builder Binary) => {
        araphor_analysis_sdk::arrow_array::builder::BinaryBuilder
    };
    (@builder Utf8) => {
        araphor_analysis_sdk::arrow_array::builder::StringBuilder
    };
    (@builder Boolean) => {
        araphor_analysis_sdk::arrow_array::builder::BooleanBuilder
    };
    (@builder UInt32) => {
        araphor_analysis_sdk::arrow_array::builder::UInt32Builder
    };
    (@builder UInt64) => {
        araphor_analysis_sdk::arrow_array::builder::UInt64Builder
    };
    (@builder Int32) => {
        araphor_analysis_sdk::arrow_array::builder::Int32Builder
    };
    (@builder Int64) => {
        araphor_analysis_sdk::arrow_array::builder::Int64Builder
    };
    (@builder TimestampMicrosecond) => {
        araphor_analysis_sdk::arrow_array::builder::TimestampMicrosecondBuilder
    };
    (@size Binary, $value:expr) => {
        $value.as_ref().map(|value| {
            value
                .as_ref()
                .map_or(0, |value| AsRef::<[u8]>::as_ref(value).len())
        })
    };
    (@size Utf8, $value:expr) => {
        $value.as_ref().map(|value| {
            value
                .as_ref()
                .map_or(0, |value| AsRef::<str>::as_ref(value).len())
        })
    };
    (@size $kind:ident, $value:expr) => {
        $value.as_ref().map(|_| 0)
    };
}

macro_rules! relation {
    ($visibility:vis $schema:ident, $method:ident($sink:ident; $($argument:ident: $argument_type:ty),* $(,)?) {
        name: $name:literal, join_keys: $keys:expr, owner: $owner:expr,
        readiness: $readiness:expr, description: $description:expr,
        setup { $($setup:tt)* }
        fields { $($field:ident: $kind:ident($units:expr, $absence:expr) => $value:expr;)* }
    }) => {
        $visibility const $schema: $crate::query::input::InputSchema = $crate::query::input::InputSchema {
            name: $name,
            columns: &[$($crate::query::input::InputField(stringify!($field), $crate::query::input::column!(@type $kind), $units, $absence)),*],
            join_keys: $keys, owner: $owner, readiness: $readiness, description: $description,
            canonical: |schema| {
                static SCHEMA: std::sync::OnceLock<std::sync::Arc<araphor_analysis_sdk::Schema>> = std::sync::OnceLock::new();
                SCHEMA.get_or_init(|| std::sync::Arc::new(araphor_analysis_sdk::Schema::new(
                    schema.columns.iter().map(|field| std::sync::Arc::new(field.arrow_field(schema.owner))).collect::<Vec<_>>()
                ))).clone()
            },
        };

        impl $crate::query::input::InputRelations {
            pub(super) fn $method(&mut self, $sink: &mut $crate::analysis::ProjectionSink<'_, ()>,
                projection: Option<&std::collections::BTreeSet<String>>, ($($argument,)*): ($($argument_type,)*)) -> $crate::Result<bool> {
                $($setup)*
                let ($($field,)*) = ($(if $schema.selects(projection, stringify!($field)) {
                    Some($value)
                } else { None },)*);
                $(if $absence.is_empty() && $field.as_ref().is_some_and(Option::is_none) {
                    return Err($crate::query::input::InputBatch::invalid("required input value"));
                })*
                let sizes = [$($crate::query::input::column!(@size $kind, $field)),*];
                self.append(&$schema, projection, $sink, &sizes, |columns| {
                    let mut columns = columns.iter_mut();
                    $(if let Some(value) = $field {
                        let column = columns.next().ok_or_else(|| $crate::query::input::InputBatch::invalid("input column"))?;
                        $crate::query::input::InputBatch::builder::<$crate::query::input::column!(@builder $kind)>(column)?.append_option(value);
                    })*
                    Ok(())
                })
            }
        }
    };
}

pub(super) struct InputField(
    pub(super) &'static str,
    pub(super) sdk::DataType,
    pub(super) &'static str,
    pub(super) &'static str,
);

pub(super) struct InputSchema {
    pub(super) name: &'static str,
    pub(super) columns: &'static [InputField],
    pub(super) join_keys: &'static str,
    pub(super) owner: &'static str,
    pub(super) readiness: &'static str,
    pub(super) description: &'static str,
    pub(super) canonical: fn(&InputSchema) -> Arc<sdk::Schema>,
}

impl InputField {
    pub(super) fn sql_type(&self) -> &'static str {
        use sdk::DataType::*;
        match self.1 {
            Boolean => "Boolean",
            UInt32 => "UInteger",
            UInt64 => "UBigint",
            Int32 => "Integer",
            Int64 => "Bigint",
            Utf8 => "Varchar",
            Binary => "Blob",
            Timestamp(sdk::TimeUnit::Microsecond, None) => "Timestamp",
            _ => unreachable!("input declarations contain only canonical source types"),
        }
    }

    fn host_type(&self) -> &'static str {
        match self.0 {
            "tenant_id" => "[u8;16]",
            "source_key" => "araphor-data.EvidenceIntakeIdentityV1",
            "graph_revision" => "araphor-data.GraphRevisionV1",
            "subject_id" | "from_subject_id" | "to_subject_id" => "araphor-data.GraphSubjectKeyV1",
            "authority" => "araphor-data.GraphSubjectAuthorityV1",
            "relationship_key" => "araphor-data.GraphEdgeKeyV1",
            "evidence" => "Vec<araphor-data.DiscoveryRecordIdV1>",
            "proof_quality" => "araphor-data.ProofQualityV1",
            "required_coverage_interval_ids" => "Vec<[u8;16]>",
            _ => match self.1 {
                sdk::DataType::Binary => "Vec<u8>",
                sdk::DataType::Utf8 => "String",
                sdk::DataType::UInt64 => "u64",
                sdk::DataType::UInt32 => "u32",
                sdk::DataType::Int32 => "i32",
                sdk::DataType::Boolean => "bool",
                _ => "i64",
            },
        }
    }

    pub(super) fn arrow_field(&self, owner: &str) -> sdk::Field {
        sdk::Field::new(self.0, self.1.clone(), !self.3.is_empty()).with_metadata(HashMap::from([
            ("araphor.owner".into(), owner.into()),
            ("araphor.description".into(), self.2.into()),
            ("araphor.host_type".into(), self.host_type().into()),
            (
                "araphor.encoding".into(),
                if self.2.starts_with("JSON") {
                    "serde-json-v1"
                } else {
                    "native"
                }
                .into(),
            ),
        ]))
    }
}

impl InputSchema {
    pub(super) fn arrow_schema(&self) -> Arc<sdk::Schema> {
        (self.canonical)(self)
    }

    pub(super) fn selects(&self, projection: Option<&BTreeSet<String>>, name: &str) -> bool {
        projection.is_none_or(|columns| columns.contains(name))
            || (self.name == "findings"
                && matches!(name, "tenant_id" | "finding_id" | "commit_revision"))
    }

    fn fields<'a>(
        &'a self,
        projection: Option<&'a BTreeSet<String>>,
    ) -> impl Iterator<Item = &'a InputField> {
        self.columns
            .iter()
            .filter(move |field| self.selects(projection, field.0))
    }

    fn projected_schema(&self, projection: Option<&BTreeSet<String>>) -> Arc<sdk::Schema> {
        let schema = self.arrow_schema();
        let Some(projection) = projection else {
            return schema;
        };
        Arc::new(sdk::Schema::new(
            self.columns
                .iter()
                .zip(schema.fields())
                .filter(|(field, _)| self.selects(Some(projection), field.0))
                .map(|(_, field)| Arc::clone(field))
                .collect::<Vec<_>>(),
        ))
    }

    pub(super) fn schema_bytes(&self, projection: Option<&BTreeSet<String>>) -> usize {
        let Some(_) = projection else {
            return 0;
        };
        self.fields(projection).fold(
            size_of::<sdk::Schema>() + 4 * size_of::<usize>(),
            |bytes, _| bytes.saturating_add(2 * size_of::<Arc<sdk::Field>>()),
        )
    }
}

#[derive(Default)]
pub(super) struct InputRelations {
    pub(super) tables: BTreeMap<&'static str, InputBatch>,
    pub(super) input_rows: usize,
    pub(super) received_min: Option<u64>,
    bytes: usize,
}

pub(super) struct InputBatch {
    pub(super) schema: Arc<sdk::Schema>,
    pub(super) batches: Vec<sdk::RecordBatch>,
    columns: Vec<Box<dyn ArrayBuilder>>,
    capacities: Vec<usize>,
    row_capacity: usize,
    rows: usize,
}

impl InputBatch {
    pub(super) fn invalid(field: &'static str) -> crate::Error {
        crate::QueryInvalidSnafu { field }.build()
    }

    pub(super) fn check_offsets(bytes: usize) -> Result<()> {
        if bytes > i32::MAX as usize {
            return crate::AnalysisInputTooLargeSnafu {
                resource: "source Arrow offsets",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn builder<B: ArrayBuilder + 'static>(
        column: &mut Box<dyn ArrayBuilder>,
    ) -> Result<&mut B> {
        column
            .as_any_mut()
            .downcast_mut()
            .ok_or_else(|| Self::invalid("input builder type"))
    }

    fn new(
        schema: &InputSchema,
        projection: Option<&BTreeSet<String>>,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<Self> {
        sink.charge(
            schema
                .schema_bytes(projection)
                .saturating_add(size_of::<Self>())
                .saturating_add(11 * size_of::<(&str, Self)>() + 16 * size_of::<usize>()),
        )?;
        let schema = schema.projected_schema(projection);
        Ok(Self {
            schema,
            batches: Vec::new(),
            columns: Vec::new(),
            capacities: Vec::new(),
            row_capacity: 0,
            rows: 0,
        })
    }

    fn fixed_width(kind: &sdk::DataType) -> usize {
        kind.primitive_width().unwrap_or(
            if matches!(kind, sdk::DataType::Binary | sdk::DataType::Utf8) {
                4
            } else {
                1
            },
        )
    }

    fn layout(kind: &sdk::DataType) -> (usize, usize, usize) {
        use sdk::arrow_array::{BooleanArray, UInt64Array};
        match kind {
            sdk::DataType::Binary | sdk::DataType::Utf8 => {
                (size_of::<BinaryBuilder>(), size_of::<BinaryArray>(), 2)
            }
            sdk::DataType::Boolean => (size_of::<BooleanBuilder>(), size_of::<BooleanArray>(), 1),
            _ => (size_of::<UInt64Builder>(), size_of::<UInt64Array>(), 1),
        }
    }

    fn data_capacity(rows: usize, bytes: usize) -> usize {
        bytes.saturating_mul(rows)
    }

    fn retained_bytes(field: &sdk::Field) -> usize {
        use datafusion::arrow::buffer::{Buffer, MutableBuffer};
        let (_, array, buffers) = Self::layout(field.data_type());
        array
            + size_of::<ArrayRef>()
            + 2 * size_of::<usize>()
            + (buffers + usize::from(field.is_nullable()))
                * (size_of::<MutableBuffer>()
                    + size_of::<Buffer>()
                    + size_of::<(Buffer, QueryLease)>()
                    + 4 * size_of::<usize>())
    }

    fn finding_bytes(&self) -> usize {
        let index = 11 * size_of::<((&[u8], &str), (u64, usize))>() + 16 * size_of::<usize>();
        let selected = self.schema.fields().iter().fold(
            self.slice_bytes() + size_of::<sdk::RecordBatch>(),
            |bytes, field| bytes.saturating_add(Self::retained_bytes(field)),
        );
        size_of::<bool>() + index.max(selected)
    }

    fn capacity_bytes(&self, rows: usize, sizes: &[Option<usize>], retain: bool) -> usize {
        use datafusion::arrow::buffer::{Buffer, MutableBuffer};
        let owner = size_of::<MutableBuffer>() + size_of::<Buffer>() + 2 * size_of::<usize>();
        let headers =
            size_of::<sdk::RecordBatch>() * (1 + usize::from(retain)) + 4 * size_of::<Buffer>();
        self.schema
            .fields()
            .iter()
            .zip(sizes.iter().flatten())
            .fold(headers, |bytes, (field, data)| {
                let (builder, array, buffers) = Self::layout(field.data_type());
                let variable = matches!(
                    field.data_type(),
                    sdk::DataType::Binary | sdk::DataType::Utf8
                );
                let values = if variable {
                    Self::data_capacity(rows, *data)
                        .saturating_add(rows.saturating_add(1).saturating_mul(size_of::<i32>()))
                        .saturating_add(4 * size_of::<i32>())
                } else if field.data_type() == &sdk::DataType::Boolean {
                    rows.div_ceil(8).next_multiple_of(64)
                } else {
                    rows.saturating_mul(Self::fixed_width(field.data_type()))
                };
                let validity = if field.is_nullable() {
                    rows.div_ceil(8).next_multiple_of(64)
                } else {
                    0
                };
                let retained = if retain {
                    Self::retained_bytes(field)
                } else {
                    0
                };
                bytes
                    .saturating_add(builder.max(retained))
                    .saturating_add(array)
                    .saturating_add(
                        size_of::<Box<dyn ArrayBuilder>>()
                            + size_of::<ArrayRef>()
                            + 3 * size_of::<usize>(),
                    )
                    .saturating_add(
                        (buffers + usize::from(field.is_nullable())).saturating_mul(owner),
                    )
                    .saturating_add(values)
                    .saturating_add(validity)
            })
    }

    fn fits(&self, sizes: &[Option<usize>]) -> bool {
        self.rows < self.row_capacity
            && self
                .columns
                .iter()
                .zip(sizes.iter().flatten())
                .zip(&self.capacities)
                .all(|((column, size), capacity)| {
                    if let Some(column) = column.as_any().downcast_ref::<BinaryBuilder>() {
                        column
                            .values_slice()
                            .len()
                            .checked_add(*size)
                            .is_some_and(|bytes| bytes <= *capacity)
                    } else if let Some(column) = column.as_any().downcast_ref::<StringBuilder>() {
                        column
                            .values_slice()
                            .len()
                            .checked_add(*size)
                            .is_some_and(|bytes| bytes <= *capacity)
                    } else {
                        true
                    }
                })
    }

    fn open(
        &mut self,
        sizes: &[Option<usize>],
        retain: bool,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<()> {
        self.flush(sink)?;
        sink.grow(&mut self.batches)?;
        let mut rows = sink.page_rows();
        while rows > 1 && self.capacity_bytes(rows, sizes, retain) > sink.remaining_bytes() {
            rows = rows.div_ceil(2);
        }
        sink.charge(self.capacity_bytes(rows, sizes, retain))?;
        self.row_capacity = rows;
        self.capacities = self
            .schema
            .fields()
            .iter()
            .zip(sizes.iter().flatten())
            .map(|(field, size)| {
                if matches!(
                    field.data_type(),
                    sdk::DataType::Binary | sdk::DataType::Utf8
                ) {
                    Self::data_capacity(rows, *size)
                } else {
                    0
                }
            })
            .collect();
        self.columns = self
            .schema
            .fields()
            .iter()
            .zip(&self.capacities)
            .map(|(field, bytes)| -> Box<dyn ArrayBuilder> {
                match field.data_type() {
                    sdk::DataType::Binary => Box::new(BinaryBuilder::with_capacity(rows, *bytes)),
                    sdk::DataType::Utf8 => Box::new(StringBuilder::with_capacity(rows, *bytes)),
                    kind => make_builder(kind, rows),
                }
            })
            .collect();
        Ok(())
    }

    fn flush(&mut self, sink: &mut ProjectionSink<'_, ()>) -> Result<()> {
        if self.rows == 0 {
            return Ok(());
        }
        sink.grow(&mut self.batches)?;
        let columns = self
            .columns
            .iter_mut()
            .map(|column| column.finish())
            .collect();
        let options = RecordBatchOptions::new().with_row_count(Some(self.rows));
        let batch = sdk::RecordBatch::try_new_with_options(self.schema.clone(), columns, &options)
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)?;
        self.batches.push(batch);
        self.columns.clear();
        self.rows = 0;
        self.row_capacity = 0;
        Ok(())
    }

    fn slice_bytes(&self) -> usize {
        self.schema
            .fields()
            .iter()
            .fold(size_of::<sdk::RecordBatch>(), |bytes, field| {
                bytes
                    .saturating_add(Self::layout(field.data_type()).1)
                    .saturating_add(size_of::<ArrayRef>() + 2 * size_of::<usize>())
            })
    }

    fn latest_findings(&mut self, sink: &mut ProjectionSink<'_, ()>) -> Result<()> {
        let count = self
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>();
        let mut keep = vec![false; count];
        let mut latest: BTreeMap<(&[u8], &str), (u64, usize)> = BTreeMap::new();
        let mut row_index = 0;
        for batch in &self.batches {
            let tenants = batch
                .column_by_name("tenant_id")
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or_else(|| Self::invalid("finding tenant"))?;
            let names = batch
                .column_by_name("finding_id")
                .and_then(|column| column.as_any().downcast_ref::<StringArray>())
                .ok_or_else(|| Self::invalid("finding identity"))?;
            let commits = batch
                .column_by_name("commit_revision")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or_else(|| Self::invalid("finding revision"))?;
            for row in 0..batch.num_rows() {
                sink.check()?;
                let key = (tenants.value(row), names.value(row));
                if let Some((revision, old)) = latest.get_mut(&key) {
                    if commits.value(row) > *revision {
                        keep[*old] = false;
                        keep[row_index] = true;
                        (*revision, *old) = (commits.value(row), row_index);
                    }
                } else {
                    latest.insert(key, (commits.value(row), row_index));
                    keep[row_index] = true;
                }
                row_index += 1;
            }
        }
        drop(latest);
        let mut selected = Vec::with_capacity(count);
        let mut offset = 0;
        for batch in &self.batches {
            let rows = &keep[offset..offset + batch.num_rows()];
            let mut cursor = 0;
            while cursor < rows.len() {
                if !rows[cursor] {
                    cursor += 1;
                    continue;
                }
                let first = cursor;
                while cursor < rows.len() && rows[cursor] {
                    cursor += 1;
                }
                let batch = batch.slice(first, cursor - first);
                selected.push(batch);
            }
            offset += batch.num_rows();
        }
        self.batches = selected;
        Ok(())
    }
}

impl InputRelations {
    pub(super) fn append(
        &mut self,
        schema: &'static InputSchema,
        projection: Option<&BTreeSet<String>>,
        sink: &mut ProjectionSink<'_, ()>,
        sizes: &[Option<usize>],
        write: impl FnOnce(&mut [Box<dyn ArrayBuilder>]) -> Result<()>,
    ) -> Result<bool> {
        InputBatch::check_offsets(sizes.iter().flatten().copied().max().unwrap_or_default())?;
        let bytes = schema.fields(projection).zip(sizes.iter().flatten()).fold(
            0usize,
            |bytes, (field, data)| {
                bytes
                    .saturating_add(InputBatch::fixed_width(&field.1))
                    .saturating_add(*data)
                    .saturating_add(1)
            },
        );
        if !sink.admit(bytes)? {
            return Ok(false);
        }
        if !self.tables.contains_key(schema.name) {
            let batch = InputBatch::new(schema, projection, sink)?;
            self.tables.insert(schema.name, batch);
        }
        let table = self
            .tables
            .get_mut(schema.name)
            .ok_or_else(|| InputBatch::invalid("input relation"))?;
        if schema.name == "findings" {
            sink.charge(table.finding_bytes())?;
        }
        if !table.fits(sizes) {
            table.open(sizes, schema.name != "findings", sink)?;
        }
        write(&mut table.columns)?;
        table.rows += 1;
        self.input_rows += 1;
        sink.projected(bytes);
        Ok(true)
    }

    pub(super) fn allocation_bytes(&self) -> usize {
        self.bytes
    }

    pub(super) fn next_expiry(&self, seconds: u32) -> Option<u64> {
        self.received_min
            .and_then(|time| time.checked_add(u64::from(seconds) * 1_000_000_000))
            .and_then(|time| time.checked_add(1_000_000_000))
            .map(|time| time / 1_000_000_000 * 1_000_000_000)
    }

    pub(super) fn json(
        sink: &mut ProjectionSink<'_, ()>,
        value: &impl serde::Serialize,
    ) -> Result<Vec<u8>> {
        let mut writer = JsonBytes {
            sink,
            bytes: Vec::new(),
            failure: None,
        };
        let result = serde_json::to_writer(&mut writer, value);
        if let Some(error) = writer.failure {
            return Err(error);
        }
        result.map_err(|source| crate::QueryEncodingSnafu.into_error(source))?;
        Ok(writer.bytes)
    }

    fn finish(
        mut self,
        extraction: &mut AnalysisExtractionV1<()>,
        template: &QueryTemplate,
        projections: &BTreeMap<&'static str, BTreeSet<String>>,
        graph_inputs: bool,
        control: &crate::AnalysisReadControl,
    ) -> Result<Self> {
        if !extraction.missing_results.is_empty() {
            return crate::QueryUnsupportedSnafu {
                relation: "results",
            }
            .fail();
        }
        let accepted = self.input_rows;
        let sources = take(&mut extraction.sources);
        let enabled = (
            extraction.discovery_enabled,
            extraction.graph_enabled,
            extraction.notification_enabled,
        );
        let result = if graph_inputs {
            Ok(())
        } else {
            self.metadata(
                &sources,
                enabled,
                template,
                projections,
                &mut extraction.sink(control),
            )
        };
        extraction.sources = sources;
        result?;
        let mut sink = extraction.sink(control);
        for schema in SCHEMAS
            .iter()
            .filter(|schema| !graph_inputs && template.reads_relation(schema.name))
            .chain(
                [&SUBJECTS, &RELATIONSHIPS, &super::analysis::MANIFEST]
                    .into_iter()
                    .filter(|_| graph_inputs),
            )
        {
            if !self.tables.contains_key(schema.name) {
                let projection =
                    projections
                        .get(schema.name)
                        .or_else(|| match (schema.name, template) {
                            ("events", QueryTemplate::Client(sql)) => sql.event_fields(),
                            _ => None,
                        });
                let batch = InputBatch::new(schema, projection, &mut sink)?;
                self.tables.insert(schema.name, batch);
            }
        }
        for (name, table) in &mut self.tables {
            table.flush(&mut sink)?;
            if *name == "findings" && !table.batches.is_empty() {
                table.latest_findings(&mut sink)?;
            }
            if table.batches.is_empty() {
                sink.grow(&mut table.batches)?;
                sink.charge(table.slice_bytes())?;
                let batch = sdk::RecordBatch::new_empty(table.schema.clone());
                sink.charge(QueryLease::batch_overhead(&batch))?;
                table.batches.push(batch);
            }
        }
        self.input_rows = accepted;
        self.bytes = extraction.input_bytes;
        Ok(self)
    }

    fn report(source: &AnalysisSourceSnapshotV1) -> Result<Option<CoverageReport>> {
        let Some(bytes) = &source.coverage_report else {
            if source.receipt.coverage_revision != 0 {
                return crate::QueryInvalidSnafu {
                    field: "coverage snapshot report",
                }
                .fail();
            }
            return Ok(None);
        };
        if bytes.is_empty() || bytes.len() > crate::MAX_EVIDENCE_GRPC_MESSAGE_BYTES {
            return crate::QueryInvalidSnafu {
                field: "coverage snapshot size",
            }
            .fail();
        }
        let report =
            CoverageReport::decode(bytes.as_slice()).context(crate::EvidenceDecodeSnafu {
                frame_bytes: bytes.len(),
            })?;
        let receipt = &source.receipt;
        if report.source_id != receipt.identity.source_id
            || report.source_epoch != receipt.identity.source_epoch
            || report.cpu_id != receipt.cpu_id
            || report.revision != receipt.coverage_revision
            || report.revision == 0
        {
            return crate::QueryInvalidSnafu {
                field: "coverage snapshot coordinates",
            }
            .fail();
        }
        Ok(Some(report))
    }
}

struct JsonBytes<'a, 'b> {
    sink: &'a mut ProjectionSink<'b, ()>,
    bytes: Vec<u8>,
    failure: Option<crate::Error>,
}

impl std::io::Write for JsonBytes<'_, '_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let required = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON input size"))?;
        if required > self.bytes.capacity() {
            let capacity = required
                .checked_next_power_of_two()
                .ok_or_else(|| std::io::Error::other("JSON input size"))?;
            if let Err(error) = self.sink.charge(capacity - self.bytes.capacity()) {
                self.failure = Some(error);
                return Err(std::io::Error::other("JSON input admission"));
            }
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(std::io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) use {column, relation};

const SOURCE_KEY: &str = "tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id";
const CONTEXT_ABSENT: &str = "No decision context is present.";
const OBJECT_ABSENT: &str = "No exact file object is present.";
const INTERVAL_ABSENT: &str = "This row is not a report interval.";
const OPENING_ABSENT: &str = "No opening counter snapshot is present.";
const CLOSING_ABSENT: &str = "No closing counter snapshot is present.";

relation! {
    pub(super) EVENTS, event(sink; identity: &EvidenceIntakeIdentityV1, cpu_id: u32, received_utc_ns: u64, record: &crate::AnalysisRecordV1, decoded: &crate::EvidenceRecord) {
        name: "events",
        join_keys: "Event identity: tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,source_cursor. Store order: commit_revision,ordinal within the result store UUID and recovery epoch. Coverage: full source identity plus coverage_interval_id=interval_id. Context requires an exact owner/entity/lifetime/revision key; names and time are not join keys.",
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "Immutable evidence rows. Row counts are not physical-action counts. Coverage corrections do not change these rows. Source, intake, and store positions are distinct.",
        setup {
            let context = decoded.decision_context.as_ref();
            let object = context.and_then(|context| context.exact_file_object.as_ref());
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(identity.tenant_id.as_slice());
            node_id: Utf8("exact Node ID", "") => Some(identity.node_id.as_str());
            node_boot_id: Binary("16-byte ID", "") => Some(identity.node_boot_id.as_slice());
            label_epoch: UInt64("label epoch", "") => Some(identity.label_epoch);
            source_id: Binary("16-byte ID", "") => Some(identity.source_id.as_slice());
            source_epoch: UInt64("source epoch", "") => Some(identity.source_epoch);
            cpu_id: UInt32("CPU ID", "") => Some(cpu_id);
            source_cursor: UInt64("source cursor", "") => Some(record.cursor);
            commit_revision: UInt64("store revision", "") => Some(record.position.commit_revision);
            ordinal: UInt32("record index within commit", "") => Some(record.position.ordinal);
            received_utc_ns: UInt64("Control intake UTC nanoseconds", "") => Some(received_utc_ns);
            received_at: TimestampMicrosecond("Control intake UTC microseconds; nanoseconds truncated", "") =>
                Some((received_utc_ns / 1_000) as i64);
            observed_boottime_ns: UInt64("Node boot-relative nanoseconds", "") =>
                Some(decoded.observed_boottime_ns);
            ingested_utc_ns: Int64("Node ingestion UTC nanoseconds", "") => Some(decoded.ingested_utc_ns);
            coverage_interval_id: Binary("exact interval ID", "") => Some(decoded.coverage_interval_id.as_ref());
            profile_generation_ref_id: UInt64("profile generation reference", "No profile reference is present.") =>
                decoded.profile_generation_ref_id;
            task_cookie: UInt64("boot-local task cookie", "") => Some(decoded.task_cookie);
            process_lineage_id: Binary("ID bytes; empty means absent", "") =>
                Some(decoded.process_lineage_id.as_ref());
            authority_domain_id: Binary("ID bytes; empty means absent", "") =>
                Some(decoded.authority_domain_id.as_ref());
            execution_set_id: Binary("ID bytes; empty means absent", "") =>
                Some(decoded.execution_set_id.as_ref());
            exact_object_id: Binary("ID bytes; empty means absent", "") => Some(decoded.exact_object_id.as_ref());
            destination_id: UInt64("destination ID; zero means absent", "") => Some(decoded.destination_id);
            policy_rule_id: UInt64("policy rule ID; zero means absent", "") => Some(decoded.policy_rule_id);
            reason: UInt32("wire reason code; unknown values retained", "") => Some(decoded.reason);
            decision: UInt32("wire decision code; unknown values retained", "") => Some(decoded.decision);
            effect_family: UInt32("wire family code; unknown values retained", "") => Some(decoded.effect_family);
            operation: UInt32("wire operation code; unknown values retained", "") => Some(decoded.operation);
            configured_errno: Int32("configured errno", "") => Some(decoded.configured_errno);
            kernel_result: Int32("kernel return value", "") => Some(decoded.kernel_result);
            temporal_coverage: Int32("wire coverage enum; 0 unknown, 1 complete, 2 gapped; other values retained", "") =>
                Some(decoded.temporal_coverage);
            target_task_cookie: UInt64("boot-local target task cookie", "No target task cookie is present.") =>
                decoded.target_task_cookie;
            operation_argument: UInt32("operation-specific argument", "No operation argument is present.") =>
                decoded.operation_argument;
            context_schema_version: UInt32("decision context version", CONTEXT_ABSENT) =>
                context.map(|context| context.schema_version);
            kernel_sequence: UInt64("original kernel sequence, not source cursor", CONTEXT_ABSENT) =>
                context.map(|context| context.original_kernel_sequence);
            process_instance_id: Binary("ID bytes; empty means absent", CONTEXT_ABSENT) =>
                context.map(|context| context.process_instance_id.as_slice());
            entry_instance_id: Binary("ID bytes; empty means absent", CONTEXT_ABSENT) =>
                context.map(|context| context.entry_instance_id.as_slice());
            binding_id: Binary("ID bytes; empty means absent", CONTEXT_ABSENT) =>
                context.map(|context| context.binding_id.as_slice());
            context_profile_generation_ref_id: UInt64("context profile generation reference", CONTEXT_ABSENT) =>
                context.map(|context| context.profile_generation_ref_id);
            role_id: UInt32("role ID", CONTEXT_ABSENT) => context.map(|context| context.role_id);
            state_id: UInt32("state ID", CONTEXT_ABSENT) => context.map(|context| context.state_id);
            entry_rule_id: UInt32("entry rule ID", CONTEXT_ABSENT) => context.map(|context| context.entry_rule_id);
            exact_object_key_id: UInt64("exact object handle", CONTEXT_ABSENT) =>
                context.map(|context| context.exact_object_key_id);
            composite_atom_id: UInt64("composite atom ID", CONTEXT_ABSENT) =>
                context.map(|context| context.composite_atom_id);
            catalog_json: Binary("unchanged catalog bytes", CONTEXT_ABSENT) =>
                context.map(|context| context.catalog_json.as_slice());
            catalog_state: Utf8("unchanged catalog state", CONTEXT_ABSENT) =>
                context.map(|context| context.catalog_state.as_str());
            exact_profile_generation_ref_id: UInt64("file object profile generation reference", OBJECT_ABSENT) =>
                object.map(|object| object.profile_generation_ref_id);
            mount_id_unique: UInt64("unique mount ID", OBJECT_ABSENT) =>
                object.map(|object| object.mount_id_unique);
            inode: UInt64("inode number", OBJECT_ABSENT) => object.map(|object| object.inode);
            inode_generation: UInt64("inode generation", OBJECT_ABSENT) =>
                object.map(|object| object.inode_generation);
            mount_namespace_inode: UInt32("mount namespace inode", OBJECT_ABSENT) =>
                object.map(|object| object.mount_namespace_inode);
            filesystem_device: UInt32("filesystem device", OBJECT_ABSENT) =>
                object.map(|object| object.filesystem_device);
        }
    }
}

relation! {
    pub(super) COVERAGE, coverage_row(sink; source: &AnalysisSourceSnapshotV1, kind: &str, state: &str, gap: Option<&AnalysisGapV1>, interval: Option<&CoverageInterval>) {
        name: "coverage",
        join_keys: SOURCE_KEY,
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "One captured source receipt plus explicit source gaps and report intervals. Reported does not mean healthy. Missing reports and absent counters are unknown. Counters are snapshots, not additive action counts.",
        setup {
            let receipt = &source.receipt;
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(receipt.identity.tenant_id.as_slice());
            node_id: Utf8("exact Node ID", "") => Some(receipt.identity.node_id.as_str());
            node_boot_id: Binary("16-byte ID", "") => Some(receipt.identity.node_boot_id.as_slice());
            label_epoch: UInt64("label epoch", "") => Some(receipt.identity.label_epoch);
            source_id: Binary("16-byte ID", "") => Some(receipt.identity.source_id.as_slice());
            source_epoch: UInt64("receipt source epoch", "") => Some(receipt.identity.source_epoch);
            cpu_id: UInt32("CPU ID", "") => Some(receipt.cpu_id);
            contiguous_cursor: UInt64("durable contiguous ACK cursor", "") => Some(receipt.contiguous_cursor);
            coverage_revision: UInt64("captured report revision; zero means no report", "") =>
                Some(receipt.coverage_revision);
            retained_floor: UInt64("retained source cursor floor", "") => Some(receipt.retained_floor);
            kind: Utf8("receipt, expired, recovery, pending, or interval", "") => Some(kind);
            state: Utf8("unchanged interval state; receipt is reported or unknown", "") => Some(state);
            first_cursor: UInt64("inclusive source gap cursor", "This row is not a source gap.") =>
                gap.map(|gap| gap.first_cursor);
            last_cursor: UInt64("inclusive source gap cursor", "This row is not a source gap.") =>
                gap.map(|gap| gap.last_cursor);
            commit_revision: UInt64("source gap store revision", "This row is not a source gap.") =>
                gap.map(|gap| gap.commit_revision);
            interval_id: Binary("exact report interval ID", INTERVAL_ABSENT) =>
                interval.map(|interval| interval.interval_id.as_slice());
            interval_source_epoch: UInt64("report interval source epoch", INTERVAL_ABSENT) =>
                interval.map(|interval| interval.source_epoch);
            interval_revision: UInt64("report interval revision", INTERVAL_ABSENT) =>
                interval.map(|interval| interval.revision);
            first_sequence: UInt64("first kernel sequence, not source cursor", INTERVAL_ABSENT) =>
                interval.map(|interval| interval.first_sequence);
            last_sequence: UInt64("last kernel sequence, not source cursor", "The interval is open or this row is not an interval.") =>
                interval.and_then(|interval| interval.last_sequence);
            current: Boolean("current report interval", INTERVAL_ABSENT) =>
                interval.map(|interval| interval.current);
            gap_reasons: Utf8("JSON array of unchanged reason strings", INTERVAL_ABSENT) =>
                interval.map(|interval| Self::json_text(sink, &interval.gap_reasons)).transpose()?;
            opening_attempted: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.attempted);
            opening_suppressed: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.suppressed);
            opening_requested: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.requested);
            opening_emitted: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.emitted);
            opening_lost: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.lost);
            opening_classifier_miss_count: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.classifier_miss_count);
            opening_unresolved: UInt64("counter", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.unresolved);
            opening_next_sequence: UInt64("next kernel sequence", OPENING_ABSENT) =>
                interval.and_then(|interval| interval.opening_counters.as_ref()).map(|counter| counter.next_sequence);
            closing_attempted: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.attempted);
            closing_suppressed: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.suppressed);
            closing_requested: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.requested);
            closing_emitted: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.emitted);
            closing_lost: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.lost);
            closing_classifier_miss_count: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.classifier_miss_count);
            closing_unresolved: UInt64("counter", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.unresolved);
            closing_next_sequence: UInt64("next kernel sequence", CLOSING_ABSENT) =>
                interval.and_then(|interval| interval.closing_counters.as_ref()).map(|counter| counter.next_sequence);
        }
    }
}

relation! {
    pub(super) CONTEXTS, context_version(sink; context: &AnalysisContextVersionV1) {
        name: "context_versions",
        join_keys: "tenant_id,owner_id,entity_key,lifetime_key,owner_revision",
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "Exact immutable context versions selected by key. Missing selected versions remain in result metadata. This relation does not assert discovery readiness.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(context.key.tenant_id.as_slice());
            owner_id: Utf8("exact owner ID", "") => Some(context.key.owner_id.as_str());
            entity_key: Binary("exact entity key", "") => Some(context.key.entity_key.as_slice());
            lifetime_key: Binary("exact lifetime key", "") => Some(context.key.lifetime_key.as_slice());
            owner_revision: UInt64("owner revision, not store revision", "") => Some(context.key.owner_revision);
            valid_from_utc_ns: UInt64("inclusive UTC nanoseconds", "The owner did not provide time bounds.") =>
                context.valid_from_utc_ns;
            valid_until_utc_ns: UInt64("exclusive UTC nanoseconds", "The owner did not provide an end time.") =>
                context.valid_until_utc_ns;
            sensitivity: Utf8("public, tenant, or host_restricted", "") => Some(<&str>::from(context.sensitivity));
            body: Binary("unchanged owner body bytes", "") => Some(context.body.as_slice());
        }
    }
}

relation! {
    pub(super) CATALOG, catalog_row(sink; schema: &InputSchema, ordinal: usize, field: &InputField, readiness: &str) {
        name: "catalog",
        join_keys: "relation,ordinal",
        owner: "araphor-data.QueryOwner",
        readiness: "available",
        description: "Code-owned schemas for this internal evaluator. An unavailable relation is not registered as an empty table. This catalog grants no client access.",
        setup {
        }
        fields {
            relation: Utf8("relation name", "") => Some(schema.name);
            ordinal: UInt32("zero-based column index", "") => Some(ordinal as u32);
            column_name: Utf8("column name", "") => Some(field.0);
            data_type: Utf8("DuckDB logical type", "") => Some(field.sql_type());
            units: Utf8("field units and representation", "") => Some(field.2);
            nullable: Boolean("whether the column can be NULL", "") => Some(!field.3.is_empty());
            null_meaning: Utf8("NULL meaning; empty for required fields", "") => Some(field.3);
            join_keys: Utf8("exact keys and join restrictions", "") => Some(schema.join_keys);
            owner: Utf8("data owner", "") => Some(schema.owner);
            readiness: Utf8("available or unavailable", "") => Some(readiness);
            description: Utf8("relation meaning and proof limits", "") => Some(schema.description);
        }
    }
}

relation! {
    pub(super) TRACES, trace(sink; state: &crate::TraceStateV1, intent: &crate::TraceIntentV1, target_index: u32, receipt: &crate::TraceOutputReceiptV1) {
        name: "traces",
        join_keys: "tenant_id,request_id,execution_id. The target index selects the immutable accepted binding. Original Node boot and source digest must match; names do not identify a target lifetime.",
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "One execution's retained intent, request state and output receipt. A closed stream is not a terminal result. Receipt counters do not prove raw output remains retained.",
        setup {
            let binding = intent.bindings.get(target_index as usize).ok_or_else(|| InputBatch::invalid("trace target index"))?;
            let identity = &binding.identity;
            let terminal = receipt.terminal.as_ref();
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(intent.tenant_id.as_slice());
            request_id: Binary("16-byte ID", "") => Some(intent.request_id.as_slice());
            target_index: UInt32("accepted target index", "") => Some(target_index);
            execution_id: Binary("16-byte frozen execution ID", "") => Some(identity.execution_id.as_slice());
            node_id: Utf8("exact Node ID", "") => Some(identity.node_id.as_str());
            node_boot_id: Binary("16-byte original Node boot ID", "") => Some(identity.node_boot_id.as_slice());
            binding_id: Binary("16-byte frozen runtime binding ID", "") => Some(binding.binding_id.as_slice());
            namespace_uid: Utf8("exact namespace UID", "") => Some(binding.namespace_uid.as_str());
            source: Binary("unchanged accepted source bytes", "") => Some(intent.source.bytes.as_slice());
            source_sha256: Binary("SHA-256 of accepted source; not a raw batch digest", "") =>
                Some(intent.source.sha256.as_slice());
            trace_schema_version: UInt32("trace schema version", "") => Some(1);
            request_revision: UInt64("metadata revision for cancellation and read revocation", "") =>
                Some(state.revision);
            accepted_unix_ns: UInt64("UTC nanoseconds", "") => Some(intent.accepted_unix_ns);
            deadline_unix_ns: UInt64("UTC nanoseconds", "") => Some(intent.deadline_unix_ns);
            last_sequence: UInt64("trace frame sequence", "") => Some(receipt.last_sequence);
            output_bytes: UInt64("bytes", "") => Some(receipt.output_bytes);
            retained_floor: UInt64("expired diagnostic record cursor; terminal uses last_sequence plus one", "") =>
                Some(receipt.retained_floor);
            cancel_requested: Boolean("request cancellation state", "") => Some(state.cancel_requested);
            read_revoked: Boolean("read authority state", "") => Some(state.read_revoked);
            terminal_reason: Utf8("terminal reason", "No terminal result is present.") =>
                terminal.map(|terminal| format!("{:?}", terminal.reason));
            output_incomplete: Boolean("terminal output completeness", "No terminal result is present.") =>
                terminal.map(|terminal| terminal.output_incomplete);
            kernel_lost_events: UInt64("lost event count", "The loss count is unknown or no terminal result is present.") =>
                terminal.and_then(|terminal| terminal.kernel_lost_events);
            ready_at_unix_ns: UInt64("UTC nanoseconds", "Readiness was not observed.") =>
                terminal.and_then(|terminal| terminal.ready_at_unix_ns);
            exit_code: Int32("process exit code", "No exit code is present.") =>
                terminal.and_then(|terminal| terminal.exit_code);
            forced_kill: Boolean("terminal forced-kill state", "No terminal result is present.") =>
                terminal.map(|terminal| terminal.forced_kill);
            cleanup: Utf8("terminal cleanup proof", "No terminal result is present.") =>
                terminal.map(|terminal| format!("{:?}", terminal.cleanup));
        }
    }
}

relation! {
    pub(super) TRACE_OUTPUT, trace_output(sink; identity: &crate::TraceIdentityV1, target_index: u32, sequence: u64, position: crate::StorePositionV1, kind: &str, bytes: &[u8]) {
        name: "trace_output",
        join_keys: "tenant_id,request_id,execution_id,sequence. Store order: commit_revision,ordinal within the result store UUID and recovery epoch. Match original Node boot and source digest.",
        owner: "araphor-data.AnalysisStore",
        readiness: "available",
        description: "Retained raw output with exact shared segment positions. Terminal bytes are unchanged TraceTerminalV1 JSON at last_sequence plus one. Empty output does not prove absence of activity. Expired output is not an empty successful read.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(identity.tenant_id.as_slice());
            request_id: Binary("16-byte request ID", "") => Some(identity.request_id.as_slice());
            execution_id: Binary("16-byte execution ID", "") => Some(identity.execution_id.as_slice());
            node_id: Utf8("exact Node ID", "") => Some(identity.node_id.as_str());
            node_boot_id: Binary("16-byte original Node boot ID", "") => Some(identity.node_boot_id.as_slice());
            source_sha256: Binary("SHA-256 of accepted source; not a raw batch digest", "") =>
                Some(identity.source_sha256.as_slice());
            target_index: UInt32("accepted target index", "") => Some(target_index);
            sequence: UInt64("trace frame sequence", "") => Some(sequence);
            commit_revision: UInt64("raw store revision", "") => Some(position.commit_revision);
            ordinal: UInt32("record index within raw commit", "") => Some(position.ordinal);
            kind: Utf8("metadata, data, diagnostic, or terminal", "") => Some(kind);
            bytes: Binary("unchanged raw output bytes", "") => Some(bytes);
        }
    }
}

relation! {
    pub(super) TRACE_MEASUREMENTS, trace_measurement(sink; identity: &crate::TraceIdentityV1, measurement: &crate::TraceMeasurementV1) {
        name: "trace_measurements",
        join_keys: "tenant_id,request_id,execution_id,sequence,ordinal. The sequence identifies the source trace_output frame; ordinal identifies a measurement within that frame, not a store ordinal.",
        owner: "araphor-data.TraceRecipeV1",
        readiness: "available",
        description: "Reviewed measurements decoded from retained raw frames. Do not sum cumulative snapshots. The execution ID separates reset epochs. Sampling and loss are not inferred from these rows.",
        setup {
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(identity.tenant_id.as_slice());
            request_id: Binary("16-byte request ID", "") => Some(identity.request_id.as_slice());
            execution_id: Binary("16-byte execution ID; reset epoch", "") => Some(identity.execution_id.as_slice());
            sequence: UInt64("source trace frame sequence", "") => Some(measurement.sequence);
            ordinal: UInt32("measurement index within frame", "") => Some(u32::from(measurement.ordinal));
            syscall_id: UInt32("syscall number", "The recipe has no exact syscall ID.") => measurement.syscall_id;
            errno: Int64("negative errno", "") => Some(measurement.errno);
            count: UInt64("recipe unit", "") => Some(measurement.count);
            cumulative: Boolean("cumulative or interval count", "") => Some(measurement.cumulative);
            atomic_snapshot: Boolean("snapshot atomicity", "") => Some(measurement.atomic_snapshot);
            unit: Utf8("reviewed recipe unit", "") => Some(measurement.unit.as_str());
        }
    }
}

relation! {
    pub(super) TARGETS, target(sink; context: &AnalysisContextVersionV1, fact: &crate::WorkloadTargetFactV1) {
        name: "targets",
        join_keys: "tenant_id,entity_key,lifetime_key,owner_revision. Join events or traces by tenant_id,node_id,node_boot_id,binding_id. Names do not identify a target lifetime.",
        owner: "mithril-control.ControlContextOwner",
        readiness: "available",
        description: "Retained policy target inventory from committed immutable snapshots. This relation is not complete live inventory and does not assert current attachment, policy readiness, or trace capability. Trace submission resolves the current exact lifetime.",
        setup {
            let entity = fact.kubernetes.as_ref().map_or(fact.execution_set_id.as_str(), |identity| identity.binding_id.as_str());
            if context.key.owner_id != "mithril-control/target" || context.key.entity_key != entity.as_bytes()
                || context.key.lifetime_key != fact.workload_binding_generation_digest.as_bytes()
                || context.key.owner_revision != 1 || !crate::node_id_is_valid(&fact.node_id) {
                return crate::QueryInvalidSnafu { field: "target context" }.fail();
            }
            let identity = fact.kubernetes.as_ref();
            let id = |value: &str| uuid::Uuid::parse_str(value).ok().filter(|id| !id.is_nil())
                .ok_or_else(|| InputBatch::invalid("target identity"));
            let boot = identity.map(|identity| id(&identity.node_boot_id)).transpose()?;
            let binding = identity.map(|identity| id(&identity.binding_id)).transpose()?;
            let kind = match fact.container_kind {
                crate::ContainerKindV1::Init => "INIT", crate::ContainerKindV1::Sidecar => "SIDECAR",
                crate::ContainerKindV1::Application => "APPLICATION", crate::ContainerKindV1::Ephemeral => "EPHEMERAL",
            };
        }
        fields {
            tenant_id: Binary("16-byte ID", "") => Some(context.key.tenant_id.as_slice());
            entity_key: Binary("exact retained context entity key", "") => Some(context.key.entity_key.as_slice());
            lifetime_key: Binary("exact retained context lifetime key", "") =>
                Some(context.key.lifetime_key.as_slice());
            owner_revision: UInt64("immutable context version", "") => Some(context.key.owner_revision);
            node_id: Utf8("exact Node ID", "") => Some(fact.node_id.as_str());
            node_boot_id: Binary("16-byte original Node boot ID", "No Kubernetes identity is present.") =>
                boot.as_ref().map(|id| id.as_bytes().as_slice());
            label_epoch: UInt64("original label epoch", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.label_epoch);
            binding_id: Binary("16-byte exact runtime binding ID", "No Kubernetes identity is present.") =>
                binding.as_ref().map(|id| id.as_bytes().as_slice());
            workload_binding_generation_digest: Utf8("existing signed fact generation identity", "") =>
                Some(fact.workload_binding_generation_digest.as_str());
            execution_set_id: Utf8("exact execution set ID", "") => Some(fact.execution_set_id.as_str());
            cluster_uid: Utf8("exact cluster UID", "") => Some(fact.cluster_uid.as_str());
            namespace_uid: Utf8("exact namespace UID", "") => Some(fact.namespace_uid.as_str());
            controller_uid: Utf8("exact controller UID", "") => Some(fact.controller_uid.as_str());
            service_account_uid: Utf8("exact service account UID", "") => Some(fact.service_account_uid.as_str());
            pod_uid: Utf8("exact Pod UID", "") => Some(fact.pod_uid.as_str());
            container_id: Utf8("exact runtime container ID", "") => Some(fact.container_id.as_str());
            container_name: Utf8("container name; not a lifetime key", "") => Some(fact.container_name.as_str());
            container_kind: Utf8("INIT, SIDECAR, APPLICATION, or EPHEMERAL", "") => Some(kind);
            image_digest: Utf8("retained image identity", "") => Some(fact.image_digest.as_str());
            pod_labels: Binary("JSON object of retained labels", "") => Some(Self::json(sink, &fact.pod_labels)?);
            namespace_name: Utf8("retained namespace name", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.namespace_name.as_str());
            pod_name: Utf8("retained Pod name; not a lifetime key", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.pod_name.as_str());
            profile_id: Utf8("exact profile ID", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.profile_id.as_str());
            policy_source_revision_id: Utf8("existing policy source identity", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.policy_source_revision_id.as_str());
            protected_scope_id: Utf8("exact protected scope ID", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.protected_scope_id.as_str());
            workload_selector_id: Utf8("exact workload selector ID", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.workload_selector_id.as_str());
            kubernetes_node_name: Utf8("retained Kubernetes Node name", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.kubernetes_node_name.as_str());
            kubernetes_node_uid: Utf8("exact Kubernetes Node UID", "No Kubernetes identity is present.") =>
                identity.map(|identity| identity.kubernetes_node_uid.as_str());
        }
    }
}

relation! {
    pub(super) TRACE_RECIPES, recipe(sink; recipe: &TraceRecipeManifestV1) {
        name: "trace_recipes",
        join_keys: "recipe,version. source_sha256 binds the exact reviewed source. A recipe row grants no execution authority.",
        owner: "araphor-data.TraceRecipeV1",
        readiness: "available",
        description: "Code-owned reviewed recipes, not stored copies. Capability status is unknown until the selected Node admits the request. This relation does not enable a backend or assert performance qualification.",
        setup {
            let name = match recipe.recipe { TraceRecipeV1::SyscallErrors => "syscall-errors@1", TraceRecipeV1::FailedOpens => "failed-opens@1" };
        }
        fields {
            recipe: Utf8("exact public recipe selector", "") => Some(name);
            version: UInt32("reviewed recipe version", "") => Some(recipe.version);
            source: Binary("unchanged reviewed bpftrace source", "") => Some(recipe.source.bytes.as_slice());
            source_sha256: Binary("SHA-256 of reviewed source", "") => Some(recipe.source.sha256.as_slice());
            parameter: Utf8("Node-owned parameter; not a client override", "") => Some(recipe.parameter.as_str());
            attribution: Utf8("recipe attribution boundary", "") => Some(recipe.attribution.as_str());
            sensitivity: Utf8("output sensitivity", "") => Some(recipe.sensitivity.as_str());
            hook: Utf8("required kernel hook", "") => Some(recipe.hook.as_str());
            measurement_keys: Binary("JSON array of measurement keys", "") =>
                Some(Self::json(sink, &recipe.measurement_keys)?);
            unit: Utf8("measurement unit", "") => Some(recipe.unit.as_str());
            cumulative: Boolean("cumulative or interval count", "") => Some(recipe.cumulative);
            atomic_snapshot: Boolean("snapshot atomicity", "") => Some(recipe.atomic_snapshot);
            maximum_probes: UInt32("probe limit", "") => Some(u32::from(recipe.maximum_probes));
            maximum_map_keys: UInt32("map key limit", "") => Some(recipe.maximum_map_keys);
            return_code_semantics: Utf8("kernel return code meaning", "") =>
                Some(recipe.return_code_semantics.as_str());
            capability_status: Utf8("unknown; backend readiness was not checked", "") => Some("unknown");
            example: Utf8("CLI example; target names require current resolution", "") =>
                Some(format!("araphor trace --target pod/default/workload --recipe {name} --duration 30s"));
        }
    }
}

pub(super) const SCHEMAS: &[InputSchema] = &[
    EVENTS,
    COVERAGE,
    CONTEXTS,
    CATALOG,
    TRACES,
    TRACE_OUTPUT,
    TRACE_MEASUREMENTS,
    TARGETS,
    TRACE_RECIPES,
    BEHAVIORS,
    CONTEXT,
    FINDINGS,
    RELATIONSHIPS,
    SUBJECTS,
    BRANCHES,
    PACKAGES,
    POLICY,
    NOTIFICATIONS,
];

pub(super) struct InputProjection<'a> {
    template: &'a QueryTemplate,
    pub(super) selection: &'a crate::AnalysisSelectionV1,
    now_utc_ns: u64,
    recipes: Vec<RecipeInput>,
    pub(super) graph_inputs: bool,
    pub(super) inputs: InputRelations,
    pub(super) projections: BTreeMap<&'static str, BTreeSet<String>>,
}

struct RecipeInput {
    identity: crate::TraceIdentityV1,
    recipe: Option<TraceRecipeV1>,
}

impl<'a> InputProjection<'a> {
    pub(super) fn new(
        template: &'a QueryTemplate,
        selection: &'a crate::AnalysisSelectionV1,
        now_utc_ns: u64,
    ) -> Self {
        Self {
            template,
            selection,
            now_utc_ns,
            recipes: Vec::new(),
            graph_inputs: false,
            inputs: InputRelations::default(),
            projections: BTreeMap::new(),
        }
    }

    pub(super) fn graph(selection: &'a crate::AnalysisSelectionV1) -> Self {
        let mut project = Self {
            graph_inputs: true,
            ..Self::new(&QueryTemplate::Catalog, selection, 0)
        };
        for schema in [&SUBJECTS, &RELATIONSHIPS] {
            project.projections.insert(
                schema.name,
                schema
                    .columns
                    .iter()
                    .filter(|field| field.0 != "graph_revision")
                    .map(|field| field.0.to_owned())
                    .collect(),
            );
        }
        project
    }

    fn needs(&self, relation: &str) -> bool {
        self.template.reads_relation(relation)
    }

    pub(super) fn expands(&self, relation: &str) -> bool {
        (self.graph_inputs && matches!(relation, "graph_subjects" | "relationships"))
            || matches!(self.template, QueryTemplate::Client(sql) if sql.dependencies().contains(relation))
    }

    pub(super) fn finish(
        self,
        extraction: &mut AnalysisExtractionV1<()>,
        control: &crate::AnalysisReadControl,
    ) -> Result<InputRelations> {
        self.inputs.finish(
            extraction,
            self.template,
            &self.projections,
            self.graph_inputs,
            control,
        )
    }

    fn emit(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<bool> {
        match input {
            AnalysisInputV1::Event {
                identity,
                cpu_id,
                received_utc_ns,
                record,
                decoded,
            } => {
                if !self.needs("events") {
                    return Ok(true);
                }
                let decoded =
                    decoded.ok_or_else(|| InputBatch::invalid("decoded evidence input"))?;
                let operation = match self.template {
                    QueryTemplate::Client(sql) => sql.event_operation(),
                    QueryTemplate::Events { operation } => *operation,
                    QueryTemplate::ExactMatch { operation, .. } => Some(*operation),
                    _ => None,
                };
                if operation.is_some_and(|operation| operation != decoded.operation) {
                    return Ok(true);
                }
                let fields = self
                    .projections
                    .get("events")
                    .or_else(|| match self.template {
                        QueryTemplate::Client(sql) => sql.event_fields(),
                        _ => None,
                    });
                let accepted = self.inputs.event(
                    sink,
                    fields,
                    (identity, cpu_id, received_utc_ns, record, decoded),
                )?;
                if accepted {
                    self.inputs.received_min = Some(
                        self.inputs
                            .received_min
                            .map_or(received_utc_ns, |time| time.min(received_utc_ns)),
                    );
                }
                Ok(accepted)
            }
            AnalysisInputV1::Context(context) => {
                if !self.needs("context_versions") {
                    return Ok(true);
                }
                self.inputs.context_version(
                    sink,
                    self.projections.get("context_versions"),
                    (context,),
                )
            }
            AnalysisInputV1::DiscoveryContext(context) => {
                if !self.needs("context") {
                    return Ok(true);
                }
                self.inputs
                    .discovery_context(sink, self.projections.get("context"), (context,))
            }
            AnalysisInputV1::Behavior {
                profile,
                commit_revision,
                atom,
                discovery_enabled,
            } => {
                if !self.needs("behaviors") {
                    return Ok(true);
                }
                self.inputs.behavior(
                    sink,
                    self.projections.get("behaviors"),
                    (profile, commit_revision, atom, discovery_enabled),
                )
            }
            AnalysisInputV1::Target { context, fact } => {
                if !self.needs("targets") {
                    return Ok(true);
                }
                self.inputs
                    .target(sink, self.projections.get("targets"), (context, fact))
            }
            AnalysisInputV1::Trace {
                state,
                intent,
                target_index,
                receipt,
            } => {
                if !self.needs("traces") {
                    return Ok(true);
                }
                self.inputs.trace(
                    sink,
                    self.projections.get("traces"),
                    (state, intent, target_index, receipt),
                )
            }
            AnalysisInputV1::TraceOutput {
                identity,
                target_index,
                sequence,
                position,
                kind,
                bytes,
            } => {
                if !self.needs("trace_output") {
                    return Ok(true);
                }
                self.inputs.trace_output(
                    sink,
                    self.projections.get("trace_output"),
                    (identity, target_index, sequence, position, kind, bytes),
                )
            }
            AnalysisInputV1::TraceMeasurement {
                identity,
                measurement,
            } => {
                if !self.needs("trace_measurements") {
                    return Ok(true);
                }
                self.inputs.trace_measurement(
                    sink,
                    self.projections.get("trace_measurements"),
                    (identity, measurement),
                )
            }
            AnalysisInputV1::Result { .. } => {
                if !self.needs("results") {
                    return Ok(true);
                }
                crate::QueryUnsupportedSnafu {
                    relation: "results",
                }
                .fail()
            }
            AnalysisInputV1::Profile { .. } => crate::QueryInvalidSnafu {
                field: "unexpanded profile",
            }
            .fail(),
            AnalysisInputV1::Graph { .. } | AnalysisInputV1::Notification { .. } => {
                crate::QueryInvalidSnafu {
                    field: "unexpanded owner input",
                }
                .fail()
            }
        }
    }
}

impl InputRelations {
    fn json_text(
        sink: &mut ProjectionSink<'_, ()>,
        value: &impl serde::Serialize,
    ) -> Result<String> {
        String::from_utf8(Self::json(sink, value)?)
            .map_err(|_| InputBatch::invalid("JSON text encoding"))
    }

    fn metadata(
        &mut self,
        sources: &[AnalysisSourceSnapshotV1],
        enabled: (bool, bool, bool),
        template: &QueryTemplate,
        projections: &BTreeMap<&'static str, BTreeSet<String>>,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<()> {
        if template.reads_relation("coverage") {
            for source in sources {
                let report = Self::report(source)?;
                let fields = projections.get("coverage");
                self.coverage_row(
                    sink,
                    fields,
                    (
                        source,
                        "receipt",
                        if report.is_some() {
                            "reported"
                        } else {
                            "unknown"
                        },
                        None,
                        None,
                    ),
                )?;
                for (kind, gaps) in [
                    ("expired", &source.expired),
                    ("recovery", &source.recovery),
                    ("pending", &source.pending),
                ] {
                    for gap in gaps {
                        self.coverage_row(sink, fields, (source, kind, kind, Some(gap), None))?;
                    }
                }
                if let Some(report) = report {
                    for interval in &report.intervals {
                        self.coverage_row(
                            sink,
                            fields,
                            (source, "interval", &interval.state, None, Some(interval)),
                        )?;
                    }
                }
            }
        }
        if template.reads_relation("catalog") {
            for schema in SCHEMAS {
                let readiness = if schema.name == "behaviors" {
                    if enabled.0 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else if super::graph::RELATIONS.contains(&schema.name) {
                    if enabled.1 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else if schema.name == "notifications" {
                    if enabled.2 {
                        "enabled"
                    } else {
                        "disabled"
                    }
                } else {
                    schema.readiness
                };
                for (ordinal, field) in schema.columns.iter().enumerate() {
                    self.catalog_row(
                        sink,
                        projections.get("catalog"),
                        (schema, ordinal, field, readiness),
                    )?;
                }
            }
        }
        if template.reads_relation("trace_recipes") {
            for recipe in [TraceRecipeV1::SyscallErrors, TraceRecipeV1::FailedOpens] {
                self.recipe(
                    sink,
                    projections.get("trace_recipes"),
                    (&recipe.manifest()?,),
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn set_boundary(
        &mut self,
        boundary: bool,
        sink: &mut ProjectionSink<'_, ()>,
    ) -> Result<()> {
        let Some(table) = self.tables.get_mut("graph_manifest") else {
            return Ok(());
        };
        let index = table
            .schema
            .index_of("hop_boundary")
            .map_err(|_| InputBatch::invalid("graph manifest boundary"))?;
        for batch in table
            .batches
            .iter_mut()
            .filter(|batch| batch.num_rows() != 0)
        {
            sink.charge(
                size_of::<sdk::RecordBatch>()
                    + batch.num_columns() * size_of::<ArrayRef>()
                    + batch.num_rows().div_ceil(8).next_multiple_of(64)
                    + 128,
            )?;
            let mut columns = batch.columns().to_vec();
            columns[index] = Arc::new(sdk::arrow_array::BooleanArray::from_iter(
                std::iter::repeat_n(boundary, batch.num_rows()),
            ));
            *batch = sdk::RecordBatch::try_new(table.schema.clone(), columns)
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
        }
        self.bytes = sink.used_bytes();
        Ok(())
    }
}

impl crate::analysis::AnalysisProjection for InputProjection<'_> {
    type Row = ();

    fn decodes_events(&self) -> bool {
        self.needs("events")
    }

    fn graph_subjects(&self) -> bool {
        self.expands("graph_subjects") || self.expands("relationships")
    }

    fn graph_relationships(&self) -> bool {
        self.expands("relationships")
            || (self.expands("graph_subjects") && !self.selection.binding_ids.is_empty())
    }

    fn project(
        &mut self,
        input: AnalysisInputV1<'_>,
        sink: &mut crate::analysis::ProjectionSink<'_, ()>,
    ) -> Result<bool> {
        sink.check()?;
        match &input {
            AnalysisInputV1::Context(context) => {
                self.emit(AnalysisInputV1::Context(context), sink)?;
                if self.expands("context") {
                    self.emit(AnalysisInputV1::DiscoveryContext(context), sink)?;
                }
                if self.selection.targets && context.key.owner_id == "mithril-control/target" {
                    let fact: crate::WorkloadTargetFactV1 = serde_json::from_slice(&context.body)
                        .map_err(|_| {
                        crate::QueryInvalidSnafu {
                            field: "retained target context",
                        }
                        .build()
                    })?;
                    if (!self.selection.nodes.is_empty()
                        && !self.selection.nodes.contains(&fact.node_id))
                        || (!self.selection.binding_ids.is_empty()
                            && !fact.kubernetes.as_ref().is_some_and(|identity| {
                                uuid::Uuid::parse_str(&identity.binding_id).is_ok_and(|id| {
                                    self.selection.binding_ids.contains(id.as_bytes())
                                })
                            }))
                    {
                        return Ok(true);
                    }
                    self.emit(
                        AnalysisInputV1::Target {
                            context,
                            fact: &fact,
                        },
                        sink,
                    )?;
                }
                Ok(true)
            }
            AnalysisInputV1::Profile {
                result_id,
                body,
                commit_revision,
                sources,
                discovery_enabled,
            } => {
                let profile = crate::DiscoveryProfileV1::try_from(*body)?;
                if profile.profile_id != *result_id || !sources.contains(&profile.scope.identity) {
                    return crate::QueryInvalidSnafu {
                        field: "discovery profile scope",
                    }
                    .fail();
                }
                if self.selection.binding_ids.is_empty() {
                    self.emit(
                        AnalysisInputV1::Behavior {
                            profile: &profile,
                            commit_revision: *commit_revision,
                            atom: None,
                            discovery_enabled: *discovery_enabled,
                        },
                        sink,
                    )?;
                }
                for atom in &profile.snapshot.atoms {
                    sink.check()?;
                    if !self.selection.binding_ids.is_empty()
                        && !self.selection.binding_ids.contains(&atom.key.binding_id)
                    {
                        continue;
                    }
                    self.emit(
                        AnalysisInputV1::Behavior {
                            profile: &profile,
                            commit_revision: *commit_revision,
                            atom: Some(atom),
                            discovery_enabled: *discovery_enabled,
                        },
                        sink,
                    )?;
                }
                Ok(true)
            }
            AnalysisInputV1::Graph { graph, .. } => {
                if graph.scope.identity.tenant_id != self.selection.tenant_id
                    || (!self.selection.sources.is_all()
                        && !self
                            .selection
                            .sources
                            .as_slice()
                            .contains(&graph.scope.identity))
                {
                    return crate::QueryDeniedSnafu.fail();
                }
                self.graph_rows(&input, &mut (None, None), sink)
            }
            AnalysisInputV1::Notification {
                obligation,
                finding,
                commit_revision,
            } => {
                if obligation.key.tenant_id != self.selection.tenant_id
                    || finding.is_some_and(|finding| !self.permits_finding(finding))
                {
                    return crate::QueryDeniedSnafu.fail();
                }
                self.inputs.notification(
                    sink,
                    self.projections.get("notifications"),
                    (obligation, *finding, *commit_revision, self.now_utc_ns),
                )
            }
            AnalysisInputV1::Trace {
                intent,
                target_index,
                ..
            } if self.expands("trace_measurements") => {
                let identity = &intent
                    .bindings
                    .get(*target_index as usize)
                    .ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "trace target index",
                        }
                        .build()
                    })?
                    .identity;
                let recipe = TraceRecipeV1::identify(&intent.source)?;
                sink.grow(&mut self.recipes)?;
                sink.charge(identity.node_id.capacity())?;
                self.recipes.push(RecipeInput {
                    identity: identity.clone(),
                    recipe,
                });
                self.emit(input, sink)
            }
            AnalysisInputV1::TraceOutput {
                identity,
                sequence,
                kind,
                bytes,
                ..
            } if self.expands("trace_measurements") && *kind == "data" => {
                let recipe = self
                    .recipes
                    .iter()
                    .find(|recipe| &recipe.identity == *identity)
                    .ok_or_else(|| {
                        crate::QueryInvalidSnafu {
                            field: "trace recipe input",
                        }
                        .build()
                    })?;
                if let Some(recipe) = recipe.recipe {
                    let frame = crate::TraceFrameV1 {
                        execution_id: identity.execution_id,
                        sequence: *sequence,
                        kind: crate::TraceFrameKindV1::Data,
                        bytes: bytes.to_vec(),
                    };
                    if let Some(measurements) = recipe.measurements(&frame) {
                        for measurement in measurements {
                            if !self.emit(
                                AnalysisInputV1::TraceMeasurement {
                                    identity,
                                    measurement: &measurement,
                                },
                                sink,
                            )? {
                                return Ok(false);
                            }
                        }
                    }
                }
                self.emit(input, sink)
            }
            _ => self.emit(input, sink),
        }
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::{
        AnalysisContextKeyV1, AnalysisRecordV1, AnalysisSourceReceiptV1, AnalysisStoreMetaV1,
        ContextSensitivityV1, CoverageCounters, EvidenceDecisionContext, EvidenceExactFileObject,
        EvidenceRecord, StorePositionV1,
    };
    use datafusion::{datasource::MemTable, prelude::SessionContext};
    use duckdb::types::{TimeUnit, Value};
    use sdk::arrow_array::{
        BooleanArray, Int32Array, Int64Array, TimestampMicrosecondArray, UInt32Array,
    };

    pub(in crate::query) type TestResult<T = ()> =
        std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    relation! {
        CANONICAL_TEST_SOURCE, canonical_test_source(sink; value: u64) {
            name: "canonical_test_source",
            join_keys: "value",
            owner: "test.owner",
            readiness: "available",
            description: "Test source rows.",
            setup {}
            fields {
                value: UInt64("count", "") => Some(value);
            }
        }
    }

    #[test]
    fn query_input_shared_schema() -> TestResult {
        for definition in SCHEMAS
            .iter()
            .chain([&super::super::analysis::MANIFEST, &CANONICAL_TEST_SOURCE])
        {
            let schema = definition.arrow_schema();
            assert!(Arc::ptr_eq(&schema, &definition.arrow_schema()));
            assert_eq!(definition.schema_bytes(None), 0);
            for (field, expected) in schema.fields().iter().zip(definition.columns) {
                assert_eq!(field.as_ref(), &expected.arrow_field(definition.owner));
            }
            let names = BTreeSet::from([definition.columns[0].0.to_owned()]);
            let projected = definition.projected_schema(Some(&names));
            for field in projected.fields() {
                let source = schema
                    .fields()
                    .iter()
                    .find(|source| source.name() == field.name())
                    .ok_or("canonical field absent")?;
                assert!(Arc::ptr_eq(source, field));
            }
            assert!(definition.schema_bytes(Some(&names)) > 0);
        }
        let mut extraction = empty_input();
        let mut input = InputRelations::default();
        assert!(input.canonical_test_source(
            &mut extraction.sink(&crate::AnalysisReadControl::default()),
            None,
            (7,),
        )?);
        assert!(Arc::ptr_eq(
            &input.tables[CANONICAL_TEST_SOURCE.name].schema,
            &CANONICAL_TEST_SOURCE.arrow_schema(),
        ));
        Ok(())
    }

    pub(in crate::query) fn empty_input() -> AnalysisExtractionV1<()> {
        AnalysisExtractionV1 {
            discovery_enabled: false,
            graph_enabled: false,
            notification_enabled: false,
            meta: AnalysisStoreMetaV1 {
                store_uuid: uuid::Uuid::from_u128(1),
                schema_version: 1,
                recovery_epoch: 2,
                commit_revision: 8,
            },
            replay_floor: None,
            sources: Vec::new(),
            missing_contexts: Vec::new(),
            missing_results: Vec::new(),
            pages: Vec::new(),
            scanned_bytes: 0,
            projected_bytes: 0,
            input_bytes: size_of::<AnalysisExtractionV1<()>>(),
            trace_reads: Vec::new(),
            graph_traversal: None,
            limits: crate::analysis::AnalysisExtractLimits {
                input_bytes: 1_000_000,
                ..Default::default()
            },
        }
    }

    pub(in crate::query) fn values(batch: &sdk::RecordBatch, row: usize) -> TestResult<Vec<Value>> {
        batch
            .columns()
            .iter()
            .map(|column| {
                if column.is_null(row) {
                    return Ok(Value::Null);
                }
                Ok(match column.data_type() {
                    sdk::DataType::Binary => Value::Blob(
                        column
                            .as_any()
                            .downcast_ref::<BinaryArray>()
                            .ok_or("binary type")?
                            .value(row)
                            .to_vec(),
                    ),
                    sdk::DataType::Utf8 => Value::Text(
                        column
                            .as_any()
                            .downcast_ref::<StringArray>()
                            .ok_or("text type")?
                            .value(row)
                            .into(),
                    ),
                    sdk::DataType::Boolean => Value::Boolean(
                        column
                            .as_any()
                            .downcast_ref::<BooleanArray>()
                            .ok_or("boolean type")?
                            .value(row),
                    ),
                    sdk::DataType::UInt32 => Value::UInt(
                        column
                            .as_any()
                            .downcast_ref::<UInt32Array>()
                            .ok_or("u32 type")?
                            .value(row),
                    ),
                    sdk::DataType::UInt64 => Value::UBigInt(
                        column
                            .as_any()
                            .downcast_ref::<UInt64Array>()
                            .ok_or("u64 type")?
                            .value(row),
                    ),
                    sdk::DataType::Int32 => Value::Int(
                        column
                            .as_any()
                            .downcast_ref::<Int32Array>()
                            .ok_or("i32 type")?
                            .value(row),
                    ),
                    sdk::DataType::Int64 => Value::BigInt(
                        column
                            .as_any()
                            .downcast_ref::<Int64Array>()
                            .ok_or("i64 type")?
                            .value(row),
                    ),
                    sdk::DataType::Timestamp(sdk::TimeUnit::Microsecond, None) => Value::Timestamp(
                        TimeUnit::Microsecond,
                        column
                            .as_any()
                            .downcast_ref::<TimestampMicrosecondArray>()
                            .ok_or("timestamp type")?
                            .value(row),
                    ),
                    _ => return Err("noncanonical source type".into()),
                })
            })
            .collect()
    }

    fn rows(input: &InputRelations, name: &str) -> TestResult<Vec<Vec<Value>>> {
        let table = input.tables.get(name).ok_or("input table absent")?;
        table
            .batches
            .iter()
            .flat_map(|batch| (0..batch.num_rows()).map(move |row| values(batch, row)))
            .collect()
    }

    fn value<'a>(schema: &InputSchema, row: &'a [Value], name: &str) -> TestResult<&'a Value> {
        let index = schema
            .columns
            .iter()
            .position(|field| field.0 == name)
            .ok_or("column absent")?;
        row.get(index).ok_or_else(|| "row value absent".into())
    }

    fn finish(
        input: InputRelations,
        extraction: &mut AnalysisExtractionV1<()>,
        template: &QueryTemplate,
    ) -> Result<InputRelations> {
        let control = crate::AnalysisReadControl::default();
        input.finish(extraction, template, &BTreeMap::new(), false, &control)
    }

    fn table_context(input: &InputRelations) -> TestResult<SessionContext> {
        let context = SessionContext::new();
        for (name, table) in &input.tables {
            context.register_table(
                *name,
                Arc::new(MemTable::try_new(
                    table.schema.clone(),
                    vec![table.batches.clone()],
                )?),
            )?;
        }
        Ok(context)
    }

    pub(in crate::query) fn mapped(input: AnalysisInputV1<'_>) -> TestResult<Vec<Value>> {
        let name = match input {
            AnalysisInputV1::Event { .. } => "events",
            AnalysisInputV1::Context(_) => "context_versions",
            AnalysisInputV1::DiscoveryContext(_) => "context",
            AnalysisInputV1::Behavior { .. } => "behaviors",
            AnalysisInputV1::Result { .. } => "results",
            _ => return Err("mapping fixture relation".into()),
        };
        let sql = if name == "results" {
            super::super::QuerySql::admit_relations(
                "SELECT 1 FROM results",
                BTreeMap::from([("results".into(), Arc::new(sdk::Schema::empty()))]),
            )?
        } else {
            super::super::QuerySql::admit(&format!("SELECT * FROM {name}"), Vec::new(), false)?
        };
        let template = QueryTemplate::Client(sql);
        let selection = crate::AnalysisSelectionV1::new([1; 16], Vec::new());
        let mut extraction = empty_input();
        let control = crate::AnalysisReadControl::default();
        let mut project = InputProjection::new(&template, &selection, 0);
        assert!(project.emit(input, &mut extraction.sink(&control))?);
        let input = project.finish(&mut extraction, &control)?;
        assert!(input.allocation_bytes() > 0);
        rows(&input, name)?
            .into_iter()
            .next()
            .ok_or_else(|| "mapped row absent".into())
    }

    fn event(record: &EvidenceRecord) -> TestResult<Vec<Value>> {
        let framed = framed(record);
        let decoded = EvidenceRecord::try_from(framed.framed_record.as_slice())?;
        mapped(AnalysisInputV1::Event {
            identity: &identity(),
            cpu_id: 6,
            received_utc_ns: u64::MAX,
            record: &framed,
            decoded: Some(&decoded),
        })
    }

    fn append_event(
        input: &mut InputRelations,
        extraction: &mut AnalysisExtractionV1<()>,
        record: &EvidenceRecord,
    ) -> TestResult {
        let control = crate::AnalysisReadControl::default();
        assert!(input.event(
            &mut extraction.sink(&control),
            None,
            (&identity(), 6, u64::MAX, &framed(record), record,),
        )?);
        Ok(())
    }

    #[test]
    fn offsets_reject_before_append() -> TestResult {
        let mut extraction = empty_input();
        let before = extraction.input_bytes;
        let mut input = InputRelations::default();
        let projection = BTreeSet::from(["catalog_json".to_owned()]);
        let mut wrote = false;
        let result = input.append(
            &EVENTS,
            Some(&projection),
            &mut extraction.sink(&crate::AnalysisReadControl::default()),
            &[Some(i32::MAX as usize + 1)],
            |_| {
                wrote = true;
                Ok(())
            },
        );
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        assert!(input.tables.is_empty());
        assert!(!wrote);
        assert_eq!(input.input_rows, 0);
        assert_eq!(extraction.input_bytes, before);
        assert_eq!(extraction.projected_bytes, 0);
        Ok(())
    }

    #[test]
    fn query_input_findings_reserve_finish() -> TestResult {
        let control = crate::AnalysisReadControl::default();
        let fields = BTreeSet::from(["finding_id".to_owned()]);
        let sizes = FINDINGS
            .columns
            .iter()
            .map(|field| match field.0 {
                "tenant_id" => Some(16),
                "commit_revision" => Some(0),
                "finding_id" => Some("finding".len()),
                _ => None,
            })
            .collect::<Vec<_>>();
        let append = |input: &mut InputRelations,
                      extraction: &mut AnalysisExtractionV1<()>,
                      wrote: &std::cell::Cell<bool>| {
            input.append(
                &FINDINGS,
                Some(&fields),
                &mut extraction.sink(&control),
                &sizes,
                |columns| {
                    wrote.set(true);
                    InputBatch::builder::<BinaryBuilder>(&mut columns[0])?.append_value([1; 16]);
                    InputBatch::builder::<UInt64Builder>(&mut columns[1])?.append_value(1);
                    InputBatch::builder::<StringBuilder>(&mut columns[2])?.append_value("finding");
                    Ok(())
                },
            )
        };
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT finding_id FROM findings",
            Vec::new(),
            false,
        )?);
        let mut extraction = empty_input();
        extraction.limits.page_rows = 1;
        let initial = extraction.input_bytes;
        let mut input = InputRelations::default();
        let wrote = std::cell::Cell::new(false);
        assert!(append(&mut input, &mut extraction, &wrote)?);
        assert!(wrote.get());
        let required = extraction.input_bytes;
        let input = input.finish(
            &mut extraction,
            &template,
            &BTreeMap::from([("findings", fields.clone())]),
            false,
            &control,
        )?;
        assert_eq!(extraction.input_bytes, required);
        let retained = input.tables["findings"]
            .batches
            .iter()
            .map(|batch| batch.get_array_memory_size() + QueryLease::batch_overhead(batch))
            .sum::<usize>();
        assert!(required - initial >= retained);
        let expected = rows(&input, "findings")?;
        assert_eq!(
            expected,
            vec![vec![
                Value::Blob(vec![1; 16]),
                Value::UBigInt(1),
                Value::Text("finding".into()),
            ]],
        );

        let mut exact = empty_input();
        exact.limits.page_rows = 1;
        exact.limits.input_bytes = required;
        let mut input = InputRelations::default();
        let wrote = std::cell::Cell::new(false);
        assert!(append(&mut input, &mut exact, &wrote)?);
        assert!(wrote.get());
        wrote.set(false);
        assert!(matches!(
            append(&mut input, &mut exact, &wrote),
            Err(crate::Error::AnalysisInputTooLarge { .. }),
        ));
        assert!(!wrote.get());
        assert_eq!(input.input_rows, 1);
        let input = input.finish(
            &mut exact,
            &template,
            &BTreeMap::from([("findings", fields.clone())]),
            false,
            &control,
        )?;
        assert_eq!(rows(&input, "findings")?, expected);
        assert_eq!(exact.input_bytes, required);

        let mut short = empty_input();
        short.limits.page_rows = 1;
        short.limits.input_bytes = required - 1;
        let mut input = InputRelations::default();
        assert!(matches!(
            append(&mut input, &mut short, &wrote),
            Err(crate::Error::AnalysisInputTooLarge { .. }),
        ));
        assert!(!wrote.get());
        assert_eq!(input.input_rows, 0);
        assert!(input.tables["findings"].columns.is_empty());
        assert!(input.tables["findings"].batches.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn query_input_append_positions() -> TestResult {
        use crate::query::{budget::QueryBudget, engine::QueryEngine, QueryLimits, QuerySql};
        use datafusion::datasource::MemTable;
        let record = EvidenceRecord {
            operation: 7,
            decision_context: Some(EvidenceDecisionContext {
                catalog_json: vec![42; 8192],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut extraction = empty_input();
        let mut input = InputRelations::default();
        append_event(&mut input, &mut extraction, &record)?;
        let input = finish(
            input,
            &mut extraction,
            &QueryTemplate::Events { operation: None },
        )?;
        let before = input.allocation_bytes();
        let table = input.tables.get("events").ok_or("events absent")?;
        let budget = QueryBudget::new(QueryLimits::default());
        let lease = budget.evaluate([1; 16])?;
        let retained = table
            .batches
            .iter()
            .map(|batch| lease.retain_batch(batch))
            .collect::<Result<Vec<_>>>()?;
        let column = retained[0]
            .column_by_name("catalog_json")
            .ok_or("catalog bytes absent")?;
        let weak = Arc::downgrade(column);
        let address = column
            .as_any()
            .downcast_ref::<BinaryArray>()
            .ok_or("catalog bytes type")?
            .value_data()
            .as_ptr();
        let tables = BTreeMap::from([(
            "events".to_owned(),
            Arc::new(MemTable::try_new(table.schema.clone(), vec![retained])?),
        )]);
        let sql = QuerySql::admit(
            "SELECT operation, catalog_json FROM events",
            Vec::new(),
            false,
        )?;
        let binding = sql.bind_at(0)?;
        let state = QueryEngine::state()?;
        let (plan, _) = QueryEngine::plan(&state, &binding, &tables, None)?;
        let (shared_plan, _) = QueryEngine::plan(&state, &sql.bind_complete(0)?, &tables, None)?;
        assert_eq!(input.allocation_bytes(), before);
        assert_eq!(table.schema.fields().len(), EVENTS.columns.len());
        assert!(table
            .schema
            .field_with_name("__araphor_commit_revision")
            .is_err());
        for _ in 0..2 {
            let mut stream = QueryEngine::stream(state.clone(), shared_plan.clone(), None).await?;
            let batch = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx))
                .await
                .ok_or("batch absent")??;
            let blob = batch
                .column_by_name("catalog_json")
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or("catalog bytes absent")?;
            assert_eq!(blob.value_data().as_ptr(), address);
            assert_eq!(blob.value(0), &vec![42; 8192]);
            assert_eq!(
                values(&batch, 0)?,
                vec![Value::UInt(7), Value::Blob(vec![42; 8192])]
            );
            let mut stream = QueryEngine::stream(state.clone(), plan.clone(), None).await?;
            let batch = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx))
                .await
                .ok_or("batch absent")??;
            let blob = batch
                .column_by_name("catalog_json")
                .and_then(|column| column.as_any().downcast_ref::<BinaryArray>())
                .ok_or("catalog bytes absent")?;
            assert_eq!(blob.value(0), &vec![42; 8192]);
            assert_eq!(
                values(&batch, 0)?,
                vec![
                    Value::UInt(7),
                    Value::Blob(vec![42; 8192]),
                    Value::UBigInt(8),
                    Value::UInt(9)
                ]
            );
        }
        drop(input);
        assert!(weak.upgrade().is_some());
        drop(tables);
        assert!(weak.upgrade().is_some());
        drop(plan);
        assert!(weak.upgrade().is_some());
        drop(shared_plan);
        assert!(weak.upgrade().is_none());
        assert!(QueryEngine::plan(&state, &binding, &BTreeMap::new(), None).is_err());
        Ok(())
    }

    #[test]
    fn query_input_append_rejects() -> TestResult {
        use crate::query::{engine::QueryEngine, QuerySql};
        use datafusion::datasource::MemTable;
        for mode in 0..4 {
            let mut extraction = empty_input();
            let mut input = InputRelations::default();
            append_event(&mut input, &mut extraction, &EvidenceRecord::default())?;
            let mut input = finish(
                input,
                &mut extraction,
                &QueryTemplate::Events { operation: None },
            )?;
            let table = input.tables.get_mut("events").ok_or("events absent")?;
            let batch = &table.batches[0];
            let revision = table.schema.index_of("commit_revision")?;
            let ordinal = table.schema.index_of("ordinal")?;
            let mut columns = batch.columns().to_vec();
            if mode == 0 {
                columns.pop();
                assert!(sdk::RecordBatch::try_new(table.schema.clone(), columns).is_err());
            } else if mode == 1 {
                columns[revision] = Arc::new(UInt64Array::from(vec![None]));
                assert!(sdk::RecordBatch::try_new(table.schema.clone(), columns).is_err());
            } else {
                let mut fields = table.schema.fields().to_vec();
                if mode == 2 {
                    fields[ordinal] =
                        Arc::new(sdk::Field::new("ordinal", sdk::DataType::UInt64, false));
                    columns[ordinal] = Arc::new(UInt64Array::from(vec![9]));
                } else {
                    fields[revision] =
                        Arc::new(sdk::Field::new("changed", sdk::DataType::UInt64, false));
                }
                let schema = Arc::new(sdk::Schema::new(fields));
                let batch = sdk::RecordBatch::try_new(schema.clone(), columns)?;
                let tables = BTreeMap::from([(
                    "events".to_owned(),
                    Arc::new(MemTable::try_new(schema, vec![vec![batch]])?),
                )]);
                let binding = QuerySql::admit("SELECT operation FROM events", Vec::new(), false)?
                    .bind_at(0)?;
                assert!(
                    QueryEngine::plan(&QueryEngine::state()?, &binding, &tables, None).is_err()
                );
            }
        }
        assert!(QuerySql::admit(
            "SELECT __araphor_commit_revision FROM events",
            Vec::new(),
            false
        )
        .is_err());
        Ok(())
    }

    fn identity() -> EvidenceIntakeIdentityV1 {
        EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 3,
            source_id: [4; 16],
            source_epoch: 5,
        }
    }

    fn framed(record: &EvidenceRecord) -> AnalysisRecordV1 {
        let mut payload = record.encode_to_vec();
        payload.extend([0xa0, 0x06, 0x07]);
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend(payload);
        bytes.extend(crc32c::crc32c(&bytes).to_be_bytes());
        AnalysisRecordV1 {
            cursor: 7,
            framed_record: bytes,
            position: StorePositionV1 {
                commit_revision: 8,
                ordinal: 9,
            },
        }
    }

    fn context() -> AnalysisContextVersionV1 {
        AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "policy".into(),
                entity_key: vec![0, 255],
                lifetime_key: vec![1, 0],
                owner_revision: u64::MAX,
            },
            valid_from_utc_ns: Some(1),
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::HostRestricted,
            body: vec![0, 128, 255],
        }
    }

    fn snapshot() -> AnalysisSourceSnapshotV1 {
        AnalysisSourceSnapshotV1 {
            receipt: AnalysisSourceReceiptV1 {
                identity: identity(),
                cpu_id: 6,
                contiguous_cursor: 0,
                coverage_revision: 0,
                retained_floor: 1,
            },
            expired: Vec::new(),
            recovery: Vec::new(),
            pending: Vec::new(),
            coverage_report: None,
        }
    }

    #[tokio::test]
    async fn query_input_record_mapping() -> TestResult {
        let record = EvidenceRecord {
            observed_boottime_ns: u64::MAX,
            ingested_utc_ns: i64::MIN,
            coverage_interval_id: vec![0, 255, 128, 0].into(),
            profile_generation_ref_id: Some(0),
            task_cookie: u64::MAX - 1,
            process_lineage_id: Vec::new().into(),
            authority_domain_id: vec![1, 0, 2].into(),
            execution_set_id: vec![3, 0, 4].into(),
            exact_object_id: vec![5, 0, 6].into(),
            destination_id: 60,
            policy_rule_id: 61,
            reason: u32::MAX,
            decision: 42,
            effect_family: 101,
            operation: 303,
            configured_errno: i32::MIN,
            kernel_result: i32::MAX,
            temporal_coverage: -17,
            target_task_cookie: Some(0),
            operation_argument: Some(0),
            decision_context: Some(EvidenceDecisionContext {
                schema_version: u32::MAX,
                original_kernel_sequence: u64::MAX,
                process_instance_id: vec![7, 0, 8],
                entry_instance_id: vec![9, 0, 10],
                binding_id: vec![11, 0, 12],
                profile_generation_ref_id: 199,
                role_id: 200,
                state_id: 201,
                entry_rule_id: 202,
                exact_file_object: Some(EvidenceExactFileObject {
                    profile_generation_ref_id: 602,
                    mount_id_unique: 603,
                    inode: u64::MAX,
                    inode_generation: 605,
                    mount_namespace_inode: u32::MAX,
                    filesystem_device: 607,
                }),
                exact_object_key_id: 900,
                composite_atom_id: 901,
                catalog_json: b"{\0}".to_vec(),
                catalog_state: "FUTURE\0STATE".into(),
            }),
        };
        let mapped = event(&record)?;
        assert_eq!(
            mapped,
            vec![
                Value::Blob(vec![1; 16]),
                Value::Text("node-a".into()),
                Value::Blob(vec![2; 16]),
                Value::UBigInt(3),
                Value::Blob(vec![4; 16]),
                Value::UBigInt(5),
                Value::UInt(6),
                Value::UBigInt(7),
                Value::UBigInt(8),
                Value::UInt(9),
                Value::UBigInt(u64::MAX),
                Value::Timestamp(TimeUnit::Microsecond, (u64::MAX / 1_000) as i64),
                Value::UBigInt(u64::MAX),
                Value::BigInt(i64::MIN),
                Value::Blob(vec![0, 255, 128, 0]),
                Value::UBigInt(0),
                Value::UBigInt(u64::MAX - 1),
                Value::Blob(Vec::new()),
                Value::Blob(vec![1, 0, 2]),
                Value::Blob(vec![3, 0, 4]),
                Value::Blob(vec![5, 0, 6]),
                Value::UBigInt(60),
                Value::UBigInt(61),
                Value::UInt(u32::MAX),
                Value::UInt(42),
                Value::UInt(101),
                Value::UInt(303),
                Value::Int(i32::MIN),
                Value::Int(i32::MAX),
                Value::Int(-17),
                Value::UBigInt(0),
                Value::UInt(0),
                Value::UInt(u32::MAX),
                Value::UBigInt(u64::MAX),
                Value::Blob(vec![7, 0, 8]),
                Value::Blob(vec![9, 0, 10]),
                Value::Blob(vec![11, 0, 12]),
                Value::UBigInt(199),
                Value::UInt(200),
                Value::UInt(201),
                Value::UInt(202),
                Value::UBigInt(900),
                Value::UBigInt(901),
                Value::Blob(b"{\0}".to_vec()),
                Value::Text("FUTURE\0STATE".into()),
                Value::UBigInt(602),
                Value::UBigInt(603),
                Value::UBigInt(u64::MAX),
                Value::UBigInt(605),
                Value::UInt(u32::MAX),
                Value::UInt(607),
            ]
        );
        assert_eq!(mapped.len(), EVENTS.columns.len());
        let expected = mapped.clone();
        let mut extraction = empty_input();
        let mut input = InputRelations::default();
        append_event(&mut input, &mut extraction, &record)?;
        let input = finish(
            input,
            &mut extraction,
            &QueryTemplate::Events { operation: None },
        )?;
        assert_eq!(rows(&input, "events")?, vec![expected.clone()]);
        let context = table_context(&input)?;
        let result = context.sql("SELECT * FROM events").await?.collect().await?;
        assert_eq!(values(&result[0], 0)?, expected);
        assert!(extraction.pages.iter().all(|page| page.rows.is_empty()));
        assert_eq!(extraction.meta.commit_revision, 8);
        Ok(())
    }

    #[test]
    fn query_input_invalid_values() -> TestResult {
        let mut record = EvidenceRecord::default();
        let absent = event(&record)?;
        for name in [
            "profile_generation_ref_id",
            "target_task_cookie",
            "operation_argument",
            "context_schema_version",
            "kernel_sequence",
            "inode",
        ] {
            assert_eq!(value(&EVENTS, &absent, name)?, &Value::Null);
        }
        assert_eq!(
            value(&EVENTS, &absent, "process_lineage_id")?,
            &Value::Blob(Vec::new())
        );
        record.decision_context = Some(EvidenceDecisionContext::default());
        let present = event(&record)?;
        assert_eq!(
            value(&EVENTS, &present, "context_schema_version")?,
            &Value::UInt(0)
        );
        assert_eq!(
            value(&EVENTS, &present, "kernel_sequence")?,
            &Value::UBigInt(0)
        );
        assert_eq!(value(&EVENTS, &present, "inode")?, &Value::Null);
        let mut corrupt = framed(&record);
        corrupt.framed_record[4] ^= 1;
        assert!(matches!(
            EvidenceRecord::try_from(corrupt.framed_record.as_slice()),
            Err(crate::Error::EvidenceFrame { .. })
        ));
        assert!(mapped(AnalysisInputV1::Result {
            result_id: "result",
            body: b"body",
        })
        .is_err_and(|error| matches!(
            error.downcast_ref::<crate::Error>(),
            Some(crate::Error::QueryUnsupported { .. })
        )));
        Ok(())
    }

    #[test]
    fn query_input_coverage_states() -> TestResult {
        let mut source = snapshot();
        source.receipt.coverage_revision = 10;
        source.expired.push(AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 3,
            commit_revision: 7,
        });
        source.recovery.push(AnalysisGapV1 {
            first_cursor: 4,
            last_cursor: 5,
            commit_revision: 8,
        });
        source.pending.push(AnalysisGapV1 {
            first_cursor: 1,
            last_cursor: 10,
            commit_revision: 9,
        });
        let report = CoverageReport {
            source_id: source.receipt.identity.source_id.to_vec(),
            cpu_id: 6,
            source_epoch: 5,
            revision: 10,
            intervals: vec![CoverageInterval {
                interval_id: vec![0, 255],
                source_epoch: 4,
                revision: 11,
                state: "FUTURE_STATE".into(),
                first_sequence: 100,
                last_sequence: None,
                opening_counters: Some(CoverageCounters {
                    attempted: u64::MAX,
                    suppressed: 2,
                    requested: 3,
                    emitted: 4,
                    lost: 5,
                    classifier_miss_count: 6,
                    unresolved: 7,
                    next_sequence: 8,
                }),
                closing_counters: None,
                gap_reasons: vec!["future\"reason".into(), "lost\0reason".into()],
                current: false,
            }],
        };
        let mut encoded = report.encode_to_vec();
        encoded.extend([0xa0, 0x06, 0x07]);
        source.coverage_report = Some(encoded);
        let mut extraction = empty_input();
        extraction.sources = vec![source, snapshot()];
        let input = finish(
            InputRelations::default(),
            &mut extraction,
            &QueryTemplate::Coverage,
        )?;
        let rows = rows(&input, "coverage")?;
        assert_eq!(rows.len(), 6);
        let kinds: Vec<_> = rows
            .iter()
            .map(|row| value(&COVERAGE, row, "kind").cloned())
            .collect::<TestResult<_>>()?;
        assert_eq!(
            kinds,
            ["receipt", "expired", "recovery", "pending", "interval", "receipt"]
                .map(|kind| Value::Text(kind.into()))
        );
        assert_eq!(
            value(&COVERAGE, &rows[0], "state")?,
            &Value::Text("reported".into())
        );
        assert_eq!(
            value(&COVERAGE, &rows[5], "state")?,
            &Value::Text("unknown".into())
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "contiguous_cursor")?,
            &Value::UBigInt(0)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "first_cursor")?,
            &Value::UBigInt(1)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "last_cursor")?,
            &Value::UBigInt(10)
        );
        assert_eq!(
            value(&COVERAGE, &rows[3], "commit_revision")?,
            &Value::UBigInt(9)
        );
        assert_eq!(value(&COVERAGE, &rows[3], "first_sequence")?, &Value::Null);
        let interval = &rows[4];
        assert_eq!(
            value(&COVERAGE, interval, "state")?,
            &Value::Text("FUTURE_STATE".into())
        );
        assert_eq!(
            value(&COVERAGE, interval, "source_epoch")?,
            &Value::UBigInt(5)
        );
        assert_eq!(
            value(&COVERAGE, interval, "interval_source_epoch")?,
            &Value::UBigInt(4)
        );
        assert_eq!(
            value(&COVERAGE, interval, "first_sequence")?,
            &Value::UBigInt(100)
        );
        assert_eq!(value(&COVERAGE, interval, "last_sequence")?, &Value::Null);
        assert_eq!(value(&COVERAGE, interval, "first_cursor")?, &Value::Null);
        assert_eq!(
            value(&COVERAGE, interval, "current")?,
            &Value::Boolean(false)
        );
        assert_eq!(
            value(&COVERAGE, interval, "opening_attempted")?,
            &Value::UBigInt(u64::MAX)
        );
        assert_eq!(
            value(&COVERAGE, interval, "opening_next_sequence")?,
            &Value::UBigInt(8)
        );
        assert_eq!(
            value(&COVERAGE, interval, "closing_attempted")?,
            &Value::Null
        );
        assert_eq!(
            value(&COVERAGE, interval, "gap_reasons")?,
            &Value::Text(serde_json::to_string(&report.intervals[0].gap_reasons)?)
        );
        assert_eq!(extraction.sources[0].receipt.coverage_revision, 10);
        Ok(())
    }

    #[test]
    fn query_input_coverage_rejects() -> TestResult {
        let mut source = snapshot();
        source.receipt.coverage_revision = 1;
        assert!(InputRelations::report(&source).is_err());
        source.coverage_report = Some(vec![255]);
        assert!(matches!(
            InputRelations::report(&source),
            Err(crate::Error::EvidenceDecode { .. })
        ));
        let mut report = CoverageReport {
            source_id: source.receipt.identity.source_id.to_vec(),
            cpu_id: source.receipt.cpu_id,
            source_epoch: source.receipt.identity.source_epoch,
            revision: 2,
            intervals: Vec::new(),
        };
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        report.revision = 1;
        report.cpu_id += 1;
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        report.cpu_id -= 1;
        report.source_id[0] ^= 1;
        source.coverage_report = Some(report.encode_to_vec());
        assert!(InputRelations::report(&source).is_err());
        Ok(())
    }

    #[test]
    fn query_input_context_pages() -> TestResult {
        let context = context();
        let mapped = mapped(AnalysisInputV1::Context(&context))?;
        assert_eq!(CONTEXTS.columns.len(), 9);
        assert!(!CONTEXTS
            .columns
            .iter()
            .any(|field| field.0 == "content_sha256"));
        assert_eq!(
            mapped,
            vec![
                Value::Blob(vec![1; 16]),
                Value::Text("policy".into()),
                Value::Blob(vec![0, 255]),
                Value::Blob(vec![1, 0]),
                Value::UBigInt(u64::MAX),
                Value::UBigInt(1),
                Value::Null,
                Value::Text("host_restricted".into()),
                Value::Blob(vec![0, 128, 255])
            ]
        );
        let expected = mapped.clone();
        let mut extraction = empty_input();
        extraction.missing_contexts.push(context.key.clone());
        let mut input = InputRelations::default();
        append_event(&mut input, &mut extraction, &EvidenceRecord::default())?;
        input.context_version(
            &mut extraction.sink(&crate::AnalysisReadControl::default()),
            None,
            (&context,),
        )?;
        append_event(
            &mut input,
            &mut extraction,
            &EvidenceRecord {
                operation: 42,
                ..Default::default()
            },
        )?;
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT e.operation, c.body FROM events e JOIN context_versions c ON e.tenant_id = c.tenant_id", Vec::new(), false)?);
        let input = finish(input, &mut extraction, &template)?;
        let events = rows(&input, "events")?;
        assert_eq!(events.len(), 2);
        assert_eq!(value(&EVENTS, &events[1], "operation")?, &Value::UInt(42));
        assert_eq!(rows(&input, "context_versions")?, vec![expected]);
        assert_eq!(extraction.missing_contexts, vec![context.key]);
        let mut unsupported = empty_input();
        unsupported.missing_results.push("result".into());
        assert!(matches!(
            finish(
                InputRelations::default(),
                &mut unsupported,
                &QueryTemplate::ContextVersions
            ),
            Err(crate::Error::QueryUnsupported { .. })
        ));
        assert_eq!(unsupported.missing_results, vec!["result"]);
        Ok(())
    }

    #[test]
    fn query_input_selected_relations() -> TestResult {
        let mut events = empty_input();
        events.limits.input_bytes = 64 * 1024;
        events.sources.push(snapshot());
        let mut input = InputRelations::default();
        append_event(&mut input, &mut events, &EvidenceRecord::default())?;
        let input = finish(
            input,
            &mut events,
            &QueryTemplate::Events { operation: None },
        )?;
        assert_eq!(rows(&input, "events")?.len(), 1);
        assert_eq!(
            input.tables.keys().copied().collect::<Vec<_>>(),
            vec!["events"]
        );
        assert!(events.input_bytes < 64 * 1024);

        let mut coverage = empty_input();
        coverage.limits.input_bytes = 64 * 1024;
        coverage.sources.push(snapshot());
        let input = finish(
            InputRelations::default(),
            &mut coverage,
            &QueryTemplate::Coverage,
        )?;
        assert_eq!(rows(&input, "coverage")?.len(), 1);
        assert_eq!(
            input.tables.keys().copied().collect::<Vec<_>>(),
            vec!["coverage"]
        );

        let mut catalog = empty_input();
        catalog.sources.push(snapshot());
        let input = finish(
            InputRelations::default(),
            &mut catalog,
            &QueryTemplate::Catalog,
        )?;
        assert_eq!(
            input.tables.keys().copied().collect::<Vec<_>>(),
            vec!["catalog"]
        );
        assert_eq!(
            rows(&input, "catalog")?.len(),
            SCHEMAS
                .iter()
                .map(|schema| schema.columns.len())
                .sum::<usize>()
        );
        Ok(())
    }

    #[tokio::test]
    async fn query_input_no_builtins() -> TestResult {
        let literal = super::super::QuerySql::admit("SELECT 1 AS value", Vec::new(), false)?;
        let alias = super::super::QuerySql::admit_relations(
            "SELECT value FROM source",
            BTreeMap::from([(
                "source".into(),
                Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                    "value",
                    sdk::DataType::Int64,
                    false,
                )])),
            )]),
        )?;
        for sql in [literal, alias] {
            let mut extraction = empty_input();
            extraction.limits.input_bytes = 1024;
            let input = finish(
                InputRelations::default(),
                &mut extraction,
                &QueryTemplate::Client(sql),
            )?;
            assert!(input.tables.is_empty());
            let context = table_context(&input)?;
            assert!(context
                .catalog("datafusion")
                .and_then(|catalog| catalog.schema("public"))
                .ok_or("default schema absent")?
                .table_names()
                .is_empty());
            assert!(context.sql("SELECT * FROM catalog").await.is_err());
            assert!(context.sql("SELECT * FROM _query_events()").await.is_err());
            let result = context.sql("SELECT 1 AS value").await?.collect().await?;
            assert_eq!(result[0].num_rows(), 1);
            assert_eq!(
                result[0]
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or("literal type")?
                    .value(0),
                1
            );
        }
        Ok(())
    }

    #[test]
    fn query_client_catalog_keys() -> TestResult {
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT relation, column_name, join_keys FROM catalog",
            Vec::new(),
            false,
        )?);
        let input = finish(InputRelations::default(), &mut empty_input(), &template)?;
        let trusted = finish(
            InputRelations::default(),
            &mut empty_input(),
            &QueryTemplate::Catalog,
        )?;
        let rows = rows(&input, "catalog")?;
        assert_eq!(rows, self::rows(&trusted, "catalog")?);
        assert!(rows.iter().any(|row| matches!(value(&CATALOG, row, "join_keys"), Ok(Value::Text(keys)) if !keys.is_empty())));
        Ok(())
    }

    #[tokio::test]
    async fn query_input_catalog_bounds() -> TestResult {
        let mut text = String::with_capacity(257);
        text.push('a');
        let mut blob = Vec::with_capacity(19);
        blob.extend([0, 1, 255]);
        let mut strings = StringBuilder::with_capacity(7, text.capacity());
        strings.append_value(&text);
        let mut binaries = BinaryBuilder::with_capacity(7, blob.capacity());
        binaries.append_value(&blob);
        assert!(strings.finish().get_buffer_memory_size() >= text.capacity());
        assert!(binaries.finish().get_buffer_memory_size() >= blob.capacity());
        let mut wrong: Box<dyn ArrayBuilder> = Box::new(StringBuilder::new());
        assert!(InputBatch::builder::<UInt64Builder>(&mut wrong).is_err());
        let mut maximum = empty_input();
        maximum.input_bytes = usize::MAX;
        maximum.limits.input_bytes = usize::MAX;
        assert!(maximum
            .sink(&crate::AnalysisReadControl::default())
            .charge(1)
            .is_err());

        let mut baseline = empty_input();
        baseline.limits.page_rows = 1;
        baseline.limits.input_bytes = 16_000_000;
        let base = baseline.input_bytes;
        let input = finish(
            InputRelations::default(),
            &mut baseline,
            &QueryTemplate::Catalog,
        )?;
        let bound = baseline.input_bytes;
        assert!(bound > base);
        let mut exact = empty_input();
        exact.limits.page_rows = 1;
        exact.limits.input_bytes = bound;
        finish(
            InputRelations::default(),
            &mut exact,
            &QueryTemplate::Catalog,
        )?;
        assert_eq!(exact.input_bytes, bound);
        let mut limited = empty_input();
        limited.limits.page_rows = 1;
        limited.limits.input_bytes = bound - 1;
        assert!(matches!(
            finish(
                InputRelations::default(),
                &mut limited,
                &QueryTemplate::Catalog
            ),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));

        let mut populated = empty_input();
        populated.limits.page_rows = 1;
        populated.limits.input_bytes = 16_000_000;
        let mut populated_input = InputRelations::default();
        append_event(
            &mut populated_input,
            &mut populated,
            &EvidenceRecord::default(),
        )?;
        populated_input
            .tables
            .get_mut("events")
            .ok_or("events absent")?
            .flush(&mut populated.sink(&crate::AnalysisReadControl::default()))?;
        let charged = populated.input_bytes;
        let populated_bound = charged + bound - base;
        populated.limits.input_bytes = populated_bound;
        finish(populated_input, &mut populated, &QueryTemplate::Catalog)?;
        assert_eq!(populated.input_bytes, populated_bound);
        let mut over_populated = empty_input();
        over_populated.limits.page_rows = 1;
        over_populated.limits.input_bytes = 16_000_000;
        let mut over_input = InputRelations::default();
        append_event(
            &mut over_input,
            &mut over_populated,
            &EvidenceRecord::default(),
        )?;
        over_input
            .tables
            .get_mut("events")
            .ok_or("events absent")?
            .flush(&mut over_populated.sink(&crate::AnalysisReadControl::default()))?;
        over_populated.limits.input_bytes = populated_bound - 1;
        assert!(matches!(
            finish(over_input, &mut over_populated, &QueryTemplate::Catalog),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));

        let rows = rows(&input, "catalog")?;
        assert_eq!(
            rows.len(),
            SCHEMAS
                .iter()
                .map(|schema| schema.columns.len())
                .sum::<usize>()
        );
        for relation in ["traces", "trace_output", "trace_measurements"] {
            let mut found = false;
            for row in &rows {
                if value(&CATALOG, row, "relation")? == &Value::Text(relation.into()) {
                    found = true;
                    assert_eq!(
                        value(&CATALOG, row, "readiness")?,
                        &Value::Text("available".into())
                    );
                }
            }
            assert!(found);
        }
        for schema in [&TRACES, &TRACE_OUTPUT, &TRACE_MEASUREMENTS] {
            for name in ["tenant_id", "request_id", "execution_id"] {
                assert!(schema.columns.iter().any(|field| field.0 == name));
            }
        }
        for name in ["source_sha256", "commit_revision", "ordinal"] {
            assert!(TRACE_OUTPUT.columns.iter().any(|field| field.0 == name));
        }
        let context = table_context(&input)?;
        assert!(context
            .sql("SELECT count(*) FROM trace_output")
            .await
            .is_err());
        let result = context
            .sql("SELECT count(*) FROM catalog")
            .await?
            .collect()
            .await?;
        assert_eq!(
            result[0]
                .column(0)
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or("count type")?
                .value(0),
            rows.len() as i64
        );
        Ok(())
    }

    #[test]
    fn query_recipe_input_bounds() -> TestResult {
        let template = QueryTemplate::Client(super::super::QuerySql::admit(
            "SELECT * FROM trace_recipes",
            Vec::new(),
            false,
        )?);
        let mut extraction = empty_input();
        extraction.limits.page_rows = 1;
        let input = finish(InputRelations::default(), &mut extraction, &template)?;
        assert_eq!(
            input.tables.keys().copied().collect::<Vec<_>>(),
            vec!["trace_recipes"]
        );
        assert_eq!(rows(&input, "trace_recipes")?.len(), 2);
        let bound = extraction.input_bytes;
        drop(input);
        let mut exact = empty_input();
        exact.limits.page_rows = 1;
        exact.limits.input_bytes = bound;
        finish(InputRelations::default(), &mut exact, &template)?;
        assert_eq!(exact.input_bytes, bound);
        let mut limited = empty_input();
        limited.limits.page_rows = 1;
        limited.limits.input_bytes = bound - 1;
        assert!(matches!(
            finish(InputRelations::default(), &mut limited, &template),
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn query_input_zero_column_rows_and_expiry() -> TestResult {
        let template = QueryTemplate::Events { operation: None };
        let selection = crate::AnalysisSelectionV1::new([1; 16], vec![identity()]);
        let mut project = InputProjection::new(&template, &selection, 0);
        project.projections.insert("events", BTreeSet::new());
        let mut extraction = empty_input();
        let control = crate::AnalysisReadControl::default();
        for received in [5_500_000_000, 7_000_000_000] {
            let record = EvidenceRecord::default();
            assert!(project.emit(
                AnalysisInputV1::Event {
                    identity: &identity(),
                    cpu_id: 0,
                    received_utc_ns: received,
                    record: &framed(&record),
                    decoded: Some(&record)
                },
                &mut extraction.sink(&control)
            )?);
        }
        let input = project.finish(&mut extraction, &control)?;
        let table = input.tables.get("events").ok_or("events absent")?;
        assert_eq!(table.schema.fields().len(), 0);
        assert_eq!(
            table
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            2
        );
        assert!(table.batches.iter().all(|batch| batch.num_columns() == 0));
        assert_eq!(input.input_rows, 2);
        assert_eq!(input.received_min, Some(5_500_000_000));
        assert_eq!(input.next_expiry(10), Some(16_000_000_000));
        assert!(extraction.pages.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn query_input_latest_findings_before_filter() -> TestResult {
        let fields = BTreeSet::from(
            ["tenant_id", "finding_id", "commit_revision", "severity"].map(str::to_owned),
        );
        let schema = FINDINGS.projected_schema(Some(&fields));
        let severity = Arc::new(StringArray::from(vec!["high", "low"]));
        let address = severity.value_data().as_ptr();
        let batch = sdk::RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(BinaryArray::from_vec(vec![&[1; 16], &[1; 16]])),
                Arc::new(UInt64Array::from(vec![1, 2])),
                Arc::new(StringArray::from(vec!["finding", "finding"])),
                severity,
            ],
        )?;
        let mut table = InputBatch {
            schema,
            batches: vec![batch],
            columns: Vec::new(),
            capacities: Vec::new(),
            row_capacity: 0,
            rows: 0,
        };
        let mut extraction = empty_input();
        table.latest_findings(&mut extraction.sink(&crate::AnalysisReadControl::default()))?;
        assert_eq!(
            table
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        let current = table.batches[0]
            .column_by_name("severity")
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or("severity absent")?;
        assert_eq!(current.value(0), "low");
        assert_eq!(current.value_data().as_ptr(), address);
        let input = InputRelations {
            tables: BTreeMap::from([("findings", table)]),
            input_rows: 2,
            received_min: None,
            bytes: 0,
        };
        let context = table_context(&input)?;
        let result = context
            .sql("SELECT finding_id FROM findings WHERE severity = 'high'")
            .await?
            .collect()
            .await?;
        assert_eq!(
            result.iter().map(sdk::RecordBatch::num_rows).sum::<usize>(),
            0
        );
        Ok(())
    }

    struct Fanout {
        inputs: InputRelations,
        count: usize,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Fanout {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl crate::analysis::AnalysisProjection for Fanout {
        type Row = ();
        fn decodes_events(&self) -> bool {
            true
        }
        fn project(
            &mut self,
            input: AnalysisInputV1<'_>,
            sink: &mut ProjectionSink<'_, ()>,
        ) -> Result<bool> {
            let AnalysisInputV1::Event {
                identity,
                cpu_id,
                received_utc_ns,
                record,
                decoded: Some(decoded),
            } = input
            else {
                return Ok(true);
            };
            let fields = BTreeSet::from(["operation".to_owned()]);
            for _ in 0..self.count {
                if !self.inputs.event(
                    sink,
                    Some(&fields),
                    (identity, cpu_id, received_utc_ns, record, decoded),
                )? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
    }

    #[test]
    fn query_input_fanout_failure_drops_all_rows_and_preserves_cursor() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = crate::AnalysisStore::open(directory.path().join("analysis"))?;
        let identity = identity();
        let bytes = framed(&EvidenceRecord::default()).framed_record;
        let frame_bytes = bytes.len();
        store.accept_validated_batch(
            identity.clone(),
            crate::ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 2,
                intake_utc_ns: 1,
                framed_records: [bytes.clone(), bytes].concat().into(),
                frame_ends: vec![frame_bytes, frame_bytes * 2],
            },
        )?;
        let selection = crate::AnalysisSelectionV1::new(identity.tenant_id, vec![identity]);
        let control = crate::AnalysisReadControl::default();
        let bounds = crate::analysis::AnalysisExtractLimits {
            page_bytes: 9,
            ..Default::default()
        };
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let before = store.meta()?;
        let result = store.position_rows(
            &selection,
            None,
            bounds,
            &control,
            Fanout {
                inputs: InputRelations::default(),
                count: 2,
                dropped: dropped.clone(),
            },
        );
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(store.meta()?, before);
        let (mut first, mut project) = store.position_rows(
            &selection,
            None,
            bounds,
            &control,
            Fanout {
                inputs: InputRelations::default(),
                count: 1,
                dropped: dropped.clone(),
            },
        )?;
        assert!(!first.exhausted);
        assert_eq!(project.inputs.input_rows, 1);
        let first_position = first.scanned_through;
        let input = finish(
            take(&mut project.inputs),
            &mut first.extraction,
            &QueryTemplate::Events { operation: None },
        )?;
        assert_eq!(
            input
                .tables
                .get("events")
                .ok_or("events absent")?
                .batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        let (second, project) = store.position_rows(
            &selection,
            Some(first_position),
            bounds,
            &control,
            Fanout {
                inputs: InputRelations::default(),
                count: 1,
                dropped,
            },
        )?;
        assert!(second.exhausted);
        assert_eq!(project.inputs.input_rows, 1);
        assert!(second.scanned_through > first_position);
        Ok(())
    }

    #[test]
    fn query_input_builder_denies_before_allocation() -> TestResult {
        let mut extraction = empty_input();
        extraction.limits.input_bytes = extraction.input_bytes;
        let mut input = InputRelations::default();
        let result = input.event(
            &mut extraction.sink(&crate::AnalysisReadControl::default()),
            None,
            (
                &identity(),
                0,
                0,
                &framed(&EvidenceRecord::default()),
                &EvidenceRecord::default(),
            ),
        );
        assert!(matches!(
            result,
            Err(crate::Error::AnalysisInputTooLarge { .. })
        ));
        assert!(input.tables.is_empty());
        assert_eq!(input.input_rows, 0);
        Ok(())
    }
}
