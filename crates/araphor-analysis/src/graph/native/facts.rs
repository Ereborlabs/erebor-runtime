use std::sync::{Arc, OnceLock};

use araphor_analysis_builtins::graph::{Fact, Unit};
use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisContextVersionV1, ContextSensitivityV1,
    DiscoveryRecordIdV1, GraphFactV1,
};
use datafusion::arrow::array::{Array, ArrayRef, ListArray, StructArray};
use datafusion::arrow::buffer::OffsetBuffer;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::common::Result;
use serde::{Deserialize, Serialize};

use super::{GraphPublication, Projection};

#[derive(Serialize, Deserialize)]
struct ContextRow {
    key: AnalysisContextKeyV1,
    valid_from_utc_ns: Option<u64>,
    valid_until_utc_ns: Option<u64>,
    sensitivity: ContextSensitivityV1,
    body: serde_bytes::ByteBuf,
}

impl GraphPublication {
    pub fn context_schema() -> SchemaRef {
        use sdk::{DataType, Field, Schema};
        Arc::new(Schema::new(vec![
            Field::new(
                "key",
                Fact::source_port().schema.field(1).data_type().clone(),
                false,
            ),
            Field::new("valid_from_utc_ns", DataType::UInt64, true),
            Field::new("valid_until_utc_ns", DataType::UInt64, true),
            Field::new("sensitivity", DataType::Utf8, false),
            Field::new("body", DataType::Binary, false),
        ]))
    }

    pub fn resolved_schema() -> SchemaRef {
        static SCHEMA: OnceLock<SchemaRef> = OnceLock::new();
        Arc::clone(SCHEMA.get_or_init(|| {
            use sdk::{DataType, Field, Schema};
            let facts = Fact::source_port().schema;
            let key = facts.field(1).data_type().clone();
            let context = DataType::Struct(Self::context_schema().fields().clone());
            let proof = DataType::Struct(
                vec![
                    Field::new("key", key, false),
                    Field::new("commit_revision", DataType::UInt64, false),
                ]
                .into(),
            );
            Arc::new(Schema::new(vec![
                Field::new("record", facts.field(0).data_type().clone(), false),
                Field::new(
                    "facts",
                    DataType::List(Arc::new(Field::new(
                        "item",
                        DataType::Struct(facts.fields().clone()),
                        false,
                    ))),
                    false,
                ),
                Field::new(
                    "contexts",
                    DataType::List(Arc::new(Field::new("item", context, false))),
                    false,
                ),
                Field::new(
                    "proofs",
                    DataType::List(Arc::new(Field::new("item", proof, false))),
                    false,
                ),
            ]))
        }))
    }

    pub fn encode_resolved(
        rows: &[(
            DiscoveryRecordIdV1,
            Vec<AnalysisContextVersionV1>,
            Vec<AnalysisContextRefV1>,
        )],
    ) -> Result<sdk::RecordBatch> {
        u32::try_from(rows.len()).map_err(Projection::external)?;
        let schema = Self::resolved_schema();
        let records = rows
            .iter()
            .map(|(record, _, _)| record.clone())
            .collect::<Vec<_>>();
        let identities = Unit::encode_affected(&records).map_err(Projection::external)?;
        let mut facts = Vec::new();
        let mut contexts = Vec::new();
        let mut proofs = Vec::new();
        let mut lengths = Vec::with_capacity(rows.len());
        for (record, values, references) in rows {
            i32::try_from(
                facts
                    .len()
                    .checked_add(values.len())
                    .ok_or_else(|| Projection::invalid("resolved graph fact count"))?,
            )
            .map_err(Projection::external)?;
            i32::try_from(
                proofs
                    .len()
                    .checked_add(references.len())
                    .ok_or_else(|| Projection::invalid("resolved graph proof count"))?,
            )
            .map_err(Projection::external)?;
            if references.iter().any(|reference| {
                reference.commit_revision == 0
                    || !reference.key.valid()
                    || reference.key.tenant_id != record.stream.tenant_id
            }) {
                return Err(Projection::invalid("resolved graph proof scope"));
            }
            for value in values {
                if !value.valid() {
                    return Err(Projection::invalid("resolved graph context interval"));
                }
                let fact = GraphFactV1::try_from(value).map_err(Projection::external)?;
                if fact.record_id != *record {
                    return Err(Projection::invalid("resolved graph fact record"));
                }
                facts.push(Fact {
                    record: 0,
                    key: value.key.clone(),
                    sensitivity: value.sensitivity,
                    value: fact.value,
                });
                contexts.push(ContextRow {
                    key: value.key.clone(),
                    valid_from_utc_ns: value.valid_from_utc_ns,
                    valid_until_utc_ns: value.valid_until_utc_ns,
                    sensitivity: value.sensitivity,
                    body: value.body.clone().into(),
                });
            }
            proofs.extend_from_slice(references);
            lengths.push((values.len(), references.len()));
        }
        let values = Fact::encode(&facts).map_err(Projection::external)?;
        let fact_ids = rows
            .iter()
            .flat_map(|(record, values, _)| std::iter::repeat_n(record.clone(), values.len()))
            .collect::<Vec<_>>();
        let fact_ids = Unit::encode_affected(&fact_ids).map_err(Projection::external)?;
        let mut columns = values.batches[0].columns().to_vec();
        columns[0] = Arc::clone(fact_ids.batches[0].column(0));
        let facts = sdk::RecordBatch::try_new(Arc::new(Fact::source_port().schema), columns)
            .map_err(Projection::external)?;
        let structs = |column: usize| -> Result<_> {
            let sdk::DataType::List(item) = schema.field(column).data_type() else {
                return Err(Projection::invalid("resolved graph list schema"));
            };
            let sdk::DataType::Struct(fields) = item.data_type() else {
                return Err(Projection::invalid("resolved graph struct schema"));
            };
            Ok((Arc::clone(item), fields.clone()))
        };
        let (fact_field, _) = structs(1)?;
        let (context_field, context_fields) = structs(2)?;
        let (proof_field, proof_fields) = structs(3)?;
        let contexts = serde_arrow::to_record_batch(&context_fields, &contexts)
            .map_err(Projection::external)?;
        let proofs =
            serde_arrow::to_record_batch(&proof_fields, &proofs).map_err(Projection::external)?;
        let list = |field, batch, lengths: Vec<usize>| -> Result<ArrayRef> {
            let offsets = OffsetBuffer::<i32>::from_lengths(lengths);
            Ok(Arc::new(
                ListArray::try_new(field, offsets, Arc::new(StructArray::from(batch)), None)
                    .map_err(Projection::external)?,
            ))
        };
        sdk::RecordBatch::try_new(
            schema,
            vec![
                Arc::clone(identities.batches[0].column(0)),
                list(
                    fact_field,
                    facts,
                    lengths.iter().map(|(facts, _)| *facts).collect(),
                )?,
                list(
                    context_field,
                    contexts,
                    lengths.iter().map(|(facts, _)| *facts).collect(),
                )?,
                list(
                    proof_field,
                    proofs,
                    lengths.iter().map(|(_, proofs)| *proofs).collect(),
                )?,
            ],
        )
        .map_err(Projection::external)
    }

    pub fn decode_contexts(batch: &sdk::RecordBatch) -> Result<Vec<AnalysisContextVersionV1>> {
        if batch.schema() != Self::context_schema() {
            return Err(Projection::invalid("resolved graph context schema"));
        }
        let rows: Vec<ContextRow> =
            serde_arrow::from_record_batch(batch).map_err(Projection::external)?;
        rows.into_iter()
            .map(|row| {
                let context = AnalysisContextVersionV1 {
                    key: row.key,
                    valid_from_utc_ns: row.valid_from_utc_ns,
                    valid_until_utc_ns: row.valid_until_utc_ns,
                    sensitivity: row.sensitivity,
                    body: row.body.into_vec(),
                };
                if !context.valid() {
                    return Err(Projection::invalid("resolved graph context interval"));
                }
                Ok(context)
            })
            .collect()
    }

    pub fn decode_resolved(
        batch: &sdk::RecordBatch,
    ) -> Result<
        Vec<(
            DiscoveryRecordIdV1,
            Vec<AnalysisContextVersionV1>,
            Vec<AnalysisContextRefV1>,
        )>,
    > {
        if batch.schema() != Self::resolved_schema() {
            return Err(Projection::invalid("resolved graph schema"));
        }
        let records = sdk::Dataset {
            name: Unit::affected_port().name,
            batches: vec![batch.project(&[0]).map_err(Projection::external)?],
        };
        let records = Unit::decode_affected(&records).map_err(Projection::external)?;
        let contexts = Projection::column::<ListArray>(batch, "contexts")?;
        let proofs = Projection::column::<ListArray>(batch, "proofs")?;
        let mut rows = Vec::with_capacity(batch.num_rows());
        for (row, record) in records.into_iter().enumerate() {
            if contexts.is_null(row) || proofs.is_null(row) {
                return Err(Projection::invalid("resolved graph null list"));
            }
            let values = contexts.value(row);
            let values = values
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| Projection::invalid("resolved graph contexts"))?;
            let values = Self::decode_contexts(&sdk::RecordBatch::from(values))?;
            let references = proofs.value(row);
            let references = references
                .as_any()
                .downcast_ref::<StructArray>()
                .ok_or_else(|| Projection::invalid("resolved graph proofs"))?;
            let references: Vec<AnalysisContextRefV1> =
                serde_arrow::from_record_batch(&sdk::RecordBatch::from(references))
                    .map_err(Projection::external)?;
            rows.push((record, values, references));
        }
        if Self::encode_resolved(&rows)? != *batch {
            return Err(Projection::invalid(
                "resolved graph facts differ from contexts",
            ));
        }
        Ok(rows)
    }
}
