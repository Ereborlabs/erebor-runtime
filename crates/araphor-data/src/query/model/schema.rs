use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::arrays::ModelArrays;
use crate::Result;

pub(super) struct ModelSchema;

impl ModelSchema {
    pub(super) fn physical(batch: &sdk::RecordBatch) -> Result<sdk::RecordBatch> {
        let fields = batch
            .schema()
            .fields()
            .iter()
            .map(|field| Self::physical_field(field))
            .collect::<Vec<_>>();
        let columns = batch
            .columns()
            .iter()
            .zip(&fields)
            .map(|(array, field)| ModelArrays::cast(array, field.data_type()))
            .collect::<Result<Vec<_>>>()?;
        sdk::RecordBatch::try_new(Arc::new(sdk::Schema::new(fields)), columns)
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)
    }

    fn physical_field(field: &sdk::Field) -> sdk::Field {
        let kind = match field.data_type() {
            sdk::DataType::Timestamp(unit, _) => sdk::DataType::Timestamp(*unit, None),
            sdk::DataType::Null => sdk::DataType::Int32,
            sdk::DataType::FixedSizeBinary(_) => sdk::DataType::Binary,
            sdk::DataType::List(child) => {
                sdk::DataType::List(Arc::new(Self::physical_field(child)))
            }
            sdk::DataType::FixedSizeList(child, size) => {
                sdk::DataType::FixedSizeList(Arc::new(Self::physical_field(child)), *size)
            }
            sdk::DataType::Struct(children) => sdk::DataType::Struct(
                children
                    .iter()
                    .map(|child| Arc::new(Self::physical_field(child)))
                    .collect(),
            ),
            other => other.clone(),
        };
        sdk::Field::new(field.name(), kind, field.is_nullable())
    }

    pub(super) fn relations(model: &sdk::Model) -> Result<BTreeMap<String, Vec<String>>> {
        let mut relations = BTreeMap::new();
        for port in &model.inputs {
            Self::relation(&mut relations, &port.name, &port.schema)?;
        }
        if !model.parameters.fields().is_empty() {
            Self::relation(&mut relations, "parameters", &model.parameters)?;
        }
        if let Some(spec) = &model.checkpoint {
            for port in &spec.datasets {
                Self::relation(
                    &mut relations,
                    &format!("prior_{}", port.name),
                    &port.schema,
                )?;
            }
        }
        Ok(relations)
    }

    pub(super) fn relation(
        relations: &mut BTreeMap<String, Vec<String>>,
        name: &str,
        schema: &sdk::Schema,
    ) -> Result<()> {
        Self::fields(schema)?;
        let mut fields: Vec<_> = schema
            .fields()
            .iter()
            .map(|field| field.name().to_ascii_lowercase())
            .collect();
        fields.push("__row_index".into());
        if relations
            .insert(name.to_ascii_lowercase(), fields)
            .is_some()
        {
            return crate::QueryInvalidSnafu {
                field: "model relation collision",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn fields(schema: &sdk::Schema) -> Result<String> {
        if schema.fields().is_empty() {
            return crate::QueryInvalidSnafu {
                field: "SQL empty schema",
            }
            .fail();
        }
        let mut names = std::collections::BTreeSet::new();
        schema
            .fields()
            .iter()
            .map(|field| {
                if field.name().eq_ignore_ascii_case("__row_index")
                    || !names.insert(field.name().to_ascii_lowercase())
                {
                    return crate::QueryInvalidSnafu {
                        field: "SQL field collision",
                    }
                    .fail();
                }
                Ok(format!(
                    "{} {}",
                    Self::quote(field.name()),
                    Self::data_type(field.data_type())?
                ))
            })
            .collect::<Result<Vec<_>>>()
            .map(|fields| fields.join(", "))
    }

    pub(super) fn quote(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    fn data_type(kind: &sdk::DataType) -> Result<String> {
        use sdk::DataType::*;
        Ok(match kind {
            Null => "INTEGER".into(),
            Boolean => "BOOLEAN".into(),
            Int8 => "TINYINT".into(),
            Int16 => "SMALLINT".into(),
            Int32 => "INTEGER".into(),
            Int64 => "BIGINT".into(),
            UInt8 => "UTINYINT".into(),
            UInt16 => "USMALLINT".into(),
            UInt32 => "UINTEGER".into(),
            UInt64 => "UBIGINT".into(),
            Float32 => "FLOAT".into(),
            Float64 => "DOUBLE".into(),
            Utf8 => "VARCHAR".into(),
            Binary | FixedSizeBinary(_) => "BLOB".into(),
            Timestamp(sdk::TimeUnit::Nanosecond, _) => "TIMESTAMP_NS".into(),
            List(field) => format!("{}[]", Self::data_type(field.data_type())?),
            FixedSizeList(field, size) => {
                format!("{}[{size}]", Self::data_type(field.data_type())?)
            }
            Struct(fields) => {
                let schema = sdk::Schema::new(fields.clone());
                format!("STRUCT({})", Self::fields(&schema)?)
            }
            _ => {
                return crate::QueryInvalidSnafu {
                    field: "SQL model field type",
                }
                .fail()
            }
        })
    }

    pub(super) fn normalize(
        batch: sdk::RecordBatch,
        schema: &sdk::Schema,
    ) -> Result<sdk::RecordBatch> {
        if batch.num_columns() != schema.fields().len() {
            return crate::QueryInvalidSnafu {
                field: "SQL result width",
            }
            .fail();
        }
        let actual = batch.schema();
        let columns = batch
            .columns()
            .iter()
            .zip(actual.fields())
            .zip(schema.fields())
            .map(|((array, field), expected)| {
                if field.name() != expected.name()
                    || !Self::compatible(field.data_type(), expected.data_type())
                    || (*expected.data_type() == sdk::DataType::Null
                        && array.null_count() != array.len())
                {
                    return crate::QueryInvalidSnafu {
                        field: "SQL result schema",
                    }
                    .fail();
                }
                ModelArrays::cast(array, expected.data_type())
            })
            .collect::<Result<Vec<_>>>()?;
        sdk::RecordBatch::try_new(Arc::new(schema.clone()), columns)
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)
    }

    fn compatible(actual: &sdk::DataType, expected: &sdk::DataType) -> bool {
        use sdk::DataType::*;
        match (actual, expected) {
            (Binary, FixedSizeBinary(_)) | (Int32, Null) => true,
            (Timestamp(sdk::TimeUnit::Nanosecond, _), Timestamp(sdk::TimeUnit::Nanosecond, _)) => {
                true
            }
            (List(left), List(right)) | (FixedSizeList(left, _), FixedSizeList(right, _)) => {
                Self::compatible(left.data_type(), right.data_type())
                    && !matches!((actual, expected), (FixedSizeList(_, a), FixedSizeList(_, b)) if a != b)
            }
            (Struct(left), Struct(right)) => {
                left.len() == right.len()
                    && left.iter().zip(right).all(|(a, b)| {
                        a.name() == b.name() && Self::compatible(a.data_type(), b.data_type())
                    })
            }
            _ => actual == expected,
        }
    }
}
