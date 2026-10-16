use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::arrays::ModelArrays;
use crate::Result;

pub(super) struct ModelSchema;

impl ModelSchema {
    pub(super) fn sources(model: &sdk::Model) -> Result<BTreeMap<String, Arc<sdk::Schema>>> {
        let mut relations = crate::query::input::SCHEMAS
            .iter()
            .filter(|schema| {
                matches!(schema.readiness, "available" | "conditional")
                    || schema.name == "behaviors"
            })
            .map(|schema| (schema.name.to_owned(), schema.arrow_schema()))
            .collect();
        for input in &model.inputs {
            if let sdk::InputSource::Table(table) = &input.source {
                if matches!(table, sdk::TableRef::Named(name) if name.eq_ignore_ascii_case(&input.port.name))
                {
                    continue;
                }
                Self::relation(&mut relations, &input.port.name, &input.port.schema)?;
            }
        }
        Ok(relations)
    }

    pub(super) fn relations(model: &sdk::Model) -> Result<BTreeMap<String, Arc<sdk::Schema>>> {
        let mut relations = BTreeMap::new();
        for port in &model.inputs {
            let port = &port.port;
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
        relations: &mut BTreeMap<String, Arc<sdk::Schema>>,
        name: &str,
        schema: &sdk::Schema,
    ) -> Result<()> {
        Self::validate(schema)?;
        let name = name.to_ascii_lowercase();
        if relations.contains_key(&name) {
            return crate::QueryInvalidSnafu {
                field: "model relation collision",
            }
            .fail();
        }
        let mut fields = schema.fields().to_vec();
        fields.push(Arc::new(sdk::Field::new(
            "__row_index",
            sdk::DataType::UInt64,
            false,
        )));
        relations.insert(
            name,
            Arc::new(sdk::Schema::new_with_metadata(
                fields,
                schema.metadata().clone(),
            )),
        );
        Ok(())
    }

    pub(super) fn validate(schema: &sdk::Schema) -> Result<()> {
        if schema.fields().is_empty() {
            return crate::QueryInvalidSnafu {
                field: "SQL empty schema",
            }
            .fail();
        }
        let mut names = std::collections::BTreeSet::new();
        for field in schema.fields() {
            if field.name().eq_ignore_ascii_case("__row_index")
                || !names.insert(field.name().to_ascii_lowercase())
            {
                return crate::QueryInvalidSnafu {
                    field: "SQL field collision",
                }
                .fail();
            }
            Self::field_type(field.data_type())?;
        }
        Ok(())
    }

    pub(super) fn quote(name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    fn field_type(kind: &sdk::DataType) -> Result<()> {
        use sdk::DataType::*;
        match kind {
            Null
            | Boolean
            | Int8
            | Int16
            | Int32
            | Int64
            | UInt8
            | UInt16
            | UInt32
            | UInt64
            | Float32
            | Float64
            | Utf8
            | Binary
            | FixedSizeBinary(_)
            | Timestamp(sdk::TimeUnit::Nanosecond, _) => Ok(()),
            List(field) | FixedSizeList(field, _) => Self::field_type(field.data_type()),
            Struct(fields) => Self::validate(&sdk::Schema::new(fields.clone())),
            _ => crate::QueryInvalidSnafu {
                field: "SQL model field type",
            }
            .fail(),
        }
    }

    pub(super) fn normalize(
        batch: sdk::RecordBatch,
        schema: Arc<sdk::Schema>,
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
                        && array.logical_null_count() != array.len())
                {
                    return crate::QueryInvalidSnafu {
                        field: "SQL result schema",
                    }
                    .fail();
                }
                ModelArrays::cast(array, expected.data_type())
            })
            .collect::<Result<Vec<_>>>()?;
        sdk::RecordBatch::try_new(schema, columns)
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn builtin_source_has_no_dataset_index() -> Result<()> {
        use crate::query::QuerySql;

        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let model = sdk::Model::new("source", vec![sdk::Port::new("events", schema)], Vec::new());
        let sources = ModelSchema::sources(&model)?;
        assert!(sources
            .values()
            .all(|schema| schema.index_of("__row_index").is_err()));
        assert!(
            QuerySql::admit_relations("SELECT events.__row_index FROM events", sources).is_err()
        );
        QuerySql::admit_relations(
            "SELECT events.__row_index FROM events",
            ModelSchema::relations(&model)?,
        )?;
        Ok(())
    }

    #[test]
    fn relation_retains_arrow_schema() -> Result<()> {
        let field = sdk::Field::new(
            "ReceivedAt",
            sdk::DataType::Timestamp(sdk::TimeUnit::Nanosecond, Some("UTC".into())),
            false,
        )
        .with_metadata(HashMap::from([("source".into(), "events".into())]));
        let schema = sdk::Schema::new_with_metadata(
            vec![field],
            HashMap::from([("owner".into(), "model".into())]),
        );
        let mut relations = BTreeMap::new();
        ModelSchema::relation(&mut relations, "InputRows", &schema)?;
        let actual = Arc::clone(&relations["inputrows"]);
        assert_eq!(actual.metadata(), schema.metadata());
        assert!(Arc::ptr_eq(&actual.fields()[0], &schema.fields()[0]));
        assert_eq!(actual.fields().len(), 2);
        assert_eq!(
            actual.field(1),
            &sdk::Field::new("__row_index", sdk::DataType::UInt64, false),
        );
        assert!(ModelSchema::relation(&mut relations, "INPUTROWS", &schema).is_err());
        assert!(Arc::ptr_eq(&relations["inputrows"], &actual));
        Ok(())
    }

    #[test]
    fn relation_rejects_field_collisions() {
        for names in [vec!["Value", "value"], vec!["__ROW_INDEX"]] {
            let schema = sdk::Schema::new(
                names
                    .into_iter()
                    .map(|name| sdk::Field::new(name, sdk::DataType::Int64, true))
                    .collect::<Vec<_>>(),
            );
            let mut relations = BTreeMap::new();
            assert!(ModelSchema::relation(&mut relations, "data", &schema).is_err());
            assert!(relations.is_empty());
        }
    }

    #[test]
    fn normalize_sliced_nested_nulls_and_metadata() -> Result<()> {
        use datafusion::arrow::array::{Array as _, ListArray};
        use datafusion::arrow::datatypes::Int32Type;

        let lists = ListArray::from_iter_primitive::<Int32Type, _, _>([
            Some(vec![None]),
            Some(vec![None, None]),
        ]);
        let actual = sdk::RecordBatch::try_from_iter([(
            "values",
            Arc::new(lists) as datafusion::arrow::array::ArrayRef,
        )])
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)?
        .slice(1, 1);
        let item = Arc::new(
            sdk::Field::new("item", sdk::DataType::Null, true)
                .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
        );
        let expected = sdk::Schema::new(vec![sdk::Field::new(
            "values",
            sdk::DataType::List(Arc::clone(&item)),
            false,
        )]);
        let schema = Arc::new(expected.clone());
        let batch = ModelSchema::normalize(actual, schema.clone())?;
        assert!(Arc::ptr_eq(&batch.schema(), &schema));
        assert_eq!(batch.schema().as_ref(), &expected);
        let data = batch.column(0).to_data();
        assert_eq!(data.data_type(), &sdk::DataType::List(item));
        assert_eq!(data.len(), 1);
        assert_eq!(data.child_data()[0].data_type(), &sdk::DataType::Null);
        assert_eq!(
            datafusion::arrow::array::make_array(data.child_data()[0].clone()).logical_null_count(),
            data.child_data()[0].len()
        );
        Ok(())
    }
}
