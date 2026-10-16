use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::arrays::ModelArrays;
use crate::Result;

pub(super) struct ModelSchema;

impl ModelSchema {
    pub(super) fn sources(model: &sdk::Model) -> Result<BTreeMap<String, Arc<sdk::Schema>>> {
        let mut relations = BTreeMap::new();
        for input in &model.inputs {
            if let sdk::InputSource::Table(table) = &input.source {
                if matches!(table, sdk::TableRef::Named(name) if name == &input.port.name) {
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
        let name = name.to_owned();
        if relations.contains_key(&name) {
            return crate::ModelInvalidSnafu {
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
            return crate::ModelInvalidSnafu {
                field: "SQL empty schema",
            }
            .fail();
        }
        let mut names = std::collections::BTreeSet::new();
        for field in schema.fields() {
            if field.name() == "__row_index" || !names.insert(field.name()) {
                return crate::ModelInvalidSnafu {
                    field: "SQL field collision",
                }
                .fail();
            }
        }
        Ok(())
    }

    pub(super) fn normalize(
        batch: sdk::RecordBatch,
        schema: Arc<sdk::Schema>,
    ) -> Result<sdk::RecordBatch> {
        if batch.num_columns() != schema.fields().len() {
            return crate::ModelInvalidSnafu {
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
                {
                    return crate::ModelInvalidSnafu {
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
            (_, Null) => true,
            (Binary, FixedSizeBinary(_)) | (Utf8View, Utf8) | (BinaryView, Binary) => true,
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
    fn builtin_has_no_index() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let fixture = crate::testing::QueryFixture::new()?;
        let engine = fixture.owner(crate::Limits::default())?;
        let native = engine.catalog(BTreeMap::new())?;
        assert!(engine
            .plan(
                &native,
                araphor_query::parser::Parser::parse("SELECT events.__row_index FROM events")?,
                Vec::new()
            )
            .is_err());
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let mut local = BTreeMap::new();
        ModelSchema::relation(&mut local, "events", &schema)?;
        let native = engine.catalog(local)?;
        let plan = engine.plan(
            &native,
            araphor_query::parser::Parser::parse("SELECT * FROM events")?,
            Vec::new(),
        )?;
        assert_eq!(plan.schema().as_arrow().field(1).name(), "__row_index");
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
        let actual = Arc::clone(&relations["InputRows"]);
        assert_eq!(actual.metadata(), schema.metadata());
        assert!(Arc::ptr_eq(&actual.fields()[0], &schema.fields()[0]));
        assert_eq!(actual.fields().len(), 2);
        assert_eq!(
            actual.field(1),
            &sdk::Field::new("__row_index", sdk::DataType::UInt64, false),
        );
        assert!(ModelSchema::relation(&mut relations, "InputRows", &schema).is_err());
        ModelSchema::relation(&mut relations, "INPUTROWS", &schema)?;
        assert!(Arc::ptr_eq(&relations["InputRows"], &actual));
        Ok(())
    }

    #[test]
    fn relation_rejects_field_collisions() {
        for names in [vec!["value", "value"], vec!["__row_index"]] {
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
    fn normalize_sliced_metadata() -> Result<()> {
        use sdk::arrow_array::types::Int32Type;
        use sdk::arrow_array::{Array as _, ListArray};

        let lists = ListArray::from_iter_primitive::<Int32Type, _, _>([
            Some(vec![None]),
            Some(vec![None, None]),
        ]);
        let actual = sdk::RecordBatch::try_from_iter([(
            "values",
            Arc::new(lists) as sdk::arrow_array::ArrayRef,
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
            sdk::arrow_array::make_array(data.child_data()[0].clone()).logical_null_count(),
            data.child_data()[0].len()
        );
        Ok(())
    }

    #[test]
    fn normalize_sliced_nulls() -> Result<()> {
        use sdk::arrow_array::cast::AsArray as _;
        use sdk::arrow_array::types::Int32Type;
        use sdk::arrow_array::{ArrayRef, FixedSizeListArray, ListArray};

        let rows = [Some(vec![Some(1)]), Some(vec![None])];
        let item = Arc::new(
            sdk::Field::new("item", sdk::DataType::Null, true)
                .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
        );
        for (array, kind) in [
            (
                Arc::new(ListArray::from_iter_primitive::<Int32Type, _, _>(
                    rows.clone(),
                )) as ArrayRef,
                sdk::DataType::List(Arc::clone(&item)),
            ),
            (
                Arc::new(FixedSizeListArray::from_iter_primitive::<Int32Type, _, _>(
                    rows, 1,
                )) as ArrayRef,
                sdk::DataType::FixedSizeList(Arc::clone(&item), 1),
            ),
        ] {
            let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "values", kind, true,
            )]));
            let actual = sdk::RecordBatch::try_from_iter([("values", array.slice(1, 1))])
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            assert_eq!(
                ModelArrays::conversion_bytes(actual.column(0), schema.field(0).data_type())?,
                0
            );
            let normalized = ModelSchema::normalize(actual, Arc::clone(&schema))?;
            assert_eq!(normalized.schema(), schema);
            assert_eq!(normalized.num_rows(), 1);
            match normalized.column(0).data_type() {
                sdk::DataType::List(_) => {
                    let lists = normalized.column(0).as_list::<i32>();
                    assert_eq!(lists.value_offsets(), &[1, 2]);
                    assert_eq!(lists.value(0).logical_null_count(), 1);
                    assert_eq!(lists.values().get_buffer_memory_size(), 0);
                }
                sdk::DataType::FixedSizeList(_, _) => {
                    let lists = normalized.column(0).as_fixed_size_list();
                    assert_eq!(lists.value(0).logical_null_count(), 1);
                    assert_eq!(lists.values().get_buffer_memory_size(), 0);
                }
                _ => unreachable!(),
            }
            let visible = sdk::RecordBatch::try_from_iter([("values", array.slice(0, 1))])
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            assert!(ModelSchema::normalize(visible, schema).is_err());
        }
        Ok(())
    }

    #[test]
    fn normalize_masked_nulls() -> Result<()> {
        use araphor_query::datafusion::arrow::buffer::{NullBuffer, OffsetBuffer};
        use sdk::arrow_array::{
            Array as _, ArrayRef, FixedSizeListArray, Int32Array, ListArray, StructArray,
        };

        let values = Arc::new(Int32Array::from(vec![Some(1), None])) as ArrayRef;
        let actual_item = Arc::new(sdk::Field::new("item", sdk::DataType::Int32, true));
        let expected_item = Arc::new(
            sdk::Field::new("item", sdk::DataType::Null, true)
                .with_metadata(HashMap::from([("unit".into(), "absent".into())])),
        );
        let nulls = NullBuffer::from(vec![false, true]);
        let lists = ListArray::new(
            Arc::clone(&actual_item),
            OffsetBuffer::new(vec![0, 1, 2].into()),
            Arc::clone(&values),
            None,
        );
        for (array, kind) in [
            (
                Arc::new(ListArray::new(
                    Arc::clone(&actual_item),
                    lists.offsets().clone(),
                    Arc::clone(&values),
                    Some(nulls.clone()),
                )) as ArrayRef,
                sdk::DataType::List(Arc::clone(&expected_item)),
            ),
            (
                Arc::new(FixedSizeListArray::new(
                    Arc::clone(&actual_item),
                    1,
                    Arc::clone(&values),
                    Some(nulls.clone()),
                )) as ArrayRef,
                sdk::DataType::FixedSizeList(Arc::clone(&expected_item), 1),
            ),
            (
                Arc::new(StructArray::new(
                    vec![Arc::clone(&actual_item)].into(),
                    vec![values],
                    Some(nulls.clone()),
                )) as ArrayRef,
                sdk::DataType::Struct(vec![Arc::clone(&expected_item)].into()),
            ),
            (
                Arc::new(StructArray::new(
                    vec![sdk::Field::new("nested", lists.data_type().clone(), true)].into(),
                    vec![Arc::new(lists)],
                    Some(nulls),
                )) as ArrayRef,
                sdk::DataType::Struct(
                    vec![sdk::Field::new(
                        "nested",
                        sdk::DataType::List(expected_item),
                        true,
                    )]
                    .into(),
                ),
            ),
        ] {
            let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "values", kind, true,
            )]));
            assert_eq!(
                ModelArrays::conversion_bytes(&array, schema.field(0).data_type())?,
                0
            );
            let actual = sdk::RecordBatch::try_from_iter([("values", Arc::clone(&array))])
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            let normalized = ModelSchema::normalize(actual, Arc::clone(&schema))?;
            assert_eq!(normalized.schema(), schema);
            assert_eq!(normalized.column(0).nulls(), array.nulls());
            assert!(normalized.column(0).is_null(0));
            assert!(normalized.column(0).is_valid(1));

            let visible = array
                .to_data()
                .into_builder()
                .nulls(None)
                .build()
                .map(sdk::arrow_array::make_array)
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            let visible = sdk::RecordBatch::try_from_iter([("values", visible)])
                .map_err(sdk::Error::from)
                .context(crate::AnalysisContractSnafu)?;
            assert!(ModelSchema::normalize(visible, schema).is_err());
        }
        Ok(())
    }
}
