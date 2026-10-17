use std::collections::BTreeMap;
use std::sync::Arc;

use crate::Result;
use araphor_analysis_sdk as sdk;

pub(super) struct ModelSchema;

impl ModelSchema {
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
}
