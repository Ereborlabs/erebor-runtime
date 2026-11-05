use arrow_schema::{DataType, Field, Schema};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntityKind {
    Node,
    Edge,
}

#[derive(Clone, Debug)]
pub struct Relation {
    pub kind: EntityKind,
    pub properties: Schema,
}

impl Relation {
    pub fn command_schema(&self) -> Schema {
        let mut fields = vec![
            Field::new("owner", DataType::Binary, false),
            Field::new("key", DataType::Binary, false),
            Field::new("operation", DataType::UInt8, false),
        ];
        if self.kind == EntityKind::Edge {
            for name in ["from", "to", "label"] {
                fields.push(Field::new(name, DataType::Binary, true));
            }
        }
        fields.push(Field::new(
            "properties",
            DataType::Struct(self.properties.fields().clone()),
            true,
        ));
        Schema::new(fields)
    }

    pub fn read_schema(&self) -> Schema {
        let mut fields = vec![
            Field::new("writer", DataType::UInt64, false),
            Field::new("owner", DataType::Binary, false),
            Field::new("key", DataType::Binary, false),
        ];
        if self.kind == EntityKind::Edge {
            for name in ["from", "to", "label"] {
                fields.push(Field::new(name, DataType::Binary, false));
            }
        }
        fields.push(Field::new(
            "properties",
            DataType::Struct(self.properties.fields().clone()),
            false,
        ));
        Schema::new(fields)
    }

    pub fn key_schema() -> Schema {
        Schema::new(vec![Field::new("key", DataType::Binary, false)])
    }

    pub fn clear_schema() -> Schema {
        Schema::new(vec![Field::new("owner", DataType::Binary, true)])
    }
}
