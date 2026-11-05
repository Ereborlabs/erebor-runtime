use std::sync::Arc;

use arrow_array::{Array, BinaryArray, RecordBatch, UInt8Array};
use arrow_schema::DataType;

use crate::{error::InvalidSnafu, Relation, Result};

pub trait Transport {
    fn read(
        &self,
        operation: &str,
        relation: &str,
        arguments: RecordBatch,
    ) -> Result<Vec<RecordBatch>>;
    fn stage(&self, relation: &str, commands: RecordBatch) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Either,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Write {
    Add = 0,
    Update = 1,
    Remove = 2,
}

pub struct Transaction<T> {
    transport: T,
}

impl<T: Transport> Transaction<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn nodes(&self, relation: &str, keys: &[&[u8]]) -> Result<Vec<RecordBatch>> {
        self.transport.read("nodes", relation, Self::keys(keys)?)
    }

    pub fn owned(&self, relation: &str) -> Result<Vec<RecordBatch>> {
        self.transport.read("owned",relation,RecordBatch::new_empty(Arc::new(arrow_schema::Schema::empty())))
    }

    pub fn neighbors(
        &self,
        relation: &str,
        keys: &[&[u8]],
        direction: Direction,
    ) -> Result<Vec<RecordBatch>> {
        let operation = match direction {
            Direction::Outgoing => "outgoing",
            Direction::Incoming => "incoming",
            Direction::Either => "neighbors",
        };
        self.transport.read(operation, relation, Self::keys(keys)?)
    }

    pub fn stage_nodes(&self, relation: &str, commands: RecordBatch) -> Result<()> {
        Commands::check(&commands, false)?;
        self.transport.stage(relation, commands)
    }

    pub fn stage_edges(&self, relation: &str, commands: RecordBatch) -> Result<()> {
        Commands::check(&commands, true)?;
        self.transport.stage(relation, commands)
    }

    pub fn clear_owner(&self, owner: &[u8]) -> Result<()> {
        self.clear(Some(owner))
    }

    pub fn clear_owners(&self, owners: BinaryArray) -> Result<()> {
        if owners.null_count() != 0 {
            return InvalidSnafu {
                field: "Graph owner clear",
            }
            .fail();
        }
        let batch =
            RecordBatch::try_new(Arc::new(Relation::clear_schema()), vec![Arc::new(owners)])?;
        self.transport.stage("graph_clear", batch)
    }

    pub fn clear_scope(&self) -> Result<()> {
        self.clear(None)
    }

    fn clear(&self, owner: Option<&[u8]>) -> Result<()> {
        let schema = Arc::new(Relation::clear_schema());
        let batch = RecordBatch::try_new(schema, vec![Arc::new(BinaryArray::from(vec![owner]))])?;
        self.transport.stage("graph_clear", batch)
    }

    fn keys(keys: &[&[u8]]) -> Result<RecordBatch> {
        Ok(RecordBatch::try_new(
            Arc::new(Relation::key_schema()),
            vec![Arc::new(BinaryArray::from_iter_values(
                keys.iter().copied(),
            ))],
        )?)
    }
}

pub(crate) struct Commands;

impl Commands {
    pub(crate) fn check(commands: &RecordBatch, edges: bool) -> Result<()> {
        let schema = commands.schema();
        for (name, data_type) in [
            ("owner", DataType::Binary),
            ("key", DataType::Binary),
            ("operation", DataType::UInt8),
        ] {
            if schema
                .field_with_name(name)
                .map_or(true, |field| field.data_type() != &data_type)
                || commands
                    .column_by_name(name)
                    .is_none_or(|array| array.null_count() != 0)
            {
                return InvalidSnafu { field: "edit key" }.fail();
            }
        }
        if edges {
            for name in ["from", "to", "label"] {
                if schema
                    .field_with_name(name)
                    .map_or(true, |field| field.data_type() != &DataType::Binary)
                {
                    return InvalidSnafu { field: "edge key" }.fail();
                }
            }
        }
        if !matches!(
            schema
                .field_with_name("properties")
                .map(|field| field.data_type()),
            Ok(DataType::Struct(_))
        ) {
            return InvalidSnafu {
                field: "edit properties",
            }
            .fail();
        }
        let operations = commands
            .column_by_name("operation")
            .and_then(|array| array.as_any().downcast_ref::<UInt8Array>())
            .ok_or_else(|| {
                InvalidSnafu {
                    field: "edit operation",
                }
                .build()
            })?;
        let properties = commands.column_by_name("properties").ok_or_else(|| {
            InvalidSnafu {
                field: "edit properties",
            }
            .build()
        })?;
        for (row, operation) in operations.values().iter().copied().enumerate() {
            if operation > Write::Remove as u8 {
                return InvalidSnafu {
                    field: "edit operation",
                }
                .fail();
            }
            if operation != Write::Remove as u8 {
                if properties.is_null(row) {
                    return InvalidSnafu {
                        field: "edit properties",
                    }
                    .fail();
                }
                if edges
                    && ["from", "to", "label"].into_iter().any(|name| {
                        commands
                            .column_by_name(name)
                            .is_none_or(|array| array.is_null(row))
                    })
                {
                    return InvalidSnafu {
                        field: "edge endpoint",
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }
}
