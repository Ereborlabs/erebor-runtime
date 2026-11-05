use std::sync::{Arc, Mutex};

use arrow_array::{Array, ArrayRef, RecordBatch, StructArray, UInt64Array};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use duckdb::core::DataChunkHandle;
use duckdb::vtab::{BindInfo, InitInfo, TableFunctionInfo, VTab};
use duckdb::{params, Connection, Transaction};
use snafu::ResultExt as _;

use crate::error::{ConflictSnafu, DatabaseSnafu, InvalidSnafu};
use crate::{EntityKind, GraphStore, Relation, Result};

type Shape = Arc<Mutex<Option<SchemaRef>>>;

struct SchemaLease(Shape);

impl Drop for SchemaLease {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }
}

struct PropertyShape;

impl VTab for PropertyShape {
    type InitData = ();
    type BindData = ();

    #[allow(unsafe_code, reason = "DuckDB retains the typed registration state.")]
    fn bind(info: &BindInfo) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let pointer = info.get_extra_info::<Shape>();
        if pointer.is_null() {
            return Err("Graph property schema is absent".into());
        }
        // DuckDB retains this exact Shape until it removes the table function.
        let shape = unsafe { &*pointer };
        let shape = shape.lock().map_err(|_| "Graph property schema lock")?;
        let shape = shape.as_ref().ok_or("Graph property schema is absent")?;
        for field in shape.fields() {
            info.add_result_column(
                field.name(),
                duckdb::vtab::to_duckdb_logical_type_for_field(field)?,
            );
        }
        Ok(())
    }

    fn init(_: &InitInfo) -> std::result::Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    fn func(
        _: &TableFunctionInfo<Self>,
        output: &mut DataChunkHandle,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        output.set_len(0);
        Ok(())
    }
}

impl GraphStore {
    pub fn install(connection: &Connection) -> Result<Self> {
        let shape = Arc::new(Mutex::new(None));
        connection
            .register_table_function_with_extra_info::<PropertyShape, Shape>(
                "__araphor_graph_shape",
                &shape,
            )
            .context(DatabaseSnafu {
                operation: "install Graph property schema function",
            })?;
        let store = Self { shape, committed: Arc::default() };
        store.restore(connection)?;
        Ok(store)
    }

    pub fn create_relation(
        &self,
        connection: &Transaction<'_>,
        graph: u64,
        relation: u64,
        shape: &Relation,
        endpoints: Option<(u64, u64)>,
    ) -> Result<()> {
        if graph == 0
            || relation == 0
            || !matches!(
                (shape.kind, endpoints),
                (EntityKind::Node, None) | (EntityKind::Edge, Some((1.., 1..)))
            )
        {
            return InvalidSnafu {
                field: "Graph relation declaration",
            }
            .fail();
        }
        Self::check_properties(&shape.properties)?;
        if let Some((from, to)) = endpoints {
            let count: u64 = connection
                .query_row(
                    "SELECT count(*) FROM graph_relations WHERE graph_id=? AND entity_kind=0
                     AND relation_id IN (?,?)",
                    params![graph, from, to],
                    |row| row.get(0),
                )
                .context(DatabaseSnafu {
                    operation: "check Graph endpoint declarations",
                })?;
            if count != if from == to { 1 } else { 2 } {
                return InvalidSnafu {
                    field: "Graph endpoint declaration",
                }
                .fail();
            }
        }
        let schema = Arc::new(Schema::new(vec![
            Field::new("property_ref", DataType::UInt64, false),
            Field::new(
                "properties",
                DataType::Struct(shape.properties.fields().clone()),
                false,
            ),
        ]));
        for field in schema.fields() {
            duckdb::vtab::to_duckdb_logical_type_for_field(field).map_err(|_| {
                InvalidSnafu {
                    field: "Graph property storage type",
                }
                .build()
            })?;
        }
        {
            let mut bound = self.shape.lock().map_err(|_| {
                ConflictSnafu {
                    resource: "property schema binding",
                }
                .build()
            })?;
            if bound.is_some() {
                return ConflictSnafu {
                    resource: "property schema binding",
                }
                .fail();
            }
            *bound = Some(schema);
        }
        let _lease = SchemaLease(Arc::clone(&self.shape));
        connection
            .execute_batch(&format!(
                "CREATE TABLE graph_properties_{relation} AS
                 SELECT * FROM __araphor_graph_shape();
                 ALTER TABLE graph_properties_{relation} ADD PRIMARY KEY(property_ref)"
            ))
            .context(DatabaseSnafu {
                operation: "create native Graph properties",
            })?;
        connection
            .execute(
                "INSERT INTO graph_relations VALUES (?,?,?,?,?)",
                params![
                    relation,
                    graph,
                    shape.kind as u8,
                    endpoints.map(|value| value.0),
                    endpoints.map(|value| value.1)
                ],
            )
            .context(DatabaseSnafu {
                operation: "register Graph relation",
            })?;
        Ok(())
    }

    pub fn append_properties(
        connection: &Transaction<'_>,
        relation: u64,
        shape: &Relation,
        values: RecordBatch,
    ) -> Result<Vec<u64>> {
        if relation == 0 || values.schema().as_ref() != &shape.properties {
            return InvalidSnafu {
                field: "Graph property batch",
            }
            .fail();
        }
        let count = i64::try_from(values.num_rows()).map_err(|_| {
            InvalidSnafu {
                field: "Graph property row count",
            }
            .build()
        })?;
        let mut statement = connection
            .prepare("SELECT nextval('graph_properties_seq') FROM range(?)")
            .context(DatabaseSnafu {
                operation: "prepare Graph property identities",
            })?;
        let identities = statement
            .query_map(params![count], |row| row.get::<_, u64>(0))
            .context(DatabaseSnafu {
                operation: "allocate Graph property identities",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(DatabaseSnafu {
                operation: "read Graph property identities",
            })?;
        if identities.len() != values.num_rows() || identities.contains(&0) {
            return InvalidSnafu {
                field: "Graph property identities",
            }
            .fail();
        }
        let properties = StructArray::from(values);
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(UInt64Array::from_iter_values(identities.iter().copied())),
            Arc::new(properties),
        ];
        let schema = Schema::new(vec![
            Field::new("property_ref", DataType::UInt64, false),
            Field::new("properties", arrays[1].data_type().clone(), false),
        ]);
        let batch = RecordBatch::try_new(Arc::new(schema), arrays)?;
        let mut appender = connection
            .appender(&format!("graph_properties_{relation}"))
            .context(DatabaseSnafu {
                operation: "open Graph property appender",
            })?;
        appender.append_record_batch(batch).context(DatabaseSnafu {
            operation: "append native Graph properties",
        })?;
        appender.flush().context(DatabaseSnafu {
            operation: "flush native Graph properties",
        })?;
        Ok(identities)
    }

    fn check_properties(schema: &Schema) -> Result<()> {
        fn check(kind: &DataType) -> bool {
            match kind {
                DataType::Boolean
                | DataType::Int8
                | DataType::Int16
                | DataType::Int32
                | DataType::Int64
                | DataType::UInt8
                | DataType::UInt16
                | DataType::UInt32
                | DataType::UInt64
                | DataType::Float32
                | DataType::Float64
                | DataType::Utf8
                | DataType::Binary => true,
                DataType::FixedSizeBinary(size) => *size > 0,
                DataType::List(child) => check(child.data_type()),
                DataType::FixedSizeList(child, size) => *size > 0 && check(child.data_type()),
                DataType::Struct(fields) => {
                    !fields.is_empty() && fields.iter().all(|field| check(field.data_type()))
                }
                _ => false,
            }
        }
        if schema.fields().is_empty()
            || schema
                .fields()
                .iter()
                .any(|field| !check(field.data_type()))
        {
            return InvalidSnafu {
                field: "Graph lossless property storage type",
            }
            .fail();
        }
        Ok(())
    }
}
