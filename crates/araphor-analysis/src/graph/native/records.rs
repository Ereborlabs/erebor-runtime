use std::collections::BTreeSet;
use std::sync::Arc;

use araphor_query::execution::Session;
use datafusion::arrow::array::{Array, Int64Array, StructArray};
use datafusion::datasource::view::ViewTable;
use datafusion::functions::core::named_struct;
use datafusion::functions_aggregate::count::count_all;
use datafusion::logical_expr::{
    col, create_udf, lit, ColumnarValue, Expr, LogicalPlan, LogicalPlanBuilder, Volatility,
};

use super::{GraphPublication, Projection};

impl GraphPublication {
    pub(super) async fn coverage_driver(
        session: &Session,
        resolved: LogicalPlan,
    ) -> crate::Result<LogicalPlan> {
        let event = resolved
            .schema()
            .field_with_unqualified_name("event")
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let araphor_analysis_sdk::DataType::Struct(fields) = event.data_type() else {
            return Err(araphor_data::PackageErrorCodeV1::Invalid
                .error("Graph native event schema")
                .into());
        };
        let mut values = vec![col("record"), col("event"), col("resolved")];
        values.extend(fields.iter().map(|field| {
            datafusion::functions::core::get_field()
                .call(vec![col("event"), lit(field.name().clone())])
                .alias(field.name())
        }));
        let events = LogicalPlanBuilder::from(resolved)
            .project(values)
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let mut scope = session.clone();
        scope.register_table(
            "__graph_coverage_events",
            Arc::new(ViewTable::new(events, None)),
        )?;
        Self::native_plan(
            &scope,
            &format!(
                "WITH events AS (SELECT * FROM __graph_coverage_events)
                SELECT record, event, resolved, coverage_revision, interval_revision,
                    coverage_interval_id, state AS coverage_state, gap_reasons AS coverage_reasons
                FROM ({}) qualified",
                araphor_analysis_builtins::discovery::sql::COVERAGE_ROWS_SQL,
            ),
        )
        .await
    }

    pub fn decode_event(
        record: &araphor_data::DiscoveryRecordIdV1,
        event: &araphor_analysis_sdk::RecordBatch,
        row: usize,
    ) -> datafusion::common::Result<(
        araphor_data::DiscoveryRecordV1,
        araphor_data::StorePositionV1,
    )> {
        use datafusion::arrow::array::{BinaryArray, UInt32Array, UInt64Array};
        if row >= event.num_rows()
            || [
                "tenant_id",
                "node_id",
                "node_boot_id",
                "label_epoch",
                "source_id",
                "source_epoch",
                "cpu_id",
                "source_cursor",
                "commit_revision",
                "ordinal",
                "framed_record",
            ]
            .iter()
            .any(|name| {
                event
                    .column_by_name(name)
                    .is_none_or(|column| column.is_null(row))
            })
        {
            return Err(Projection::invalid("Graph event row"));
        }
        if record.stream != Projection::identity(event, row)?
            || record.cpu_id != Projection::column::<UInt32Array>(event, "cpu_id")?.value(row)
            || record.durable_cursor
                != Projection::column::<UInt64Array>(event, "source_cursor")?.value(row)
        {
            return Err(Projection::invalid("Graph event record key"));
        }
        let bytes = Projection::column::<BinaryArray>(event, "framed_record")?.value(row);
        let value = araphor_data::DiscoveryRecordV1::try_from((record.clone(), bytes))
            .map_err(Projection::external)?;
        let position = araphor_data::StorePositionV1 {
            commit_revision: Projection::column::<UInt64Array>(event, "commit_revision")?
                .value(row),
            ordinal: Projection::column::<UInt32Array>(event, "ordinal")?.value(row),
        };
        if position.commit_revision == 0 {
            return Err(Projection::invalid("Graph event source position"));
        }
        Ok((value, position))
    }

    pub(super) async fn event_driver(
        session: &Session,
        events: LogicalPlan,
    ) -> crate::Result<LogicalPlan> {
        let canonical = session
            .engine()
            .prepare("SELECT * FROM events", Vec::new())
            .await?
            .0;
        let project = |plan: LogicalPlan| -> datafusion::common::Result<LogicalPlan> {
            let mut names = BTreeSet::new();
            let fields = plan
                .schema()
                .fields()
                .iter()
                .flat_map(|field| {
                    names.insert(field.name().clone());
                    [lit(field.name().clone()), col(field.name())]
                })
                .collect::<Vec<_>>();
            if names.len() != plan.schema().fields().len() {
                return Err(Projection::invalid("Graph event column identity"));
            }
            let stream = named_struct().call(
                [
                    "tenant_id",
                    "node_id",
                    "node_boot_id",
                    "label_epoch",
                    "source_id",
                    "source_epoch",
                ]
                .into_iter()
                .flat_map(|name| [lit(name), col(name)])
                .collect(),
            );
            let record = named_struct().call(vec![
                lit("stream"),
                stream,
                lit("cpu_id"),
                col("cpu_id"),
                lit("durable_cursor"),
                col("source_cursor"),
            ]);
            LogicalPlanBuilder::from(plan)
                .project([
                    record.alias("record"),
                    named_struct().call(fields).alias("event"),
                ])?
                .build()
        };
        let selected = project(events)
            .and_then(|plan| {
                LogicalPlanBuilder::from(plan)
                    .aggregate(
                        [col("record"), col("event")],
                        [count_all().alias("__graph_count")],
                    )?
                    .build()
            })
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let canonical =
            project(canonical).map_err(|source| araphor_query::Error::Sql { source })?;
        let selected_type = selected.schema().field(1).data_type().clone();
        let canonical_type = canonical.schema().field(1).data_type().clone();
        let record_type = selected.schema().field(0).data_type().clone();
        let function = create_udf(
            "araphor_graph_event",
            vec![
                record_type.clone(),
                selected_type,
                record_type,
                canonical_type.clone(),
                selected.schema().field(2).data_type().clone(),
            ],
            canonical_type,
            Volatility::Immutable,
            Arc::new(|args| {
                let arrays = ColumnarValue::values_to_arrays(args)?;
                if arrays.len() != 5 {
                    return Err(Projection::invalid("Graph event arguments"));
                }
                let selected = arrays[1]
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| Projection::invalid("Graph selected event"))?;
                let canonical = arrays[3]
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| Projection::invalid("Graph canonical event"))?;
                let counts = arrays[4]
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .ok_or_else(|| Projection::invalid("Graph selected event count"))?;
                for row in 0..selected.len() {
                    if selected.is_null(row)
                        || canonical.is_null(row)
                        || counts.is_null(row)
                        || counts.value(row) != 1
                        || arrays[0].slice(row, 1) != arrays[2].slice(row, 1)
                    {
                        return Err(Projection::invalid("Graph event identity or multiplicity"));
                    }
                    for name in [
                        "tenant_id",
                        "node_id",
                        "node_boot_id",
                        "label_epoch",
                        "source_id",
                        "source_epoch",
                        "cpu_id",
                        "source_cursor",
                        "commit_revision",
                        "ordinal",
                        "framed_record",
                        "temporal_coverage",
                        "kernel_sequence",
                        "coverage_interval_id",
                    ] {
                        let left = selected
                            .column_by_name(name)
                            .ok_or_else(|| Projection::invalid("Graph selected event column"))?;
                        let right = canonical
                            .column_by_name(name)
                            .ok_or_else(|| Projection::invalid("Graph canonical event column"))?;
                        if left.slice(row, 1) != right.slice(row, 1) {
                            return Err(Projection::invalid("Graph event differs from journal"));
                        }
                    }
                }
                Ok(ColumnarValue::Array(Arc::clone(&arrays[3])))
            }),
        );
        let mut scope = session.clone();
        scope.register_table("__graph_selected", Arc::new(ViewTable::new(selected, None)))?;
        scope.register_table(
            "__graph_canonical",
            Arc::new(ViewTable::new(canonical, None)),
        )?;
        let checked = Self::native_plan(&scope,
            "SELECT selected.record, selected.event AS selected_event, canonical.record AS canonical_record,
                canonical.event AS canonical_event, selected.__graph_count
             FROM __graph_selected selected LEFT JOIN __graph_canonical canonical
                ON selected.record = canonical.record").await?;
        let value = function
            .call(vec![
                col("record"),
                col("selected_event"),
                col("canonical_record"),
                col("canonical_event"),
                col("__graph_count"),
            ])
            .alias("event");
        LogicalPlanBuilder::from(checked)
            .project([Expr::Column("record".into()), value])
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source }.into())
    }
}
