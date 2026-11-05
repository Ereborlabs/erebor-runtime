use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_analysis::GraphPublication;
use araphor_analysis_builtins::graph::Unit;
use araphor_analysis_sdk as sdk;
use araphor_data::AnalysisContextRefV1;
use araphor_query::datafusion as df;
use araphor_query::execution::Session;
use araphor_query::sources::SourceImage;
use df::arrow::array::{
    new_empty_array, Array, BinaryArray, ListArray, StringArray, StructArray, UInt64Array,
};
use df::arrow::datatypes::{DataType, Field, Fields};
use df::common::{DataFusionError, Result, ScalarValue};
use df::datasource::view::ViewTable;
use df::logical_expr::{
    col, create_udf, ColumnarValue, LogicalPlan, LogicalPlanBuilder, ScalarUDF, Volatility,
};

use super::{AnalysisContextKeyV1, AnalysisContextVersionV1, GraphContext};

impl GraphContext {
    pub(super) fn column<'a, T: Array + 'static>(
        batch: &'a sdk::RecordBatch,
        name: &str,
    ) -> Result<&'a T> {
        batch
            .column_by_name(name)
            .and_then(|array| array.as_any().downcast_ref())
            .ok_or_else(|| DataFusionError::Execution(format!("canonical context field {name}")))
    }

    pub(super) fn context_row(
        batch: &sdk::RecordBatch,
        row: usize,
    ) -> Result<(AnalysisContextVersionV1, AnalysisContextRefV1)> {
        if row >= batch.num_rows()
            || [
                "tenant_id",
                "owner_id",
                "entity_key",
                "lifetime_key",
                "owner_revision",
                "commit_revision",
                "sensitivity",
                "body",
            ]
            .iter()
            .any(|name| {
                batch
                    .column_by_name(name)
                    .is_none_or(|column| column.is_null(row))
            })
        {
            return df::common::exec_err!("canonical context row is incomplete");
        }
        let key = AnalysisContextKeyV1 {
            tenant_id: Self::column::<BinaryArray>(batch, "tenant_id")?
                .value(row)
                .try_into()
                .map_err(|_| DataFusionError::Execution("canonical context tenant".into()))?,
            owner_id: Self::column::<StringArray>(batch, "owner_id")?
                .value(row)
                .into(),
            entity_key: Self::column::<BinaryArray>(batch, "entity_key")?
                .value(row)
                .into(),
            lifetime_key: Self::column::<BinaryArray>(batch, "lifetime_key")?
                .value(row)
                .into(),
            owner_revision: Self::column::<UInt64Array>(batch, "owner_revision")?.value(row),
        };
        let from = Self::column::<UInt64Array>(batch, "valid_from_utc_ns")?;
        let until = Self::column::<UInt64Array>(batch, "valid_until_utc_ns")?;
        let version = AnalysisContextVersionV1 {
            key: key.clone(),
            valid_from_utc_ns: (!from.is_null(row)).then(|| from.value(row)),
            valid_until_utc_ns: (!until.is_null(row)).then(|| until.value(row)),
            sensitivity: Self::column::<StringArray>(batch, "sensitivity")?
                .value(row)
                .try_into()
                .map_err(|_| DataFusionError::Execution("canonical context sensitivity".into()))?,
            body: Self::column::<BinaryArray>(batch, "body")?
                .value(row)
                .into(),
        };
        let reference = AnalysisContextRefV1 {
            key,
            commit_revision: Self::column::<UInt64Array>(batch, "commit_revision")?.value(row),
        };
        Ok((version, reference))
    }

    fn key_fields() -> Fields {
        vec![
            Field::new("tenant_id", DataType::Binary, true),
            Field::new("node_id", DataType::Utf8, true),
            Field::new("profile_id", DataType::Utf8, true),
            Field::new("profile_version", DataType::UInt64, true),
            Field::new("policy_document_digest", DataType::Utf8, true),
        ]
        .into()
    }

    fn candidate_key(context: &AnalysisContextVersionV1) -> Result<Vec<ScalarValue>> {
        let empty = || {
            vec![
                ScalarValue::Binary(None),
                ScalarValue::Utf8(None),
                ScalarValue::Utf8(None),
                ScalarValue::UInt64(None),
                ScalarValue::Utf8(None),
            ]
        };
        if context.key.owner_id != "mithril-control/policy-candidate" {
            return Ok(empty());
        }
        let parsed = Self::new(std::slice::from_ref(context))
            .map_err(|source| DataFusionError::External(Box::new(source)))?;
        let Some(material) = parsed.candidates.into_values().next() else {
            return Ok(empty());
        };
        if material.source_tenant != material.candidate.tenant_id {
            return Ok(empty());
        }
        Ok(vec![
            ScalarValue::Binary(Some(context.key.tenant_id.to_vec())),
            ScalarValue::Utf8(Some(material.candidate.exact_target.node_id)),
            ScalarValue::Utf8(Some(material.profile_id)),
            ScalarValue::UInt64(Some(material.profile_version)),
            ScalarValue::Utf8(Some(material.policy_digest)),
        ])
    }

    fn key_function(raw: DataType) -> ScalarUDF {
        let fields = Self::key_fields();
        let output = DataType::Struct(fields.clone());
        create_udf(
            "mithril_graph_candidate_key",
            vec![raw],
            output.clone(),
            Volatility::Immutable,
            Arc::new(move |args| {
                let args = ColumnarValue::values_to_arrays(args)?;
                let raw = args[0]
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| DataFusionError::Execution("canonical context struct".into()))?;
                if raw.is_empty() {
                    return Ok(ColumnarValue::Array(new_empty_array(&output)));
                }
                if raw.null_count() != 0 {
                    return df::common::exec_err!("canonical candidate context is null");
                }
                let batch = sdk::RecordBatch::from(raw.clone());
                let mut keys = Vec::with_capacity(raw.len());
                for row in 0..raw.len() {
                    keys.push(Self::candidate_key(&Self::context_row(&batch, row)?.0)?);
                }
                let columns = (0..fields.len())
                    .map(|column| {
                        ScalarValue::iter_to_array(keys.iter().map(|key| key[column].clone()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                Ok(ColumnarValue::Array(Arc::new(StructArray::new(
                    fields.clone(),
                    columns,
                    None,
                ))))
            }),
        )
    }

    fn resolve_function(
        record: DataType,
        event: DataType,
        candidates: DataType,
        acknowledgements: DataType,
    ) -> ScalarUDF {
        let output = DataType::Struct(GraphPublication::resolved_schema().fields().clone());
        create_udf(
            "mithril_graph_resolve",
            vec![record, event, candidates, acknowledgements],
            output,
            Volatility::Immutable,
            Arc::new(move |args| {
                let args = ColumnarValue::values_to_arrays(args)?;
                let affected = Unit::affected_port();
                let record_values = df::arrow::compute::cast(
                    args[0].as_ref(),
                    affected.schema.field(0).data_type(),
                )?;
                let ids = Unit::decode_affected(&sdk::Dataset {
                    name: affected.name,
                    batches: vec![sdk::RecordBatch::try_new(
                        Arc::new(affected.schema),
                        vec![record_values],
                    )?],
                })
                .map_err(|source| DataFusionError::External(Box::new(source)))?;
                let events = args[1]
                    .as_any()
                    .downcast_ref::<StructArray>()
                    .ok_or_else(|| DataFusionError::Execution("canonical event struct".into()))?;
                if events.null_count() != 0 {
                    return df::common::exec_err!("canonical resolver input is null");
                }
                let events_batch = sdk::RecordBatch::from(events.clone());
                let candidates = args[2]
                    .as_any()
                    .downcast_ref::<ListArray>()
                    .ok_or_else(|| DataFusionError::Execution("canonical candidate list".into()))?;
                let acknowledgements =
                    args[3]
                        .as_any()
                        .downcast_ref::<ListArray>()
                        .ok_or_else(|| {
                            DataFusionError::Execution("canonical acknowledgement list".into())
                        })?;
                let mut resolved = Vec::with_capacity(ids.len());
                for (row, id) in ids.into_iter().enumerate() {
                    if events.is_null(row)
                        || candidates.is_null(row)
                        || acknowledgements.is_null(row)
                    {
                        return df::common::exec_err!("canonical resolver input is null");
                    }
                    let (record, _) = GraphPublication::decode_event(&id, &events_batch, row)?;
                    let values = candidates.value(row);
                    let values =
                        values
                            .as_any()
                            .downcast_ref::<StructArray>()
                            .ok_or_else(|| {
                                DataFusionError::Execution("canonical candidate pair".into())
                            })?;
                    if values.null_count() != 0 {
                        return df::common::exec_err!("canonical candidate pair is null");
                    }
                    let values = sdk::RecordBatch::from(values.clone());
                    let contexts = Self::column::<StructArray>(&values, "context")?;
                    let keys = Self::column::<StructArray>(&values, "key_struct")?;
                    let mut canonical = BTreeMap::<
                        AnalysisContextKeyV1,
                        (AnalysisContextVersionV1, AnalysisContextRefV1),
                    >::new();
                    let mut add =
                        |value: (AnalysisContextVersionV1, AnalysisContextRefV1)| -> Result<()> {
                            if value.0.key.tenant_id != id.stream.tenant_id
                                || value.0.key.lifetime_key != id.stream.node_id.as_bytes()
                            {
                                return df::common::exec_err!("canonical context source differs");
                            }
                            match canonical.entry(value.0.key.clone()) {
                                std::collections::btree_map::Entry::Occupied(previous)
                                    if previous.get() != &value =>
                                {
                                    return df::common::exec_err!(
                                        "canonical context version conflicts"
                                    )
                                }
                                std::collections::btree_map::Entry::Occupied(_) => {}
                                std::collections::btree_map::Entry::Vacant(slot) => {
                                    slot.insert(value);
                                }
                            }
                            Ok(())
                        };
                    for index in 0..values.num_rows() {
                        if contexts.is_null(index) && keys.is_null(index) {
                            continue;
                        }
                        if contexts.is_null(index) || keys.is_null(index) {
                            return df::common::exec_err!("canonical candidate padding differs");
                        }
                        let candidate_batch = sdk::RecordBatch::from(contexts.slice(index, 1));
                        let candidate = Self::context_row(&candidate_batch, 0)?;
                        let expected = Self::candidate_key(&candidate.0)?;
                        if expected.len() != keys.num_columns() {
                            return df::common::exec_err!("canonical candidate key shape differs");
                        }
                        for (column, expected) in expected.into_iter().enumerate() {
                            if ScalarValue::try_from_array(keys.column(column), index)? != expected
                            {
                                return df::common::exec_err!("canonical candidate key differs");
                            }
                        }
                        add(candidate)?;
                    }
                    let values = acknowledgements.value(row);
                    let values =
                        values
                            .as_any()
                            .downcast_ref::<StructArray>()
                            .ok_or_else(|| {
                                DataFusionError::Execution(
                                    "canonical acknowledgement struct".into(),
                                )
                            })?;
                    for index in 0..values.len() {
                        if !values.is_null(index) {
                            let batch = sdk::RecordBatch::from(values.slice(index, 1));
                            add(Self::context_row(&batch, 0)?)?;
                        }
                    }
                    let (versions, mut proofs): (Vec<_>, Vec<_>) = canonical.into_values().unzip();
                    let context = Self::new(&versions)
                        .map_err(|source| DataFusionError::External(Box::new(source)))?;
                    let facts = context
                        .facts(&record)
                        .map_err(|source| DataFusionError::External(Box::new(source)))?;
                    Self::fact_proofs(&facts, &id.stream.node_id, &mut proofs);
                    resolved.push((id, facts, proofs));
                }
                Ok(ColumnarValue::Array(Arc::new(StructArray::from(
                    GraphPublication::encode_resolved(&resolved)?,
                ))))
            }),
        )
    }

    pub(super) fn fact_proofs(
        facts: &[AnalysisContextVersionV1],
        node: &str,
        proofs: &mut Vec<AnalysisContextRefV1>,
    ) {
        let consulted = facts
            .iter()
            .filter(|fact| fact.key.owner_id == "mithril-control/policy-ack")
            .flat_map(|fact| {
                let original = |owner: &str, revision| AnalysisContextKeyV1 {
                    tenant_id: fact.key.tenant_id,
                    owner_id: owner.into(),
                    entity_key: fact.key.entity_key.clone(),
                    lifetime_key: node.as_bytes().to_vec(),
                    owner_revision: revision,
                };
                [
                    original("mithril-control/policy-candidate", 1),
                    original("mithril-control/activation-ack", fact.key.owner_revision),
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        proofs.retain(|proof| consulted.contains(&proof.key));
    }

    fn view(session: &mut Session, name: &str, plan: LogicalPlan) -> araphor_query::Result<()> {
        session.register_table(name, Arc::new(ViewTable::new(plan, None)))
    }

    async fn query(session: &Session, sql: String) -> araphor_query::Result<LogicalPlan> {
        Ok(session.prepare(&sql, Vec::new()).await?.0)
    }

    pub(super) async fn plans(
        session: &Session,
        events: &LogicalPlan,
        contexts: &LogicalPlan,
    ) -> araphor_query::Result<(LogicalPlan, LogicalPlan)> {
        let mut session = session.clone();
        Self::view(&mut session, "__graph_input_events", events.clone())?;
        Self::view(&mut session, "__control_contexts", contexts.clone())?;
        let raw_sql = "SELECT named_struct('tenant_id', tenant_id, 'owner_id', owner_id,
            'entity_key', entity_key, 'lifetime_key', lifetime_key, 'owner_revision', owner_revision,
            'commit_revision', commit_revision, 'valid_from_utc_ns', valid_from_utc_ns,
            'valid_until_utc_ns', valid_until_utc_ns, 'sensitivity', sensitivity, 'body', body) AS raw_context
            FROM __control_contexts";
        let raw = Self::query(&session, raw_sql.into()).await?;
        Self::view(&mut session, "__control_raw_contexts", raw)?;
        let candidates = Self::query(&session, "SELECT raw_context FROM __control_raw_contexts WHERE raw_context.owner_id = 'mithril-control/policy-candidate'".into()).await?;
        let key = Self::key_function(candidates.schema().field(0).data_type().clone());
        let candidates = LogicalPlanBuilder::from(candidates)
            .project([
                col("raw_context"),
                key.call(vec![col("raw_context")]).alias("key_struct"),
            ])
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        let acknowledgements = Self::query(&session, "SELECT raw_context FROM __control_raw_contexts WHERE raw_context.owner_id = 'mithril-control/activation-ack'".into()).await?;
        Self::view(&mut session, "__graph_input_candidates", candidates.clone())?;
        Self::view(&mut session, "__graph_input_acks", acknowledgements.clone())?;
        let grouped = Self::query(&session, araphor_data::ResolvedInput::SQL.into()).await?;
        let resolve = Self::resolve_function(
            grouped.schema().field(0).data_type().clone(),
            grouped.schema().field(1).data_type().clone(),
            grouped.schema().field(2).data_type().clone(),
            grouped.schema().field(3).data_type().clone(),
        );
        let resolved = LogicalPlanBuilder::from(grouped)
            .project([
                col("record"),
                col("event"),
                resolve
                    .call(vec![
                        col("record"),
                        col("event"),
                        col("candidates"),
                        col("acknowledgements"),
                    ])
                    .alias("resolved"),
            ])
            .and_then(LogicalPlanBuilder::build)
            .map_err(|source| araphor_query::Error::Sql { source })?;
        for (suffix, image) in [
            ("after", SourceImage::After),
            ("before", SourceImage::Before),
            ("inserted", SourceImage::Inserted),
            ("removed", SourceImage::Removed),
        ] {
            for (name, plan) in [
                ("events", events),
                ("candidates", &candidates),
                ("acks", &acknowledgements),
            ] {
                Self::view(
                    &mut session,
                    &format!("__control_{name}_{suffix}"),
                    image
                        .plan_rows(plan)
                        .map_err(|source| araphor_query::Error::Sql { source })?,
                )?;
            }
        }
        let changed = Self::query(&session, include_str!("native/changed.sql").into()).await?;
        Ok((resolved, changed))
    }
}
