use araphor_data::{DiscoverySnapshotRowV1 as NativeSnapshot, DiscoveryStateRowV1 as NativeState};
use serde_json::{json, Value};

use super::*;

struct Live {
    records: Recorded,
    state: NativeState,
    expired: Vec<araphor_data::AnalysisGapV1>,
    resolved: bool,
    target_revision: u64,
}

#[derive(Deserialize)]
struct Output {
    snapshot: NativeSnapshot,
    consumed_cursor: u64,
    input_bytes: u64,
    facts_revision: u64,
    incomplete: bool,
    gaps: Option<Vec<araphor_data::AnalysisGapV1>>,
    repair: bool,
    notice_only: bool,
    notice_facts_revision: u64,
    current_result_id: Option<String>,
    result_commit_revision: Option<u64>,
}

impl Live {
    fn new(count: u64) -> Self {
        let mut records = Recorded::new(count);
        for record in &mut records.records {
            record.effect.execution_set_id = vec![4; 16];
            record.source = Some(builtin::Lifetime {
                process: vec![1; 16],
                entry: vec![2; 16],
                binding: vec![3; 16],
                role: 1,
                state: 1,
                rule: 1,
                sequence: record.id.durable_cursor + 100,
            });
        }
        Self {
            records,
            expired: Vec::new(),
            state: NativeState {
                tenant_id: [1; 16],
                node_id: "node".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
                cpu_id: 3,
                contiguous_cursor: count,
                input_unbounded: true,
                retained_floor: 0,
                source_coverage_revision: 0,
                method_version: 1,
                processor_present: true,
                processor_class: Some("OPTIONAL".into()),
                start_cursor: Some(0),
                consumed_cursor: Some(0),
                resume_floor: None,
                context_revision: None,
                retired: Some(false),
                current_result_id: None,
                result_commit_revision: None,
                current_compatible: false,
                notice_facts_revision: None,
                notice_coverage_revision: None,
                interval_id: None,
                profile_revision: None,
                facts_revision: None,
                coverage_revision: None,
                created_utc_ns: None,
                updated_utc_ns: None,
                sealed: None,
                input_bytes: None,
                incomplete: None,
                gaps: None,
                context_refs: None,
                history: Vec::new(),
                snapshot: None,
            },
            resolved: false,
            target_revision: 0,
        }
    }

    fn fixture(&self, split: bool) -> TestResult<Fixture> {
        let tables = araphor_data::AnalysisStore::table_schemas();
        let schema = &tables["events"];
        let fields = schema
            .fields()
            .iter()
            .filter(|field| {
                EVENT_FIELDS.contains(&field.name().as_str())
                    || field.name().starts_with("catalog_")
            })
            .cloned()
            .collect::<Vec<_>>();
        let fixture = Fixture {
            context: SessionContext::new(),
            schema: Arc::new(Schema::new(fields.clone())),
        };
        let mut events = Vec::new();
        for record in &self.records.records {
            let mut event = Recorded::event(record)?;
            let key = &self.records.contexts[0].static_key;
            event["catalog_profile_id"] = json!("profile");
            event["catalog_profile_version"] = json!(1);
            event["catalog_policy_document_digest"] = json!("config");
            for (name, value) in serde_json::to_value(key)?.as_object().ok_or("key object")? {
                event[format!("catalog_key_{name}")] = value.clone();
            }
            events.push(event);
        }
        Recorded::table(&fixture, "events", fields, &events, split)?;
        let mut target = defaults(&tables["targets"]);
        for (name, value) in [
            ("tenant_id", json!(vec![1u8; 16])),
            ("commit_revision", json!(self.target_revision)),
            ("node_id", json!("node")),
            ("node_boot_id", json!(vec![2u8; 16])),
            (
                "node_boot_id_text",
                json!("02020202-0202-0202-0202-020202020202"),
            ),
            ("label_epoch", json!(1)),
            (
                "binding_id_text",
                json!("03030303-0303-0303-0303-030303030303"),
            ),
            (
                "execution_set_id",
                json!("04040404-0404-0404-0404-040404040404"),
            ),
            ("workload_binding_generation_digest", json!("subject")),
            ("workload_digest_valid", json!(true)),
            ("image_digest", json!("image")),
            ("profile_id", json!("profile")),
            ("policy_source_revision_id", json!("source")),
            ("source_revision_id", json!("source")),
            ("signed_profile_digest", json!("digest")),
            ("protected_scope_id", json!("scope")),
            ("workload_selector_id", json!("workload")),
            ("pod_labels", json!("{}")),
        ] {
            target[name] = value;
        }
        let mut policy = defaults(&tables["compiled_policies"]);
        for (name, value) in [
            ("tenant_id", json!(vec![1u8; 16])),
            ("source_revision_id", json!("source")),
            ("signed_profile_digest", json!("digest")),
            ("profile_id", json!("profile")),
            ("profile_version", json!(1)),
            ("policy_document_digest", json!("config")),
            ("commit_revision", json!(7)),
            ("execution_set_ids", json!(["execution"])),
            (
                "compiled_keys",
                json!([self.records.contexts[0].static_key]),
            ),
        ] {
            policy[name] = value;
        }
        let coverage = self
            .expired
            .iter()
            .map(|gap| {
                let mut report = defaults(&tables["coverage"]);
                for (name, value) in [
                    ("tenant_id", json!(self.state.tenant_id)),
                    ("node_id", json!(self.state.node_id)),
                    ("node_boot_id", json!(self.state.node_boot_id)),
                    ("label_epoch", json!(self.state.label_epoch)),
                    ("source_id", json!(self.state.source_id)),
                    ("source_epoch", json!(self.state.source_epoch)),
                    ("cpu_id", json!(self.state.cpu_id)),
                    ("kind", json!("expired")),
                    ("first_cursor", json!(gap.first_cursor)),
                    ("last_cursor", json!(gap.last_cursor)),
                    ("commit_revision", json!(gap.commit_revision)),
                ] {
                    report[name] = value;
                }
                report
            })
            .collect::<Vec<_>>();
        for (name, rows) in [
            ("targets", if self.resolved { vec![target] } else { vec![] }),
            (
                "compiled_policies",
                if self.resolved { vec![policy] } else { vec![] },
            ),
            ("coverage", coverage),
        ] {
            Recorded::table(&fixture, name, tables[name].fields().to_vec(), &rows, split)?;
        }
        Recorded::table(
            &fixture,
            "discovery_state",
            NativeState::schema().fields().to_vec(),
            &[&self.state],
            false,
        )?;
        Ok(fixture)
    }

    async fn query(&self, split: bool) -> TestResult<Vec<Output>> {
        let fixture = self.fixture(split)?;
        let bundle = crate::Package::discovery_bundle()?;
        let input = bundle.artifacts[0].descriptor.exports[0]
            .inputs
            .iter()
            .find(|input| input.port.name == "discovery_state")
            .ok_or("state input absent")?;
        let sdk::InputSource::Query(sql) = &input.source else {
            return Err("state input query absent".into());
        };
        let schema = Arc::new(input.port.schema.clone());
        let batches = native_frame(&fixture.context, sql)
            .await?
            .collect()
            .await?
            .into_iter()
            .map(|batch| sdk::Dataset::normalize_batch(batch, Arc::clone(&schema)))
            .collect::<sdk::Result<Vec<_>>>()?;
        let _previous = fixture.context.deregister_table("discovery_state")?;
        fixture.context.register_table(
            "discovery_state",
            Arc::new(MemTable::try_new(schema, vec![batches])?),
        )?;
        let sql = LIVE_SQL.as_str();
        let frame = native_frame(&fixture.context, sql).await?;
        frame.logical_plan().apply_with_subqueries(|plan| {
            assert!(!matches!(plan, LogicalPlan::Extension(_)));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let frame = frame.select(vec![
            datafusion::logical_expr::col("snapshot"),
            datafusion::logical_expr::col("consumed_cursor"),
            datafusion::logical_expr::col("input_bytes"),
            datafusion::logical_expr::col("facts_revision"),
            datafusion::logical_expr::col("incomplete"),
            datafusion::logical_expr::col("gaps"),
            datafusion::logical_expr::col("repair"),
            datafusion::logical_expr::col("notice_only"),
            datafusion::logical_expr::col("notice_facts_revision"),
            datafusion::logical_expr::col("current_result_id"),
            datafusion::logical_expr::col("result_commit_revision"),
        ])?;
        let schema = Arc::new(frame.schema().as_arrow().clone());
        let plan = frame.create_physical_plan().await?;
        plan.apply(|node| {
            assert!(!node.name().contains("Discovery") && !node.name().contains("Package"));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let batches = datafusion::physical_plan::collect(plan, fixture.context.task_ctx()).await?;
        Ok(serde_arrow::from_record_batch(&concat_batches(
            &schema, &batches,
        )?)?)
    }

    fn advance(&mut self, output: &Output) {
        self.state.consumed_cursor = Some(output.consumed_cursor);
        self.state.facts_revision = Some(output.facts_revision);
        self.state.notice_facts_revision = Some(output.notice_facts_revision);
        self.state.notice_coverage_revision = Some(self.state.source_coverage_revision);
        self.state.coverage_revision = Some(self.state.source_coverage_revision);
        self.state.input_bytes = Some(output.input_bytes);
        self.state.snapshot = Some(output.snapshot.clone());
        self.state.incomplete = Some(output.incomplete);
        self.state.gaps = output.gaps.clone();
        self.state.current_result_id = Some("retained-result".into());
        self.state.result_commit_revision = Some(9);
    }
}

fn defaults(schema: &Schema) -> Value {
    fn field_value(field: &Field) -> Value {
        if field.is_nullable() {
            return Value::Null;
        }
        match field.data_type() {
            DataType::Utf8 | DataType::Utf8View | DataType::LargeUtf8 => json!("value"),
            DataType::Binary | DataType::LargeBinary => json!(vec![1u8; 16]),
            DataType::Boolean => json!(false),
            DataType::List(_) | DataType::LargeList(_) => json!([]),
            DataType::Struct(fields) => defaults(&Schema::new(fields.clone())),
            _ => json!(0),
        }
    }
    Value::Object(
        schema
            .fields()
            .iter()
            .map(|field| (field.name().clone(), field_value(field)))
            .collect(),
    )
}

#[tokio::test]
async fn live_cold_append_settles() -> TestResult {
    let mut live = Live::new(2);
    let mut rows = live.query(false).await?;
    assert_eq!(rows.len(), 1);
    let first = rows.remove(0);
    assert_eq!(
        (
            first.snapshot.accepted_records,
            first.snapshot.unresolved_records
        ),
        (2, 2)
    );
    assert_eq!(first.snapshot.lifecycle.len(), 9);
    assert_eq!(
        first.input_bytes,
        live.records
            .records
            .iter()
            .map(|record| record.bytes.len() as u64)
            .sum::<u64>()
    );
    first.snapshot.clone().into_snapshot()?;
    assert_eq!(live.query(true).await?[0].snapshot, first.snapshot);
    live.advance(&first);
    assert!(live.query(false).await?.is_empty());
    let full = Live::new(4);
    live.records = full.records;
    live.state.contiguous_cursor = 4;
    live.records
        .records
        .retain(|record| record.id.durable_cursor > 2);
    let appended = live.query(true).await?.remove(0);
    assert_eq!(
        (
            appended.snapshot.accepted_records,
            appended.snapshot.unresolved_records
        ),
        (4, 4)
    );
    assert_eq!(appended.snapshot.coverage.len(), 1);
    assert_eq!(
        (
            appended.snapshot.coverage[0].first_cursor,
            appended.snapshot.coverage[0].last_cursor
        ),
        (1, 4)
    );
    assert_eq!(
        appended.input_bytes,
        first.input_bytes
            + live
                .records
                .records
                .iter()
                .map(|record| record.bytes.len() as u64)
                .sum::<u64>()
    );
    appended.snapshot.into_snapshot()?;
    Ok(())
}

#[tokio::test]
async fn live_repairs_retained_unresolved() -> TestResult {
    let mut live = Live::new(3);
    let first = live.query(false).await?.remove(0);
    live.advance(&first);
    live.resolved = true;
    live.records
        .records
        .retain(|record| record.id.durable_cursor != 2);
    let repaired = live.query(true).await?.remove(0);
    assert_eq!(repaired.snapshot.accepted_records, 3);
    assert_eq!(
        (
            repaired.snapshot.included_records,
            repaired.snapshot.unresolved_records
        ),
        (2, 1)
    );
    assert_eq!(repaired.snapshot.unresolved[0].record_id.durable_cursor, 2);
    assert_eq!(repaired.input_bytes, first.input_bytes);
    assert_eq!(repaired.facts_revision, 7);
    assert_eq!(repaired.snapshot.coverage, first.snapshot.coverage);
    assert_eq!(
        repaired.snapshot.atoms[0]
            .evidence_sample
            .iter()
            .map(|id| id.durable_cursor)
            .collect::<Vec<_>>(),
        vec![1, 3]
    );
    repaired.snapshot.clone().into_snapshot()?;
    live.advance(&repaired);
    assert!(live.query(false).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn live_rejects_missing_input() -> TestResult {
    let mut live = Live::new(3);
    live.records
        .records
        .retain(|record| record.id.durable_cursor != 2);
    let error = live
        .query(false)
        .await
        .err()
        .ok_or("missing frontier accepted")?;
    assert!(error.to_string().contains("input frontier"), "{error}");
    let mut live = Live::new(3);
    live.state.input_bytes = Some(u64::MAX);
    let error = live
        .query(false)
        .await
        .err()
        .ok_or("byte overflow accepted")?;
    assert!(error.to_string().contains("input bytes"), "{error}");
    Ok(())
}

#[tokio::test]
async fn live_proves_expired_ranges() -> TestResult {
    let mut live = Live::new(7);
    live.expired = vec![
        araphor_data::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 3,
            commit_revision: 8,
        },
        araphor_data::AnalysisGapV1 {
            first_cursor: 5,
            last_cursor: 5,
            commit_revision: 9,
        },
    ];
    live.records.records.retain(|record| {
        !live
            .expired
            .iter()
            .any(|gap| (gap.first_cursor..=gap.last_cursor).contains(&record.id.durable_cursor))
    });
    let output = live.query(false).await?.remove(0);
    assert_eq!(output.consumed_cursor, 7);
    assert_eq!(output.snapshot.accepted_records, 4);
    assert_eq!(output.snapshot.unresolved_records, 4);
    assert_eq!(
        output
            .snapshot
            .coverage
            .iter()
            .map(|range| (
                range.first_cursor,
                range.last_cursor,
                range.expected_records
            ))
            .collect::<Vec<_>>(),
        vec![(1, 1, 1), (4, 4, 1), (6, 7, 2)]
    );
    assert!(output.incomplete);
    assert_eq!(output.gaps.as_deref(), Some(live.expired.as_slice()));
    assert_eq!(
        output.input_bytes,
        live.records
            .records
            .iter()
            .map(|record| record.bytes.len() as u64)
            .sum::<u64>()
    );
    output.snapshot.clone().into_snapshot()?;
    assert_eq!(live.query(true).await?[0].snapshot, output.snapshot);
    live.advance(&output);
    assert!(live.query(false).await?.is_empty());
    live.resolved = true;
    let repaired = live.query(false).await?.remove(0);
    assert_eq!(repaired.snapshot.accepted_records, 4);
    assert_eq!(repaired.snapshot.included_records, 4);
    assert_eq!(repaired.input_bytes, output.input_bytes);
    assert_eq!(repaired.gaps, output.gaps);
    Ok(())
}

#[tokio::test]
async fn live_empty_expiry_scope() -> TestResult {
    let gap = araphor_data::AnalysisGapV1 {
        first_cursor: 1,
        last_cursor: 3,
        commit_revision: 4,
    };
    let mut live = Live::new(3);
    live.expired = vec![gap];
    live.records.records.clear();
    live.state.input_unbounded = false;
    let bounded = live.query(false).await?.remove(0);
    assert_eq!(bounded.consumed_cursor, 0);
    assert_eq!(bounded.snapshot.accepted_records, 0);
    assert!(!bounded.incomplete);
    assert!(bounded.gaps.as_ref().is_none_or(Vec::is_empty));
    live.state.input_unbounded = true;
    let resumed = live.query(false).await?.remove(0);
    assert_eq!(resumed.consumed_cursor, 3);
    assert_eq!(resumed.snapshot.accepted_records, 0);
    assert!(resumed.incomplete);
    assert_eq!(resumed.gaps.as_deref(), Some([gap].as_slice()));
    resumed.snapshot.clone().into_snapshot()?;
    live.advance(&resumed);
    assert!(live.query(false).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn live_keeps_resume_gaps() -> TestResult {
    let gap = araphor_data::AnalysisGapV1 {
        first_cursor: 1,
        last_cursor: 2,
        commit_revision: 1,
    };
    for incomplete in [None, Some(false), Some(true)] {
        let mut live = Live::new(3);
        live.state.consumed_cursor = Some(0);
        live.state.resume_floor = Some(2);
        live.state.retained_floor = 2;
        live.state.incomplete = incomplete;
        live.state.gaps = Some(vec![gap]);
        live.records
            .records
            .retain(|record| record.id.durable_cursor > 2);
        let output = live.query(false).await?.remove(0);
        assert!(output.incomplete);
        assert_eq!(output.gaps.as_deref(), Some([gap].as_slice()));
        assert_eq!(output.snapshot.accepted_records, 1);
        assert_eq!(output.snapshot.coverage[0].first_cursor, 3);
        output.snapshot.clone().into_snapshot()?;
        live.advance(&output);
        assert!(live.query(false).await?.is_empty());
    }
    let mut live = Live::new(1);
    let initial = live.query(false).await?.remove(0);
    live.advance(&initial);
    live.state.contiguous_cursor = 3;
    live.state.resume_floor = Some(3);
    live.state.retained_floor = 3;
    let skipped = araphor_data::AnalysisGapV1 {
        first_cursor: 2,
        last_cursor: 3,
        commit_revision: 2,
    };
    live.state.gaps = Some(vec![skipped]);
    live.records.records.clear();
    let resumed = live.query(false).await?.remove(0);
    assert_eq!(resumed.snapshot, initial.snapshot);
    assert_eq!(resumed.input_bytes, initial.input_bytes);
    assert!(resumed.incomplete);
    assert_eq!(resumed.gaps.as_deref(), Some([skipped].as_slice()));
    live.advance(&resumed);
    assert!(live.query(false).await?.is_empty());
    let mut live = Live::new(1);
    live.state.incomplete = Some(true);
    let output = live.query(false).await?.remove(0);
    assert!(output.incomplete);
    assert!(output.gaps.is_none());
    Ok(())
}

#[tokio::test]
async fn live_sealed_starts_fresh() -> TestResult {
    let mut live = Live::new(2);
    let first = live.query(false).await?.remove(0);
    live.advance(&first);
    live.state.sealed = Some(true);
    live.state.incomplete = Some(true);
    live.state.gaps = Some(vec![araphor_data::AnalysisGapV1 {
        first_cursor: 1,
        last_cursor: 1,
        commit_revision: 1,
    }]);
    assert!(live.query(false).await?.is_empty());
    live.resolved = true;
    assert!(live.query(false).await?.is_empty());
    let records = Live::new(4);
    live.records = records.records;
    live.state.contiguous_cursor = 4;
    let fresh = live.query(false).await?.remove(0);
    assert_eq!(
        (
            fresh.snapshot.accepted_records,
            fresh.snapshot.included_records
        ),
        (2, 2)
    );
    assert_eq!(fresh.snapshot.unresolved_records, 0);
    assert_eq!(fresh.snapshot.coverage[0].first_cursor, 3);
    assert_eq!(
        fresh.input_bytes,
        live.records
            .records
            .iter()
            .filter(|record| record.id.durable_cursor > 2)
            .map(|record| record.bytes.len() as u64)
            .sum::<u64>()
    );
    assert!(!fresh.incomplete);
    assert_eq!(fresh.gaps.as_deref(), Some([].as_slice()));
    fresh.snapshot.clone().into_snapshot()?;
    live.advance(&fresh);
    live.state.sealed = Some(false);
    assert!(live.query(false).await?.is_empty());
    live.state.sealed = Some(true);
    live.state.contiguous_cursor = 6;
    live.state.retained_floor = 6;
    live.state.resume_floor = Some(6);
    live.state.gaps = Some(vec![araphor_data::AnalysisGapV1 {
        first_cursor: 5,
        last_cursor: 6,
        commit_revision: 2,
    }]);
    live.records.records.clear();
    let skipped = live.query(false).await?.remove(0);
    assert_eq!(skipped.snapshot.accepted_records, 0);
    assert_eq!(skipped.input_bytes, 0);
    assert!(skipped.incomplete);
    assert_eq!(skipped.gaps.as_deref(), live.state.gaps.as_deref());
    skipped.snapshot.into_snapshot()?;
    Ok(())
}

#[test]
fn live_bundle_pins_body() -> TestResult {
    let bundle = crate::Package::discovery_bundle()?;
    bundle.validate()?;
    let restored = araphor_data::PackageBundleV1::from_bytes(&bundle.encode()?)?;
    assert_eq!(restored.root, bundle.root);
    assert_eq!(restored.artifacts, bundle.artifacts);
    assert_eq!(restored.digest()?, bundle.digest()?);
    let artifact = &restored.artifacts[0];
    assert_eq!(
        artifact.descriptor.exports[0].input_mode,
        sdk::InputMode::Resolved
    );
    assert!(!artifact.prepared("live"));
    let araphor_data::PackageImplementationV1::Sql { program, .. } = &artifact.implementations[0]
    else {
        return Err("SQL implementation absent".into());
    };
    assert_eq!(program.outputs["snapshot"], LIVE_SQL.as_str());
    assert!(!program.outputs["snapshot"].contains("@@"));
    assert!(!program.outputs["snapshot"].contains("discovery."));
    for input in &artifact.descriptor.exports[0].inputs {
        if input.port.name == "discovery_state" {
            let sdk::InputSource::Query(sql) = &input.source else {
                return Err("state input query absent".into());
            };
            assert!(matches!(
                native_statement(sql)?,
                datafusion::sql::parser::Statement::Statement(_)
            ));
            assert!(!sql.contains("@@"));
            for name in ["required_facts", "pending", "prior", "repair", "available"] {
                input.port.schema.field_with_name(name)?;
            }
            assert!(input.port.schema.field_with_name("prior")?.is_nullable());
        } else {
            assert_eq!(
                input.source,
                sdk::InputSource::Table(sdk::TableRef::Named(input.port.name.clone()))
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn live_repairs_sealed_history() -> TestResult {
    let mut live = Live::new(3);
    let original = live.query(false).await?.remove(0);
    live.advance(&original);
    live.state.sealed = Some(true);
    live.state.facts_revision = Some(7);
    live.state.current_result_id = Some("new-head".into());
    live.state
        .history
        .push(araphor_data::DiscoveryHistoryRowV1 {
            result_id: "sealed-prior".into(),
            commit_revision: 4,
            notice_facts_revision: 0,
            notice_coverage_revision: 0,
            compatible: true,
            interval_id: "sealed-interval".into(),
            profile_revision: 2,
            facts_revision: 0,
            coverage_revision: 0,
            created_utc_ns: 1,
            updated_utc_ns: 2,
            input_bytes: original.input_bytes,
            incomplete: false,
            gaps: Vec::new(),
            context_refs: Vec::new(),
            snapshot: original.snapshot.clone(),
        });
    live.resolved = true;
    let prior = live.state.history.clone();
    let repaired = live.query(true).await?.remove(0);
    assert!(repaired.repair);
    assert!(!repaired.notice_only);
    assert_eq!(repaired.current_result_id.as_deref(), Some("sealed-prior"));
    assert_eq!(repaired.result_commit_revision, Some(4));
    assert_eq!(repaired.input_bytes, original.input_bytes);
    assert_eq!(
        (
            repaired.snapshot.accepted_records,
            repaired.snapshot.included_records,
            repaired.snapshot.unresolved_records
        ),
        (3, 3, 0)
    );
    assert_eq!(repaired.facts_revision, 7);
    assert_eq!(live.state.current_result_id.as_deref(), Some("new-head"));
    assert_eq!(live.state.consumed_cursor, Some(3));
    assert_eq!(live.state.history, prior);
    live.state.history[0].notice_facts_revision = 7;
    live.target_revision = 8;
    let target = live.query(false).await?.remove(0);
    assert!(target.repair && !target.notice_only);
    assert_eq!(target.facts_revision, 8);
    assert_eq!(target.snapshot.included_records, 3);
    live.state.history[0].compatible = false;
    let incompatible = live.query(false).await?.remove(0);
    assert!(incompatible.repair && incompatible.notice_only);
    assert_eq!(incompatible.snapshot, original.snapshot);
    assert_eq!(incompatible.facts_revision, 0);
    assert_eq!(incompatible.notice_facts_revision, 8);
    live.state.history[0].compatible = true;
    live.records.records.remove(1);
    let missing = live.query(false).await?.remove(0);
    assert!(missing.repair && missing.notice_only);
    assert_eq!(missing.snapshot, original.snapshot);
    live.state.history[0].notice_facts_revision = 8;
    assert!(live.query(false).await?.is_empty());
    Ok(())
}
