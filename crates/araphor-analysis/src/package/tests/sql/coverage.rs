use araphor_data::{CoverageCounters, CoverageInterval};
use datafusion::arrow::array::ListArray;
use datafusion::arrow::util::display::array_value_to_string;
use datafusion::common::ScalarValue;
use datafusion::logical_expr::{Expr, ExprSchemable, Operator};

use super::*;

const EVENT_FIELDS: [&str; 11] = [
    "tenant_id",
    "node_id",
    "node_boot_id",
    "label_epoch",
    "source_id",
    "source_epoch",
    "cpu_id",
    "source_cursor",
    "coverage_interval_id",
    "temporal_coverage",
    "kernel_sequence",
];

const REPORT_FIELDS: [&str; 31] = [
    "tenant_id",
    "node_id",
    "node_boot_id",
    "label_epoch",
    "source_id",
    "source_epoch",
    "cpu_id",
    "coverage_revision",
    "kind",
    "state",
    "interval_id",
    "interval_source_epoch",
    "first_sequence",
    "last_sequence",
    "gap_reasons",
    "opening_attempted",
    "opening_suppressed",
    "opening_requested",
    "opening_emitted",
    "opening_lost",
    "opening_classifier_miss_count",
    "opening_unresolved",
    "opening_next_sequence",
    "closing_attempted",
    "closing_suppressed",
    "closing_requested",
    "closing_emitted",
    "closing_lost",
    "closing_classifier_miss_count",
    "closing_unresolved",
    "closing_next_sequence",
];

#[derive(Clone)]
struct Event {
    tenant: u8,
    node: &'static str,
    boot: u8,
    label: u64,
    source: u8,
    epoch: u64,
    cpu: u32,
    cursor: u64,
    interval: Vec<u8>,
    temporal: i32,
    sequence: Option<u64>,
}

impl Default for Event {
    fn default() -> Self {
        Self {
            tenant: 1,
            node: "node",
            boot: 2,
            label: 1,
            source: 3,
            epoch: 1,
            cpu: 0,
            cursor: 1,
            interval: vec![255; 16],
            temporal: 1,
            sequence: Some(1),
        }
    }
}

impl Event {
    fn value(&self, name: &str) -> ScalarValue {
        match name {
            "tenant_id" => ScalarValue::Binary(Some(vec![self.tenant; 16])),
            "node_id" => ScalarValue::Utf8(Some(self.node.into())),
            "node_boot_id" => ScalarValue::Binary(Some(vec![self.boot; 16])),
            "label_epoch" => ScalarValue::UInt64(Some(self.label)),
            "source_id" => ScalarValue::Binary(Some(vec![self.source; 16])),
            "source_epoch" => ScalarValue::UInt64(Some(self.epoch)),
            "cpu_id" => ScalarValue::UInt32(Some(self.cpu)),
            "source_cursor" => ScalarValue::UInt64(Some(self.cursor)),
            "coverage_interval_id" => ScalarValue::Binary(Some(self.interval.clone())),
            "temporal_coverage" => ScalarValue::Int32(Some(self.temporal)),
            "kernel_sequence" => ScalarValue::UInt64(self.sequence),
            _ => unreachable!("event fixture field"),
        }
    }
}

#[derive(Clone)]
struct Report {
    event: Event,
    revision: u64,
    interval: Option<CoverageInterval>,
}

impl Report {
    fn new(event: &Event) -> Self {
        Self {
            event: event.clone(),
            revision: 7,
            interval: Some(CoverageInterval {
                interval_id: event.interval.clone(),
                source_epoch: event.epoch,
                revision: 1,
                state: "HEALTHY".into(),
                first_sequence: 1,
                last_sequence: Some(10),
                opening_counters: Some(Default::default()),
                closing_counters: Some(CoverageCounters {
                    attempted: 10,
                    requested: 10,
                    emitted: 10,
                    next_sequence: 11,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    fn value(&self, name: &str, interval: Option<&CoverageInterval>) -> ScalarValue {
        match name {
            "tenant_id" | "node_id" | "node_boot_id" | "label_epoch" | "source_id"
            | "source_epoch" | "cpu_id" => self.event.value(name),
            "coverage_revision" => ScalarValue::UInt64(Some(self.revision)),
            "kind" => ScalarValue::Utf8(Some(
                if interval.is_some() {
                    "interval"
                } else {
                    "receipt"
                }
                .into(),
            )),
            "state" => ScalarValue::Utf8(Some(
                interval
                    .map_or("reported", |value| value.state.as_str())
                    .into(),
            )),
            "interval_id" => ScalarValue::Binary(interval.map(|value| value.interval_id.clone())),
            "interval_source_epoch" => {
                ScalarValue::UInt64(interval.map(|value| value.source_epoch))
            }
            "first_sequence" => ScalarValue::UInt64(interval.map(|value| value.first_sequence)),
            "last_sequence" => ScalarValue::UInt64(interval.and_then(|value| value.last_sequence)),
            "gap_reasons" => ScalarValue::Utf8(interval.map(|value| value.gap_reasons.join(","))),
            _ => {
                let (counter, name) = if let Some(name) = name.strip_prefix("opening_") {
                    (
                        interval.and_then(|value| value.opening_counters.as_ref()),
                        name,
                    )
                } else {
                    (
                        interval.and_then(|value| value.closing_counters.as_ref()),
                        name.strip_prefix("closing_").unwrap(),
                    )
                };
                ScalarValue::UInt64(counter.map(|value| match name {
                    "attempted" => value.attempted,
                    "suppressed" => value.suppressed,
                    "requested" => value.requested,
                    "emitted" => value.emitted,
                    "lost" => value.lost,
                    "classifier_miss_count" => value.classifier_miss_count,
                    "unresolved" => value.unresolved,
                    "next_sequence" => value.next_sequence,
                    _ => unreachable!("coverage fixture counter"),
                }))
            }
        }
    }
}

impl Fixture {
    fn coverage_schema(name: &str, fields: &[&str]) -> Result<Arc<Schema>> {
        let canonical = &araphor_data::AnalysisStore::table_schemas()[name];
        let fields = fields
            .iter()
            .map(|name| canonical.field_with_name(name).cloned())
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Arc::new(Schema::new(fields)))
    }

    fn coverage_tables(&self, events: &[Event], reports: &[Report], split: bool) -> Result<()> {
        let event_schema = Self::coverage_schema("events", &EVENT_FIELDS)?;
        let event_rows: Vec<Vec<ScalarValue>> = events
            .iter()
            .map(|event| EVENT_FIELDS.iter().map(|name| event.value(name)).collect())
            .collect();
        let report_schema = Self::coverage_schema("coverage", &REPORT_FIELDS)?;
        let report_rows: Vec<Vec<ScalarValue>> = reports
            .iter()
            .flat_map(|report| {
                std::iter::once(None)
                    .chain(report.interval.iter().map(Some))
                    .map(move |interval| {
                        REPORT_FIELDS
                            .iter()
                            .map(|name| report.value(name, interval))
                            .collect()
                    })
            })
            .collect();
        for (name, schema, mut rows) in [
            ("events", event_schema, event_rows),
            ("coverage", report_schema, report_rows),
        ] {
            let partitions = if split && !rows.is_empty() {
                rows.reverse();
                rows.into_iter()
                    .map(|row| {
                        Self::coverage_batch(Arc::clone(&schema), &[row]).map(|batch| vec![batch])
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                vec![vec![Self::coverage_batch(Arc::clone(&schema), &rows)?]]
            };
            let _previous = self.context.deregister_table(name)?;
            self.context
                .register_table(name, Arc::new(MemTable::try_new(schema, partitions)?))?;
        }
        Ok(())
    }

    fn coverage_batch(schema: Arc<Schema>, rows: &[Vec<ScalarValue>]) -> Result<RecordBatch> {
        if rows.is_empty() {
            return Ok(RecordBatch::new_empty(schema));
        }
        let columns = (0..schema.fields().len())
            .map(|index| ScalarValue::iter_to_array(rows.iter().map(|row| row[index].clone())))
            .collect::<Result<Vec<_>>>()?;
        Ok(RecordBatch::try_new(schema, columns)?)
    }

    async fn coverage_query(&self, sql: &str) -> Result<RecordBatch> {
        let dataframe = self.context.sql(sql).await?;
        dataframe.logical_plan().apply(|plan| {
            assert!(!matches!(plan, LogicalPlan::Extension(_)));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let schema = Arc::new(dataframe.schema().as_arrow().clone());
        let physical = dataframe.create_physical_plan().await?;
        physical.apply(|plan| {
            assert!(!plan.name().contains("Discovery") && !plan.name().contains("Package"));
            Ok(TreeNodeRecursion::Continue)
        })?;
        let batches = datafusion::physical_plan::collect(physical, self.context.task_ctx()).await?;
        Ok(concat_batches(&schema, &batches)?)
    }

    async fn coverage(
        &self,
        events: &[Event],
        reports: &[Report],
        split: bool,
    ) -> Result<RecordBatch> {
        self.coverage_tables(events, reports, split)?;
        self.view("coverage_ranges", COVERAGE_RANGES_SQL).await?;
        self.coverage_query("SELECT * FROM discovery.coverage_ranges ORDER BY tenant_id,node_id,node_boot_id,label_epoch,source_id,source_epoch,cpu_id,first_cursor").await
    }
}

fn cells(batch: &RecordBatch, name: &str) -> Result<Vec<String>> {
    let column = batch.column_by_name(name).unwrap();
    (0..batch.num_rows())
        .map(|index| Ok(array_value_to_string(column.as_ref(), index)?))
        .collect()
}

fn reasons(batch: &RecordBatch, row: usize) -> Result<Vec<String>> {
    let values = batch
        .column_by_name("gap_reasons")
        .unwrap()
        .as_any()
        .downcast_ref::<ListArray>()
        .unwrap()
        .value(row);
    (0..values.len())
        .map(|index| Ok(array_value_to_string(values.as_ref(), index)?))
        .collect()
}

#[tokio::test]
async fn boundary_operands_are_boolean() -> Result<()> {
    let fixture = Fixture::new()?;
    let event = Event::default();
    fixture.coverage_tables(std::slice::from_ref(&event), &[Report::new(&event)], false)?;
    fixture.view("coverage_ranges", COVERAGE_RANGES_SQL).await?;
    let plan = fixture
        .context
        .state()
        .create_logical_plan("SELECT * FROM discovery.coverage_ranges")
        .await?;
    let mut disjunctions = 0;
    plan.apply(|plan| {
        for expression in plan.expressions() {
            expression.apply(|expression| {
                let Expr::BinaryExpr(binary) = expression else {
                    return Ok(TreeNodeRecursion::Continue);
                };
                if binary.op != Operator::Or {
                    return Ok(TreeNodeRecursion::Continue);
                }
                for operand in [&binary.left, &binary.right] {
                    let datatype = operand.get_type(plan.schema())?;
                    assert!(
                        matches!(datatype, DataType::Boolean | DataType::Null),
                        "{expression}: {datatype}"
                    );
                }
                disjunctions += 1;
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(TreeNodeRecursion::Continue)
    })?;
    assert!(disjunctions > 0);
    Ok(())
}

#[tokio::test]
async fn coverage_states_match() -> Result<()> {
    let fixture = Fixture::new()?;
    for (case, expected, reason) in [
        ("healthy", "HEALTHY", ""),
        ("closed", "CLOSED", ""),
        ("state gap", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("reason gap", "GAPPED", "RING_LOSS,DECODER_ERROR"),
        ("unknown state", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("missing opening", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("missing closing", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("missing last", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("opening sequence", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("closing sequence", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("counter mismatch", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("lost", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("suppressed", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("unresolved", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("classifier", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("attempted regression", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("requested regression", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("emitted regression", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("sequence regression", "GAPPED", "SOURCE_COVERAGE_GAPPED"),
        ("no sequence", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("before sequence", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("after sequence", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("last sequence", "HEALTHY", ""),
        ("temporal unknown", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("temporal gap", "UNKNOWN", "COVERAGE_UNQUALIFIED"),
        ("interval epoch", "UNKNOWN", "MISSING_COVERAGE_REPORT"),
        ("missing interval", "UNKNOWN", "MISSING_COVERAGE_REPORT"),
        ("missing report", "UNKNOWN", "MISSING_COVERAGE_REPORT"),
    ] {
        let mut event = Event::default();
        let mut report = Report::new(&event);
        let interval = report.interval.as_mut().unwrap();
        match case {
            "healthy" => {}
            "closed" => interval.state = "CLOSED".into(),
            "state gap" => interval.state = "GAPPED".into(),
            "reason gap" => interval.gap_reasons = vec!["RING_LOSS".into(), "DECODER_ERROR".into()],
            "unknown state" => interval.state = "UNKNOWN".into(),
            "missing opening" => interval.opening_counters = None,
            "missing closing" => interval.closing_counters = None,
            "missing last" => interval.last_sequence = None,
            "opening sequence" => interval.opening_counters.as_mut().unwrap().next_sequence = 2,
            "closing sequence" => interval.closing_counters.as_mut().unwrap().next_sequence = 9,
            "counter mismatch" => interval.closing_counters.as_mut().unwrap().requested = 11,
            "lost" => interval.closing_counters.as_mut().unwrap().lost = 1,
            "suppressed" => interval.closing_counters.as_mut().unwrap().suppressed = 1,
            "unresolved" => interval.closing_counters.as_mut().unwrap().unresolved = 1,
            "classifier" => {
                interval
                    .closing_counters
                    .as_mut()
                    .unwrap()
                    .classifier_miss_count = 1
            }
            "attempted regression" => interval.opening_counters.as_mut().unwrap().attempted = 11,
            "requested regression" => interval.opening_counters.as_mut().unwrap().requested = 11,
            "emitted regression" => interval.opening_counters.as_mut().unwrap().emitted = 11,
            "sequence regression" => interval.opening_counters.as_mut().unwrap().next_sequence = 12,
            "no sequence" => event.sequence = None,
            "before sequence" => {
                interval.first_sequence = 2;
                event.sequence = Some(1);
            }
            "after sequence" => event.sequence = Some(11),
            "last sequence" => event.sequence = Some(10),
            "temporal unknown" => event.temporal = 0,
            "temporal gap" => event.temporal = 2,
            "interval epoch" => interval.source_epoch += 1,
            "missing interval" => report.interval = None,
            "missing report" => {
                report.interval = None;
                report.revision = 0;
            }
            _ => unreachable!("coverage state case"),
        }
        let result = fixture.coverage(&[event], &[report], false).await?;
        assert_eq!(cells(&result, "state")?, [expected], "{case}");
        assert_eq!(reasons(&result, 0)?.join(","), reason, "{case}");
        assert_eq!(
            cells(&result, "coverage_revision")?,
            [if case == "missing report" { "0" } else { "7" }]
        );
        assert_eq!(
            result.schema().field_with_name("state")?.data_type(),
            &DataType::Utf8
        );
        assert_eq!(
            result
                .schema()
                .field_with_name("expected_records")?
                .data_type(),
            &DataType::UInt64
        );
    }
    Ok(())
}

#[tokio::test]
async fn overflow_cannot_prove_coverage() -> Result<()> {
    let fixture = Fixture::new()?;
    let event = Event::default();
    for case in ["attempted", "requested"] {
        let mut report = Report::new(&event);
        let interval = report.interval.as_mut().unwrap();
        let counters = match case {
            "attempted" => CoverageCounters {
                attempted: 0,
                suppressed: 1,
                requested: u64::MAX,
                emitted: u64::MAX,
                ..Default::default()
            },
            _ => CoverageCounters {
                attempted: 1,
                suppressed: 1,
                requested: 0,
                emitted: u64::MAX,
                lost: 1,
                ..Default::default()
            },
        };
        interval.opening_counters = Some(counters);
        interval.closing_counters = Some(CoverageCounters {
            next_sequence: 11,
            ..interval.opening_counters.unwrap()
        });
        assert!(!interval.has_gap());
        assert!(!interval.is_complete());
        let result = fixture
            .coverage(std::slice::from_ref(&event), &[report], false)
            .await?;
        assert_eq!(cells(&result, "state")?, ["UNKNOWN"], "{case}");
        assert_eq!(reasons(&result, 0)?, ["COVERAGE_UNQUALIFIED"]);
    }
    let mut event = event;
    event.cursor = u64::MAX - 1;
    event.sequence = Some(u64::MAX - 1);
    let mut next = event.clone();
    next.cursor = u64::MAX;
    let mut report = Report::new(&event);
    let interval = report.interval.as_mut().unwrap();
    interval.first_sequence = u64::MAX - 1;
    interval.last_sequence = Some(u64::MAX - 1);
    interval.opening_counters = Some(CoverageCounters {
        attempted: u64::MAX,
        requested: u64::MAX,
        emitted: u64::MAX,
        next_sequence: u64::MAX - 1,
        ..Default::default()
    });
    interval.closing_counters = Some(CoverageCounters {
        next_sequence: u64::MAX,
        ..interval.opening_counters.unwrap()
    });
    assert!(interval.is_complete());
    let result = fixture.coverage(&[event, next], &[report], true).await?;
    assert_eq!(cells(&result, "state")?, ["HEALTHY"]);
    assert_eq!(
        cells(&result, "first_cursor")?,
        [(u64::MAX - 1).to_string()]
    );
    assert_eq!(cells(&result, "last_cursor")?, [u64::MAX.to_string()]);
    assert_eq!(cells(&result, "expected_records")?, ["2"]);
    Ok(())
}

#[tokio::test]
async fn ranges_keep_source_identity() -> Result<()> {
    let fixture = Fixture::new()?;
    let mut events = vec![Event::default(); 8];
    events[1].tenant = 4;
    events[2].node = "other";
    events[3].boot = 5;
    events[4].label = 2;
    events[5].source = 6;
    events[6].epoch = 2;
    events[7].cpu = 1;
    let reports = events.iter().map(Report::new).collect::<Vec<_>>();
    let whole = fixture.coverage(&events, &reports, false).await?;
    let split = fixture.coverage(&events, &reports, true).await?;
    assert_eq!(whole, split);
    assert_eq!(split.num_rows(), 8);
    assert_eq!(cells(&split, "state")?, vec!["HEALTHY"; 8]);
    assert_eq!(cells(&split, "expected_records")?, vec!["1"; 8]);
    for column in &EVENT_FIELDS[..7] {
        assert_eq!(split.column_by_name(column).unwrap().null_count(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn batches_preserve_cursor_holes() -> Result<()> {
    let fixture = Fixture::new()?;
    let events = [1, 2, 4, 5, 6].map(|cursor| Event {
        cursor,
        sequence: (cursor != 5).then_some(cursor),
        ..Default::default()
    });
    let report = Report::new(&events[0]);
    let whole = fixture
        .coverage(&events, std::slice::from_ref(&report), false)
        .await?;
    let split = fixture.coverage(&events, &[report], true).await?;
    assert_eq!(whole, split);
    assert_eq!(cells(&split, "first_cursor")?, ["1", "4", "5", "6"]);
    assert_eq!(cells(&split, "last_cursor")?, ["2", "4", "5", "6"]);
    assert_eq!(cells(&split, "expected_records")?, ["2", "1", "1", "1"]);
    assert_eq!(
        cells(&split, "state")?,
        ["HEALTHY", "HEALTHY", "UNKNOWN", "HEALTHY"]
    );
    assert_eq!(fixture.coverage(&[], &[], true).await?.num_rows(), 0);
    Ok(())
}

#[tokio::test]
async fn interval_bytes_keep_fallback() -> Result<()> {
    let fixture = Fixture::new()?;
    for length in [0, 15, 16, 17] {
        let event = Event {
            interval: vec![255; length],
            ..Default::default()
        };
        let result = fixture.coverage(&[event], &[], false).await?;
        let interval = result
            .column_by_name("coverage_interval_id")
            .unwrap()
            .as_any()
            .downcast_ref::<BinaryArray>()
            .unwrap();
        assert_eq!(
            interval.value(0),
            if length == 16 { &[255; 16] } else { &[3; 16] }
        );
        assert_eq!(cells(&result, "state")?, ["UNKNOWN"]);
        assert_eq!(cells(&result, "coverage_revision")?, ["0"]);
    }
    Ok(())
}

#[tokio::test]
async fn sql_keeps_cte_scope() -> Result<()> {
    let fixture = Fixture::new()?;
    let event = Event::default();
    fixture.coverage_tables(std::slice::from_ref(&event), &[Report::new(&event)], true)?;
    let sql = format!(
        "WITH records AS (SELECT * FROM events), reports AS (SELECT * FROM coverage), \
        qualified AS (SELECT * FROM records), previous AS (SELECT * FROM reports), \
        marked AS (SELECT * FROM qualified), ranges AS (SELECT * FROM previous) \
        SELECT * FROM (WITH events AS (SELECT * FROM marked), coverage AS (SELECT * FROM ranges) \
        {}) AS result",
        query(COVERAGE_RANGES_SQL)?
    );
    let result = fixture.coverage_query(&sql).await?;
    assert_eq!(cells(&result, "state")?, ["HEALTHY"]);
    assert_eq!(cells(&result, "expected_records")?, ["1"]);
    Ok(())
}

#[tokio::test]
async fn coverage_includes_assigned_tail() -> Result<()> {
    let fixture = Fixture::new()?;
    for last in [10, u64::MAX] {
        for state in ["HEALTHY", "CLOSED"] {
            for case in ["exact", "stale", "accounting"] {
                let event = Event {
                    sequence: Some(last),
                    ..Default::default()
                };
                let mut report = Report::new(&event);
                let interval = report.interval.as_mut().unwrap();
                interval.state = state.into();
                interval.first_sequence = last;
                interval.last_sequence = Some(last);
                interval.opening_counters = Some(CoverageCounters {
                    attempted: last - 1,
                    requested: last - 1,
                    emitted: last - 1,
                    next_sequence: last - 1,
                    ..Default::default()
                });
                interval.closing_counters = Some(CoverageCounters {
                    attempted: last,
                    requested: last,
                    emitted: last,
                    next_sequence: last,
                    ..Default::default()
                });
                match case {
                    "stale" => interval.closing_counters.as_mut().unwrap().next_sequence = last - 1,
                    "accounting" => {
                        interval.closing_counters.as_mut().unwrap().attempted = last - 1
                    }
                    _ => {}
                }
                let complete = interval.is_complete();
                let result = fixture.coverage(&[event], &[report], false).await?;
                let expected = if case == "exact" { state } else { "UNKNOWN" };
                assert_eq!(
                    (cells(&result, "state")?, complete),
                    (vec![expected.to_string()], case == "exact"),
                    "{last} {state} {case}"
                );
                assert_eq!(
                    reasons(&result, 0)?,
                    if case == "exact" {
                        Vec::<String>::new()
                    } else {
                        vec!["COVERAGE_UNQUALIFIED".into()]
                    },
                    "{last} {state} {case}"
                );
            }
        }
    }
    Ok(())
}
