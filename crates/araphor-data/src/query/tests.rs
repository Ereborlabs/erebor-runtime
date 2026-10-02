use std::ops::Bound;

use prost::Message as _;

use super::*;
use crate::{
    evidence::EvidenceRecord, AnalysisSelectionV1, EvidenceIntakeIdentityV1,
    ValidatedEvidenceBatchV1,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub(super) struct QueryFixture {
    pub(super) store: Arc<AnalysisStore>,
    pub(super) source: EvidenceIntakeIdentityV1,
    _directory: tempfile::TempDir,
}

impl QueryFixture {
    pub(super) fn root(&self) -> std::path::PathBuf {
        self._directory.path().join("analysis")
    }

    pub(super) fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        Ok(Self {
            store: Arc::new(AnalysisStore::open(directory.path().join("analysis"))?),
            source: EvidenceIntakeIdentityV1 {
                tenant_id: [1; 16],
                node_id: "query-node".into(),
                node_boot_id: [2; 16],
                label_epoch: 1,
                source_id: [3; 16],
                source_epoch: 1,
            },
            _directory: directory,
        })
    }

    pub(super) fn commit(
        &self,
        cursor: u64,
        received_ns: u64,
        record: EvidenceRecord,
    ) -> TestResult {
        self.commit_as(&self.source, 0, cursor, received_ns, record)
    }

    fn commit_as(
        &self,
        source: &EvidenceIntakeIdentityV1,
        cpu_id: u32,
        cursor: u64,
        received_ns: u64,
        record: EvidenceRecord,
    ) -> TestResult {
        let payload = record.encode_to_vec();
        let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        self.store.accept_validated_batch(
            source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: received_ns,
                frame_ends: vec![frame.len()],
                framed_records: frame.into(),
            },
        )?;
        Ok(())
    }

    pub(super) fn event(&self, cursor: u64, received_ns: u64, operation: u32) -> TestResult {
        self.commit(
            cursor,
            received_ns,
            EvidenceRecord {
                operation,
                ..Default::default()
            },
        )
    }

    pub(super) fn plan(&self, template: QueryTemplate) -> Result<QueryPlan> {
        QueryPlan::new(
            AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()]),
            template,
        )
    }

    pub(super) fn owner(&self, limits: QueryLimits) -> Result<QueryOwner> {
        QueryOwner::new(self.store.clone(), limits)
    }

    fn baseline(&self, plan: &QueryPlan, now_ns: u64) -> TestResult<Vec<Vec<Value>>> {
        use super::adapter::{InputColumn, InputTable};

        let mut selection = plan.selection.clone();
        selection.received_from = Bound::Unbounded;
        selection.received_until = Bound::Unbounded;
        let (template, relation) = match &plan.template {
            QueryTemplate::ContextVersions | QueryTemplate::RevisionDifference => {
                (QueryTemplate::ContextVersions, "context_versions")
            }
            QueryTemplate::Coverage => (QueryTemplate::Coverage, "coverage"),
            QueryTemplate::Catalog => (QueryTemplate::Catalog, "catalog"),
            _ => (QueryTemplate::Events { operation: None }, "events"),
        };
        let result = self
            .owner(QueryLimits::default())?
            .query_at(&QueryPlan::new(selection, template)?, now_ns)?;
        assert!(!result.limited);
        let schema = input::SCHEMAS
            .iter()
            .find(|schema| schema.name == relation)
            .ok_or("input schema absent")?;
        let input = Arc::new(InputTable {
            columns: schema
                .columns
                .iter()
                .map(|field| InputColumn(field.0, field.1))
                .collect(),
            rows: result.rows,
            ..Default::default()
        });
        let config = Config::default()
            .enable_external_access(false)?
            .enable_autoload_extension(false)?
            .threads(1)?;
        let connection = Connection::open_in_memory_with_flags(config)?;
        input.register(&connection, "baseline_rows", relation)?;
        let mut statement = connection.prepare(&plan.sql())?;
        let parameters = plan.parameters(now_ns);
        let mut rows = statement.query(params_from_iter(parameters.iter()))?;
        let mut output = Vec::new();
        while let Some(row) = rows.next()? {
            output.push(
                (0..row.as_ref().column_count())
                    .map(|index| row.get(index))
                    .collect::<duckdb::Result<Vec<Value>>>()?,
            );
        }
        Ok(output)
    }
}

#[test]
fn query_input_exact_time() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1_000_000_001, 7)?;
    fixture.event(2, 1_000_000_002, u32::MAX)?;
    fixture.event(3, 1_000_000_003, 7)?;
    let owner = fixture.owner(QueryLimits::default())?;
    let mut selection =
        AnalysisSelectionV1::new(fixture.source.tenant_id, vec![fixture.source.clone()]);
    selection.received_from = Bound::Excluded(1_000_000_001);
    selection.received_until = Bound::Included(1_000_000_002);
    let plan = QueryPlan::new(selection, QueryTemplate::Events { operation: None })?;
    let result = owner.query_at(&plan, 0)?;
    assert_eq!(result.rows.len(), 1);
    let index = |name| {
        result
            .columns
            .iter()
            .position(|column| column == name)
            .ok_or("column absent")
    };
    assert_eq!(result.rows[0][index("operation")?], Value::UInt(u32::MAX));
    assert_eq!(
        result.rows[0][index("received_utc_ns")?],
        Value::UBigInt(1_000_000_002)
    );
    assert_eq!(
        result.rows[0][index("received_at")?],
        Value::Timestamp(duckdb::types::TimeUnit::Microsecond, 1_000_000)
    );
    assert_eq!(result.rows[0][index("kernel_sequence")?], Value::Null);
    assert_eq!(result.sources[0].receipt.contiguous_cursor, 3);
    assert!(!result.limited);
    assert_eq!(result.rows, fixture.baseline(&plan, 0)?);
    let filtered = fixture.plan(QueryTemplate::Events { operation: Some(7) })?;
    assert_eq!(
        owner.query_at(&filtered, 0)?.rows,
        fixture.baseline(&filtered, 0)?
    );
    Ok(())
}

#[test]
fn query_input_windows() -> TestResult {
    let fixture = QueryFixture::new()?;
    let minute = 60_000_000_000_u64;
    for (cursor, time) in [(1, 601), (2, 604), (3, 607)] {
        fixture.event(cursor, time * minute, 7)?;
    }
    let owner = fixture.owner(QueryLimits::default())?;
    let moving = fixture.plan(QueryTemplate::MovingCount { seconds: 300 })?;
    for (time, count) in [(608, 2), (610, 1)] {
        let result = owner.query_at(&moving, time * minute)?;
        assert_eq!(result.rows, vec![vec![Value::BigInt(count)]]);
        assert_eq!(result.rows, fixture.baseline(&moving, time * minute)?);
    }
    let mut selection = moving.selection.clone();
    selection.received_from = Bound::Included(600 * minute);
    selection.received_until = Bound::Excluded(610 * minute);
    let buckets = QueryPlan::new(selection, QueryTemplate::FixedBuckets { seconds: 300 })?;
    let result = owner.query_at(&buckets, 610 * minute)?;
    assert_eq!(
        result.rows,
        vec![
            vec![
                Value::Timestamp(
                    duckdb::types::TimeUnit::Microsecond,
                    (600 * minute / 1_000) as i64
                ),
                Value::BigInt(2)
            ],
            vec![
                Value::Timestamp(
                    duckdb::types::TimeUnit::Microsecond,
                    (605 * minute / 1_000) as i64
                ),
                Value::BigInt(1)
            ],
        ]
    );
    assert_eq!(result.rows, fixture.baseline(&buckets, 610 * minute)?);
    fixture.event(4, 605 * minute, 7)?;
    let result = owner.query_at(&buckets, 610 * minute)?;
    assert_eq!(result.rows[0][1], Value::BigInt(2));
    assert_eq!(result.rows[1][1], Value::BigInt(2));
    assert_eq!(result.rows, fixture.baseline(&buckets, 610 * minute)?);
    fixture.commit(
        5,
        620 * minute,
        EvidenceRecord {
            operation: 7,
            ingested_utc_ns: (604 * minute) as i64,
            ..Default::default()
        },
    )?;
    let all = fixture.plan(QueryTemplate::FixedBuckets { seconds: 300 })?;
    let result = owner.query_at(&all, 620 * minute)?;
    assert_eq!(
        result.rows[2],
        vec![
            Value::Timestamp(
                duckdb::types::TimeUnit::Microsecond,
                (620 * minute / 1_000) as i64
            ),
            Value::BigInt(1)
        ]
    );
    assert_eq!(result.rows, fixture.baseline(&all, 620 * minute)?);
    Ok(())
}

#[test]
fn query_scope_plan_binding() -> TestResult {
    let fixture = QueryFixture::new()?;
    let plan = fixture.plan(QueryTemplate::Events { operation: Some(7) })?;
    let binding = plan.binding()?;
    assert_eq!(plan.clone().binding()?, binding);
    assert_ne!(
        fixture
            .plan(QueryTemplate::Events { operation: Some(8) })?
            .binding()?,
        binding
    );
    let mut selection = plan.selection.clone();
    selection.received_from = Bound::Included(0);
    assert_ne!(
        QueryPlan::new(selection, plan.template.clone())?.binding()?,
        binding
    );
    let mut selection = plan.selection.clone();
    selection.sources[0].source_epoch += 1;
    assert_ne!(
        QueryPlan::new(selection, plan.template.clone())?.binding()?,
        binding
    );
    let mut selection = plan.selection.clone();
    selection.sources[0].tenant_id = [9; 16];
    assert!(QueryPlan::new(selection, plan.template.clone()).is_err());
    assert!(fixture
        .plan(QueryTemplate::MovingCount { seconds: 0 })
        .is_err());
    assert!(fixture
        .plan(QueryTemplate::MovingCount { seconds: 86_401 })
        .is_err());
    assert!(fixture
        .plan(QueryTemplate::FixedBuckets { seconds: 0 })
        .is_err());
    Ok(())
}

#[test]
fn query_input_output_bounds() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 1, 7)?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let owner = fixture.owner(QueryLimits::default())?;
    let result = owner.query_at(&plan, 0)?;
    let (input_bytes, output_bytes, scan_bytes) = (
        result.input_bytes,
        result.output_bytes,
        result.scanned_bytes,
    );
    drop(result);
    for (field, limit) in [
        ("input", input_bytes),
        ("output", output_bytes),
        ("scan", scan_bytes),
    ] {
        for excess in [false, true] {
            let mut limits = QueryLimits::default();
            let value = limit - usize::from(excess);
            match field {
                "input" => limits.input_bytes = value,
                "output" => limits.output_bytes = value,
                _ => limits.scan_bytes = value,
            }
            let owner = fixture.owner(limits)?;
            let result = owner.query_at(&plan, 0);
            assert_eq!(result.is_err(), excess, "{field} bound {value}: {result:?}");
        }
    }
    fixture.event(2, 2, 8)?;
    let owner = fixture.owner(QueryLimits {
        output_rows: 1,
        ..QueryLimits::default()
    })?;
    let result = owner.query_at(&plan, 0)?;
    assert_eq!(result.rows.len(), 1);
    assert!(result.limited);
    drop(result);
    assert!(owner
        .query_at(&fixture.plan(QueryTemplate::OperationCounts)?, 0)
        .is_err());
    fixture.event(3, 3, 7)?;
    assert_eq!(
        fixture
            .store
            .source_receipt(&fixture.source)?
            .ok_or("receipt absent")?
            .contiguous_cursor,
        3
    );
    assert!(owner
        .query_at(&fixture.plan(QueryTemplate::MovingCount { seconds: 1 })?, 3)
        .is_ok());
    Ok(())
}

#[test]
fn query_follow_append_pages() -> TestResult {
    let fixture = QueryFixture::new()?;
    for (cursor, operation) in [(1, 9), (2, 7), (3, 9), (4, 7), (5, 7), (6, 9)] {
        fixture.event(cursor, cursor, operation)?;
    }
    let owner = fixture.owner(QueryLimits {
        output_rows: 1,
        ..QueryLimits::default()
    })?;
    let plan = fixture.plan(QueryTemplate::Events { operation: Some(7) })?;
    let mut after = None;
    let mut cursors = Vec::new();
    for expected in [2_u64, 4, 5] {
        let result = owner.evaluate(&plan, 6, after, true, &AnalysisReadControl::default())?;
        let column = result
            .columns
            .iter()
            .position(|name| name == "source_cursor")
            .ok_or("cursor absent")?;
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][column], Value::UBigInt(expected));
        cursors.push(expected);
        after = Some(result.scanned_through);
        assert_eq!(result.exhausted, expected == 5);
    }
    assert_eq!(cursors, vec![2, 4, 5]);
    let result = owner.evaluate(&plan, 6, after, true, &AnalysisReadControl::default())?;
    assert!(result.rows.is_empty());
    assert!(result.exhausted);
    Ok(())
}

#[test]
fn query_scope_bounded_history() -> TestResult {
    let fixture = QueryFixture::new()?;
    for cursor in 1..=20 {
        fixture.event(cursor, cursor * 1_000, 7)?;
    }
    let mut plan = fixture.plan(QueryTemplate::OperationCounts)?;
    plan.selection.received_from = Bound::Included(19_000);
    let result = fixture
        .owner(QueryLimits::default())?
        .query_at(&plan, 20_000)?;
    let limit = result.scanned_bytes;
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(2)]]);
    assert_eq!(result.rows, fixture.baseline(&plan, 20_000)?);
    drop(result);
    let owner = fixture.owner(QueryLimits {
        scan_bytes: limit,
        ..QueryLimits::default()
    })?;
    assert_eq!(
        owner.query_at(&plan, 20_000)?.rows,
        vec![vec![Value::UInt(7), Value::BigInt(2)]]
    );
    assert!(owner
        .query_at(&fixture.plan(QueryTemplate::OperationCounts)?, 20_000)
        .is_err());
    plan.selection.received_from = Bound::Included(20_000);
    fixture.event(21, 21_000, 7)?;
    let result = owner.query_at(&plan, 21_000)?;
    assert_eq!(result.rows, vec![vec![Value::UInt(7), Value::BigInt(2)]]);
    assert_eq!(result.rows, fixture.baseline(&plan, 21_000)?);
    Ok(())
}

#[test]
fn query_input_exact_match() -> TestResult {
    let fixture = QueryFixture::new()?;
    let object = [5; 16];
    for (cursor, operation, id) in [
        (1, 7, object.to_vec()),
        (2, 7, vec![6; 16]),
        (3, 8, object.to_vec()),
        (4, 7, object.to_vec()),
        (5, 7, Vec::new()),
        (6, 7, object.to_vec()),
        (7, u32::MAX, object.to_vec()),
    ] {
        fixture.commit(
            cursor,
            1_000 + cursor,
            EvidenceRecord {
                operation,
                exact_object_id: id.into(),
                ..Default::default()
            },
        )?;
    }
    for tenant in [[1; 16], [9; 16]] {
        let source = EvidenceIntakeIdentityV1 {
            tenant_id: tenant,
            source_id: [8; 16],
            ..fixture.source.clone()
        };
        fixture.commit_as(
            &source,
            0,
            1,
            1_004,
            EvidenceRecord {
                operation: 7,
                exact_object_id: object.to_vec().into(),
                ..Default::default()
            },
        )?;
    }
    let owner = fixture.owner(QueryLimits::default())?;
    let mut plan = fixture.plan(QueryTemplate::ExactMatch {
        operation: 7,
        object_id: object,
    })?;
    plan.selection.received_from = Bound::Excluded(1_001);
    plan.selection.received_until = Bound::Included(1_006);
    let result = owner.query_at(&plan, 2_000)?;
    let cursor = result
        .columns
        .iter()
        .position(|name| name == "source_cursor")
        .ok_or("cursor absent")?;
    assert_eq!(
        result
            .rows
            .iter()
            .map(|row| row[cursor].clone())
            .collect::<Vec<_>>(),
        vec![Value::UBigInt(4), Value::UBigInt(6)]
    );
    assert_eq!(result.rows, fixture.baseline(&plan, 2_000)?);
    assert_eq!(result.sources.len(), 1);
    assert_eq!(result.sources[0].receipt.identity, fixture.source);
    drop(result);
    for (operation, object_id, expected) in [(7, [6; 16], 2), (u32::MAX, object, 7)] {
        let plan = fixture.plan(QueryTemplate::ExactMatch {
            operation,
            object_id,
        })?;
        let result = owner.query_at(&plan, 2_000)?;
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0][cursor], Value::UBigInt(expected));
        assert_eq!(result.rows, fixture.baseline(&plan, 2_000)?);
    }
    let absent = fixture.plan(QueryTemplate::ExactMatch {
        operation: 8,
        object_id: [6; 16],
    })?;
    assert!(owner.query_at(&absent, 2_000)?.rows.is_empty());
    Ok(())
}

#[test]
fn query_input_subject_sequence() -> TestResult {
    let fixture = QueryFixture::new()?;
    let record =
        |operation, task_cookie, sequence: Option<u64>, temporal_coverage| EvidenceRecord {
            operation,
            task_cookie,
            temporal_coverage,
            decision_context: sequence.map(|original_kernel_sequence| {
                crate::EvidenceDecisionContext {
                    schema_version: 1,
                    original_kernel_sequence,
                    ..Default::default()
                }
            }),
            ..Default::default()
        };
    let owner = fixture.owner(QueryLimits::default())?;
    let mut plan = fixture.plan(QueryTemplate::SubjectSequence {
        first: 10,
        second: 20,
    })?;
    fixture.commit(2, 20, record(20, 11, Some(101), 1))?;
    let pending = owner.query_at(&plan, 30)?;
    assert!(pending.rows.is_empty());
    assert_eq!(pending.sources[0].receipt.contiguous_cursor, 0);
    assert_eq!(pending.sources[0].pending[0].first_cursor, 1);
    assert_eq!(pending.sources[0].pending[0].last_cursor, 1);
    drop(pending);
    fixture.commit(1, 10, record(10, 11, Some(100), 1))?;
    fixture.commit(3, 30, record(10, 22, Some(u64::MAX - 1), 1))?;
    fixture.commit(4, 40, record(20, 22, Some(u64::MAX), 1))?;

    let mut cursor = 5;
    for (task, first_sequence, second_sequence, first_coverage, second_coverage) in [
        (31, Some(0), Some(1), 1, 1),
        (32, Some(10), Some(12), 1, 1),
        (33, Some(10), Some(11), 0, 1),
        (34, Some(10), Some(11), 1, 2),
        (35, Some(10), Some(11), 2, 1),
        (36, None, Some(11), 1, 1),
        (37, Some(10), None, 1, 1),
        (0, Some(10), Some(11), 1, 1),
    ] {
        fixture.commit(
            cursor,
            cursor * 10,
            record(10, task, first_sequence, first_coverage),
        )?;
        fixture.commit(
            cursor + 1,
            (cursor + 1) * 10,
            record(20, task, second_sequence, second_coverage),
        )?;
        cursor += 2;
    }
    fixture.commit(cursor, cursor * 10, record(10, 40, Some(10), 1))?;
    fixture.commit(cursor + 1, (cursor + 1) * 10, record(20, 41, Some(11), 1))?;
    cursor += 2;
    for (operation, sequence) in [(10, 10), (99, 11), (20, 12)] {
        fixture.commit(
            cursor,
            cursor * 10,
            record(operation, 42, Some(sequence), 1),
        )?;
        cursor += 1;
    }
    assert!(fixture
        .commit_as(
            &fixture.source,
            1,
            cursor,
            cursor * 10,
            record(20, 99, Some(101), 1)
        )
        .is_err());
    for change in 0..6 {
        let mut source = fixture.source.clone();
        let cpu_id = match change {
            0 => {
                source.node_id = "other-node".into();
                0
            }
            1 => {
                source.node_boot_id = [4; 16];
                source.source_epoch = 2;
                0
            }
            2 => {
                source.label_epoch = 2;
                source.source_epoch = 3;
                0
            }
            3 => {
                source.source_id = [5; 16];
                0
            }
            4 => {
                source.source_epoch = 4;
                0
            }
            _ => {
                source.source_id = [6; 16];
                1
            }
        };
        let task = 50 + change;
        fixture.commit(cursor, cursor * 10, record(10, task, Some(100), 1))?;
        cursor += 1;
        fixture.commit_as(
            &source,
            cpu_id,
            1,
            cursor * 10,
            record(20, task, Some(101), 1),
        )?;
        plan.selection.sources.push(source);
    }
    let result = owner.query_at(&plan, 1_000)?;
    let cursor = result
        .columns
        .iter()
        .position(|name| name == "source_cursor")
        .ok_or("cursor absent")?;
    let revision = result
        .columns
        .iter()
        .position(|name| name == "commit_revision")
        .ok_or("revision absent")?;
    let task = result
        .columns
        .iter()
        .position(|name| name == "task_cookie")
        .ok_or("task absent")?;
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0][cursor], Value::UBigInt(2));
    assert_eq!(result.rows[0][revision], Value::UBigInt(1));
    assert_eq!(result.rows[0][task], Value::UBigInt(11));
    assert_eq!(result.rows[1][cursor], Value::UBigInt(4));
    assert_eq!(result.rows[1][task], Value::UBigInt(22));
    assert!(result
        .sources
        .iter()
        .all(|source| source.state == QueryCoverageState::Unknown));
    assert_eq!(result.rows, fixture.baseline(&plan, 1_000)?);
    Ok(())
}

#[test]
fn query_scope_revision_difference() -> TestResult {
    let fixture = QueryFixture::new()?;
    let key = crate::AnalysisContextKeyV1 {
        tenant_id: fixture.source.tenant_id,
        owner_id: "policy-owner".into(),
        entity_key: vec![1, 2],
        lifetime_key: vec![3, 4],
        owner_revision: 10,
    };
    let context = |key, body| crate::AnalysisContextVersionV1 {
        key,
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: Some(2),
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body,
    };
    for (revision, body) in [
        (10, b"before".to_vec()),
        (20, b"after".to_vec()),
        (30, b"after".to_vec()),
    ] {
        fixture.store.commit_context(&context(
            crate::AnalysisContextKeyV1 {
                owner_revision: revision,
                ..key.clone()
            },
            body,
        ))?;
    }
    for change in 0..4 {
        let mut other = key.clone();
        match change {
            0 => other.tenant_id = [9; 16],
            1 => other.owner_id = "other-owner".into(),
            2 => other.entity_key.push(9),
            _ => other.lifetime_key.push(9),
        }
        fixture
            .store
            .commit_context(&context(other, b"not selected".to_vec()))?;
    }
    let owner = fixture.owner(QueryLimits::default())?;
    let mut selection = AnalysisSelectionV1::new(fixture.source.tenant_id, Vec::new());
    selection.received_from = Bound::Included(100);
    selection.received_until = Bound::Excluded(200);
    for (left, right, changed) in [(10, 20, true), (20, 30, false), (30, 10, true)] {
        selection.contexts = vec![
            crate::AnalysisContextKeyV1 {
                owner_revision: left,
                ..key.clone()
            },
            crate::AnalysisContextKeyV1 {
                owner_revision: right,
                ..key.clone()
            },
        ];
        let plan = QueryPlan::new(selection.clone(), QueryTemplate::RevisionDifference)?;
        let result = owner.query_at(&plan, 1_000)?;
        assert_eq!(
            result.rows,
            vec![vec![
                Value::UBigInt(left),
                Value::UBigInt(right),
                Value::Boolean(changed)
            ]]
        );
        assert!(result.missing_contexts.is_empty());
        assert_eq!(result.scanned_bytes, 0);
        assert_eq!(result.input_rows, 2);
        assert_eq!(result.rows, fixture.baseline(&plan, 1_000)?);
    }
    selection.contexts[1].owner_revision = 99;
    let missing = selection.contexts[1].clone();
    let plan = QueryPlan::new(selection.clone(), QueryTemplate::RevisionDifference)?;
    let result = owner.query_at(&plan, 1_000)?;
    assert!(result.rows.is_empty());
    assert_eq!(result.missing_contexts, vec![missing.clone()]);
    assert_eq!(result.rows, fixture.baseline(&plan, 1_000)?);
    drop(result);
    let mut versions = selection.clone();
    versions.contexts = [30, 10, 20, 99]
        .into_iter()
        .map(|owner_revision| crate::AnalysisContextKeyV1 {
            owner_revision,
            ..key.clone()
        })
        .collect();
    let versions = QueryPlan::new(versions, QueryTemplate::ContextVersions)?;
    let result = owner.query_at(&versions, 1_000)?;
    assert_eq!(result.rows, fixture.baseline(&versions, 1_000)?);
    assert_eq!(result.missing_contexts, vec![missing]);
    assert_eq!(result.scanned_bytes, 0);
    assert_eq!(result.input_rows, 3);
    assert!(result.sources.is_empty());
    let index = |name| {
        result
            .columns
            .iter()
            .position(|column| column == name)
            .ok_or("context column absent")
    };
    let revision = index("owner_revision")?;
    let body = index("body")?;
    assert_eq!(result.rows.len(), 3);
    for (row, (expected_revision, expected_body)) in result.rows.iter().zip([
        (10, b"before".as_slice()),
        (20, b"after".as_slice()),
        (30, b"after".as_slice()),
    ]) {
        assert_eq!(row[revision], Value::UBigInt(expected_revision));
        assert_eq!(row[body], Value::Blob(expected_body.to_vec()));
        assert_eq!(
            row[index("tenant_id")?],
            Value::Blob(key.tenant_id.to_vec())
        );
        assert_eq!(row[index("owner_id")?], Value::Text(key.owner_id.clone()));
        assert_eq!(
            row[index("entity_key")?],
            Value::Blob(key.entity_key.clone())
        );
        assert_eq!(
            row[index("lifetime_key")?],
            Value::Blob(key.lifetime_key.clone())
        );
    }
    for change in 0..3 {
        let mut invalid = selection.clone();
        match change {
            0 => invalid.contexts[1].owner_id.push('x'),
            1 => invalid.contexts[1].entity_key.push(9),
            _ => invalid.contexts[1].lifetime_key.push(9),
        }
        assert!(QueryPlan::new(invalid, QueryTemplate::RevisionDifference).is_err());
    }
    selection.contexts.pop();
    assert!(QueryPlan::new(selection, QueryTemplate::RevisionDifference).is_err());
    Ok(())
}

#[test]
fn query_input_catalog() -> TestResult {
    let fixture = QueryFixture::new()?;
    let owner = fixture.owner(QueryLimits::default())?;
    let selection = AnalysisSelectionV1::new(fixture.source.tenant_id, Vec::new());
    let plan = QueryPlan::new(selection.clone(), QueryTemplate::Catalog)?;
    let result = owner.query_at(&plan, 0)?;
    assert_eq!(result.rows, fixture.baseline(&plan, 0)?);
    assert_eq!(
        result.rows.len(),
        input::SCHEMAS
            .iter()
            .map(|schema| schema.columns.len())
            .sum::<usize>()
    );
    assert_eq!(result.scanned_bytes, 0);
    assert_eq!(result.input_rows, 0);
    assert!(result.sources.is_empty());
    let index = |name| {
        result
            .columns
            .iter()
            .position(|column| column == name)
            .ok_or("catalog column absent")
    };
    let relation = index("relation")?;
    let ordinal = index("ordinal")?;
    let readiness = index("readiness")?;
    let column = index("column_name")?;
    let units = index("units")?;
    let null_meaning = index("null_meaning")?;
    let join_keys = index("join_keys")?;
    let mut expected = input::SCHEMAS
        .iter()
        .flat_map(|schema| {
            schema
                .columns
                .iter()
                .enumerate()
                .map(move |(ordinal, _)| (schema.name, ordinal as u32))
        })
        .collect::<Vec<_>>();
    expected.sort_unstable();
    for (row, (name, position)) in result.rows.iter().zip(expected) {
        assert_eq!(row[relation], Value::Text(name.into()));
        assert_eq!(row[ordinal], Value::UInt(position));
        let state = if name.starts_with("trace") {
            "unavailable"
        } else {
            "available"
        };
        assert_eq!(row[readiness], Value::Text(state.into()));
    }
    let kernel = result
        .rows
        .iter()
        .find(|row| {
            row[relation] == Value::Text("events".into())
                && row[column] == Value::Text("kernel_sequence".into())
        })
        .ok_or("kernel sequence schema absent")?;
    assert_eq!(
        kernel[units],
        Value::Text("original kernel sequence, not source cursor".into())
    );
    assert_eq!(
        kernel[null_meaning],
        Value::Text("No decision context is present.".into())
    );
    assert!(
        matches!(&kernel[join_keys], Value::Text(keys) if keys.contains("node_boot_id") && keys.contains("source_cursor"))
    );
    let mut unsupported = selection;
    unsupported.results.push("not-a-query-relation".into());
    assert!(matches!(
        QueryPlan::new(unsupported, QueryTemplate::Catalog),
        Err(crate::Error::QueryUnsupported {
            relation: "results",
            ..
        })
    ));
    Ok(())
}

#[test]
fn query_scope_coverage() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(2, 20, 7)?;
    let mut other = fixture.source.clone();
    other.source_id = [8; 16];
    fixture.commit_as(&other, 1, 1, 10, EvidenceRecord::default())?;
    let report = crate::CoverageReport {
        source_id: fixture.source.source_id.to_vec(),
        cpu_id: 0,
        source_epoch: fixture.source.source_epoch,
        revision: 1,
        intervals: vec![crate::CoverageInterval {
            interval_id: vec![9; 16],
            source_epoch: fixture.source.source_epoch,
            revision: 1,
            state: "GAPPED".into(),
            first_sequence: 300,
            last_sequence: Some(400),
            gap_reasons: vec!["ring_lost".into()],
            current: false,
            ..Default::default()
        }],
    };
    fixture
        .store
        .accept_validated_coverage(crate::ValidatedCoverageV1 {
            identity: fixture.source.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: report.encode_to_vec(),
        })?;
    let owner = fixture.owner(QueryLimits::default())?;
    let mut plan = fixture.plan(QueryTemplate::Coverage)?;
    let complete = owner.query_at(&plan, 100)?;
    assert_eq!(complete.rows, fixture.baseline(&plan, 100)?);
    assert_eq!(complete.sources.len(), 1);
    assert_eq!(complete.sources[0].receipt.identity, fixture.source);
    assert_eq!(complete.sources[0].state, QueryCoverageState::Gapped);
    assert_eq!(complete.sources[0].receipt.contiguous_cursor, 0);
    assert_eq!(complete.scanned_bytes, 0);
    assert_eq!(complete.input_rows, 0);
    assert_eq!(complete.rows.len(), 3);
    let index = |name| {
        complete
            .columns
            .iter()
            .position(|column| column == name)
            .ok_or("coverage column absent")
    };
    let kind = index("kind")?;
    let state = index("state")?;
    let first = index("first_cursor")?;
    let sequence = index("first_sequence")?;
    let report = complete
        .rows
        .iter()
        .find(|row| row[kind] == Value::Text("interval".into()))
        .ok_or("interval absent")?;
    assert_eq!(report[state], Value::Text("GAPPED".into()));
    assert_eq!(report[first], Value::Null);
    assert_eq!(report[sequence], Value::UBigInt(300));
    let pending = complete
        .rows
        .iter()
        .find(|row| row[kind] == Value::Text("pending".into()))
        .ok_or("pending gap absent")?;
    assert_eq!(pending[first], Value::UBigInt(1));
    assert_eq!(pending[sequence], Value::Null);
    for (from, until) in [
        (Bound::Included(100), Bound::Unbounded),
        (Bound::Included(100), Bound::Excluded(100)),
    ] {
        plan.selection.received_from = from;
        plan.selection.received_until = until;
        let result = owner.query_at(&plan, 100)?;
        assert_eq!(result.rows, complete.rows);
        assert_eq!(result.rows, fixture.baseline(&plan, 100)?);
        assert_eq!(&result.sources[..], &complete.sources[..]);
        assert_eq!(result.scanned_bytes, 0);
    }
    drop(complete);
    fixture.event(1, 10, 7)?;
    let result = owner.query_at(&plan, 100)?;
    assert_eq!(result.rows, fixture.baseline(&plan, 100)?);
    assert_eq!(result.sources[0].receipt.contiguous_cursor, 2);
    assert_eq!(result.sources[0].state, QueryCoverageState::Reported);
    assert!(result.sources[0].pending.is_empty());
    assert_eq!(result.rows.len(), 2);
    assert!(result
        .rows
        .iter()
        .any(|row| row[kind] == Value::Text("interval".into())
            && row[state] == Value::Text("GAPPED".into())));
    Ok(())
}
