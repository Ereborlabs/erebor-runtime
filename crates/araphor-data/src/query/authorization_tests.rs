use std::collections::BTreeSet;
use std::ops::Bound;

use duckdb::types::Value;

use super::authorization::QueryGrant;
use super::tests::QueryFixture;
use super::{
    QueryCheckpoint, QueryFrame, QueryHealth, QueryLimits, QueryPayload, QueryPlan, QuerySql,
    QueryTemplate, QUERY_CHECKPOINT_BYTES, QUERY_SCHEMA_VERSION,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn grant(fixture: &QueryFixture) -> QueryGrant {
    QueryGrant {
        principal: "query-operator".into(),
        revision: 1,
        selection: crate::AnalysisSelectionV1::new(
            fixture.source.tenant_id,
            vec![fixture.source.clone()],
        ),
    }
}

#[test]
fn query_sql_rejects_names() -> TestResult {
    for statement in [
        "SELECT operation FROM foreign_relation",
        "SELECT foreign_field FROM events",
    ] {
        assert!(matches!(
            QuerySql::admit(statement, Vec::new(), false),
            Err(crate::Error::QueryInvalid { .. })
        ));
    }
    Ok(())
}

#[test]
fn query_column_tracks_source() -> TestResult {
    let direct = QuerySql::admit("SELECT operation FROM events", Vec::new(), false)?;
    let (relation, field) = direct.source_column("operation").ok_or("source absent")?;
    assert_eq!(relation.name, "events");
    assert_eq!(field.0, "operation");
    assert!(!field.2.is_empty());
    for (statement, name) in [
        ("SELECT e.operation AS chosen FROM events e", "chosen"),
        ("SELECT operation AS reason FROM events", "reason"),
    ] {
        let sql = QuerySql::admit(statement, Vec::new(), false)?;
        let (origin, column) = sql.source_column(name).ok_or("source absent")?;
        assert_eq!(origin.name, relation.name);
        assert_eq!(column.0, field.0);
        assert_eq!(column.1, field.1);
        assert_eq!(column.2, field.2);
        assert_eq!(column.3, field.3);
    }
    for statement in [
        "SELECT COUNT(*) AS operation FROM events",
        "SELECT operation + 1 AS operation FROM events",
    ] {
        let sql = QuerySql::admit(statement, Vec::new(), false)?;
        assert!(sql.source_column("operation").is_none(), "{statement}");
    }
    Ok(())
}

#[test]
fn client_health_hides_usage() -> TestResult {
    let fixture = QueryFixture::new()?;
    let meta = fixture.store.meta()?;
    let health = crate::StorageHealthV1 {
        write_ready: false,
        retention_healthy: true,
        intake_capacity: false,
        maintenance_capacity: true,
        usage: crate::StorageUsageV1 {
            file_bytes: 1,
            allocated_bytes: 2,
            available_bytes: 3,
        },
    };
    let changed = crate::StorageHealthV1 {
        usage: crate::StorageUsageV1 {
            file_bytes: 4,
            allocated_bytes: 5,
            available_bytes: 6,
        },
        ..health
    };
    let sql = QuerySql::admit("SELECT operation FROM events", Vec::new(), false)?;
    let plan = QueryPlan::client(grant(&fixture), sql)?;
    let first = QueryFrame::health(&plan, &meta, 7, None, health, false)?;
    let second = QueryFrame::health(&plan, &meta, 7, None, changed, false)?;
    let mut expected = QueryHealth::from(health);
    expected.usage = None;
    for frame in [first, second] {
        let QueryPayload::Health { storage_health, .. } = frame.payload else {
            return Err("health payload absent".into());
        };
        assert_eq!(storage_health, expected);
    }
    let trusted = fixture.plan(QueryTemplate::Events { operation: None })?;
    let first = QueryFrame::health(&trusted, &meta, 7, None, health, false)?;
    let second = QueryFrame::health(&trusted, &meta, 7, None, changed, false)?;
    for (frame, original) in [(first, health), (second, changed)] {
        let QueryPayload::Health { storage_health, .. } = frame.payload else {
            return Err("health payload absent".into());
        };
        assert_eq!(storage_health, QueryHealth::from(original));
        assert_eq!(storage_health.usage, Some(original.usage));
    }
    Ok(())
}

#[test]
fn client_metadata_source_keys() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let trusted = fixture.plan(QueryTemplate::OperationCounts)?;
    let limits = QueryLimits::default();
    let result = fixture.owner(limits.clone())?.query_at(&trusted, 20)?;
    let sql = QuerySql::admit(
        "SELECT operation, COUNT(*) AS event_count FROM events GROUP BY operation",
        Vec::new(),
        false,
    )?;
    assert!(sql.source_column("operation").is_some());
    let plan = QueryPlan::client(grant(&fixture), sql)?;
    let frame = QueryFrame::metadata(&plan, &result, &limits, 7)?;
    let QueryPayload::Metadata(client) = frame.payload else {
        return Err("metadata payload absent".into());
    };
    let column = client
        .columns
        .iter()
        .find(|column| column.name == "operation")
        .ok_or("operation column absent")?;
    assert!(!column.join_keys.is_empty());
    assert!(!column.units.is_empty());
    let count = client
        .columns
        .iter()
        .find(|column| column.name == "event_count")
        .ok_or("count column absent")?;
    assert!(count.join_keys.is_empty());
    let frame = QueryFrame::metadata(&trusted, &result, &limits, 7)?;
    let QueryPayload::Metadata(metadata) = frame.payload else {
        return Err("metadata payload absent".into());
    };
    let original = metadata
        .columns
        .iter()
        .find(|column| column.name == "operation")
        .ok_or("operation column absent")?;
    assert_eq!(column, original);
    assert_eq!(client.row_limit, limits.output_rows);
    assert_eq!(client.byte_limit, limits.output_bytes);
    assert_eq!(client.evaluated_utc_ns, result.evaluated_utc_ns);
    assert_eq!(client.dependency_revision, 7);
    Ok(())
}

#[test]
fn query_grant_rejects_scope() -> TestResult {
    let fixture = QueryFixture::new()?;
    let base = grant(&fixture);
    base.validate()?;
    for principal in [String::new(), "x".repeat(257), "operator\nforeign".into()] {
        let mut changed = base.clone();
        changed.principal = principal;
        assert!(matches!(
            changed.validate(),
            Err(crate::Error::QueryDenied { .. })
        ));
    }
    for change in 0..5 {
        let mut invalid = base.clone();
        match change {
            0 => invalid.selection.tenant_id = [0; 16],
            1 => invalid.selection.sources[0].tenant_id = [9; 16],
            2 => invalid.selection.sources[0].node_id.clear(),
            3 => invalid.selection.sources.push(fixture.source.clone()),
            _ => invalid
                .selection
                .contexts
                .push(crate::AnalysisContextKeyV1 {
                    tenant_id: [9; 16],
                    owner_id: "query-context".into(),
                    entity_key: vec![1],
                    lifetime_key: vec![2],
                    owner_revision: 1,
                }),
        }
        assert!(
            matches!(invalid.validate(), Err(crate::Error::QueryDenied { .. })),
            "change {change}"
        );
    }
    Ok(())
}

#[test]
fn client_frame_keeps_limits() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let trusted = fixture.plan(QueryTemplate::OperationCounts)?;
    let owner = fixture.owner(QueryLimits::default())?;
    for follow in [false, true] {
        let sql = QuerySql::admit(
            "SELECT operation, COUNT(*) AS event_count FROM events GROUP BY operation",
            Vec::new(),
            follow,
        )?;
        let plan = QueryPlan::client(grant(&fixture), sql)?;
        let mut result = owner.query_at(&trusted, 20)?;
        result.limited = true;
        let frame = QueryFrame::data(&plan, result);
        if follow {
            assert!(matches!(frame, Err(crate::Error::QueryLimit { .. })));
        } else {
            let QueryPayload::Replace { result, .. } = frame?.payload else {
                return Err("replacement payload absent".into());
            };
            assert!(result.limited);
        }
    }
    let mut result = owner.query_at(&trusted, 20)?;
    result.limited = true;
    assert!(matches!(
        QueryFrame::data(&trusted, result),
        Err(crate::Error::QueryLimit { .. })
    ));
    Ok(())
}

#[test]
fn query_bookmark_roundtrip() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    for template in [
        QueryTemplate::Events { operation: None },
        QueryTemplate::OperationCounts,
    ] {
        let plan = fixture.plan(template)?;
        let result = fixture.owner(QueryLimits::default())?.query_at(&plan, 20)?;
        let checkpoint = QueryCheckpoint::from_result(&plan, &result)?;
        let bytes = checkpoint.encode()?;
        assert!(bytes.len() <= QUERY_CHECKPOINT_BYTES);
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        let fields = body.as_object().ok_or("bookmark object absent")?;
        assert_eq!(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "schema_version",
                "store_uuid",
                "recovery_epoch",
                "operation",
                "position",
                "read_revision",
            ])
        );
        assert_eq!(body["schema_version"], QUERY_SCHEMA_VERSION);
        assert_eq!(
            body["store_uuid"],
            serde_json::to_value(result.meta.store_uuid.as_bytes())?
        );
        assert_eq!(body["recovery_epoch"], result.meta.recovery_epoch);
        assert_eq!(body["read_revision"], result.meta.commit_revision);
        let decoded = QueryCheckpoint::try_from(bytes.as_slice())?;
        assert_eq!(decoded, checkpoint);
        assert_eq!(
            decoded.validate(&plan, &result.meta, None)?,
            checkpoint.position()
        );
        let mut padded = vec![b' '; QUERY_CHECKPOINT_BYTES - bytes.len()];
        padded.extend_from_slice(&bytes);
        assert_eq!(QueryCheckpoint::try_from(padded.as_slice())?, checkpoint);
        padded.push(b' ');
        assert!(matches!(
            QueryCheckpoint::try_from(padded.as_slice()),
            Err(crate::Error::QueryInvalid {
                field: "checkpoint size",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn query_bookmark_rejects_shape() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let result = fixture.owner(QueryLimits::default())?.query_at(&plan, 20)?;
    let checkpoint = QueryCheckpoint::from_result(&plan, &result)?;
    let bytes = checkpoint.encode()?;
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    for (field, value) in [
        (
            "schema_version",
            serde_json::json!(QUERY_SCHEMA_VERSION + 1),
        ),
        ("store_uuid", serde_json::to_value([0_u8; 16])?),
        ("operation", serde_json::json!("Replace")),
        ("position", serde_json::Value::Null),
        (
            "position",
            serde_json::json!({"commit_revision": result.meta.commit_revision + 1, "ordinal": 0}),
        ),
    ] {
        let mut changed = body.clone();
        changed[field] = value;
        let encoded = serde_json::to_vec(&changed)?;
        assert!(
            matches!(
                QueryCheckpoint::try_from(encoded.as_slice()),
                Err(crate::Error::QueryInvalid {
                    field: "checkpoint",
                    ..
                })
            ),
            "{field}"
        );
    }
    for field in [
        "grant",
        "principal",
        "tenant_id",
        "binding",
        "signature",
        "unknown",
    ] {
        let mut changed = body.clone();
        changed[field] = serde_json::json!("untrusted input");
        let encoded = serde_json::to_vec(&changed)?;
        assert!(
            matches!(
                QueryCheckpoint::try_from(encoded.as_slice()),
                Err(crate::Error::QueryInvalid {
                    field: "checkpoint encoding",
                    ..
                })
            ),
            "{field}"
        );
    }
    for encoded in [
        b"{".as_slice(),
        b"{}".as_slice(),
        b"[]".as_slice(),
        b"null".as_slice(),
        b"\xff".as_slice(),
    ] {
        assert!(matches!(
            QueryCheckpoint::try_from(encoded),
            Err(crate::Error::QueryInvalid {
                field: "checkpoint encoding",
                ..
            })
        ));
    }
    let mut trailing = bytes;
    trailing.push(b'x');
    assert!(matches!(
        QueryCheckpoint::try_from(trailing.as_slice()),
        Err(crate::Error::QueryInvalid {
            field: "checkpoint encoding",
            ..
        })
    ));
    for encoded in [Vec::new(), vec![b' '; QUERY_CHECKPOINT_BYTES + 1]] {
        assert!(matches!(
            QueryCheckpoint::try_from(encoded.as_slice()),
            Err(crate::Error::QueryInvalid {
                field: "checkpoint size",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn query_bookmark_checks_store() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let result = fixture.owner(QueryLimits::default())?.query_at(&plan, 20)?;
    let checkpoint = QueryCheckpoint::from_result(&plan, &result)?;
    for change in 0..3 {
        let mut meta = result.meta.clone();
        match change {
            0 => meta.store_uuid = uuid::Uuid::from_bytes([9; 16]),
            1 => meta.recovery_epoch += 1,
            _ => meta.commit_revision -= 1,
        }
        assert!(matches!(
            checkpoint.validate(&plan, &meta, None),
            Err(crate::Error::QueryInvalid { .. })
        ));
    }
    let mut future = serde_json::to_value(&checkpoint)?;
    future["read_revision"] = serde_json::json!(result.meta.commit_revision + 1);
    let future = serde_json::to_vec(&future)?;
    let future = QueryCheckpoint::try_from(future.as_slice())?;
    assert!(matches!(
        future.validate(&plan, &result.meta, None),
        Err(crate::Error::QueryInvalid { .. })
    ));
    let replace = fixture.plan(QueryTemplate::OperationCounts)?;
    assert!(matches!(
        checkpoint.validate(&replace, &result.meta, None),
        Err(crate::Error::QueryInvalid { .. })
    ));
    fixture.event(2, 30, 9)?;
    let meta = fixture.store.meta()?;
    assert!(meta.commit_revision > result.meta.commit_revision);
    assert_eq!(
        checkpoint.validate(&plan, &meta, None)?,
        checkpoint.position()
    );
    let page = fixture.store.read_page(&fixture.source, 2)?;
    let floor = page
        .records
        .first()
        .ok_or("later position absent")?
        .position;
    assert!(
        matches!(checkpoint.validate(&plan, &meta, Some(floor)), Err(crate::Error::QueryCursorExpired {
        position, floor: actual, ..
    }) if Some(position) == checkpoint.position() && actual == floor)
    );
    Ok(())
}

#[test]
fn query_bookmark_keeps_scope() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let plan = fixture.plan(QueryTemplate::Events { operation: None })?;
    let result = fixture.owner(QueryLimits::default())?.query_at(&plan, 20)?;
    let bytes = QueryCheckpoint::from_result(&plan, &result)?.encode()?;
    let checkpoint = QueryCheckpoint::try_from(bytes.as_slice())?;
    for change in 0..7 {
        let mut selection = plan.selection.clone();
        let mut template = plan.template.clone();
        match change {
            0 => template = QueryTemplate::Events { operation: Some(7) },
            1 => selection.sources[0].source_id = [8; 16],
            2 => selection.sources[0].source_epoch += 1,
            3 => selection.sources[0].node_boot_id = [8; 16],
            4 => selection.sources[0].node_id = "foreign-node".into(),
            5 => selection.received_from = Bound::Excluded(10),
            _ => {
                selection.tenant_id = [8; 16];
                selection.sources[0].tenant_id = [8; 16];
            }
        }
        let changed = QueryPlan::new(selection.clone(), template)?;
        assert_eq!(
            checkpoint.validate(&changed, &result.meta, None)?,
            checkpoint.position()
        );
        assert_eq!(changed.selection.tenant_id, selection.tenant_id);
        assert_eq!(changed.selection.sources, selection.sources);
        assert_eq!(changed.selection.received_from, selection.received_from);
    }
    Ok(())
}

#[test]
fn client_plan_keeps_bounds() -> TestResult {
    let fixture = QueryFixture::new()?;
    let mut scoped = grant(&fixture);
    scoped.selection.received_from = Bound::Included(2500);
    let sql = QuerySql::admit(
        "SELECT operation FROM events WHERE received_at >= TIMESTAMP '1970-01-01 00:00:00.000002' AND received_at < TIMESTAMP '1970-01-01 00:00:00.000004'",
        Vec::new(),
        false,
    )?;
    let plan = QueryPlan::client(scoped.clone(), sql.clone())?;
    let input = plan.dependencies(5000)?;
    assert_eq!(input.received_from, Bound::Included(2500));
    assert_eq!(input.received_until, Bound::Included(3999));
    assert_eq!(input.tenant_id, scoped.selection.tenant_id);
    assert_eq!(input.sources, scoped.selection.sources);
    scoped.selection.received_until = Bound::Included(3800);
    let changed = QueryPlan::client(scoped, sql)?;
    let input = changed.dependencies(5000)?;
    assert_eq!(input.received_from, Bound::Included(2500));
    assert_eq!(input.received_until, Bound::Included(3800));
    Ok(())
}

#[test]
fn client_plan_rejects_scope() -> TestResult {
    let fixture = QueryFixture::new()?;
    let base = grant(&fixture);
    let sql = QuerySql::admit(
        "SELECT operation FROM events WHERE operation = ?",
        vec![Value::UInt(7)],
        false,
    )?;
    let plan = QueryPlan::client(base.clone(), sql.clone())?;
    assert!(matches!(
        fixture.owner(QueryLimits::default())?.query_at(&plan, 10),
        Err(crate::Error::QueryDenied { .. })
    ));
    assert!(matches!(
        QueryPlan::new(base.selection.clone(), QueryTemplate::Client(sql.clone())),
        Err(crate::Error::QueryDenied { .. })
    ));
    for change in 0..3 {
        let mut changed = base.clone();
        match change {
            0 => changed.principal.clear(),
            1 => changed.selection.sources[0].tenant_id = [9; 16],
            _ => changed.selection.results.push("retained-result".into()),
        }
        assert!(matches!(
            QueryPlan::client(changed, sql.clone()),
            Err(crate::Error::QueryDenied { .. })
        ));
    }
    Ok(())
}

#[test]
fn client_bookmark_keeps_grant() -> TestResult {
    let fixture = QueryFixture::new()?;
    fixture.event(1, 10, 7)?;
    let trusted = fixture.plan(QueryTemplate::Events { operation: None })?;
    let result = fixture
        .owner(QueryLimits::default())?
        .query_at(&trusted, 20)?;
    let base = grant(&fixture);
    let statement = "SELECT operation FROM events WHERE operation = ?";
    let sql = QuerySql::admit(statement, vec![Value::UInt(7)], false)?;
    let plan = QueryPlan::client(base.clone(), sql)?;
    let bytes = QueryCheckpoint::from_result(&plan, &result)?.encode()?;
    let checkpoint = QueryCheckpoint::try_from(bytes.as_slice())?;
    for change in 0..5 {
        let mut current = base.clone();
        let mut statement = statement;
        let mut parameters = vec![Value::UInt(7)];
        match change {
            0 => current.principal = "other-operator".into(),
            1 => current.revision += 1,
            2 => current.selection.received_from = Bound::Included(11),
            3 => statement = "SELECT operation FROM events WHERE operation >= ?",
            _ => parameters = vec![Value::UInt(9)],
        }
        let sql = QuerySql::admit(statement, parameters, false)?;
        let changed = QueryPlan::client(current.clone(), sql)?;
        assert_eq!(
            checkpoint.validate(&changed, &result.meta, None)?,
            checkpoint.position()
        );
        let retained = changed.grant.as_ref().ok_or("current grant absent")?;
        assert_eq!(retained.principal, current.principal);
        assert_eq!(retained.revision, current.revision);
        assert_eq!(retained.selection.tenant_id, current.selection.tenant_id);
        assert_eq!(retained.selection.sources, current.selection.sources);
        assert_eq!(
            retained.selection.received_from,
            current.selection.received_from
        );
    }
    Ok(())
}
