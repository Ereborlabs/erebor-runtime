use std::collections::{BTreeMap, BTreeSet};

use super::*;
use araphor_data::{Selection, TraceIdentityV1};
use datafusion::logical_expr::{lit, LogicalPlanBuilder};

fn meta() -> AnalysisStoreMetaV1 {
    AnalysisStoreMetaV1 {
        store_uuid: uuid::Uuid::from_bytes([3; 16]),
        schema_version: 1,
        recovery_epoch: 4,
        commit_revision: u64::MAX,
    }
}

fn plan(value: i64, alias: &str) -> LogicalPlan {
    LogicalPlanBuilder::empty(true)
        .project(vec![lit(value).alias(alias)])
        .unwrap()
        .build()
        .unwrap()
}

#[test]
fn maximum_fields_round_trip() {
    let mut cursor = Cursor::new(
        &meta(),
        Operation::Append,
        [255; 32],
        StorePositionV1 {
            commit_revision: u64::MAX,
            ordinal: u32::MAX,
        },
        u64::MAX,
    );
    cursor.set_windows(
        &(0..32)
            .map(|call| WindowRange {
                source: WindowSource::Input { call, slot: 0 },
                start_utc_ns: 0,
                end_utc_ns: 1,
                active: true,
            })
            .collect::<Vec<_>>(),
        &[],
    );
    let bytes = cursor.encode().unwrap();
    let decoded = Cursor::decode(&bytes).unwrap();
    assert_eq!(decoded, cursor);
    assert_eq!(decoded.read_revision(), u64::MAX);
    assert_eq!(decoded.position().commit_revision, u64::MAX);
    assert_eq!(decoded.position().ordinal, u32::MAX);
    assert_eq!(decoded.evaluated, u64::MAX);
    decoded.check_store(&meta()).unwrap();
}

#[test]
fn invalid_store_cursors() {
    let cursor = Cursor::new(
        &meta(),
        Operation::Replace,
        [5; 32],
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        0,
    );
    assert!(Cursor::decode(&[]).is_err());
    assert!(Cursor::decode(&vec![b' '; 1025]).is_err());
    assert!(Cursor::decode(b"{}").is_err());
    assert!(Cursor::decode(b"not a cursor").is_err());
    let mut trailing = cursor.encode().unwrap();
    trailing.push(0);
    assert!(Cursor::decode(&trailing).is_err());
    #[derive(Serialize)]
    struct Extra<'a> {
        #[serde(flatten)]
        cursor: &'a Cursor,
        unknown: bool,
    }
    let unknown = Extra {
        cursor: &cursor,
        unknown: true,
    };
    assert!(Cursor::decode(&rmp_serde::to_vec_named(&unknown).unwrap()).is_err());
    let mut invalid = cursor.clone();
    invalid.version = 2;
    assert!(Cursor::decode(&invalid.encode().unwrap()).is_err());
    invalid.version = 1;
    invalid.revision = 1;
    invalid.position.commit_revision = 2;
    assert!(Cursor::decode(&invalid.encode().unwrap()).is_err());
    let window = WindowRange {
        source: WindowSource::Query,
        start_utc_ns: 0,
        end_utc_ns: 2,
        active: true,
    };
    let mut window_cursor = cursor.clone();
    window_cursor.set_windows(&[window], &[window]);
    for case in 0..3 {
        let mut invalid = window_cursor.clone();
        match case {
            0 => invalid.windows[0].start_utc_ns = 2,
            1 => invalid.windows[0].end_utc_ns = 0,
            _ => invalid.windows[0].active = false,
        }
        assert!(matches!(
            Cursor::decode(&invalid.encode().unwrap()),
            Err(crate::Error::Invalid {
                field: "cursor fields",
                ..
            })
        ));
    }
    for completed in [false, true] {
        let mut invalid = window_cursor.clone();
        let windows = if completed {
            &mut invalid.completed_windows
        } else {
            &mut invalid.windows
        };
        windows.push(windows[0]);
        assert!(matches!(
            Cursor::decode(&invalid.encode().unwrap()),
            Err(crate::Error::Invalid {
                field: "cursor fields",
                ..
            })
        ));
    }
    let mut invalid = window_cursor;
    invalid.completed_windows[0].end_utc_ns = 3;
    assert!(matches!(
        Cursor::decode(&invalid.encode().unwrap()),
        Err(crate::Error::Invalid {
            field: "cursor fields",
            ..
        })
    ));
    let mut other = meta();
    other.store_uuid = uuid::Uuid::from_bytes([7; 16]);
    assert!(cursor.check_store(&other).is_err());
    other = meta();
    other.schema_version += 1;
    assert!(cursor.check_store(&other).is_err());
    other = meta();
    other.recovery_epoch += 1;
    assert!(cursor.check_store(&other).is_err());
    other = meta();
    other.commit_revision -= 1;
    assert!(cursor.check_store(&other).is_err());
}

#[test]
fn native_scope_binding() {
    let plan = plan(11, "value");
    let scope = AnalysisSelectionV1::new([1; 16], vec![]);
    let sources = BTreeMap::from([("events".to_owned(), None)]);
    let bind = |plan: &LogicalPlan,
                sources: &araphor_data::AnalysisTableRequests,
                scope: &AnalysisSelectionV1,
                operation: Operation,
                caller: &[u8]| {
        Cursor::binding(Some(plan), sources, scope, operation, caller).unwrap()
    };
    let binding = bind(&plan, &sources, &scope, Operation::Append, b"principal A");
    let cursor = Cursor::new(
        &meta(),
        Operation::Append,
        binding,
        StorePositionV1 {
            commit_revision: 0,
            ordinal: 0,
        },
        0,
    );
    cursor
        .check_binding(
            &bind(
                &plan.clone(),
                &sources,
                &scope,
                Operation::Append,
                b"principal A",
            ),
            Operation::Append,
        )
        .unwrap();
    for other in [
        bind(
            &super::tests::plan(12, "value"),
            &sources,
            &scope,
            Operation::Append,
            b"principal A",
        ),
        bind(
            &super::tests::plan(11, "other"),
            &sources,
            &scope,
            Operation::Append,
            b"principal A",
        ),
        bind(
            &plan,
            &BTreeMap::from([("coverage".to_owned(), None)]),
            &scope,
            Operation::Append,
            b"principal A",
        ),
        bind(
            &plan,
            &sources,
            &AnalysisSelectionV1::new([2; 16], vec![]),
            Operation::Append,
            b"principal A",
        ),
        bind(&plan, &sources, &scope, Operation::Replace, b"principal A"),
        bind(&plan, &sources, &scope, Operation::Append, b"principal B"),
    ] {
        assert!(cursor.check_binding(&other, Operation::Append).is_err());
    }
    assert!(cursor.check_binding(&binding, Operation::Replace).is_err());
    let mut first = scope.clone();
    first.traces = Selection::Exact(vec![TraceIdentityV1 {
        tenant_id: [1; 16],
        node_id: "trace-node".into(),
        node_boot_id: [2; 16],
        request_id: [3; 16],
        execution_id: [4; 16],
        source_sha256: [5; 32],
    }]);
    let mut second = first.clone();
    second.traces.exact_mut().unwrap()[0].execution_id = [9; 16];
    assert_ne!(
        bind(
            &plan,
            &sources,
            &first,
            Operation::Append,
            b"same principal"
        ),
        bind(
            &plan,
            &sources,
            &second,
            Operation::Append,
            b"same principal"
        )
    );
}

#[test]
fn source_keys_keep_binding() {
    let plan = plan(11, "value");
    let scope = AnalysisSelectionV1::new([1; 16], vec![]);
    let names = BTreeSet::from(["coverage".to_owned(), "events".to_owned()]);
    let mut requests: AnalysisTableRequests = names.into_iter().map(|name| (name, None)).collect();
    let binding = Cursor::binding(
        Some(&plan),
        &requests,
        &scope,
        Operation::Append,
        b"principal",
    )
    .unwrap();
    for columns in [None, Some(BTreeSet::new()), Some(BTreeSet::from([1, 3]))] {
        requests.insert("events".to_owned(), columns);
        assert_eq!(
            Cursor::binding(
                Some(&plan),
                &requests,
                &scope,
                Operation::Append,
                b"principal"
            )
            .unwrap(),
            binding
        );
    }
}
