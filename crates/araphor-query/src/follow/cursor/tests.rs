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
    let cursor = Cursor::new(
        &meta(),
        Operation::Append,
        [255; 32],
        StorePositionV1 {
            commit_revision: u64::MAX,
            ordinal: u32::MAX,
        },
        u64::MAX,
    );
    let bytes = cursor.encode().unwrap();
    assert!(bytes.len() <= Cursor::BYTES);
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
    assert!(Cursor::decode(&vec![b' '; Cursor::BYTES + 1]).is_err());
    assert!(Cursor::decode(b"{}").is_err());
    assert!(Cursor::decode(b"not a cursor").is_err());
    let mut value = serde_json::to_value(&cursor).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(Cursor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value.as_object_mut().unwrap().remove("unknown");
    value["version"] = serde_json::json!(2);
    assert!(Cursor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    value["version"] = serde_json::json!(1);
    value["revision"] = serde_json::json!(1);
    value["position"]["commit_revision"] = serde_json::json!(2);
    assert!(Cursor::decode(&serde_json::to_vec(&value).unwrap()).is_err());
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
        Fingerprint::binding(plan, sources, scope, operation, caller).unwrap()
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
    let mut legacy = Fingerprint::new();
    Hasher::write(&mut legacy, b"araphor-query.follow.v1\0");
    plan.hash(&mut legacy);
    names.hash(&mut legacy);
    Operation::Append.hash(&mut legacy);
    b"principal".as_slice().hash(&mut legacy);
    serde_json::to_writer(&mut legacy, &scope).unwrap();
    let legacy = legacy.finish_digest();
    let mut requests: AnalysisTableRequests = names.into_iter().map(|name| (name, None)).collect();
    for columns in [None, Some(BTreeSet::new()), Some(BTreeSet::from([1, 3]))] {
        requests.insert("events".to_owned(), columns);
        assert_eq!(
            Fingerprint::binding(&plan, &requests, &scope, Operation::Append, b"principal")
                .unwrap(),
            legacy
        );
    }
}
