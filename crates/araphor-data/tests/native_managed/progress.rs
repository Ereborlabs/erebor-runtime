use super::*;
use araphor_data::{
    AnalysisResultCommitV1, ProcessorClassV1, ProcessorRetirementV1, ProcessorScopeV1,
};

#[path = "progress/profile.rs"]
mod profile;

#[path = "progress/pins.rs"]
mod pins;

#[cfg(feature = "test-fixtures")]
#[path = "progress/history.rs"]
mod history;

fn scope() -> ProcessorScopeV1 {
    ProcessorScopeV1 {
        processor_id: "native-progress".into(),
        method_version: 1,
        identity: araphor_data::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
    }
}

#[test]
fn processor_lifecycle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let scope = scope();
    let before = store.view()?.revision();
    assert!(store
        .register_processor_guarded(&scope, ProcessorClassV1::Required, 1, || Err(
            Code::Denied.error("guard")
        ))
        .is_err());
    assert_eq!(store.view()?.revision(), before);
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    assert!(store.processor_result(&scope)?.is_none());
    super::attempts::append(&store, 1)?;
    let before = store.view()?.revision();
    assert_eq!(
        store.ensure_optional_processor_guarded(&scope, || Ok(()))?,
        before
    );
    assert_eq!(store.view()?.revision(), before);
    let request = AnalysisResultCommitV1 {
        scope: scope.clone(),
        expected_cursor: 0,
        consumed_cursor: 1,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "native-result".into(),
        body: vec![1, 2, 3],
        created_utc_ns: 1000,
        witnesses: Vec::new(),
        context_refs: Vec::new(),
    };
    let receipt = store.commit_result(&request)?;
    assert_eq!(
        store.processor_result(&scope)?.ok_or("result")?.body,
        request.body
    );
    assert!(store.read_at(before)?.processor_result(&scope)?.is_none());
    super::attempts::append(&store, 2)?;
    let retirement = ProcessorRetirementV1 {
        scope: scope.clone(),
        change_id: "retire".into(),
        reason: "Replace the processor".into(),
        expected_cursor: 1,
        cutoff_cursor: 2,
    };
    let retired = store.retire_required(&retirement)?;
    assert_eq!(
        store.processor_gaps(&scope, 0)?,
        vec![araphor_data::AnalysisGapV1 {
            first_cursor: 2,
            last_cursor: 2,
            commit_revision: retired
        }]
    );
    let current = store.view()?.revision();
    assert_eq!(store.commit_result(&request)?, receipt);
    assert_eq!(store.view()?.revision(), current);
    assert_eq!(store.retire_required(&retirement)?, retired);
    let mut changed = request.clone();
    changed.body.push(4);
    assert!(store.commit_result(&changed).is_err());
    let mut foreign = request.clone();
    foreign.scope.identity.tenant_id = [9; 16];
    assert!(store.commit_result(&foreign).is_err());
    assert_eq!(store.view()?.revision(), current);
    drop(store);
    let store = NativeStore::open(&root).map_err(|error| format!("reopen: {error}"))?;
    assert_eq!(
        store.processor_retirement(&scope)?,
        Some((retirement, retired))
    );
    assert_eq!(
        store
            .processor_result(&scope)?
            .ok_or("reopened result")?
            .body,
        request.body
    );
    assert_eq!(store.commit_result(&request)?, receipt);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
struct State {
    scope: ProcessorScopeV1,
    class: ProcessorClassV1,
    start: u64,
    consumed: u64,
    resumed: u64,
    coverage: u64,
    context: u64,
    required: u64,
    head: Option<araphor_data::analysis::PackageResultRefV1>,
    retirement: Option<(ProcessorRetirementV1, u64)>,
    revision: u64,
}

#[test]
fn processor_recovery() -> TestResult {
    for mode in [
        "valid",
        "missing-gap",
        "orphan-gap",
        "body-fragment",
        "history-class",
        "history-start",
        "history-progress",
        "retirement-revision",
        "declared-revision",
        "result-body",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let mut scope = scope();
        scope.processor_id = araphor_data::DISCOVERY_PROCESSOR.into();
        store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
        super::attempts::append(&store, 1)?;
        let request = AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "opaque-discovery".into(),
            body: vec![1, 2],
            created_utc_ns: 1000,
            witnesses: Vec::new(),
            context_refs: Vec::new(),
        };
        store.commit_result(&request)?;
        super::attempts::append(&store, 2)?;
        if matches!(mode, "history-class" | "history-start" | "history-progress") {
            let (key, bytes) = store
                .view()?
                .snapshot()
                .prefix(b"\0data/@progress/state/")
                .next()
                .ok_or("state")??;
            let original: State = rmp_serde::from_slice(&bytes[1..])?;
            let mut tx = store.write()?;
            let mut changed = original.clone();
            match mode {
                "history-class" => changed.class = ProcessorClassV1::Optional,
                "history-start" => changed.start = 2,
                _ => {
                    changed.consumed = 0;
                    changed.required = 0;
                }
            }
            changed.revision = tx.revision();
            let mut bytes = vec![0];
            bytes.extend(rmp_serde::to_vec_named(&changed)?);
            tx.native().insert(key.as_ref(), bytes);
            tx.commit([])?;
            super::attempts::append(&store, 3)?;
            let mut tx = store.write()?;
            let mut restored = original;
            restored.revision = tx.revision();
            let mut bytes = vec![0];
            bytes.extend(rmp_serde::to_vec_named(&restored)?);
            tx.native().insert(key, bytes);
            tx.commit([])?;
        } else {
            store.retire_required(&ProcessorRetirementV1 {
                scope: scope.clone(),
                change_id: "retire".into(),
                reason: "Replace the processor".into(),
                expected_cursor: 1,
                cutoff_cursor: 2,
            })?;
            let view = store.view()?;
            if mode == "retirement-revision" || mode == "declared-revision" {
                let (key, bytes) = view
                    .snapshot()
                    .prefix(b"\0data/@progress/state/")
                    .next()
                    .ok_or("state")??;
                let mut changed: State = rmp_serde::from_slice(&bytes[1..])?;
                let mut tx = store.write()?;
                changed.revision = tx.revision();
                if mode == "retirement-revision" {
                    changed.retirement.as_mut().ok_or("retirement")?.1 -= 1;
                } else {
                    changed.revision = 0;
                }
                let mut bytes = vec![0];
                bytes.extend(rmp_serde::to_vec_named(&changed)?);
                tx.native().insert(key, bytes);
                tx.commit([])?;
            }
            if mode == "missing-gap" || mode == "orphan-gap" {
                let (key, bytes) = view
                    .snapshot()
                    .prefix(b"\0data/@progress/gap/")
                    .next()
                    .ok_or("gap")??;
                let mut tx = store.write()?;
                if mode == "missing-gap" {
                    tx.native().remove(key);
                } else {
                    let mut extra = key.to_vec();
                    extra.push(0);
                    tx.native().insert(extra, bytes);
                }
                tx.commit([])?;
            }
            if mode == "body-fragment" || mode == "result-body" {
                let (key, _) = view
                    .snapshot()
                    .prefix(b"\0data/@progress/body/")
                    .next()
                    .ok_or("body")??;
                let mut tx = store.write()?;
                if mode == "body-fragment" {
                    let mut extra = key.to_vec();
                    extra.extend(0u64.to_be_bytes());
                    tx.native().insert(extra, [1]);
                } else {
                    tx.native().insert(key, [0, 3, 4]);
                }
                tx.commit([])?;
            }
        }
        store.database().inner().flush_memtables()?;
        store.database().inner().major_compact()?;
        drop(store);
        if mode == "valid" {
            let store = NativeStore::open(&root)?;
            assert_eq!(
                store.processor_result(&scope)?.ok_or("opaque result")?.body,
                vec![1, 2]
            );
        } else {
            assert!(NativeStore::open(&root).is_err(), "{mode}");
        }
    }
    Ok(())
}
