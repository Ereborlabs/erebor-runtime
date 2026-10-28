use super::*;
use duckdb::params;

#[test]
fn context_guard_rolls_back() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let input = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "discovery-facts-v1".into(),
            entity_key: b"guarded".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"captured".to_vec(),
    };
    let control = std::sync::Arc::new(crate::AnalysisReadControl::default());
    control.check()?;
    let cancelled = std::sync::Arc::clone(&control);
    store.set_commit_hook(
        super::super::AnalysisCommitStage::BeforeContextCommit,
        move || cancelled.cancel(),
    )?;
    let mut notices = store.subscribe_revision();
    let before = store.meta()?;
    assert!(matches!(
        store.intern_context_guarded(&input, || control.check()),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(store.context_version(&input.key)?, None);
    assert!(!notices.has_changed()?);
    let reference = store.intern_context_guarded(&input, || Ok(()))?;
    notices.borrow_and_update();
    let committed = store.meta()?;
    assert!(matches!(
        store.intern_context_guarded(&input, || control.check()),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert_eq!(store.meta()?, committed);
    assert_eq!(store.context_version(&reference.key)?, Some(input.clone()));
    assert!(!notices.has_changed()?);
    drop(store);
    assert_eq!(
        AnalysisStore::open(root)?.context_version(&reference.key)?,
        Some(input)
    );
    Ok(())
}

#[test]
fn control_graph_context_head_pages_keep_exact_versions_and_bounds(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let tenant = [1; 16];
    let owner = "paging-owner";
    let original = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: owner.into(),
            entity_key: 1u32.to_be_bytes().to_vec(),
            lifetime_key: b"a".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    for entity in 1..=257u32 {
        let mut version = original.clone();
        version.key.entity_key = entity.to_be_bytes().to_vec();
        store.commit_context(&version)?;
    }
    let mut later = original.clone();
    later.key.owner_revision = 2;
    later.body = vec![2];
    store.commit_context_checked(&later, 1)?;
    let mut other_lifetime = original.clone();
    other_lifetime.key.lifetime_key = b"b".to_vec();
    store.commit_context(&other_lifetime)?;
    let first = store.context_head_page(tenant, owner, None)?;
    assert_eq!(first.len(), super::super::MAX_ANALYSIS_PAGE_RECORDS);
    assert_eq!(first[0], later);
    assert_eq!(first[1], other_lifetime);
    assert!(first.windows(2).all(|pair| pair[0].key < pair[1].key));
    let last = &first.last().ok_or("page cursor")?.key;
    let second = store.context_head_page(tenant, owner, Some(last))?;
    assert_eq!(second.len(), 2);
    assert!(second.iter().all(|version| &version.key > last));
    assert!(store
        .context_head_page(tenant, owner, Some(&second.last().ok_or("last")?.key))?
        .is_empty());
    assert!(store.context_heads(tenant, owner, 256).is_err());
    assert_eq!(
        store.context_head(tenant, owner, &original.key.entity_key, b"a")?,
        Some(later)
    );
    assert_eq!(
        store.context_version(&original.key)?,
        Some(original.clone())
    );
    assert!(store
        .context_head([2; 16], owner, &original.key.entity_key, b"a")?
        .is_none());
    assert!(store
        .context_head(tenant, "other-owner", &original.key.entity_key, b"a")?
        .is_none());
    assert!(store.context_head(tenant, owner, b"", b"a").is_err());
    let mut foreign = last.clone();
    foreign.tenant_id = [2; 16];
    assert!(store
        .context_head_page(tenant, owner, Some(&foreign))
        .is_err());
    foreign = last.clone();
    foreign.owner_id = "other-owner".into();
    assert!(store
        .context_head_page(tenant, owner, Some(&foreign))
        .is_err());

    for entity in 1..=34u32 {
        let mut version = original.clone();
        version.key.owner_id = "large-owner".into();
        version.key.entity_key = entity.to_be_bytes().to_vec();
        version.body = vec![
            1;
            if entity == 1 {
                2 * 1024 * 1024
            } else {
                32 * 1024
            }
        ];
        store.commit_context(&version)?;
    }
    let page = store.context_head_page(tenant, "large-owner", None)?;
    assert_eq!(page.len(), 34);
    assert_eq!(page[0].body.len(), 2 * 1024 * 1024);
    assert!(page.windows(2).all(|pair| pair[0].key < pair[1].key));
    for version in &page {
        assert_eq!(store.context_version(&version.key)?, Some(version.clone()));
    }
    let next = store.context_head_page(
        tenant,
        "large-owner",
        Some(&page.last().ok_or("page cursor")?.key),
    )?;
    assert!(next.is_empty());
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ?
             AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
            params![
                b"".as_slice(),
                tenant.as_slice(),
                "large-owner",
                original.key.entity_key.as_slice(),
                original.key.lifetime_key.as_slice(),
                original.key.owner_revision
            ],
        )?;
    }
    assert!(matches!(
        store.context_head_page(tenant, "large-owner", None),
        Err(crate::Error::AnalysisState { .. })
    ));
    Ok(())
}

#[test]
fn analysis_store_context_versions() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("analysis");
    let store = AnalysisStore::open(&path)?;
    let input = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "policy".into(),
            entity_key: b"workload-a".to_vec(),
            lifetime_key: b"pod-a".to_vec(),
            owner_revision: 4,
        },
        valid_from_utc_ns: Some(100),
        valid_until_utc_ns: Some(200),
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"policy-revision-4".to_vec(),
    };
    let revision = store.commit_context(&input)?;
    assert_eq!(store.commit_context(&input)?, revision);
    assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
    for change in 0..4 {
        let mut conflict = input.clone();
        match change {
            0 => conflict.body.push(0),
            1 => conflict.valid_from_utc_ns = Some(101),
            2 => conflict.valid_until_utc_ns = Some(201),
            _ => conflict.sensitivity = ContextSensitivityV1::HostRestricted,
        }
        assert!(matches!(
            store.commit_context(&conflict),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(store.meta()?.commit_revision, revision);
    }
    let mut later = input.clone();
    later.key.owner_revision = 5;
    later.valid_from_utc_ns = Some(300);
    later.valid_until_utc_ns = None;
    store.commit_context(&later)?;
    assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
    let mut unknown = input.clone();
    unknown.key.owner_revision = 0;
    unknown.valid_from_utc_ns = None;
    unknown.valid_until_utc_ns = None;
    let zero_revision = store.commit_context(&unknown)?;
    assert_eq!(store.commit_context(&unknown)?, zero_revision);
    let before = store.meta()?;
    for (from, until) in [(None, Some(200)), (Some(0), None), (Some(200), Some(200))] {
        let mut invalid = unknown.clone();
        invalid.valid_from_utc_ns = from;
        invalid.valid_until_utc_ns = until;
        assert!(store.commit_context(&invalid).is_err());
        assert_eq!(store.meta()?, before);
    }
    drop(store);
    let reopened = AnalysisStore::open(path)?;
    assert_eq!(reopened.commit_context(&input)?, revision);
    assert_eq!(reopened.context_version(&later.key)?, Some(later));
    assert_eq!(reopened.context_version(&unknown.key)?, Some(unknown));
    let mut foreign = input.key.clone();
    foreign.tenant_id = [2; 16];
    assert_eq!(reopened.context_version(&foreign)?, None);
    reopened.writer()?.get()?.execute(
        "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ?",
        duckdb::params![
            b"".as_slice(),
            input.key.tenant_id.as_slice(),
            input.key.owner_id,
        ],
    )?;
    assert!(reopened.context_version(&input.key).is_err());
    Ok(())
}

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn context_value(entity: u8, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "p".into(),
            entity_key: vec![entity],
            lifetime_key: vec![1],
            owner_revision: revision,
        },
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![entity],
    }
}

#[test]
fn context_batch_commits() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let mut changes = store.subscribe_revision();
    let first = context_value(1, 1);
    let mut second = context_value(2, 1);
    second.key.tenant_id = [2; 16];
    let inputs = [second, first];
    let references = store.commit_contexts(&inputs)?;
    assert_eq!(references.len(), inputs.len());
    assert_eq!(store.meta()?.commit_revision, 1);
    assert!(changes.has_changed()?);
    assert_eq!(*changes.borrow_and_update(), 1);
    assert!(!changes.has_changed()?);
    for (input, reference) in inputs.iter().zip(&references) {
        assert_eq!(reference.key, input.key);
        assert_eq!(reference.commit_revision, 1);
        assert_eq!(store.context_version(&input.key)?, Some(input.clone()));
    }
    drop(store);
    let store = AnalysisStore::open(root)?;
    assert_eq!(store.commit_contexts(&inputs)?, references);
    assert_eq!(store.meta()?.commit_revision, 1);
    Ok(())
}

#[test]
fn context_batch_retries() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context_value(1, 1);
    let second = context_value(2, 1);
    assert_eq!(store.commit_context(&first)?, 1);
    let mut changes = store.subscribe_revision();
    let inputs = [second.clone(), first, second];
    let references = store.commit_contexts(&inputs)?;
    assert_eq!(
        references
            .iter()
            .map(|reference| reference.commit_revision)
            .collect::<Vec<_>>(),
        vec![2, 1, 2]
    );
    assert_eq!(references[0], references[2]);
    assert!(changes.has_changed()?);
    assert_eq!(*changes.borrow_and_update(), 2);
    let before = store.meta()?;
    assert_eq!(store.commit_contexts(&inputs)?, references);
    assert!(store.commit_contexts(&[])?.is_empty());
    assert_eq!(store.meta()?, before);
    assert!(!changes.has_changed()?);
    Ok(())
}

#[test]
fn context_batch_conflicts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context_value(1, 1);
    store.commit_context(&first)?;
    let changes = store.subscribe_revision();
    let before = store.meta()?;
    let second = context_value(2, 1);
    let mut conflict = first.clone();
    conflict.body.push(3);
    assert!(matches!(
        store.commit_contexts(&[second.clone(), conflict]),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    let mut duplicate = second.clone();
    duplicate.body.push(3);
    assert!(matches!(
        store.commit_contexts(&[second.clone(), duplicate]),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(store.context_version(&second.key)?.is_none());
    assert_eq!(store.context_version(&first.key)?, Some(first));
    assert_eq!(store.meta()?, before);
    assert!(!changes.has_changed()?);
    Ok(())
}

#[test]
fn context_batch_checked() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context_value(1, 1);
    assert_eq!(store.commit_context_checked(&first, 0)?, 1);
    assert_eq!(store.commit_context_checked(&first, u64::MAX)?, 1);
    let next = context_value(1, 2);
    let changes = store.subscribe_revision();
    assert!(matches!(
        store.commit_context_checked(&next, 0),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert!(store.context_version(&next.key)?.is_none());
    assert_eq!(store.meta()?.commit_revision, 1);
    assert!(!changes.has_changed()?);
    assert_eq!(store.commit_context_checked(&next, 1)?, 2);
    assert_eq!(store.commit_context_checked(&next, 0)?, 2);
    assert_eq!(store.commit_context_checked(&first, 0)?, 1);
    Ok(())
}

#[test]
fn context_batch_interns() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let mut first = context_value(1, 1);
    first.key.owner_id = "discovery-facts-v1".into();
    let reference = store.intern_context(&first)?;
    let mut second = first.clone();
    second.key.entity_key = vec![2];
    second.key.owner_revision = 2;
    let changes = store.subscribe_revision();
    assert_eq!(store.intern_context(&second)?, reference);
    assert!(store.context_version(&second.key)?.is_none());
    assert_eq!(store.meta()?.commit_revision, reference.commit_revision);
    assert!(!changes.has_changed()?);
    second.key.owner_id = "unqualified".into();
    assert!(store.intern_context(&second).is_err());
    assert_eq!(store.meta()?.commit_revision, reference.commit_revision);
    Ok(())
}

#[test]
fn context_batch_packages() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let first = context_value(1, 1);
    let mut invalid = context_value(2, 1);
    invalid.key.owner_id = "native-package-v1".into();
    invalid.valid_from_utc_ns = None;
    let digest = format!("sha256:{}", "0".repeat(64));
    invalid.body = serde_json::to_vec(&serde_json::json!({
        "root": {"package_id": "absent", "revision": "1"},
        "digest": digest,
        "package": {"package_id": "absent", "revision": "1"},
        "export": "run", "output": "rows"
    }))?;
    invalid.key.entity_key = crate::Qualification::digest(&invalid.body).into_bytes();
    invalid.key.lifetime_key = digest.into_bytes();
    let changes = store.subscribe_revision();
    let failure = store
        .commit_contexts(&[first.clone(), invalid])
        .err()
        .ok_or("missing native context artifact accepted")?;
    assert!(matches!(
        failure,
        crate::Error::Package {
            code: crate::PackageErrorCodeV1::Missing,
            ..
        }
    ));
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&failure),
        erebor_runtime_error::StatusCode::NotFound
    );
    assert!(store.context_version(&first.key)?.is_none());
    assert_eq!(store.meta()?.commit_revision, 0);
    assert!(!changes.has_changed()?);
    Ok(())
}

#[test]
fn context_batch_history() -> TestResult {
    use crate::{
        DiscoveryContextDocumentV1, DiscoveryContextKindV1, DiscoveryContextRevisionV1,
        DiscoveryMethodV1,
    };

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let mut imported = DiscoveryContextRevisionV1 {
        imported_utc_ns: 1,
        document: DiscoveryContextDocumentV1 {
            schema_version: crate::DISCOVERY_SCHEMA_VERSION,
            tenant_id: [1; 16],
            id: "runbook".into(),
            revision: 1,
            kind: DiscoveryContextKindV1::Runbook,
            subject: context_value(1, 1).key,
            method: DiscoveryMethodV1 {
                id: "fixture".into(),
                revision: 1,
            },
            origin: "fixture".into(),
            valid_from_utc_ns: 1,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            approver: None,
            text: "first".into(),
        },
    };
    let first = AnalysisContextVersionV1::try_from(&imported)?;
    imported.document.revision = 3;
    let skipped = AnalysisContextVersionV1::try_from(&imported)?;
    let changes = store.subscribe_revision();
    assert!(store.commit_contexts(&[first.clone(), skipped]).is_err());
    assert!(store.context_version(&first.key)?.is_none());
    assert_eq!(store.meta()?.commit_revision, 0);
    assert!(!changes.has_changed()?);
    imported.document.revision = 2;
    imported.imported_utc_ns = 2;
    let second = AnalysisContextVersionV1::try_from(&imported)?;
    let references = store.commit_contexts(&[first.clone(), second.clone()])?;
    assert!(references
        .iter()
        .all(|reference| reference.commit_revision == 1));
    assert_eq!(store.context_version(&first.key)?, Some(first));
    assert_eq!(store.context_version(&second.key)?, Some(second));
    assert_eq!(store.meta()?.commit_revision, 1);
    Ok(())
}

#[test]
fn context_body_quota() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let mut large = context_value(1, 1);
    large.body = vec![1; 32 * 1024 + 1];
    assert_eq!(store.commit_context(&large)?, 1);
    assert_eq!(store.context_version(&large.key)?, Some(large.clone()));
    drop(store);
    let store = AnalysisStore::open_with_limits(
        &root,
        Default::default(),
        crate::StorageLimitsV1 {
            context_max_bytes: Some(0),
            ..Default::default()
        },
    )?;
    let changes = store.subscribe_revision();
    assert_eq!(store.commit_context_checked(&large, 0)?, 1);
    assert!(!changes.has_changed()?);
    let fresh = context_value(2, 1);
    assert!(matches!(
        store.commit_context(&fresh),
        Err(crate::Error::StorageCapacity {
            resource: "context version bytes",
            ..
        })
    ));
    assert_eq!(store.meta()?.commit_revision, 1);
    assert!(!changes.has_changed()?);
    drop(store);
    let store = AnalysisStore::open_with_limits(
        &root,
        Default::default(),
        crate::StorageLimitsV1 {
            context_max_bytes: Some(3),
            ..Default::default()
        },
    )?;
    let changes = store.subscribe_revision();
    let mut exact = fresh.clone();
    exact.body = vec![2; 3];
    let mut oversized = context_value(3, 1);
    oversized.body = vec![3; 4];
    assert!(matches!(
        store.commit_contexts(&[exact.clone(), oversized.clone()]),
        Err(crate::Error::StorageCapacity {
            resource: "context version bytes",
            ..
        })
    ));
    assert!(store.context_version(&exact.key)?.is_none());
    assert!(store.context_version(&oversized.key)?.is_none());
    assert_eq!(store.meta()?.commit_revision, 1);
    assert!(!changes.has_changed()?);
    assert_eq!(store.commit_context(&exact)?, 2);
    let mut empty = oversized;
    empty.body.clear();
    assert!(matches!(
        store.commit_context(&empty),
        Err(crate::Error::AnalysisState { .. })
    ));
    assert_eq!(store.context_version(&exact.key)?, Some(exact));
    assert_eq!(store.meta()?.commit_revision, 2);
    Ok(())
}

#[test]
fn discovery_context_keeps_body() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let input = crate::AnalysisContextVersionV1 {
        key: crate::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "discovery-source-v1".into(),
            entity_key: b"result".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: crate::ContextSensitivityV1::Tenant,
        body: br#"{"kind":"SOURCE_HEALTH","unknown":true}"#.to_vec(),
    };
    store.commit_context(&input)?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.context_version(&input.key)?, Some(input));
    Ok(())
}
