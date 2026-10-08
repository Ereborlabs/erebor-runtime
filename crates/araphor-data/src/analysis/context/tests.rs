use super::*;
use duckdb::params;

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
        version.body = vec![1; MAX_CONTEXT_BYTES];
        store.commit_context(&version)?;
    }
    let page = store.context_head_page(tenant, "large-owner", None)?;
    assert!(!page.is_empty() && page.len() < 34);
    assert!(
        page.iter().map(|version| version.body.len()).sum::<usize>()
            <= super::super::MAX_ANALYSIS_PAGE_BYTES
    );
    let next = store.context_head_page(
        tenant,
        "large-owner",
        Some(&page.last().ok_or("byte cursor")?.key),
    )?;
    assert_eq!(page.len() + next.len(), 34);
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE context_versions SET body = ? WHERE tenant_id = ? AND owner_id = ?
             AND entity_key = ? AND lifetime_key = ? AND owner_revision = ?",
            params![
                vec![1u8; super::super::MAX_ANALYSIS_PAGE_BYTES + 1].as_slice(),
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
