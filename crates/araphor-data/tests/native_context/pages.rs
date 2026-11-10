use super::*;

fn row(entity: Vec<u8>, lifetime: Vec<u8>, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "head-pages".into(),
            entity_key: entity,
            lifetime_key: lifetime,
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![revision as u8],
    }
}

#[test]
fn ordered_heads_keep_exact_versions_pages_and_historical_candidates() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut inputs = (0u32..300)
        .rev()
        .map(|id| row(id.to_be_bytes().to_vec(), b"life".to_vec(), 1))
        .collect::<Vec<_>>();
    let mut latest = inputs[20].clone();
    latest.key.owner_revision = 2;
    latest.body = vec![2];
    inputs.push(latest.clone());
    store.commit_contexts(&inputs)?;
    let old = store.view()?;
    let revision = old.revision();
    let mut expected = inputs[..300].to_vec();
    expected[20] = latest.clone();
    expected.sort_by(|a, b| {
        (&a.key.entity_key, &a.key.lifetime_key).cmp(&(&b.key.entity_key, &b.key.lifetime_key))
    });
    assert_eq!(store.context_heads([1; 16], "head-pages", 300)?, expected);
    assert!(store.context_heads([1; 16], "head-pages", 299).is_err());
    let first = store.context_head_page([1; 16], "head-pages", None)?;
    assert_eq!(first.len(), 256);
    let second = store.context_head_page(
        [1; 16],
        "head-pages",
        Some(&first.last().ok_or("first page")?.key),
    )?;
    assert_eq!(second.len(), 44);
    assert_eq!([first, second].concat(), expected);
    let future = row(vec![255], b"life".to_vec(), 1);
    store.commit_context(&future)?;
    assert_eq!(old.context_heads([1; 16], "head-pages", 300)?, expected);
    assert_eq!(
        store
            .read_at(revision)?
            .context_heads([1; 16], "head-pages", 300)?,
        expected
    );
    assert_eq!(
        store.context_head(
            [1; 16],
            "head-pages",
            &latest.key.entity_key,
            &latest.key.lifetime_key
        )?,
        Some(latest)
    );
    assert!(store
        .context_heads([2; 16], "head-pages", usize::MAX)?
        .is_empty());
    let mut foreign = future.key;
    foreign.tenant_id = [2; 16];
    assert!(store
        .context_head_page([1; 16], "head-pages", Some(&foreign))
        .is_err());
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(old);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .read_at(revision)?
            .context_heads([1; 16], "head-pages", 300)?,
        expected
    );
    assert_eq!(store.context_heads([1; 16], "head-pages", 301)?.len(), 301);
    Ok(())
}

#[test]
fn head_identity_order_has_no_native_key_width_limit() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let a = row(vec![0; 70001], vec![0; 70001], 1);
    let b = row(vec![0; 70001], vec![1; 70001], 1);
    let c = row(vec![255; 70001], b"life".to_vec(), 1);
    store.commit_contexts(&[c.clone(), b.clone(), a.clone()])?;
    assert_eq!(
        store.context_heads([1; 16], "head-pages", 3)?,
        vec![a.clone(), b.clone(), c.clone()]
    );
    assert_eq!(
        store.context_head_page([1; 16], "head-pages", Some(&a.key))?,
        vec![b, c]
    );
    assert_eq!(store.context_version(&a.key)?, Some(a));
    Ok(())
}
