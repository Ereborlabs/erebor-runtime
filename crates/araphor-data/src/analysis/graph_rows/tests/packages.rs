use super::*;
use crate::graph::tests::native_storage::CommitFixture;
use duckdb::params;

#[test]
fn graph_package_commit_refs() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let refs = fixture.add_packages()?;
    let reference = fixture.request.context_refs[0].clone();
    let context = fixture
        .store
        .context_version(&reference.key)?
        .ok_or("package context absent")?;
    let before = fixture.store.meta()?;
    let mut changed = fixture.request.clone();
    changed.context_refs[0].key.entity_key = b"other-result".to_vec();
    assert!(fixture.store.commit_graph(&changed, true).is_err());
    fixture.store.writer_access()?.get_mut()?.execute(
        "UPDATE context_versions SET body = ? WHERE owner_id = ? AND entity_key = ?",
        params![
            b"invalid".as_slice(),
            reference.key.owner_id,
            reference.key.entity_key
        ],
    )?;
    assert!(fixture.store.commit_graph(&fixture.request, true).is_err());
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture
        .store
        .read_result(reference.key.tenant_id, &fixture.request.result_id)?
        .is_none());
    fixture.store.writer_access()?.get_mut()?.execute(
        "UPDATE context_versions SET body = ? WHERE owner_id = ? AND entity_key = ?",
        params![
            context.body,
            reference.key.owner_id,
            reference.key.entity_key
        ],
    )?;
    let receipt = fixture.store.commit_graph(&fixture.request, true)?;
    assert_eq!(fixture.store.commit_graph(&fixture.request, true)?, receipt);
    assert_eq!(
        fixture
            .owner
            .snapshot_result(reference.key.tenant_id, &fixture.request.result_id)?,
        Some(fixture.snapshot.clone())
    );
    assert_eq!(
        fixture
            .owner
            .installed_refs(reference.key.tenant_id, &fixture.request.result_id)?,
        Some(refs)
    );
    let retained = fixture
        .store
        .processor_result(&fixture.request.scope)?
        .ok_or("committed graph absent")?;
    let (_, contexts) = fixture.store.package_evidence(
        reference.key.tenant_id,
        std::slice::from_ref(&fixture.request.result_id),
    )?;
    assert_eq!(contexts, vec![reference]);
    assert_eq!(retained.body, fixture.request.body);
    Ok(())
}
