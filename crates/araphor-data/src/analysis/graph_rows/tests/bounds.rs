use super::*;

#[test]
fn canonical_graph_accepts_metadata() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot.previous_result_id = None;
    snapshot.context_notice_revision = 0;
    snapshot.witness_deadline_utc_ns = 0;
    snapshot.input_positions.clear();
    let body = serde_json::to_vec(&snapshot)?;
    let prepared = CanonicalGraph::new(snapshot.clone())?;
    assert_eq!(prepared.snapshot(), &snapshot);
    let before = fixture.store.meta()?;
    snapshot.previous_result_id = Some(format!("graph:{}", "x".repeat(128)));
    snapshot.context_notice_revision = u64::MAX;
    snapshot.witness_deadline_utc_ns = u64::MAX;
    snapshot.validate()?;
    let prepared = CanonicalGraph::new(snapshot.clone())?;
    assert_eq!(fixture.store.meta()?, before);
    let final_body = serde_json::to_vec(&snapshot)?;
    assert!(final_body.len() > body.len());
    assert_eq!(prepared.snapshot(), &snapshot);
    assert_eq!(prepared.into_snapshot(), snapshot);
    Ok(())
}

#[test]
fn graph_typed_commit_rejects_metadata() -> TestResult {
    let fixture = CommitFixture::new()?;
    let before = fixture.store.meta()?;
    assert!(fixture
        .store
        .commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &[],
            &[],
            &[],
            true,
            || Ok(()),
        )
        .is_err());
    for fault in [0, 1, 2] {
        let mut request = fixture.request.clone();
        request.body.clear();
        match fault {
            0 => request.scope.identity.tenant_id = [99; 16],
            1 => request.witnesses[0].expires_utc_ns += 1,
            _ => request.consumed_cursor += 1,
        }
        assert!(fixture
            .store
            .commit_graph_snapshot(
                request,
                CanonicalGraph::new(fixture.snapshot.clone())?,
                &[],
                &[],
                &[],
                true,
                || Ok(()),
            )
            .is_err());
        assert_eq!(fixture.store.meta()?, before);
        assert!(fixture
            .store
            .read_result(
                fixture.request.scope.identity.tenant_id,
                &fixture.request.result_id
            )?
            .is_none());
    }
    Ok(())
}
