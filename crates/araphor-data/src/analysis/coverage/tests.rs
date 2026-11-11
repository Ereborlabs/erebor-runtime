use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn report(source: &EvidenceIntakeIdentityV1, revision: u64) -> ValidatedCoverageV1 {
    ValidatedCoverageV1 {
        identity: source.clone(),
        cpu_id: 1,
        revision,
        encoded_report: revision.to_be_bytes().to_vec(),
    }
}

#[test]
fn source_history_rejects_corruption() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let source = crate::analysis::tests::identity();
    store.accept_validated_coverage(report(&source, 7))?;
    let first = store.meta()?.commit_revision;
    store.accept_validated_coverage(report(&source, 9))?;
    let mut writer = store.writer()?;
    AnalysisStore::validate_state(writer.get()?, &root)?;
    for mutation in [
        "UPDATE source_versions SET identity_json = '{}' WHERE commit_revision = ?",
        "UPDATE source_versions SET tenant_id = X'00' WHERE commit_revision = ?",
        "UPDATE source_versions SET cpu_id = 2 WHERE commit_revision = ?",
        "UPDATE source_versions SET contiguous_cursor = 1 WHERE commit_revision = ?",
        "UPDATE source_versions SET retained_floor = 1 WHERE commit_revision = ?",
        "UPDATE source_versions SET coverage_revision = 8 WHERE commit_revision = ?",
        "UPDATE source_versions SET commit_revision = 0 WHERE commit_revision = ?",
        "UPDATE source_versions SET commit_revision = 99 WHERE commit_revision = ?",
        "DELETE FROM source_versions WHERE commit_revision = ?",
    ] {
        let transaction = writer.get_mut()?.transaction()?;
        assert_eq!(
            transaction.execute(mutation, params![first])?,
            1,
            "{mutation}"
        );
        assert!(
            AnalysisStore::validate_state(&transaction, &root).is_err(),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    AnalysisStore::validate_state(writer.get()?, &root)?;
    Ok(())
}
