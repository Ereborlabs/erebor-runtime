use super::*;

fn check_source_history(report: bool) -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = identity();
    if report {
        store.accept_validated_coverage(coverage(&source, 1))?;
    } else {
        store.record_recovery_floor(&source, 4)?;
    }
    let revision = store.meta()?.commit_revision;
    let reports = store
        .coverage_changes(
            &selection(&source),
            StorePositionV1 {
                commit_revision: 0,
                ordinal: u32::MAX,
            },
            &AnalysisReadControl::default(),
        )?
        .reports;
    let gaps = store.recovery_gaps(&source, 0)?;
    if report {
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reference.position.commit_revision, revision);
    } else {
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].commit_revision, revision);
    }
    for value in [1, 2] {
        let mut tx = store.write()?;
        tx.native().insert(b"history-point", [value]);
        tx.commit([])?;
    }
    store.checkpoint()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let historical = store.read_at(revision)?;
    assert_eq!(historical.recovery_gaps(&source, 0)?, gaps);
    let actual = historical.coverage_changes(
        &selection(&source),
        StorePositionV1 {
            commit_revision: 0,
            ordinal: u32::MAX,
        },
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(actual, reports);
    assert!(store.read_at(0).is_err());
    Ok(())
}

#[test]
fn coverage_ref_keeps_history() -> TestResult {
    check_source_history(true)
}

#[test]
fn recovery_ref_keeps_history() -> TestResult {
    check_source_history(false)
}
