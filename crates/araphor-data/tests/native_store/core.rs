use super::*;
use araphor_data::analysis::{AnalysisStore, ANALYSIS_SCHEMA_VERSION};
use std::{fs, os::unix::fs::PermissionsExt as _};

fn inventory(
    branch: &fjall::Branch,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error>> {
    Ok(branch
        .snapshot()?
        .iter()
        .map(|row| row.map(|(key, value)| (key.to_vec(), value.to_vec())))
        .collect::<fjall::Result<_>>()?)
}

#[test]
fn analysis_store_reopen_rollback() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let initial = store.meta()?;
    assert_eq!(i64::from(initial.schema_version), ANALYSIS_SCHEMA_VERSION);
    assert_eq!(initial.commit_revision, 0);
    assert!(AnalysisStore::open(&root).is_err());
    let before = inventory(store.branch())?;
    let head = store.database().inner().journal_head()?;
    let changed = store.subscribe_revision();
    {
        let mut transaction = store.write()?;
        transaction.native().insert(HEAD, 1u64.to_be_bytes());
    }
    assert_eq!(store.meta()?, initial);
    assert_eq!(inventory(store.branch())?, before);
    assert_eq!(store.database().inner().journal_head()?, head);
    assert!(!changed.has_changed()?);
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(reopened.meta()?, initial);
    assert_eq!(inventory(reopened.branch())?, before);
    Ok(())
}

#[test]
fn analysis_store_schema_permissions() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("schema");
    let store = AnalysisStore::open(&root)?;
    let before = store.meta()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?, before);
    {
        let mut transaction = store.branch().write_tx()?;
        transaction.insert(b"\0data/schema", 0u64.to_be_bytes());
        transaction.commit_stamped([cut(before.commit_revision)])?;
    }
    let corrupted = inventory(store.branch())?;
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(Error::NativeState {
            field: "logical Data metadata",
            ..
        })
    ));
    let database = SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = database.branch("data")?.ok_or("corrupted branch")?;
    assert_eq!(inventory(&branch)?, corrupted);
    assert_eq!(
        branch.snapshot()?.get(b"\0data/schema")?.as_deref(),
        Some(0u64.to_be_bytes().as_slice())
    );
    drop((branch, database));
    let root = directory.path().join("nonprivate");
    let store = AnalysisStore::open(&root)?;
    drop(store);
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755))?;
    assert!(AnalysisStore::open(&root).is_err());
    assert!(AnalysisStore::open("relative-analysis").is_err());
    Ok(())
}
