#![cfg(feature = "test-fixtures")]

use araphor_data::{AnalysisStore, Error};

#[test]
fn graph_schema_reopens() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.verify_state()?;
    drop(store);
    let store = AnalysisStore::open(&root)?;
    store.verify_state()?;
    store.fault_write("CREATE TABLE graph_unexpected (id UBIGINT)", &[])?;
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(Error::GraphInvalid {
            field: "native graph schema",
            ..
        })
    ));
    Ok(())
}
