use std::path::PathBuf;

use super::{IdentityTestRunner, IDENTITY_FIXTURES, REQUIRED_IDENTITY_MAPS};

#[test]
fn production_object_and_identity_fixture_allocation_are_exact() -> crate::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let temporary = tempfile::tempdir().map_err(|error| {
        super::invalid_state(format!("create identity test directory: {error}"))
    })?;

    let bundle = IdentityTestRunner::new(root).verify(temporary.path())?;

    assert_eq!(bundle.schema_version, 1);
    assert_eq!(bundle.layout.maps.len(), REQUIRED_IDENTITY_MAPS.len());
    assert_eq!(bundle.identity_fixture_ids.len(), IDENTITY_FIXTURES.len());
    Ok(())
}
