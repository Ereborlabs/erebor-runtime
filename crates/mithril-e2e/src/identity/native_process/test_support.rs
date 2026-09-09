use std::path::PathBuf;

use super::super::IdentityTestRunner;

pub(super) fn runner() -> IdentityTestRunner {
    IdentityTestRunner::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}
