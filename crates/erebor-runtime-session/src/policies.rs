use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_policy::{LocalPolicy, PolicySet};
use snafu::ResultExt;

use crate::{
    error::{InvalidPolicySnafu, ReadPolicySnafu},
    SessionExecutionError,
};

fn read_policy(path: &Path) -> Result<LocalPolicy, SessionExecutionError> {
    tracing::debug!(path = %path.display(), "reading session policy");
    let source = fs::read_to_string(path).context(ReadPolicySnafu {
        path: path.to_path_buf(),
    })?;

    LocalPolicy::from_json_str(&source).context(InvalidPolicySnafu)
}

pub(crate) fn read_policy_set(paths: &[PathBuf]) -> Result<PolicySet, SessionExecutionError> {
    let policies = paths
        .iter()
        .map(|path| read_policy(path))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PolicySet::from_policies(policies))
}
