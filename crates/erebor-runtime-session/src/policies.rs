use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_policy::{LocalPolicy, PolicySet};
use erebor_runtime_telemetry::debug;
use snafu::ResultExt;

use crate::{
    error::{InvalidPolicySnafu, ReadPolicySnafu},
    SessionExecutionError,
};

fn read_policy(path: &Path) -> Result<LocalPolicy, SessionExecutionError> {
    debug!("reading session policy", path = %path.display());
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
