use std::path::Path;

use snafu::ensure;

use crate::{
    error::OstreeInitFailedSnafu,
    ostree::{OstreeCommandRunner, SystemOstreeCommandRunner},
    Result,
};

pub(super) fn initialize_ostree_repo(repo: &Path) -> Result<()> {
    initialize_ostree_repo_with_runner(repo, &SystemOstreeCommandRunner)
}

fn initialize_ostree_repo_with_runner(
    repo: &Path,
    runner: &impl OstreeCommandRunner,
) -> Result<()> {
    let args = vec![String::from("init"), String::from("--mode=bare-user-only")];
    let output = runner.run(repo, &args)?;
    ensure!(
        output.success(),
        OstreeInitFailedSnafu {
            repo: repo.to_path_buf(),
            code: output.code(),
            stderr: output.stderr().to_owned(),
        }
    );
    Ok(())
}
