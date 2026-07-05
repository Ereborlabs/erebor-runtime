use std::path::Path;

use snafu::ensure;

use crate::{
    error::{OstreeCommandFailedSnafu, OstreeInitFailedSnafu},
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
    configure_min_free_space(repo, runner)?;
    Ok(())
}

fn configure_min_free_space(repo: &Path, runner: &impl OstreeCommandRunner) -> Result<()> {
    let args = vec![
        String::from("config"),
        String::from("set"),
        String::from("core.min-free-space-percent"),
        String::from("0"),
    ];
    let output = runner.run(repo, &args)?;
    ensure!(
        output.success(),
        OstreeCommandFailedSnafu {
            repo: repo.to_path_buf(),
            operation: "configure ostree minimum free space",
            code: output.code(),
            stderr: output.stderr().to_owned(),
        }
    );
    Ok(())
}
