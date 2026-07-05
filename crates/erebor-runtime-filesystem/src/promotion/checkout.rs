use std::{fs, path::Path};

use snafu::{ensure, ResultExt};

use crate::{
    error::{OstreeCommandFailedSnafu, PromotionIoSnafu},
    ostree::OstreeCommandRunner,
    Result,
};

pub(super) fn checkout_tree(
    runner: &impl OstreeCommandRunner,
    repo: &Path,
    ref_name: &str,
    destination: &Path,
    operation: &'static str,
) -> Result<()> {
    reset_destination(destination)?;
    let args = vec![
        String::from("checkout"),
        String::from("--user-mode"),
        ref_name.to_owned(),
        destination.display().to_string(),
    ];
    let output = runner.run(repo, &args)?;
    ensure!(
        output.success(),
        OstreeCommandFailedSnafu {
            repo: repo.to_path_buf(),
            operation,
            code: output.code(),
            stderr: output.stderr().to_owned(),
        }
    );
    Ok(())
}

fn reset_destination(destination: &Path) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination).context(PromotionIoSnafu {
            action: "remove ostree checkout destination",
            path: destination,
        })?;
    }
    let parent = destination
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    fs::create_dir_all(&parent).context(PromotionIoSnafu {
        action: "create ostree checkout parent",
        path: parent.as_path(),
    })
}
