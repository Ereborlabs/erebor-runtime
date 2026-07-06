use std::{
    fs,
    path::{Path, PathBuf},
};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::ResultExt;

use crate::cli::external_error;

pub struct SessionAudit {
    path: PathBuf,
}

impl SessionAudit {
    pub fn from_workspace(workspace: &Path) -> Result<Self, E2eError> {
        let registry = workspace.join(".erebor/sessions");
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&registry).context(IoSnafu)? {
            let path = entry.context(IoSnafu)?.path().join("audit.jsonl");
            if path.exists() {
                candidates.push(path);
            }
        }
        if candidates.len() == 1 {
            Ok(Self {
                path: candidates.remove(0),
            })
        } else {
            Err(external_error(
                "locate session audit",
                std::io::Error::other(format!(
                    "expected one audit under {}, got {}",
                    registry.display(),
                    candidates.len()
                )),
            ))
        }
    }

    pub fn read(&self) -> Result<String, E2eError> {
        fs::read_to_string(&self.path).context(IoSnafu)
    }
}
