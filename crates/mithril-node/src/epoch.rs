use std::fs;
use std::path::{Path, PathBuf};

use snafu::{ensure, ResultExt as _};
use uuid::Uuid;

use crate::error::{InvalidConfigurationSnafu, IoSnafu};
use crate::Result;

pub(crate) struct NodeEpochs;

impl NodeEpochs {
    pub(crate) fn boot_id() -> Result<[u8; 16]> {
        let path = PathBuf::from("/proc/sys/kernel/random/boot_id");
        let value = fs::read_to_string(&path).context(IoSnafu { path: &path })?;
        Uuid::parse_str(value.trim())
            .map(|id| *id.as_bytes())
            .map_err(|error| {
                InvalidConfigurationSnafu {
                    reason: format!("kernel boot ID is invalid: {error}"),
                }
                .build()
            })
    }

    pub(crate) fn next_label_epoch(state_directory: &Path) -> Result<u64> {
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let path = state_directory.join("label-epoch");
        let current = match fs::read_to_string(&path) {
            Ok(value) => value.trim().parse::<u64>().map_err(|error| {
                InvalidConfigurationSnafu {
                    reason: format!("stored label epoch is invalid: {error}"),
                }
                .build()
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(source) => {
                return Err(crate::Error::Io {
                    path,
                    source,
                    location: snafu::Location::default(),
                })
            }
        };
        let next = current.checked_add(1).ok_or_else(|| {
            InvalidConfigurationSnafu {
                reason: "label epoch exhausted".to_owned(),
            }
            .build()
        })?;
        ensure!(
            next > 0,
            InvalidConfigurationSnafu {
                reason: "label epoch must be nonzero",
            }
        );
        let temporary = state_directory.join("label-epoch.next");
        fs::write(&temporary, format!("{next}\n")).context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &path).context(IoSnafu { path: &path })?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use snafu::ResultExt as _;

    use super::NodeEpochs;
    use crate::error::IoSnafu;

    #[test]
    fn label_epoch_is_persistent_monotonic_and_nonzero() -> crate::Result<()> {
        let directory = tempfile::tempdir().context(IoSnafu {
            path: "temporary epoch directory",
        })?;
        assert_eq!(NodeEpochs::next_label_epoch(directory.path())?, 1);
        assert_eq!(NodeEpochs::next_label_epoch(directory.path())?, 2);
        Ok(())
    }
}
