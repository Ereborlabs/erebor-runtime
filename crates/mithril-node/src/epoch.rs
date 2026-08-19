use std::fs;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use snafu::{ensure, ResultExt as _};
use uuid::Uuid;

use crate::error::{InvalidConfigurationSnafu, IoSnafu};
use crate::Result;

pub(crate) struct NodeEpochs;

impl NodeEpochs {
    pub(crate) fn evidence_wal_directory(state_directory: &Path) -> PathBuf {
        state_directory.join("evidence-wal-v1")
    }

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

    pub(crate) fn label_epoch(state_directory: &Path, recover: bool) -> Result<u64> {
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let path = state_directory.join("label-epoch");
        let current = read_epoch(&path, "label")?;
        if recover {
            ensure!(
                current > 0,
                InvalidConfigurationSnafu {
                    reason: "pinned identity state has no persisted label epoch",
                }
            );
            return Ok(current);
        }
        write_next_epoch(state_directory, &path, current, "label")
    }

    pub(crate) fn source_epoch(state_directory: &Path, recover: bool) -> Result<u64> {
        fs::create_dir_all(state_directory).context(IoSnafu {
            path: state_directory,
        })?;
        let path = state_directory.join("evidence-source-epoch");
        let current = read_epoch(&path, "evidence source")?;
        let durable_state_exists = Self::evidence_wal_directory(state_directory).exists()
            || state_directory.join("evidence-coverage-v1.json").exists();
        if recover && current > 0 {
            return Ok(current);
        }
        if recover && durable_state_exists {
            ensure!(
                current > 0,
                InvalidConfigurationSnafu {
                    reason: "recovered effect source has no persisted source epoch",
                }
            );
        }
        write_next_epoch(state_directory, &path, current, "evidence source")
    }
}

fn read_epoch(path: &Path, name: &str) -> Result<u64> {
    match fs::read_to_string(path) {
        Ok(value) => value.trim().parse::<u64>().map_err(|error| {
            InvalidConfigurationSnafu {
                reason: format!("stored {name} epoch is invalid: {error}"),
            }
            .build()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(source) => Err(crate::Error::Io {
            path: path.to_owned(),
            source,
            location: snafu::Location::default(),
        }),
    }
}

fn write_next_epoch(state_directory: &Path, path: &Path, current: u64, name: &str) -> Result<u64> {
    let next = current.checked_add(1).ok_or_else(|| {
        InvalidConfigurationSnafu {
            reason: format!("{name} epoch exhausted"),
        }
        .build()
    })?;
    let temporary = path.with_extension("next");
    let mut file = File::create(&temporary).context(IoSnafu { path: &temporary })?;
    file.write_all(format!("{next}\n").as_bytes())
        .context(IoSnafu { path: &temporary })?;
    file.sync_all().context(IoSnafu { path: &temporary })?;
    fs::rename(&temporary, path).context(IoSnafu { path })?;
    File::open(state_directory)
        .context(IoSnafu {
            path: state_directory,
        })?
        .sync_all()
        .context(IoSnafu {
            path: state_directory,
        })?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::NodeEpochs;
    use crate::{EvidenceWal, EvidenceWalLimits};

    #[test]
    fn epochs_are_persistent_monotonic_and_nonzero() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        assert_eq!(NodeEpochs::label_epoch(directory.path(), false)?, 1);
        assert_eq!(NodeEpochs::label_epoch(directory.path(), true)?, 1);
        assert_eq!(NodeEpochs::label_epoch(directory.path(), false)?, 2);
        assert_eq!(NodeEpochs::source_epoch(directory.path(), false)?, 1);
        assert_eq!(NodeEpochs::source_epoch(directory.path(), true)?, 1);
        assert_eq!(NodeEpochs::source_epoch(directory.path(), false)?, 2);
        Ok(())
    }

    #[test]
    fn first_effect_source_can_follow_identity_only_recovery(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        assert_eq!(NodeEpochs::label_epoch(directory.path(), false)?, 1);
        assert_eq!(NodeEpochs::source_epoch(directory.path(), true)?, 1);
        Ok(())
    }

    #[test]
    fn durable_evidence_without_its_source_epoch_is_rejected(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let _wal = EvidenceWal::open(
            NodeEpochs::evidence_wal_directory(directory.path()),
            EvidenceWalLimits::default(),
        )?;
        assert!(NodeEpochs::source_epoch(directory.path(), true).is_err());
        Ok(())
    }
}
