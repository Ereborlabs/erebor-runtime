#![allow(unsafe_code)]

use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use memmap2::{MmapMut, MmapOptions};
use serde::{de::DeserializeOwned, Serialize};
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::Result;

pub(super) const EMPTY: u32 = 0;
pub(super) const READY: u32 = 1;
pub(super) const REQUEST: u32 = 2;
pub(super) const RESPONSE: u32 = 3;

const MAILBOX_BYTES: usize = 64 * 1024;
const LENGTH_OFFSET: usize = size_of::<u32>();
const PAYLOAD_OFFSET: usize = LENGTH_OFFSET + size_of::<u32>();

pub(super) struct SharedMailbox {
    map: MmapMut,
}

impl SharedMailbox {
    pub(super) fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .context(IoSnafu { path })?;
        file.set_len(MAILBOX_BYTES as u64)
            .context(IoSnafu { path })?;
        Self::map(path, &file)
    }

    pub(super) fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .context(IoSnafu { path })?;
        ensure!(
            file.metadata().context(IoSnafu { path })?.len() == MAILBOX_BYTES as u64,
            InvalidInputSnafu {
                path,
                reason: "effect mailbox has the wrong size",
            }
        );
        Self::map(path, &file)
    }

    fn map(path: &Path, file: &std::fs::File) -> Result<Self> {
        // SAFETY: the owner creates a fixed-size file before either mapping is
        // made and keeps it until the child exits. Neither process truncates it.
        let map = unsafe { MmapOptions::new().len(MAILBOX_BYTES).map_mut(file) }
            .context(IoSnafu { path })?;
        Ok(Self { map })
    }

    pub(super) fn state(&self) -> u32 {
        self.state_atomic().load(Ordering::Acquire)
    }

    pub(super) fn publish<T: Serialize>(&mut self, state: u32, value: &T) -> Result<()> {
        let payload = serde_json::to_vec(value).context(JsonSnafu {
            path: Path::new("effect mailbox"),
        })?;
        ensure!(
            payload.len() <= MAILBOX_BYTES - PAYLOAD_OFFSET,
            InvalidInputSnafu {
                path: Path::new("effect mailbox"),
                reason: "effect mailbox payload is too large",
            }
        );
        let length = u32::try_from(payload.len()).map_err(|error| {
            InvalidInputSnafu {
                path: Path::new("effect mailbox"),
                reason: format!("effect mailbox length overflow: {error}"),
            }
            .build()
        })?;
        self.map[LENGTH_OFFSET..PAYLOAD_OFFSET].copy_from_slice(&length.to_ne_bytes());
        self.map[PAYLOAD_OFFSET..PAYLOAD_OFFSET + payload.len()].copy_from_slice(&payload);
        self.state_atomic().store(state, Ordering::Release);
        Ok(())
    }

    pub(super) fn read<T: DeserializeOwned>(&self) -> Result<T> {
        let length =
            u32::from_ne_bytes(self.map[LENGTH_OFFSET..PAYLOAD_OFFSET].try_into().map_err(
                |error| {
                    InvalidInputSnafu {
                        path: Path::new("effect mailbox"),
                        reason: format!("effect mailbox length is invalid: {error}"),
                    }
                    .build()
                },
            )?) as usize;
        ensure!(
            length <= MAILBOX_BYTES - PAYLOAD_OFFSET,
            InvalidInputSnafu {
                path: Path::new("effect mailbox"),
                reason: "effect mailbox contains an invalid payload length",
            }
        );
        serde_json::from_slice(&self.map[PAYLOAD_OFFSET..PAYLOAD_OFFSET + length]).context(
            JsonSnafu {
                path: Path::new("effect mailbox"),
            },
        )
    }

    pub(super) fn reset(&self) {
        self.state_atomic().store(EMPTY, Ordering::Release);
    }

    pub(super) fn set_state(&self, state: u32) {
        self.state_atomic().store(state, Ordering::Release);
    }

    fn state_atomic(&self) -> &AtomicU32 {
        // SAFETY: an mmap begins at page alignment and is at least four bytes.
        // Both processes access this word only through AtomicU32.
        unsafe { &*self.map.as_ptr().cast::<AtomicU32>() }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{SharedMailbox, REQUEST, RESPONSE};

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Message {
        value: u32,
    }

    #[test]
    fn shared_mappings_round_trip_without_stream_io() -> crate::Result<()> {
        let directory = tempfile::tempdir().map_err(|source| crate::Error::Io {
            path: "effect mailbox fixture".into(),
            source,
            location: snafu::location!(),
        })?;
        let path = directory.path().join("mailbox");
        let mut parent = SharedMailbox::create(&path)?;
        let mut child = SharedMailbox::open(&path)?;

        parent.publish(REQUEST, &Message { value: 7 })?;
        assert_eq!(child.state(), REQUEST);
        assert_eq!(child.read::<Message>()?, Message { value: 7 });
        child.publish(RESPONSE, &Message { value: 9 })?;
        assert_eq!(parent.state(), RESPONSE);
        assert_eq!(parent.read::<Message>()?, Message { value: 9 });
        parent.reset();
        Ok(())
    }
}
