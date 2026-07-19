//! Fast local IPC contract between Erebor session brokers and process guards.

mod codec;
mod error;
mod frame;
#[cfg(test)]
mod standalone;
pub mod v1;

pub use codec::{AsyncFrameCodec, SyncFrameCodec};
pub use error::{IpcProtocolError, Result};
pub use frame::{EreborIpcFrame, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN};
