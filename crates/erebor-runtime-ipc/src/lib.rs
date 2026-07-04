//! Fast local IPC contract between Erebor session brokers and process guards.

mod error;
mod frame;
pub mod v1;

pub use error::{IpcProtocolError, Result};
pub use frame::{EreborIpcFrame, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN};
