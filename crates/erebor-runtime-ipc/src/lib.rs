//! Generated gRPC contracts and bounded Unix transport for Erebor Runtime IPC.

mod codec;
mod error;
mod frame;
pub mod transport;
pub mod v1;

pub use codec::{AsyncFrameCodec, SyncFrameCodec};
pub use error::{IpcProtocolError, Result};
pub use frame::{EreborIpcFrame, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN};
