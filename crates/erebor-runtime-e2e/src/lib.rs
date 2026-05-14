//! End-to-end test harnesses for erebor-runtime.

pub mod error;
pub mod system;
pub mod websocket;

pub use error::E2eError;
pub use system::MiniSystem;
pub use websocket::{send_json_request, JsonWebSocketHandler, MiniJsonWebSocketServer};
