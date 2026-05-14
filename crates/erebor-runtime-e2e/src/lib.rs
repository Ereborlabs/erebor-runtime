//! End-to-end test harnesses for erebor-runtime.

pub mod error;
pub mod system;
pub mod websocket;

pub use error::E2eError;
pub use system::MiniSystem;
pub use websocket::{
    assert_json_request_has_no_response, send_json_request, JsonWebSocketHandler,
    MiniJsonWebSocketServer,
};
