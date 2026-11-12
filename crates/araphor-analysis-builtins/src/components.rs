pub const DISCOVERY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/discovery.wasm"));
pub const CREDENTIALS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/credentials.wasm"));
pub const DETECTOR: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/detector.wasm"));
pub const RUNTIME: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/runtime.wasm"));
