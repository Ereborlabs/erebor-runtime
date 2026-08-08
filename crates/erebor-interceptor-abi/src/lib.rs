mod abi;
mod generated;
mod portable;

pub use generated::*;
pub use portable::*;

/// Generated from the same authority as the Rust BPF-map layouts.
pub const C_HEADER_V1: &str =
    include_str!(concat!(env!("OUT_DIR"), "/erebor_interceptor_abi_v1.h"));

/// Stable candidate ABI revision. It is not a platform qualification result.
pub const ABI_REVISION_V1: u32 = 1;

#[cfg(test)]
mod tests;
