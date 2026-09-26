//! Limits for Mithril admission transport and deadlines.

pub const TIMEOUT_MS: std::ops::RangeInclusive<u128> = 100..=30_000;
pub const REQUEST_BYTES: std::ops::RangeInclusive<usize> = 1_024..=1_048_576;
pub const RUNTIME_TIMEOUT_SECONDS: std::ops::RangeInclusive<u64> = 1..=30;
pub const RESPONSE_BYTES: usize = 4_096;
