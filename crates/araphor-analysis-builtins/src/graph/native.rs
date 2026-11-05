use super::*;
use araphor_analysis_types::arrow::{decode, encode, port};
use araphor_analysis_types::arrow::views;
use std::sync::OnceLock;
mod units;

fn invalid(field: &str) -> sdk::Error {
    sdk::Error::contract(sdk::ErrorCode::Invalid, field)
}

#[cfg(test)]
mod tests;
