use std::{fs, path::Path};

use serde::Serialize;
use snafu::ResultExt as _;

use crate::{
    error::{IoSnafu, JsonSnafu},
    Result,
};

mod data_store;
#[cfg(test)]
mod packages;
mod query_follow;
#[cfg(test)]
mod roundtrip;
#[cfg(test)]
mod storage;
mod storage_contract;

pub use data_store::DataStoreQualification;
pub use query_follow::QueryFollowQualification;
pub use storage_contract::run as run_discovery_storage_contract;

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context(IoSnafu { path })?;
    serde_json::to_writer_pretty(&file, value).context(JsonSnafu { path })?;
    file.sync_all().context(IoSnafu { path })
}
