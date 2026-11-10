use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{
    results::{ResultBody, StoredResult},
    InstanceRecord, Records,
};
use crate::analysis::{
    managed::{
        source::publication::{PreparedSource, SourcePublication},
        PreparedMemory, Step,
    },
    native::{
        context::ContextRecord, progress::Processor, DataView, DataWrite, ManagedCommit,
        NativeStore,
    },
    PackageResultRefV1,
};
use crate::{
    AnalysisReadControl, DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, ManagedDestination,
    ManagedGraphOperation, ManagedReceipt, PackageErrorCodeV1 as Code, Result, StorePositionV1,
};

mod frozen;
mod history;
mod inputs;
mod publication;
mod records;
mod recovery;
mod windows;

#[derive(Deserialize, Serialize)]
pub(in crate::analysis::native) struct SourceRecord {
    pub(in crate::analysis::native) captured: StorePositionV1,
    pub(in crate::analysis::native) coverage: u64,
    gaps: Vec<(u64, u64)>,
    count: u64,
    restricted: u64,
    append: bool,
}

#[derive(Deserialize, Eq, PartialEq, Serialize)]
struct Member {
    position: StorePositionV1,
    origin: u64,
    restricted: u64,
}
