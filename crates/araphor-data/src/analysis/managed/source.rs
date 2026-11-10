use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::codec::ManagedCodec;
use super::model::{Attempt, ManagedInstance, ManagedRead, Step};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisDatabaseSnafu, AnalysisGapV1, AnalysisReadControl, AnalysisReadModeV1,
    AnalysisSelectionV1, AnalysisStore, AnalysisStoreMetaV1, AnalysisStreamIdentityV1,
    AnalysisTableRead, AnalysisTableRequests, PackageErrorCodeV1 as Code, Result, StorePositionV1,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSourceRef {
    pub result: PackageResultRefV1,
    pub position: StorePositionV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ManagedSourceRead {
    Initial,
    Changes(ManagedSourceRef),
}

pub(in crate::analysis) struct SourceEvidence {
    pub witnesses: Vec<crate::AnalysisWitnessV1>,
    pub contexts: Vec<crate::AnalysisContextRefV1>,
}

impl SourceEvidence {
    pub(in crate::analysis) fn metadata_bytes<'a>(
        witnesses: impl Iterator<Item = &'a crate::AnalysisWitnessV1>,
        contexts: impl Iterator<Item = &'a crate::AnalysisContextRefV1>,
    ) -> Result<usize> {
        let mut bytes = 0usize;
        for value in witnesses {
            let node = match &value.identity {
                AnalysisStreamIdentityV1::Evidence(source) => &source.node_id,
                AnalysisStreamIdentityV1::Diagnostic(source) => &source.node_id,
            };
            bytes = bytes
                .checked_add(
                    12 * (std::mem::size_of::<crate::AnalysisWitnessV1>()
                        + std::mem::size_of::<AnalysisStreamIdentityV1>()),
                )
                .and_then(|bytes| bytes.checked_add(node.capacity().checked_mul(4)?))
                .ok_or_else(|| Code::Limit.error("managed evidence memory"))?;
        }
        for value in contexts {
            bytes = bytes
                .checked_add(
                    12 * (std::mem::size_of::<crate::AnalysisContextRefV1>()
                        + std::mem::size_of::<crate::AnalysisContextKeyV1>()),
                )
                .and_then(|bytes| bytes.checked_add(value.key.allocated_bytes().checked_mul(4)?))
                .ok_or_else(|| Code::Limit.error("managed context memory"))?;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug)]
pub struct ManagedSourceFrame {
    pub(super) tables: Vec<sdk::Dataset>,
    pub(super) removals: BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    pub(super) proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    scope: Arc<SourceScope>,
    selected: Arc<Mutex<SourceSelection>>,
    coverage: Vec<coverage::SourceCoverage>,
}

#[derive(Debug, PartialEq)]
pub struct SourceScope {
    tenant: [u8; 16],
    instance: String,
    generation: u64,
    store: uuid::Uuid,
    schema: u32,
    recovery: u64,
    read: ManagedSourceRead,
    position: StorePositionV1,
    selection: AnalysisSelectionV1,
    tables: AnalysisTableRequests,
    event_ranges: Option<Vec<(u64, u64)>>,
    context_owners: Option<BTreeSet<String>>,
}

#[derive(Debug, Default)]
struct SourceSelection {
    frozen: bool,
    input: Option<Arc<ManagedInputSelection>>,
    witnesses: BTreeMap<(AnalysisStreamIdentityV1, u64), crate::AnalysisWitnessV1>,
    contexts: BTreeMap<(crate::AnalysisContextKeyV1, u64), crate::AnalysisContextRefV1>,
    cells: Vec<Arc<SourceCells>>,
    calls: BTreeMap<u64, SourceCall>,
}

#[derive(Default)]
struct SourceCall {
    cells: Vec<Arc<SourceCells>>,
    leases: Vec<Arc<dyn std::any::Any + Send + Sync>>,
    derived: Vec<Arc<ManagedDerivedSource>>,
}

impl std::fmt::Debug for SourceCall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCall")
            .field("reads", &self.cells.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct ManagedSourceBlock {
    scope: Arc<SourceScope>,
    proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    rows: Arc<Vec<SourceRow>>,
    table: Arc<str>,
    batch: Arc<sdk::RecordBatch>,
}

#[derive(Clone, Debug)]
enum SourceRow {
    Event(crate::AnalysisWitnessV1, StorePositionV1),
    Context(crate::AnalysisContextRefV1),
}

#[derive(Clone, Debug)]
pub struct ManagedSourceRows {
    scope: Arc<SourceScope>,
    proof: Arc<OnceLock<Arc<PackageResultRefV1>>>,
    witnesses: Vec<crate::AnalysisWitnessV1>,
    contexts: Vec<crate::AnalysisContextRefV1>,
    selected_position: StorePositionV1,
    cells: Arc<SourceCells>,
}

struct SourceCells {
    table: Arc<str>,
    batch: Arc<sdk::RecordBatch>,
    rows: Arc<Vec<SourceRow>>,
    indices: Vec<usize>,
    _lease: Arc<dyn std::any::Any + Send + Sync>,
}

impl std::fmt::Debug for SourceCells {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCells")
            .field("table", &self.table)
            .field("rows", &self.indices.len())
            .finish_non_exhaustive()
    }
}

mod allocation;
mod canonical;
mod check;
mod coverage;
mod derived;
pub use derived::{ManagedDerivedSource, ManagedSourceHistory};
pub(in crate::analysis) mod import;
mod input;
mod reader;
mod selection;
pub use input::ManagedInputSelection;
pub(in crate::analysis) mod publication;

impl ManagedSourceRead {
    pub fn after(&self) -> Option<StorePositionV1> {
        match self {
            Self::Initial => None,
            Self::Changes(parent) => Some(parent.position),
        }
    }
}

impl ManagedSourceFrame {
    pub fn scope(&self) -> &Arc<SourceScope> {
        &self.scope
    }

    pub fn proof(&self) -> Option<&Arc<PackageResultRefV1>> {
        self.proof.get()
    }

    pub(super) fn check_proof(&self, proof: &PackageResultRefV1) -> Result<()> {
        if self
            .proof
            .get()
            .is_some_and(|saved| saved.as_ref() != proof)
        {
            return Err(Code::Conflict.error("managed source proof"));
        }
        Ok(())
    }

    pub(super) fn commit_proof(&self, proof: Arc<PackageResultRefV1>) {
        self.proof.get_or_init(|| proof);
    }

    pub fn read(&self) -> &ManagedSourceRead {
        &self.scope.read
    }

    pub fn position(&self) -> StorePositionV1 {
        self.scope.position
    }

    pub fn selection(&self) -> &AnalysisSelectionV1 {
        &self.scope.selection
    }

    pub fn projection(&self) -> &AnalysisTableRequests {
        &self.scope.tables
    }

    pub fn datasets(&self) -> &[sdk::Dataset] {
        &self.tables
    }

    pub fn removals(&self) -> &BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>> {
        &self.removals
    }
}

impl SourceScope {
    fn check_witness(&self, witness: &crate::AnalysisWitnessV1) -> Result<()> {
        use std::ops::RangeBounds as _;
        let valid = match &witness.identity {
            AnalysisStreamIdentityV1::Evidence(source) => {
                source.valid()
                    && self.selection.includes_source(source)
                    && witness.cursor != 0
                    && (self.selection.cursor_from, self.selection.cursor_until)
                        .contains(&witness.cursor)
            }
            AnalysisStreamIdentityV1::Diagnostic(_) => false,
        };
        if !valid {
            return Err(Code::Invalid.error("managed source event scope"));
        }
        Ok(())
    }

    fn check_context(&self, context: &crate::AnalysisContextRefV1) -> Result<()> {
        if !context.key.valid()
            || context.key.tenant_id != self.selection.tenant_id
            || (!self.selection.contexts.is_all()
                && !self.selection.contexts.as_slice().contains(&context.key))
            || self
                .context_owners
                .as_ref()
                .is_some_and(|owners| !owners.contains(&context.key.owner_id))
            || context.commit_revision == 0
            || context.commit_revision > self.position.commit_revision
        {
            return Err(Code::Invalid.error("managed source context scope"));
        }
        Ok(())
    }

    pub(super) fn schema(&self, name: &str) -> Result<sdk::Schema> {
        let columns = self
            .tables
            .get(name)
            .and_then(Option::as_ref)
            .ok_or_else(|| Code::Invalid.error("managed source projection"))?;
        let schema = AnalysisStore::table_schemas()
            .get(name)
            .ok_or_else(|| Code::Invalid.error("managed source relation"))?;
        schema
            .project(&columns.iter().copied().collect::<Vec<_>>())
            .context(crate::PackageArrowSnafu)
    }
}

impl ManagedSourceFrame {
    pub(super) fn check_tables(&self) -> Result<()> {
        let names = self
            .scope
            .tables
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, _)| name.as_str());
        if !names.eq(self.tables.iter().map(|data| data.name.as_str())) {
            return Err(Code::Invalid.error("managed source table names"));
        }
        for data in &self.tables {
            let schema = self.scope.schema(&data.name)?;
            if data
                .batches
                .iter()
                .any(|batch| batch.schema().as_ref() != &schema)
            {
                return Err(Code::Invalid.error("managed source table shape"));
            }
        }
        Ok(())
    }
}
