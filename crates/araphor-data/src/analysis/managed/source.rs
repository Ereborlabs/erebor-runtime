use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};
use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::codec::ManagedCodec;
use super::model::{Attempt, ManagedInstance, ManagedRead, RecordInput, Step};
use crate::analysis::PackageResultRefV1;
use crate::{
    AnalysisDatabaseSnafu, AnalysisGapV1, AnalysisReadControl, AnalysisReadModeV1,
    AnalysisSelectionV1, AnalysisSourceReceiptV1, AnalysisStore, AnalysisStoreMetaV1,
    AnalysisStreamIdentityV1, AnalysisTableRead, AnalysisTableRequests, CoverageReportRef,
    PackageErrorCodeV1 as Code, Result, StorePositionV1,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSourceMetadata {
    pub receipt: AnalysisSourceReceiptV1,
    pub state: ManagedSourceState,
    pub expired: Vec<AnalysisGapV1>,
    pub recovery: Vec<AnalysisGapV1>,
    pub coverage: Option<CoverageReportRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ManagedSourceState {
    Initial {
        high: u64,
        pending: Vec<AnalysisGapV1>,
    },
    Changes {
        accepted: Vec<AnalysisGapV1>,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceContract {
    pub read: ManagedSourceRead,
    pub position: StorePositionV1,
    pub selection: AnalysisSelectionV1,
    pub tables: AnalysisTableRequests,
    pub event_ranges: Option<Vec<(u64, u64)>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecordSource {
    pub contract: SourceContract,
    pub tables: Vec<RecordInput>,
    pub removals: BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>>,
    pub metadata: Vec<ManagedSourceMetadata>,
    pub support: Vec<SourceSupport>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceSupport {
    pub origin: ManagedSourceRef,
    pub witnesses: Vec<usize>,
    pub contexts: Vec<usize>,
}

pub(super) struct SourceEvidence {
    pub witnesses: Vec<crate::AnalysisWitnessV1>,
    pub contexts: Vec<crate::AnalysisContextRefV1>,
    pub support: Vec<SourceSupport>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedSourceProof {
    pub result: PackageResultRefV1,
    pub witnesses: Vec<crate::AnalysisWitnessV1>,
    pub contexts: Vec<crate::AnalysisContextRefV1>,
}

#[derive(Clone, Debug)]
pub struct ManagedSourceFrame {
    pub(super) record: RecordSource,
    pub(super) tables: Vec<sdk::Dataset>,
    pub(super) proof: Arc<OnceLock<Arc<ManagedSourceProof>>>,
    scope: Arc<SourceScope>,
    selected: Arc<Mutex<SourceSelection>>,
}

#[derive(Debug, PartialEq)]
struct SourceScope {
    tenant: [u8; 16],
    instance: String,
    generation: u64,
    store: uuid::Uuid,
    schema: u32,
    recovery: u64,
    contract: SourceContract,
}

#[derive(Debug, Default)]
struct SourceSelection {
    frozen: bool,
    witnesses: BTreeMap<(AnalysisStreamIdentityV1, u64), crate::AnalysisWitnessV1>,
    contexts: BTreeMap<(crate::AnalysisContextKeyV1, u64), crate::AnalysisContextRefV1>,
    support: BTreeMap<String, SourceSupport>,
}

#[derive(Clone, Debug)]
pub struct ManagedSourceBlock {
    scope: Arc<SourceScope>,
    proof: Arc<OnceLock<Arc<ManagedSourceProof>>>,
    rows: Arc<Vec<SourceRow>>,
}

#[derive(Clone, Debug)]
enum SourceRow {
    Event(crate::AnalysisWitnessV1),
    Context(crate::AnalysisContextRefV1),
}

#[derive(Clone, Debug)]
pub struct ManagedSourceRows {
    scope: Arc<SourceScope>,
    proof: Arc<OnceLock<Arc<ManagedSourceProof>>>,
    witnesses: Vec<crate::AnalysisWitnessV1>,
    contexts: Vec<crate::AnalysisContextRefV1>,
}

#[derive(Clone, Debug)]
pub(super) struct SourceCapture {
    pub frame: Arc<ManagedSourceFrame>,
    pub members: Arc<BTreeSet<Vec<u8>>>,
}

mod allocation;
mod metadata;
mod reader;
mod selection;

impl ManagedSourceRead {
    pub fn after(&self) -> Option<StorePositionV1> {
        match self {
            Self::Initial => None,
            Self::Changes(parent) => Some(parent.position),
        }
    }
}

impl ManagedSourceFrame {
    pub fn proof(&self) -> Option<&Arc<ManagedSourceProof>> {
        self.proof.get()
    }

    pub(super) fn check_proof(&self, proof: &ManagedSourceProof) -> Result<()> {
        if self
            .proof
            .get()
            .is_some_and(|saved| saved.as_ref() != proof)
        {
            return Err(Code::Conflict.error("managed source proof"));
        }
        Ok(())
    }

    pub(super) fn commit_proof(&self, proof: Arc<ManagedSourceProof>) {
        self.proof.get_or_init(|| proof);
    }

    pub fn read(&self) -> &ManagedSourceRead {
        &self.record.contract.read
    }

    pub fn position(&self) -> StorePositionV1 {
        self.record.contract.position
    }

    pub fn selection(&self) -> &AnalysisSelectionV1 {
        &self.record.contract.selection
    }

    pub fn projection(&self) -> &AnalysisTableRequests {
        &self.record.contract.tables
    }

    pub fn datasets(&self) -> &[sdk::Dataset] {
        &self.tables
    }

    pub fn removals(&self) -> &BTreeMap<AnalysisStreamIdentityV1, Vec<AnalysisGapV1>> {
        &self.record.removals
    }

    pub fn metadata(&self) -> &[ManagedSourceMetadata] {
        &self.record.metadata
    }

    pub(super) fn encode(&self) -> Result<Vec<sdk::wire::Dataset>> {
        self.record.check_tables(&self.tables)?;
        self.tables
            .iter()
            .filter(|data| !data.batches.is_empty())
            .map(|data| {
                let schema = self.record.schema(&data.name)?;
                sdk::wire::Dataset::encode(data, &schema).context(crate::AnalysisContractSnafu)
            })
            .collect()
    }
}

impl RecordSource {
    pub(super) fn schema(&self, name: &str) -> Result<sdk::Schema> {
        let columns = self
            .contract
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

    pub(super) fn check_tables(&self, tables: &[sdk::Dataset]) -> Result<()> {
        self.check_metadata()?;
        let names = self
            .contract
            .tables
            .iter()
            .filter(|(_, columns)| columns.is_some())
            .map(|(name, _)| name.as_str());
        if !names.eq(self.tables.iter().map(|data| data.name.as_str()))
            || tables.len() != self.tables.len()
        {
            return Err(Code::Invalid.error("managed source table names"));
        }
        for (header, data) in self.tables.iter().zip(tables) {
            let schema = self.schema(&header.name)?;
            if data.name != header.name
                || data.rows() != header.rows
                || data.batches.len() != header.batches
                || data
                    .batches
                    .iter()
                    .any(|batch| batch.schema().as_ref() != &schema)
            {
                return Err(Code::Invalid.error("managed source table shape"));
            }
        }
        Ok(())
    }

    fn check_metadata(&self) -> Result<()> {
        let after = self
            .contract
            .read
            .after()
            .map(|position| position.commit_revision);
        let mut previous = None;
        for metadata in &self.metadata {
            let receipt = &metadata.receipt;
            let key = receipt.identity.key();
            if !receipt.identity.valid()
                || !self.contract.selection.includes_source(&receipt.identity)
                || receipt.retained_floor > receipt.contiguous_cursor
                || previous.as_ref().is_some_and(|previous| previous >= &key)
            {
                return Err(Code::Invalid.error("managed source metadata identity"));
            }
            previous = Some(key);
            let initial = matches!(metadata.state, ManagedSourceState::Initial { .. });
            if after.is_none() && !initial {
                return Err(Code::Invalid.error("managed source initial metadata"));
            }
            match &metadata.state {
                ManagedSourceState::Initial { high, pending } => {
                    if *high < receipt.contiguous_cursor
                        || pending.iter().any(|range| {
                            range.first_cursor <= receipt.contiguous_cursor
                                || range.last_cursor >= *high
                        })
                    {
                        return Err(Code::Invalid.error("managed source pending frontier"));
                    }
                    self.check_ranges(pending, None)?;
                }
                ManagedSourceState::Changes { accepted } => self.check_ranges(accepted, after)?,
            }
            let since = if initial { None } else { after };
            self.check_ranges(&metadata.expired, since)?;
            self.check_ranges(&metadata.recovery, since)?;
            if metadata
                .expired
                .iter()
                .any(|range| range.last_cursor > receipt.contiguous_cursor)
            {
                return Err(Code::Invalid.error("managed source expired frontier"));
            }
            if let Some(report) = &metadata.coverage {
                if report.revision == 0
                    || report.source != receipt.identity
                    || report.revision != receipt.coverage_revision
                    || report.position.ordinal != 0
                    || report.position.commit_revision == 0
                    || report.position.commit_revision > self.contract.position.commit_revision
                    || since.is_some_and(|after| report.position.commit_revision <= after)
                {
                    return Err(Code::Invalid.error("managed source coverage reference"));
                }
            }
        }
        for (identity, ranges) in &self.removals {
            let allowed = match identity {
                AnalysisStreamIdentityV1::Evidence(source) => {
                    self.contract.selection.includes_source(source)
                }
                AnalysisStreamIdentityV1::Diagnostic(source) => {
                    source.tenant_id == self.contract.selection.tenant_id
                        && (self.contract.selection.traces.is_all()
                            || self.contract.selection.traces.as_slice().contains(source))
                }
            };
            if after.is_none() || !allowed {
                return Err(Code::Invalid.error("managed source removal scope"));
            }
            self.check_ranges(ranges, after)?;
        }
        Ok(())
    }

    fn check_ranges(&self, ranges: &[AnalysisGapV1], after: Option<u64>) -> Result<()> {
        if ranges.iter().any(|range| {
            range.first_cursor == 0
                || range.last_cursor < range.first_cursor
                || range.commit_revision == 0
                || range.commit_revision > self.contract.position.commit_revision
                || after.is_some_and(|after| range.commit_revision <= after)
        }) {
            return Err(Code::Invalid.error("managed source change range"));
        }
        Ok(())
    }
}
