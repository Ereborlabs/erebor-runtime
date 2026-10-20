use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_sdk as sdk;
use araphor_discovery_definition::{ImagePin, ResolvedDefinition};
use serde::{Deserialize, Serialize};

use super::super::{AnalysisPositionPageV1, PackageResultRefV1};
use crate::{
    AnalysisContextRefV1, AnalysisWitnessV1, PackageGrantV1, PackageRefV1, Result, ResultContext,
};

type Code = crate::PackageErrorCodeV1;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedCall {
    pub image: ImagePin,
    pub package: PackageRefV1,
    pub export: String,
    pub arguments: Vec<String>,
    pub target: String,
    pub artifact: Option<araphor_package::PackageArtifactIdentityV1>,
    pub dependencies: BTreeSet<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedManifest {
    pub format: u32,
    pub planner: String,
    pub definition: String,
    pub calls: BTreeMap<u64, ManagedCall>,
}

impl ManagedManifest {
    pub fn order(&self) -> Result<Vec<u64>> {
        if self.format != 1 || self.planner.is_empty() || self.definition.is_empty() {
            return Err(Code::Invalid.error("managed manifest format"));
        }
        let mut done = BTreeSet::new();
        let mut order = Vec::new();
        while done.len() < self.calls.len() {
            let next = self.calls.iter().find(|(id, call)| {
                !done.contains(*id) && call.dependencies.iter().all(|id| done.contains(id))
            });
            let Some((id, _)) = next else {
                return Err(Code::Invalid.error("managed call dependencies"));
            };
            done.insert(*id);
            order.push(*id);
        }
        Ok(order)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSpec {
    pub tenant: [u8; 16],
    pub id: String,
    pub grant: PackageGrantV1,
    pub definition: ResolvedDefinition,
    pub manifest: ManagedManifest,
}

impl ManagedSpec {
    pub(super) fn validate(&self) -> Result<()> {
        if self.tenant == [0; 16]
            || self.id.is_empty()
            || self.id.chars().any(char::is_control)
            || self.grant.selection.tenant_id != self.tenant
            || !self.grant.selection.valid()
            || self.manifest.definition != self.definition.digest()?
        {
            return Err(Code::Invalid.error("managed instance"));
        }
        self.definition.validate()?;
        self.manifest.order()?;
        self.grant.validate()?;
        for call in self.manifest.calls.values() {
            if call.export.is_empty() || !self.definition.images.contains(&call.image) {
                return Err(Code::Invalid.error("managed call pin"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedInstance {
    pub spec: ManagedSpec,
    pub generation: u64,
    pub progress: u64,
}

#[derive(Clone, Debug)]
pub struct ManagedRead {
    pub instance: ManagedInstance,
    pub rebuild: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRequest {
    pub id: String,
    pub time_utc_ns: u64,
    pub seed: Option<u64>,
    pub rebuild: bool,
    pub witness_expiry: u64,
}

#[derive(Clone, Debug)]
pub struct ManagedPrior {
    pub revision: u64,
    pub result: String,
    pub context: ResultContext,
    pub parameters: Option<sdk::Dataset>,
    pub checkpoint: Option<sdk::Checkpoint>,
}

impl ManagedPrior {
    pub fn checkpoint(
        &self,
        model: &sdk::Model,
        inputs: &[sdk::Input],
        parameters: Option<&sdk::RecordBatch>,
        rebuild: bool,
    ) -> Result<Option<sdk::Checkpoint>> {
        if rebuild || !self.context.matches(inputs) {
            return Ok(None);
        }
        if self
            .parameters
            .as_ref()
            .is_some_and(|data| data.batches.len() != 1 || data.rows() != 1)
        {
            return Err(Code::Invalid.error("managed retained parameters"));
        }
        let saved = self
            .parameters
            .as_ref()
            .and_then(|data| data.batches.first());
        if saved != parameters {
            return Ok(None);
        }
        if saved.is_some_and(|batch| batch.schema().as_ref() != &model.parameters) {
            return Ok(None);
        }
        let Some(checkpoint) = &self.checkpoint else {
            return Ok(None);
        };
        let Some(spec) = &model.checkpoint else {
            return Ok(None);
        };
        if checkpoint.version != spec.version
            || checkpoint.datasets.len() != spec.datasets.len()
            || checkpoint.datasets.iter().any(|data| {
                spec.datasets
                    .iter()
                    .find(|port| port.name == data.name)
                    .is_none_or(|port| {
                        data.batches
                            .iter()
                            .any(|batch| batch.schema().as_ref() != &port.schema)
                    })
            })
        {
            return Ok(None);
        }
        Ok(Some(checkpoint.clone()))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct Capture {
    pub tenant: [u8; 16],
    pub instance: String,
    pub generation: u64,
    pub progress: u64,
    pub rebuild: bool,
    pub prior: BTreeMap<u64, Option<PackageResultRefV1>>,
    pub store: uuid::Uuid,
    pub schema: u32,
    pub recovery: u64,
    pub revision: u64,
    pub time_utc_ns: u64,
    pub sources: Vec<(String, u64)>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
    pub traces: Vec<[u8; 16]>,
}

#[derive(Clone, Debug)]
pub struct ManagedCapture {
    pub(super) instance: ManagedInstance,
    pub(super) contract: Capture,
    pub(super) prior: BTreeMap<u64, ManagedPrior>,
    pub(super) bytes: usize,
}

impl ManagedCapture {
    pub fn instance(&self) -> &ManagedInstance {
        &self.instance
    }
    pub fn prior(&self, call: u64) -> Option<&ManagedPrior> {
        self.prior.get(&call)
    }
    pub fn revision(&self) -> u64 {
        self.contract.revision
    }
    pub fn rebuild(&self) -> bool {
        self.contract.rebuild
    }
    pub fn allocated_bytes(&self) -> usize {
        self.bytes
    }
    pub fn datasets(&self) -> impl Iterator<Item = &sdk::Dataset> {
        self.prior.values().flat_map(|prior| {
            prior
                .parameters
                .iter()
                .chain(prior.checkpoint.iter().flat_map(|state| &state.datasets))
        })
    }
    pub fn metadata_bytes(&self) -> usize {
        self.bytes
            .saturating_sub(self.datasets().fold(0usize, |bytes, data| {
                bytes.saturating_add(data.allocated_bytes().saturating_sub(data.metadata_bytes()))
            }))
    }
}

pub struct ManagedPage {
    pub page: AnalysisPositionPageV1,
    pub state: ManagedCapture,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedReceipt {
    pub instance: String,
    pub attempt: String,
    pub commit_revision: u64,
    pub selected: PackageResultRefV1,
    pub results: BTreeMap<u64, PackageResultRefV1>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct Attempt {
    pub request: ManagedRequest,
    pub capture: Capture,
    pub registered: u64,
    pub receipt: Option<ManagedReceipt>,
}

#[derive(Clone, Debug)]
pub struct ManagedAttempt(
    pub(super) Attempt,
    pub(super) ManagedInstance,
    pub(super) bool,
    pub(super) BTreeMap<u64, ManagedPrior>,
);

impl ManagedAttempt {
    pub fn request(&self) -> &ManagedRequest {
        &self.0.request
    }
    pub fn instance(&self) -> &ManagedInstance {
        &self.1
    }
    pub fn receipt(&self) -> Option<&ManagedReceipt> {
        self.0.receipt.as_ref()
    }
}

pub struct ManagedReturn<'a> {
    pub call: u64,
    pub evaluation: &'a sdk::Evaluation,
    pub output: &'a sdk::Output,
}

pub struct ManagedCommit<'a> {
    pub attempt: &'a ManagedAttempt,
    pub now_utc_ns: u64,
    pub returns: &'a [ManagedReturn<'a>],
    pub selected: &'a sdk::Dataset,
    pub selected_limits: sdk::Limits,
    pub selected_schema: &'a sdk::Schema,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Record {
    pub instance: String,
    pub call: u64,
    pub attempt: String,
    pub declaration: ManagedCall,
    pub context: ResultContext,
    pub parameters: Option<sdk::wire::Dataset>,
    pub rows: BTreeMap<String, u64>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
}

#[derive(Clone, Debug)]
pub struct ManagedResult {
    pub context: ResultContext,
    pub output: sdk::Output,
    pub commit_revision: u64,
    pub current: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Step {
    pub instance: String,
    pub attempt: String,
    pub rows: u64,
    pub dependencies: Vec<PackageResultRefV1>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
}

#[derive(Clone, Debug)]
pub struct ManagedSelected {
    pub data: sdk::Dataset,
    pub commit_revision: u64,
}
