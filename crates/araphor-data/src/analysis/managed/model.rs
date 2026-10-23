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
    pub selected_schema: sdk::Schema,
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
    pub definition: ResolvedDefinition,
    pub manifest: ManagedManifest,
    pub destination: ManagedDestination,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedGraphOperation {
    Evaluate,
    Expire,
}

impl ManagedGraphOperation {
    pub fn instance_id(self, source: &crate::EvidenceIntakeIdentityV1) -> String {
        let key = source
            .key()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let operation = match self {
            Self::Evaluate => "evaluate",
            Self::Expire => "expire",
        };
        format!("araphor-graph:{key}:{operation}")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedDestination {
    Selected,
    Notification,
    DiscoveryProfile {
        source: crate::EvidenceIntakeIdentityV1,
        call: u64,
        output: String,
    },
    Graph {
        source: crate::EvidenceIntakeIdentityV1,
        events_sql: String,
        calls: BTreeSet<u64>,
        operation: ManagedGraphOperation,
    },
}

impl ManagedDestination {
    pub fn selection(
        &self,
        grant: &crate::AnalysisSelectionV1,
    ) -> Result<crate::AnalysisSelectionV1> {
        let source = match self {
            Self::Selected | Self::Notification => return Ok(grant.clone()),
            Self::DiscoveryProfile { source, .. } | Self::Graph { source, .. } => source,
        };
        if !source.valid()
            || source.tenant_id != grant.tenant_id
            || !grant.sources.is_all() && !grant.sources.as_slice().contains(source)
        {
            return Err(Code::Denied.error("managed destination source"));
        }
        let mut selection = grant.clone();
        selection.sources = crate::Selection::Exact(vec![source.clone()]);
        Ok(selection)
    }
}

impl ManagedSpec {
    pub(in crate::analysis) fn same_call(&self, previous: &Self, call: u64) -> bool {
        self.definition.sql == previous.definition.sql
            && self.manifest.format == previous.manifest.format
            && self.manifest.planner == previous.manifest.planner
            && self.manifest.calls.get(&call) == previous.manifest.calls.get(&call)
    }

    pub fn allocation_bytes(&self) -> Option<usize> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(self.id.capacity())?
            .checked_add(
                self.definition
                    .allocation_bytes()?
                    .checked_sub(std::mem::size_of::<ResolvedDefinition>())?,
            )?
            .checked_add(self.manifest.planner.capacity())?
            .checked_add(self.manifest.definition.capacity())?
            .checked_add(self.manifest.selected_schema.fields().size())?
            .checked_add(
                self.manifest
                    .selected_schema
                    .metadata()
                    .capacity()
                    .checked_mul(std::mem::size_of::<(String, String)>())?,
            )?
            .checked_add(match &self.destination {
                ManagedDestination::Selected | ManagedDestination::Notification => 0,
                ManagedDestination::DiscoveryProfile { source, output, .. } => {
                    source.node_id.capacity().checked_add(output.capacity())?
                }
                ManagedDestination::Graph {
                    source,
                    calls,
                    events_sql,
                    ..
                } => source
                    .node_id
                    .capacity()
                    .checked_add(events_sql.capacity())?
                    .checked_add(calls.len().checked_mul(std::mem::size_of::<u64>())?)?,
            })?;
        let bytes = self.manifest.selected_schema.metadata().iter().try_fold(
            bytes,
            |bytes, (key, value)| {
                bytes
                    .checked_add(key.capacity())?
                    .checked_add(value.capacity())
            },
        )?;
        self.manifest.calls.values().try_fold(bytes, |bytes, call| {
            let bytes = bytes
                .checked_add(std::mem::size_of::<(u64, ManagedCall)>())?
                .checked_add(call.image.image.package_id.capacity())?
                .checked_add(call.image.image.revision.capacity())?
                .checked_add(call.image.digest.capacity())?
                .checked_add(call.package.package_id.capacity())?
                .checked_add(call.package.revision.capacity())?
                .checked_add(call.export.capacity())?
                .checked_add(call.target.capacity())?
                .checked_add(call.artifact.as_ref().map_or(
                    0,
                    araphor_package::PackageArtifactIdentityV1::allocated_bytes,
                ))?
                .checked_add(
                    call.dependencies
                        .len()
                        .checked_mul(std::mem::size_of::<u64>())?,
                )?
                .checked_add(
                    call.arguments
                        .capacity()
                        .checked_mul(std::mem::size_of::<String>())?,
                )?;
            call.arguments
                .iter()
                .try_fold(bytes, |bytes, value| bytes.checked_add(value.capacity()))
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.tenant == [0; 16]
            || self.id.is_empty()
            || self.id.chars().any(char::is_control)
            || self.manifest.definition != self.definition.digest()?
        {
            return Err(Code::Invalid.error("managed instance"));
        }
        self.definition.validate()?;
        self.manifest.order()?;
        for call in self.manifest.calls.values() {
            if call.export.is_empty() || !self.definition.images.contains(&call.image) {
                return Err(Code::Invalid.error("managed call pin"));
            }
        }
        match &self.destination {
            ManagedDestination::Selected => {}
            ManagedDestination::Notification => {
                if !self.manifest.calls.is_empty() || !self.definition.images.is_empty() {
                    return Err(Code::Invalid.error("notification managed calls"));
                }
            }
            ManagedDestination::DiscoveryProfile {
                source,
                call,
                output,
            } => {
                if !source.valid()
                    || source.tenant_id != self.tenant
                    || !self.manifest.calls.contains_key(call)
                    || output.is_empty()
                {
                    return Err(Code::Invalid.error("managed profile destination"));
                }
            }
            ManagedDestination::Graph {
                source,
                calls,
                operation,
                events_sql,
            } => {
                if !source.valid()
                    || source.tenant_id != self.tenant
                    || calls
                        .iter()
                        .any(|call| !self.manifest.calls.contains_key(call))
                    || match operation {
                        ManagedGraphOperation::Evaluate => {
                            calls.is_empty() || events_sql.is_empty()
                        }
                        ManagedGraphOperation::Expire => {
                            !calls.is_empty() || !self.manifest.calls.is_empty()
                        }
                    }
                {
                    return Err(Code::Invalid.error("managed graph destination"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedInstance {
    pub spec: ManagedSpec,
    pub grant: PackageGrantV1,
    pub generation: u64,
    pub progress: u64,
    pub running: bool,
    pub removed: bool,
    pub lifecycle: u64,
}

impl ManagedInstance {
    pub fn allocation_bytes(&self) -> Option<usize> {
        self.spec
            .allocation_bytes()?
            .checked_sub(std::mem::size_of::<ManagedSpec>())?
            .checked_add(std::mem::size_of::<Self>())?
            .checked_add(self.grant.principal.capacity())?
            .checked_add(
                self.grant
                    .authorization_id
                    .as_ref()
                    .map_or(0, String::capacity),
            )?
            .checked_add(
                self.grant
                    .selection
                    .allocation_bytes()
                    .checked_sub(std::mem::size_of::<crate::AnalysisSelectionV1>())?,
            )
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.spec.validate()?;
        self.grant.validate()?;
        if self.grant.selection.tenant_id != self.spec.tenant || self.removed && self.running {
            return Err(Code::Invalid.error("managed instance grant"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ManagedStatus {
    pub instance: ManagedInstance,
    pub readiness: crate::PackageReadinessV1,
    pub status_progress: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ManagedMember {
    pub tenant: [u8; 16],
    pub id: String,
    pub generation: u64,
    pub lifecycle: u64,
}

#[derive(Clone, Debug)]
pub struct ManagedRead {
    pub instance: ManagedInstance,
    pub expected: Option<ManagedInstance>,
    pub rebuild: bool,
    /// Require this completion when a native frontier was selected.
    pub completed: Option<u64>,
}

impl ManagedRead {
    pub(super) fn expected(&self) -> &ManagedInstance {
        self.expected.as_ref().unwrap_or(&self.instance)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ManagedResume {
    pub instance: ManagedInstance,
    pub frontier: Option<ManagedFrontier>,
    pub completed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFrontier {
    pub cursor: Vec<u8>,
    pub next_change: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRequest {
    pub id: String,
    pub time_utc_ns: u64,
    pub seed: Option<u64>,
    pub rebuild: bool,
    pub witness_expiry: u64,
    pub frontier: Option<ManagedFrontier>,
}

#[derive(Clone, Debug)]
pub struct ManagedPrior {
    pub revision: u64,
    pub result: String,
    pub context: ResultContext,
    pub parameters: Option<sdk::Dataset>,
    pub checkpoint: Option<sdk::Checkpoint>,
    pub retained: Option<std::sync::Arc<RetainedCall>>,
}

#[derive(Clone, Debug)]
pub struct RetainedCall {
    pub evaluation: sdk::Evaluation,
    pub output: sdk::Output,
}

impl RetainedCall {
    pub fn matches(&self, evaluation: &sdk::Evaluation) -> bool {
        self.evaluation.export == evaluation.export
            && self.evaluation.parameters == evaluation.parameters
            && self.evaluation.inputs.len() == evaluation.inputs.len()
            && self
                .evaluation
                .inputs
                .iter()
                .zip(&evaluation.inputs)
                .all(|(left, right)| {
                    left.data.name == right.data.name
                        && left.data.batches == right.data.batches
                        && left.revision == right.revision
                        && left.coverage == right.coverage
                })
    }
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
    pub grant: PackageGrantV1,
    pub generation: u64,
    pub expected_generation: u64,
    pub progress: u64,
    pub completed: u64,
    pub running: bool,
    pub lifecycle: u64,
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
    pub fn source_revision(&self) -> u64 {
        self.contract
            .sources
            .iter()
            .map(|(_, revision)| *revision)
            .max()
            .unwrap_or(0)
    }
    pub fn time_utc_ns(&self) -> u64 {
        self.contract.time_utc_ns
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
                .chain(prior.retained.iter().flat_map(|retained| {
                    retained
                        .evaluation
                        .inputs
                        .iter()
                        .map(|input| &input.data)
                        .chain(retained.output.datasets.iter())
                        .chain(
                            retained
                                .output
                                .checkpoint
                                .iter()
                                .flat_map(|state| &state.datasets),
                        )
                }))
        })
    }
    pub fn metadata_bytes(&self) -> usize {
        self.bytes.saturating_sub(
            self.batches()
                .flat_map(sdk::RecordBatch::columns)
                .fold(0usize, |bytes, array| {
                    bytes.saturating_add(array.get_buffer_memory_size())
                }),
        )
    }

    pub fn batches(&self) -> impl Iterator<Item = &sdk::RecordBatch> {
        self.datasets()
            .flat_map(|data| &data.batches)
            .chain(self.prior.values().flat_map(|prior| {
                prior.retained.iter().flat_map(|retained| {
                    retained
                        .evaluation
                        .parameters
                        .iter()
                        .chain(retained.output.reasons.iter().map(|reason| &reason.details))
                })
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
    pub frontier: Option<ManagedFrontier>,
    pub instance: String,
    pub attempt: String,
    pub commit_revision: u64,
    pub selected: PackageResultRefV1,
    pub results: BTreeMap<u64, PackageResultRefV1>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ManagedExit {
    Cancelled,
    Failed(crate::PackageErrorCodeV1),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedTerminal {
    pub instance: String,
    pub attempt: String,
    pub revision: u64,
    pub exit: ManagedExit,
    pub suspended: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(super) struct Attempt {
    pub request: ManagedRequest,
    pub capture: Capture,
    pub registered: u64,
    pub receipt: Option<ManagedReceipt>,
    pub terminal: Option<ManagedTerminal>,
}

impl Attempt {
    pub(super) fn decode(tenant: [u8; 16], instance: &str, id: &str, bytes: &[u8]) -> Result<Self> {
        use snafu::ResultExt as _;

        let attempt: Self = serde_json::from_slice(bytes).context(crate::PackageEncodingSnafu)?;
        if attempt.capture.tenant != tenant
            || attempt.capture.instance != instance
            || attempt.request.id != id
        {
            return Err(Code::Invalid.error("managed attempt key"));
        }
        Ok(attempt)
    }
}

#[derive(Clone, Debug)]
pub struct ManagedAttempt(
    pub(super) Attempt,
    pub(super) ManagedInstance,
    pub(super) Option<tokio::sync::watch::Receiver<u64>>,
    pub(super) BTreeMap<u64, ManagedPrior>,
);

impl ManagedAttempt {
    pub(in crate::analysis) fn switches_version(&self) -> bool {
        self.0.capture.generation != self.0.capture.expected_generation
    }

    pub(in crate::analysis) fn witnesses(&self) -> &[AnalysisWitnessV1] {
        &self.0.capture.witnesses
    }

    pub fn request(&self) -> &ManagedRequest {
        &self.0.request
    }
    pub fn instance(&self) -> &ManagedInstance {
        &self.1
    }
    pub fn receipt(&self) -> Option<&ManagedReceipt> {
        self.0.receipt.as_ref()
    }
    pub fn terminal(&self) -> Option<&ManagedTerminal> {
        self.0.terminal.as_ref()
    }
}

pub struct ManagedReturn<'a> {
    pub call: u64,
    pub evaluation: &'a sdk::Evaluation,
    pub output: &'a sdk::Output,
    pub retained: Option<&'a PackageResultRefV1>,
}

impl Attempt {
    pub(super) fn retains(
        &self,
        spec: &ManagedSpec,
        call: u64,
        reference: &PackageResultRefV1,
    ) -> bool {
        self.request.frontier.is_some()
            && !self.request.rebuild
            && self.capture.generation == self.capture.expected_generation
            && matches!(
                &spec.destination,
                ManagedDestination::Graph {
                    calls,
                    operation: ManagedGraphOperation::Evaluate,
                    ..
                } if calls.contains(&call)
            )
            && spec
                .manifest
                .calls
                .get(&call)
                .is_some_and(|declaration| matches!(declaration.target.as_str(), "wasm" | "native"))
            && self.capture.prior.get(&call).and_then(Option::as_ref) == Some(reference)
            && reference.commit_revision > 0
            && reference.commit_revision <= self.capture.progress
            && reference.commit_revision < self.registered
    }
}

pub struct ManagedCommit<'a> {
    pub attempt: &'a ManagedAttempt,
    pub now_utc_ns: u64,
    pub returns: &'a [ManagedReturn<'a>],
    pub selected: &'a sdk::Dataset,
    pub selected_schema: &'a sdk::Schema,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct RecordInput {
    pub name: String,
    pub rows: u64,
    pub batches: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Record {
    pub instance: String,
    pub call: u64,
    pub attempt: String,
    pub declaration: ManagedCall,
    pub context: ResultContext,
    pub parameters: Option<sdk::wire::Dataset>,
    pub inputs: Vec<RecordInput>,
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
pub enum ManagedOutput {
    Call {
        result: Box<crate::InstanceResultV1>,
        data: sdk::Output,
    },
    Selected {
        packet: sdk::wire::Dataset,
        data: sdk::Dataset,
    },
}

#[derive(Clone, Debug)]
pub struct ManagedSelected {
    pub data: sdk::Dataset,
    pub commit_revision: u64,
}
