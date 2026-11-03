use super::codec::ManagedCodec;
use super::execution::ManagedExecution;
use super::source::{ManagedSourceFrame, ManagedSourceRead, ManagedSourceRef};
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
    pub definition: u64,
    pub calls: BTreeMap<u64, ManagedCall>,
    pub selected_schema: sdk::Schema,
}

impl ManagedManifest {
    pub fn order(&self) -> Result<Vec<u64>> {
        if self.format != 1 || self.planner.is_empty() || self.definition == 0 {
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
        control_sql: String,
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
                    control_sql,
                    ..
                } => source
                    .node_id
                    .capacity()
                    .checked_add(events_sql.capacity())?
                    .checked_add(control_sql.capacity())?
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
        if self.tenant == [0; 16] || self.id.is_empty() || self.id.chars().any(char::is_control) {
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
                control_sql,
            } => {
                if !source.valid()
                    || source.tenant_id != self.tenant
                    || calls
                        .iter()
                        .any(|call| !self.manifest.calls.contains_key(call))
                    || match operation {
                        ManagedGraphOperation::Evaluate => {
                            calls.is_empty() || events_sql.is_empty() || control_sql.is_empty()
                        }
                        ManagedGraphOperation::Expire => {
                            !calls.is_empty()
                                || !self.manifest.calls.is_empty()
                                || !control_sql.is_empty()
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
    pub execution: Option<std::sync::Arc<ManagedExecution>>,
    pub instance: ManagedInstance,
    pub expected: Option<ManagedInstance>,
    pub rebuild: bool,
    pub follow: bool,
    pub source: Option<ManagedSourceRead>,
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
    pub source: Option<ManagedSourceRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedFrontier {
    pub cursor: Vec<u8>,
    pub next_change: Option<u64>,
    /// Resume this captured cut before waiting for a source change.
    pub pending: bool,
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
    pub source: super::ManagedSourceRef,
    pub context: ResultContext,
    pub parameters: Option<sdk::Dataset>,
    pub checkpoint: Option<sdk::Checkpoint>,
    pub retained: Option<std::sync::Arc<RetainedCall>>,
}

#[derive(Clone, Debug)]
pub struct RetainedCall {
    pub evaluation: sdk::Evaluation,
    pub output: sdk::Output,
    pub changes: Option<ManagedChanges>,
}

#[derive(Clone, Debug)]
pub struct ManagedChanges {
    pub base: Option<PackageResultRefV1>,
}

impl ManagedChanges {
    pub fn metadata_bytes(&self) -> usize {
        std::mem::size_of::<Self>().saturating_add(
            self.base
                .as_ref()
                .map_or(0, |base| base.result_id.capacity()),
        )
    }
}

impl ManagedPrior {
    pub fn state(
        &self,
        model: &sdk::Model,
        inputs: &[sdk::Input],
        parameters: Option<&sdk::RecordBatch>,
        rebuild: bool,
    ) -> Result<(Option<sdk::Checkpoint>, Vec<sdk::Dataset>)> {
        let continuation = model
            .checkpoint
            .as_ref()
            .is_some_and(|spec| spec.resume_input_changes);
        if rebuild || (!continuation && !self.context.matches(inputs)) {
            return Ok((None, Vec::new()));
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
            return Ok((None, Vec::new()));
        }
        if saved.is_some_and(|batch| batch.schema().as_ref() != &model.parameters) {
            return Ok((None, Vec::new()));
        }
        let Some(checkpoint) = &self.checkpoint else {
            return Ok((None, Vec::new()));
        };
        if model.validate_checkpoint(Some(checkpoint), false).is_err() {
            return Ok((None, Vec::new()));
        }
        let previous = if continuation {
            let datasets = &self
                .retained
                .as_ref()
                .ok_or_else(|| Code::Invalid.error("managed prior outputs"))?
                .output
                .datasets;
            sdk::Dataset::validate_all(datasets, &model.outputs)
                .map_err(|_| Code::Invalid.error("managed prior outputs"))?;
            datasets.clone()
        } else {
            Vec::new()
        };
        Ok((Some(checkpoint.clone()), previous))
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
    #[serde(default)]
    pub follow: bool,
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

impl Capture {
    fn source_meta(&self) -> crate::AnalysisStoreMetaV1 {
        crate::AnalysisStoreMetaV1 {
            store_uuid: self.store,
            schema_version: self.schema,
            recovery_epoch: self.recovery,
            commit_revision: self.revision,
        }
    }

    pub(super) fn follows_graph(&self, spec: &ManagedSpec) -> bool {
        self.follow && matches!(&spec.destination, ManagedDestination::Graph { .. })
    }

    pub(super) fn check_follow_mode(&self, spec: &ManagedSpec) -> Result<()> {
        if self.follows_graph(spec)
            && (!self.running || self.rebuild || self.generation != self.expected_generation)
        {
            return Err(Code::Invalid.error("managed Graph follow mode"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ManagedCapture {
    pub(super) execution: Option<std::sync::Arc<ManagedExecution>>,
    pub(super) instance: ManagedInstance,
    pub(super) contract: Capture,
    pub(super) prior: BTreeMap<u64, std::sync::Arc<ManagedPrior>>,
    pub(super) bytes: usize,
    pub(super) source: Option<std::sync::Arc<ManagedSourceFrame>>,
}

impl ManagedCapture {
    pub(in crate::analysis) fn check_reference(&self, reference: &ManagedAttempt) -> Result<()> {
        if self.contract != reference.0.capture
            || self.instance.spec != reference.1.spec
            || self.instance.grant != reference.1.grant
            || self.instance.generation != reference.1.generation
        {
            return Err(Code::Conflict.error("frozen Graph capture reference"));
        }
        Ok(())
    }

    pub(in crate::analysis) fn source_meta(&self) -> crate::AnalysisStoreMetaV1 {
        self.contract.source_meta()
    }

    pub fn discard_prior(&mut self, call: u64) -> usize {
        let before = self.metadata_bytes();
        if let Some(prior) = self.prior.remove(&call) {
            self.bytes = self.bytes.saturating_sub(prior.allocated_bytes());
        }
        before.saturating_sub(self.metadata_bytes())
    }

    pub fn hydrate_prior(
        &mut self,
        call: u64,
        model: &sdk::Model,
        parameters: Option<sdk::Dataset>,
        retained: Option<std::sync::Arc<RetainedCall>>,
    ) -> Result<usize> {
        let prior = self
            .prior
            .get_mut(&call)
            .ok_or_else(|| Code::Missing.error("managed prior reference"))?;
        if prior.retained.is_some()
            || self
                .instance
                .spec
                .manifest
                .calls
                .get(&call)
                .is_none_or(|declaration| declaration.export != model.name)
        {
            return Err(Code::Invalid.error("managed prior hydration"));
        }
        match (&parameters, model.parameters.fields().is_empty()) {
            (None, true) => {}
            (Some(data), false)
                if data.name == "parameters" && data.batches.len() == 1 && data.rows() == 1 =>
            {
                data.validate(&sdk::Port::new("parameters", model.parameters.clone()))
                    .map_err(|_| Code::Invalid.error("managed prior parameters"))?;
            }
            _ => return Err(Code::Invalid.error("managed prior parameters")),
        }
        if let Some(saved) = &retained {
            let same = match (&prior.checkpoint, &saved.output.checkpoint) {
                (None, None) => true,
                (Some(left), Some(right)) => {
                    left.version == right.version
                        && left.datasets.len() == right.datasets.len()
                        && left
                            .datasets
                            .iter()
                            .zip(&right.datasets)
                            .all(|(left, right)| {
                                left.name == right.name && left.batches == right.batches
                            })
                }
                _ => false,
            };
            if !same
                || saved.evaluation.export != model.name
                || saved.evaluation.context != prior.context.context
                || !prior.context.matches(&saved.evaluation.inputs)
                || saved.evaluation.parameters.as_ref()
                    != parameters.as_ref().and_then(|data| data.batches.first())
            {
                return Err(Code::Conflict.error("managed prior evaluation"));
            }
            sdk::Dataset::validate_all(&saved.output.datasets, &model.outputs)
                .map_err(|_| Code::Invalid.error("managed prior outputs"))?;
        }
        let before = prior.allocated_bytes();
        let metadata = prior.metadata_bytes();
        let prior = std::sync::Arc::make_mut(prior);
        prior.parameters = parameters;
        prior.retained = retained;
        let added = prior.allocated_bytes().saturating_sub(before);
        self.bytes = self.bytes.saturating_add(added);
        Ok(prior.metadata_bytes().saturating_sub(metadata))
    }

    pub fn source(&self) -> Option<&std::sync::Arc<ManagedSourceFrame>> {
        self.source.as_ref()
    }
    pub fn follows_graph(&self) -> bool {
        self.contract.follows_graph(&self.instance.spec)
    }

    pub fn instance(&self) -> &ManagedInstance {
        &self.instance
    }
    pub fn prior(&self, call: u64) -> Option<&ManagedPrior> {
        self.prior.get(&call).map(std::sync::Arc::as_ref)
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
        self.source
            .iter()
            .flat_map(|source| source.datasets())
            .flat_map(|data| &data.batches)
            .chain(self.prior.values().flat_map(|prior| prior.batches()))
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
    pub graph: Option<PackageResultRefV1>,
}

impl ManagedReceipt {
    pub(super) fn matches_frontier(&self, offered: &Option<ManagedFrontier>) -> bool {
        match (&self.frontier, offered) {
            (None, None) => true,
            (Some(saved), Some(offered)) => {
                !offered.pending
                    && saved.cursor == offered.cursor
                    && saved.next_change == offered.next_change
            }
            _ => false,
        }
    }
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

        let attempt: Self = ManagedCodec::decode(bytes).context(crate::ManagedDecodingSnafu)?;
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
    pub(super) BTreeMap<u64, std::sync::Arc<ManagedPrior>>,
    pub(super) Option<std::sync::Arc<ManagedExecution>>,
    pub(super) Option<std::sync::Arc<ManagedSourceFrame>>,
);

impl ManagedAttempt {
    pub fn source_meta(&self) -> crate::AnalysisStoreMetaV1 {
        self.0.capture.source_meta()
    }
    pub fn prior_result(&self, call: u64) -> Option<&PackageResultRefV1> {
        self.0.capture.prior.get(&call).and_then(Option::as_ref)
    }

    pub(in crate::analysis) fn follows_graph(&self) -> bool {
        self.0.capture.follows_graph(&self.1.spec)
    }

    pub fn captured_revision(&self) -> u64 {
        self.0.capture.revision
    }

    pub(in crate::analysis) fn switches_version(&self) -> bool {
        self.0.capture.generation != self.0.capture.expected_generation
    }

    pub(in crate::analysis) fn witnesses(&self) -> &[AnalysisWitnessV1] {
        &self.0.capture.witnesses
    }

    pub(in crate::analysis) fn contexts(&self) -> &[AnalysisContextRefV1] {
        &self.0.capture.contexts
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

impl From<&ManagedAttempt> for ManagedCapture {
    fn from(reference: &ManagedAttempt) -> Self {
        Self {
            execution: None,
            instance: reference.1.clone(),
            contract: reference.0.capture.clone(),
            prior: reference.3.clone(),
            bytes: 0,
            source: None,
        }
    }
}

pub struct ManagedReturn<'a> {
    pub call: u64,
    pub evaluation: &'a sdk::Evaluation,
    pub output: &'a sdk::Output,
    pub changes: Option<&'a ManagedChanges>,
}

pub struct ManagedCommit<'a> {
    pub attempt: &'a ManagedAttempt,
    /// The native publication has no remaining work for this captured input.
    pub completed: bool,
    pub now_utc_ns: u64,
    pub returns: &'a [ManagedReturn<'a>],
    pub selected: &'a sdk::Dataset,
    pub selected_schema: &'a sdk::Schema,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Record {
    pub instance: String,
    pub call: u64,
    pub attempt: String,
    pub context: ResultContext,
    pub changes: Option<RecordChanges>,
    pub dependencies: Vec<PackageResultRefV1>,
    pub witnesses: Vec<AnalysisWitnessV1>,
    pub contexts: Vec<AnalysisContextRefV1>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct RecordChanges {
    pub base: Option<PackageResultRefV1>,
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
