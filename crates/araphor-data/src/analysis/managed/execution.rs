use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;
use duckdb::Connection;

use super::model::*;
use super::source::ManagedSourceRef;
use crate::{AnalysisStore, AnalysisStoreMetaV1, Result, ResultContext};

#[derive(Debug, Default)]
pub struct ManagedExecution {
    state: Mutex<Option<Committed>>,
}

#[derive(Debug)]
pub(super) struct Committed {
    meta: AnalysisStoreMetaV1,
    instance: ManagedInstance,
    calls: BTreeMap<u64, Arc<ManagedPrior>>,
    source: Option<SourceHead>,
}

#[derive(Debug)]
struct SourceHead {
    reference: ManagedSourceRef,
    members: Arc<std::collections::BTreeSet<Vec<u8>>>,
}

#[derive(Debug)]
pub(in crate::analysis) struct Retention {
    owner: Arc<ManagedExecution>,
}

impl ManagedExecution {
    pub fn clear(&self) {
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = None;
    }
    pub(super) fn calls(
        &self,
        request: &ManagedRead,
        meta: &AnalysisStoreMetaV1,
    ) -> BTreeMap<u64, Arc<ManagedPrior>> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state
            .as_ref()
            .filter(|state| {
                !request.rebuild
                    && request.expected.is_none()
                    && state.instance == request.instance
                    && state.meta.store_uuid == meta.store_uuid
                    && state.meta.schema_version == meta.schema_version
                    && state.meta.recovery_epoch == meta.recovery_epoch
                    && state.meta.commit_revision <= meta.commit_revision
            })
            .map(|state| state.calls.clone())
            .unwrap_or_default()
    }

    pub(super) fn promote(&self, state: Committed) {
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = Some(state);
    }

    pub(super) fn source_members(
        &self,
        instance: &ManagedInstance,
        meta: &AnalysisStoreMetaV1,
        reference: &ManagedSourceRef,
    ) -> Option<Arc<std::collections::BTreeSet<Vec<u8>>>> {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let state = state.as_ref().filter(|state| {
            &state.instance == instance
                && state.meta.store_uuid == meta.store_uuid
                && state.meta.schema_version == meta.schema_version
                && state.meta.recovery_epoch == meta.recovery_epoch
                && state.meta.commit_revision <= meta.commit_revision
        })?;
        let source = state
            .source
            .as_ref()
            .filter(|source| &source.reference == reference)?;
        Some(Arc::clone(&source.members))
    }

    pub fn metadata_bytes(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.as_ref().map_or(0, |state| {
            state
                .instance
                .allocation_bytes()
                .unwrap_or(usize::MAX)
                .saturating_add(
                    state
                        .calls
                        .values()
                        .map(|prior| prior.metadata_bytes())
                        .sum::<usize>(),
                )
                .saturating_add(state.source.as_ref().map_or(0, |source| {
                    size_of::<SourceHead>()
                        .saturating_add(source.reference.result.result_id.capacity())
                        .saturating_add(super::source::SourceCapture::member_bytes(&source.members))
                }))
        })
    }
}

impl ManagedPrior {
    pub(super) fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.result.capacity())
            .saturating_add(self.context.target.capacity())
            .saturating_add(self.context.context.id.capacity())
            .saturating_add(self.context.artifact.as_ref().map_or(
                0,
                araphor_package::PackageArtifactIdentityV1::allocated_bytes,
            ))
            .saturating_add(
                self.context
                    .inputs
                    .iter()
                    .map(|revision| {
                        std::mem::size_of_val(revision)
                            + revision.owner.capacity()
                            + revision.id.capacity()
                            + revision
                                .window
                                .as_ref()
                                .map_or(0, |window| window.source.capacity())
                    })
                    .sum::<usize>(),
            )
            .saturating_add(
                self.context
                    .input_coverage
                    .iter()
                    .chain(std::iter::once(&self.context.coverage))
                    .map(sdk::Coverage::metadata_bytes)
                    .sum::<usize>(),
            )
            .saturating_add(
                self.parameters
                    .as_ref()
                    .map_or(0, sdk::Dataset::allocated_bytes),
            )
            .saturating_add(self.checkpoint.as_ref().map_or(0, |state| {
                state
                    .datasets
                    .iter()
                    .map(sdk::Dataset::allocated_bytes)
                    .sum::<usize>()
            }))
            .saturating_add(self.retained.as_ref().map_or(0, |state| {
                state
                    .evaluation
                    .allocated_bytes()
                    .saturating_add(state.output.allocated_bytes())
                    .saturating_add(
                        state
                            .changes
                            .as_ref()
                            .map_or(0, ManagedChanges::allocated_bytes),
                    )
            }))
    }

    fn metadata_bytes(&self) -> usize {
        let buffers = self
            .parameters
            .iter()
            .chain(self.checkpoint.iter().flat_map(|state| &state.datasets))
            .chain(self.retained.iter().flat_map(|state| {
                state
                    .evaluation
                    .inputs
                    .iter()
                    .map(|input| &input.data)
                    .chain(state.output.datasets.iter())
                    .chain(
                        state
                            .output
                            .checkpoint
                            .iter()
                            .flat_map(|state| &state.datasets),
                    )
            }))
            .flat_map(|data| &data.batches)
            .chain(self.retained.iter().flat_map(|state| {
                state
                    .evaluation
                    .parameters
                    .iter()
                    .chain(state.output.reasons.iter().map(|reason| &reason.details))
            }))
            .flat_map(sdk::RecordBatch::columns)
            .map(|array| array.get_buffer_memory_size())
            .sum::<usize>();
        self.allocated_bytes().saturating_sub(buffers)
    }
}

impl Retention {
    pub(super) fn new(owner: Arc<ManagedExecution>) -> Self {
        Self { owner }
    }
}

impl AnalysisStore {
    pub(super) fn retain_managed(
        &self,
        reader: &Connection,
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
        verified: &mut crate::analysis::context::VerifiedPackages,
    ) -> Result<Option<(Arc<ManagedExecution>, Committed)>> {
        let Some(retention) = &input.attempt.4 else {
            return Ok(None);
        };
        let mut calls = input.attempt.3.clone();
        let instance = input.attempt.instance();
        for returned in input.returns {
            if returned.retained.is_some() {
                continue;
            }
            let declaration = &instance.spec.manifest.calls[&returned.call];
            self.verify_package_revision(
                reader,
                instance.spec.tenant,
                &declaration.package,
                verified,
            )?;
            let mut evaluation = returned.evaluation.clone();
            evaluation.checkpoint = None;
            evaluation.previous_outputs.clear();
            let mut context = ResultContext::new(
                &evaluation.context.id,
                input.attempt.request().time_utc_ns,
                &evaluation.inputs,
            );
            context.context = evaluation.context.clone();
            context.target = declaration.target.clone();
            context.artifact = declaration.artifact.clone();
            let reference = &receipt.results[&returned.call];
            let parameters = evaluation.parameters.as_ref().map(|batch| sdk::Dataset {
                name: "parameters".into(),
                batches: vec![batch.clone()],
            });
            calls.insert(
                returned.call,
                Arc::new(ManagedPrior {
                    revision: reference.commit_revision,
                    result: reference.result_id.clone(),
                    context,
                    parameters,
                    checkpoint: returned.output.checkpoint.clone(),
                    retained: Some(Arc::new(RetainedCall {
                        evaluation,
                        output: returned.output.clone(),
                        changes: returned.changes.cloned(),
                    })),
                    reusable: false,
                }),
            );
        }
        let mut instance = instance.clone();
        instance.progress = receipt.commit_revision;
        let capture = &input.attempt.0.capture;
        let state = Committed {
            meta: AnalysisStoreMetaV1 {
                store_uuid: capture.store,
                schema_version: capture.schema,
                recovery_epoch: capture.recovery,
                commit_revision: receipt.commit_revision,
            },
            instance,
            calls,
            source: input.attempt.5.as_ref().map(|frame| SourceHead {
                reference: ManagedSourceRef {
                    result: receipt.selected.clone(),
                    position: frame.frame.position(),
                },
                members: Arc::clone(&frame.members),
            }),
        };
        let owner = Arc::clone(&retention.owner);
        Ok(Some((owner, state)))
    }
}
