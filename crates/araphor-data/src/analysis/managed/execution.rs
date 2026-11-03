use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use araphor_analysis_sdk as sdk;

use super::model::*;
use crate::{AnalysisStore, AnalysisStoreMetaV1, ResultContext};

#[derive(Debug, Default)]
pub struct ManagedExecution {
    state: Mutex<Option<Committed>>,
}

#[derive(Debug)]
pub(super) struct Committed {
    meta: AnalysisStoreMetaV1,
    instance: ManagedInstance,
    calls: BTreeMap<u64, Arc<ManagedPrior>>,
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
        })
    }
}

impl ManagedPrior {
    pub(super) fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.result.capacity())
            .saturating_add(self.source.result.result_id.capacity())
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
                            .map_or(0, ManagedChanges::metadata_bytes),
                    )
            }))
    }

    pub(super) fn batches(&self) -> impl Iterator<Item = &sdk::RecordBatch> {
        self.parameters
            .iter()
            .chain(self.checkpoint.iter().flat_map(|state| &state.datasets))
            .flat_map(|data| &data.batches)
            .chain(
                self.retained
                    .iter()
                    .flat_map(|state| state.evaluation.batches().chain(state.output.batches())),
            )
    }

    pub(super) fn metadata_bytes(&self) -> usize {
        self.allocated_bytes().saturating_sub(
            self.batches()
                .flat_map(sdk::RecordBatch::columns)
                .fold(0usize, |bytes, array| {
                    bytes.saturating_add(array.get_buffer_memory_size())
                }),
        )
    }
}

impl AnalysisStore {
    pub(super) fn retain_managed(
        input: &ManagedCommit<'_>,
        receipt: &ManagedReceipt,
    ) -> Option<(Arc<ManagedExecution>, Committed)> {
        let owner = input.attempt.4.as_ref()?;
        let mut calls = input.attempt.3.clone();
        let instance = input.attempt.instance();
        for returned in input.returns {
            let declaration = &instance.spec.manifest.calls[&returned.call];
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
                    source: super::ManagedSourceRef {
                        result: receipt.selected.clone(),
                        position: crate::StorePositionV1 {
                            commit_revision: input.attempt.captured_revision(),
                            ordinal: u32::MAX,
                        },
                    },
                    context,
                    parameters,
                    checkpoint: returned.output.checkpoint.clone(),
                    retained: Some(Arc::new(RetainedCall {
                        evaluation,
                        output: returned.output.clone(),
                        changes: returned.changes.cloned(),
                    })),
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
        };
        Some((Arc::clone(owner), state))
    }
}
