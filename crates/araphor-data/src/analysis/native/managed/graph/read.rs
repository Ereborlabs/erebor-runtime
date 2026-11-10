use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use araphor_graph::{Read, ReadOrigin};
use sdk::arrow_array::{Array, BinaryArray, UInt64Array};

use super::ManagedGraphTransaction;
use crate::analysis::native::NativeStore;
use crate::analysis::PackageResultRefV1;
use crate::{AnalysisReadControl, PackageErrorCodeV1 as Code, Result};

type Identity = (u64, Vec<u8>, Vec<u8>);

impl ManagedGraphTransaction {
    pub fn read(
        &self,
        store: &NativeStore,
        operation: &str,
        name: &str,
        arguments: &sdk::RecordBatch,
        mut reserve: impl FnMut(usize) -> Result<Arc<dyn Any + Send + Sync>>,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Input> {
        self.call
            .spec
            .read_schema(operation, name)
            .map_err(|_| Code::Denied.error("Graph read capability"))?;
        let shape = self
            .call
            .spec
            .relation(name)
            .map_err(|_| Code::Denied.error("Graph read relation"))?
            .engine();
        if arguments.schema().as_ref()
            != &self
                .call
                .spec
                .argument_schema(operation)
                .map_err(|_| Code::Denied.error("Graph read arguments"))?
        {
            return Err(Code::Invalid.error("Graph read argument schema"));
        }
        reserve(arguments.get_array_memory_size().saturating_mul(4))?;
        let keys = if operation == "owned" {
            if arguments.num_rows() != 0 {
                return Err(Code::Invalid.error("Graph owned arguments"));
            }
            Vec::new()
        } else {
            arguments
                .column(0)
                .as_any()
                .downcast_ref::<BinaryArray>()
                .filter(|array| array.null_count() == 0)
                .ok_or_else(|| Code::Invalid.error("Graph read keys"))?
                .iter()
                .flatten()
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>()
        };
        let read = match operation {
            "owned" => Read::Owned(self.call.writer),
            "nodes" => Read::Nodes,
            "outgoing" => Read::Outgoing,
            "incoming" => Read::Incoming,
            "neighbors" => Read::Neighbors,
            _ => return Err(Code::Invalid.error("Graph read operation")),
        };
        let relation = self.call.relations[name];
        let mut callback = self.callback()?;
        let work = callback
            .work
            .as_mut()
            .ok_or_else(|| Code::Incomplete.error("Graph callback state"))?;
        let (mut batches, base) = {
            let bound = self.authority()?;
            let authority = bound
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?;
            authority.check_snapshot(&self.call, store, control)?;
            let mut batches = Vec::new();
            let mut origins = BTreeMap::new();
            authority.prepared.view.read(
                relation,
                read,
                arguments,
                &|_, bytes, total| Self::reserve(self.budget.as_ref(), control, bytes, total),
                |read| {
                    let batch = read.batch().clone();
                    let identities =
                        Self::identities(&batch).map_err(araphor_graph::Error::backend)?;
                    for (identity, origin) in
                        identities.into_iter().zip(read.origins().iter().copied())
                    {
                        if origins.insert(identity, origin).is_some() {
                            return Err(araphor_graph::Error::backend(
                                Code::Invalid.error("Graph duplicate base member"),
                            ));
                        }
                    }
                    work.leases.push(Arc::new(read));
                    batches.push(batch);
                    Ok(())
                },
            )?;
            (batches, origins)
        };
        let bytes = self
            .predecessors
            .iter()
            .map(|prior| &prior.work.journal)
            .chain(std::iter::once(&work.journal))
            .try_fold(0usize, |bytes, journal| {
                journal.batches().iter().try_fold(bytes, |bytes, staged| {
                    let batch = match staged {
                        araphor_graph::Staged::Edits { batch, .. }
                        | araphor_graph::Staged::Clear { batch, .. } => batch,
                    };
                    bytes.checked_add(batch.get_array_memory_size().saturating_mul(4))
                })
            })
            .ok_or_else(|| Code::Limit.error("Graph overlay memory"))?;
        reserve(bytes)?;
        for journal in self
            .predecessors
            .iter()
            .map(|prior| &prior.work.journal)
            .chain(std::iter::once(&work.journal))
        {
            batches = journal.overlay(relation, &shape, read, &keys, batches)?;
        }
        let mut committed = BTreeSet::new();
        let mut pending = BTreeMap::new();
        let mut selected = BTreeSet::new();
        for batch in &batches {
            for identity in Self::identities(batch)? {
                if identity.0 == self.call.writer
                    && work.journal.contains(relation, &identity.1, &identity.2)
                {
                    continue;
                }
                if let Some(prior) = self.predecessors.iter().find(|prior| {
                    prior.call.writer == identity.0
                        && prior
                            .work
                            .journal
                            .contains(relation, &identity.1, &identity.2)
                }) {
                    pending.insert(prior.call.call, Arc::clone(prior));
                    continue;
                }
                let origin = *base
                    .get(&identity)
                    .ok_or_else(|| Code::Invalid.error("Graph read origin"))?;
                committed.insert(origin);
                selected.insert(super::transaction::ReadRow {
                    relation,
                    writer: identity.0,
                    owner: identity.1,
                    key: identity.2,
                    revision: origin.revision,
                });
            }
        }
        let origins = {
            let mut bound = self.authority()?;
            let authority = bound
                .as_mut()
                .ok_or_else(|| Code::Incomplete.error("Graph invocation authority"))?;
            let mut origins = BTreeMap::new();
            for origin in committed {
                origins.insert(
                    origin,
                    authority.origin(&self.call, store, origin, control, &mut reserve)?,
                );
            }
            authority.check_snapshot(&self.call, store, control)?;
            origins
        };
        let bytes = selected
            .iter()
            .try_fold(0usize, |bytes, row| {
                bytes
                    .checked_add(
                        3 * std::mem::size_of::<super::transaction::ReadRow>()
                            + 32 * std::mem::size_of::<usize>(),
                    )?
                    .checked_add(row.owner.capacity())?
                    .checked_add(row.key.capacity())
            })
            .and_then(|bytes| {
                origins.values().try_fold(bytes, |bytes, reference| {
                    bytes
                        .checked_add(
                            3 * std::mem::size_of::<(ReadOrigin, PackageResultRefV1)>()
                                + 32 * std::mem::size_of::<usize>(),
                        )?
                        .checked_add(reference.result_id.capacity())
                })
            })
            .ok_or_else(|| Code::Limit.error("Graph read provenance memory"))?;
        let lease = reserve(bytes)?;
        control.check()?;
        work.origins.extend(origins);
        work.reads.extend(selected);
        work.pending.extend(pending);
        work.leases.push(lease);
        Ok(sdk::Input {
            data: sdk::Dataset {
                name: name.into(),
                batches,
            },
            revision: sdk::Revision {
                owner: "araphor-graph".into(),
                id: self.call.attempt.captured_revision().to_string(),
                window: None,
            },
            coverage: sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            },
        })
    }

    fn identities(batch: &sdk::RecordBatch) -> Result<Vec<Identity>> {
        let writers = batch
            .column_by_name("writer")
            .and_then(|array| array.as_any().downcast_ref::<UInt64Array>());
        let owners = batch
            .column_by_name("owner")
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>());
        let keys = batch
            .column_by_name("key")
            .and_then(|array| array.as_any().downcast_ref::<BinaryArray>());
        let (Some(writers), Some(owners), Some(keys)) = (writers, owners, keys) else {
            return Err(Code::Invalid.error("Graph read identity shape"));
        };
        if writers.null_count() != 0 || owners.null_count() != 0 || keys.null_count() != 0 {
            return Err(Code::Invalid.error("Graph read identity null"));
        }
        Ok((0..batch.num_rows())
            .map(|row| {
                (
                    writers.value(row),
                    owners.value(row).to_vec(),
                    keys.value(row).to_vec(),
                )
            })
            .collect())
    }
}
