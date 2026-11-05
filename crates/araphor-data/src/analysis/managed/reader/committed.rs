use super::*;
use std::sync::Mutex;

type OwnerKey = ([u8; 16], String);

#[derive(Default)]
struct Owners {
    selected: BTreeMap<OwnerKey, Arc<SelectedOwner>>,
    producers: BTreeMap<OwnerKey, Arc<ProducerOwner>>,
}

#[derive(Default)]
pub(in crate::analysis) struct CommittedOwners(Mutex<Owners>);

pub(in crate::analysis::managed) struct ResultOwners {
    selected: Arc<SelectedOwner>,
    producers: Vec<(String, Arc<ProducerOwner>)>,
}

impl ResultOwners {
    pub(in crate::analysis::managed) fn new(
        step: Step,
        attempt: Attempt,
        spec: ManagedSpec,
        revision: u64,
        records: Vec<(String, Record)>,
    ) -> Self {
        let selected = Arc::new(SelectedOwner {
            step,
            attempt,
            spec,
            revision,
        });
        let producers = records
            .into_iter()
            .map(|(id, record)| {
                (
                    id,
                    Arc::new(ProducerOwner {
                        record,
                        selected: Arc::clone(&selected),
                    }),
                )
            })
            .collect();
        Self {
            selected,
            producers,
        }
    }
}

pub(in crate::analysis::managed) struct PendingOwners<'a> {
    store: &'a CommittedOwners,
    selected: OwnerKey,
    producers: Vec<OwnerKey>,
    committed: bool,
}

impl PendingOwners<'_> {
    pub(in crate::analysis::managed) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingOwners<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut owners = self
            .store
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        owners.selected.remove(&self.selected);
        for key in &self.producers {
            owners.producers.remove(key);
        }
    }
}

impl CommittedOwners {
    pub(in crate::analysis) fn restore(reader: &Connection) -> Result<Self> {
        let mut query = reader
            .prepare(
                "SELECT tenant_id,result_id,commit_revision FROM analysis_results
             WHERE processor_id='managed-definition-v1' ORDER BY commit_revision,result_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare committed managed owners",
            })?;
        let rows = query
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read committed managed owners",
            })?
            .collect::<duckdb::Result<Vec<_>>>()
            .context(AnalysisDatabaseSnafu {
                operation: "decode committed managed owners",
            })?;
        let store = Self::default();
        for (tenant, id, revision) in rows {
            let tenant = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("managed result tenant"))?;
            let (step, _) = AnalysisStore::managed_step_header(reader, tenant, &id)?;
            let attempt =
                AnalysisStore::managed_attempt_from(reader, tenant, &step.instance, &step.attempt)?
                    .ok_or_else(|| Code::Missing.error("managed selected attempt"))?;
            let spec = AnalysisStore::managed_version_from(
                reader,
                tenant,
                &step.instance,
                attempt.capture.generation,
            )?;
            let receipt = attempt
                .receipt
                .as_ref()
                .ok_or_else(|| Code::Invalid.error("unpublished managed selected result"))?;
            let records = receipt
                .results
                .values()
                .map(|reference| {
                    AnalysisStore::managed_meta_from(reader, tenant, &reference.result_id)
                        .map(|(record, _)| (reference.result_id.clone(), record))
                })
                .collect::<Result<Vec<_>>>()?;
            store
                .seal(ResultOwners::new(step, attempt, spec, revision, records))?
                .commit();
        }
        Ok(store)
    }

    pub(in crate::analysis) fn replace(&self, reader: &Connection) -> Result<()> {
        let values = Self::restore(reader)?
            .0
            .into_inner()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?;
        *self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))? = values;
        Ok(())
    }

    pub(in crate::analysis::managed) fn seal(
        &self,
        values: ResultOwners,
    ) -> Result<PendingOwners<'_>> {
        let mut owners = self
            .0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?;
        let tenant = values.selected.spec.tenant;
        let id = values
            .selected
            .attempt
            .receipt
            .as_ref()
            .ok_or_else(|| Code::Invalid.error("unpublished managed selected result"))?
            .selected
            .result_id
            .clone();
        let selected = (tenant, id);
        let mut producers = Vec::with_capacity(values.producers.len());
        owners.selected.insert(selected.clone(), values.selected);
        for (id, value) in values.producers {
            let key = (tenant, id);
            owners.producers.insert(key.clone(), value);
            producers.push(key);
        }
        Ok(PendingOwners {
            store: self,
            selected,
            producers,
            committed: false,
        })
    }

    pub(super) fn selected(
        &self,
        tenant: [u8; 16],
        id: &str,
        revision: u64,
    ) -> Result<Arc<SelectedOwner>> {
        self.0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?
            .selected
            .get(&(tenant, id.to_owned()))
            .filter(|value| value.revision == revision)
            .cloned()
            .ok_or_else(|| Code::Missing.error("managed selected owner"))
    }

    pub(super) fn producer(
        &self,
        tenant: [u8; 16],
        id: &str,
        revision: u64,
    ) -> Result<Arc<ProducerOwner>> {
        self.0
            .lock()
            .map_err(|_| Code::Invalid.error("committed managed owner lock"))?
            .producers
            .get(&(tenant, id.to_owned()))
            .filter(|value| value.selected.revision == revision)
            .cloned()
            .ok_or_else(|| Code::Missing.error("managed result owner"))
    }
}
