use super::*;
use araphor_data::ManagedSourceRows;
use datafusion::execution::memory_pool::MemoryReservation;

pub(super) struct NativeRead {
    pub(super) image: SourceImage,
    pub(super) rows: Vec<Arc<ManagedSourceRows>>,
    pub(super) _memory: Vec<MemoryReservation>,
}

#[derive(Default, Debug)]
pub(super) struct PortLineage {
    reads: BTreeSet<usize>,
    derived: BTreeMap<usize, Arc<araphor_data::ManagedDerivedSource>>,
}

impl PortLineage {
    fn matches(&self, other: &Self) -> bool {
        self.reads == other.reads && self.derived.keys().eq(other.derived.keys())
    }
    fn allocated_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(
                self.reads
                    .len()
                    .saturating_mul(2 * std::mem::size_of::<usize>()),
            )
            .saturating_add(self.derived.len().saturating_mul(
                2 * std::mem::size_of::<(usize, Arc<araphor_data::ManagedDerivedSource>)>(),
            ))
    }
}

impl SourceSnapshot {
    fn lineage(
        &self,
        plans: &[Arc<dyn ExecutionPlan>],
        owner: &crate::definition::CallContext,
    ) -> Result<PortLineage> {
        let mut result = PortLineage::default();
        for plan in plans {
            PortExec::apply(plan, &mut |node| {
                if let Some(package) =
                    node.downcast_ref::<crate::definition::physical::PackageExec>()
                {
                    if owner.cached(package.logical_call())? {
                        return Ok(TreeNodeRecursion::Jump);
                    }
                }
                if let Some(source) = SourceData::from_plan(node.as_ref()) {
                    match source.origin {
                        SourceOrigin::Durable(_) => {
                            result.reads.insert(source.read);
                        }
                        SourceOrigin::Port(id) => {
                            let captured = self.captured.lock().map_err(|_| {
                                DataFusionError::Internal("source lineage lock is poisoned".into())
                            })?;
                            if let Some(lineage) = captured
                                .as_ref()
                                .and_then(|captured| captured.lineage.get(&id))
                            {
                                result.reads.extend(lineage.reads.iter().copied());
                                result.derived.extend(
                                    lineage
                                        .derived
                                        .iter()
                                        .map(|(key, value)| (*key, Arc::clone(value))),
                                );
                            }
                        }
                        SourceOrigin::Local(_) => {}
                    }
                }
                Ok(TreeNodeRecursion::Continue)
            })?;
        }
        Ok(result)
    }

    pub(super) fn bind_lineage(
        &self,
        read: usize,
        plans: &[Arc<dyn ExecutionPlan>],
        owner: &crate::definition::CallContext,
        derived: Option<Arc<araphor_data::ManagedDerivedSource>>,
    ) -> Result<()> {
        let mut lineage = self.lineage(plans, owner)?;
        if let Some(derived) = derived {
            lineage
                .derived
                .insert(Arc::as_ptr(&derived) as usize, derived);
        }
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source lineage lock is poisoned".into()))?;
        let captured = captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("source capture is absent".into()))?;
        if let Some(prior) = captured.lineage.get(&read) {
            if !prior.matches(&lineage) {
                return Err(DataFusionError::Execution("source lineage differs".into()));
            }
            return Ok(());
        }
        captured._memory.try_grow(
            std::mem::size_of::<(usize, Arc<PortLineage>)>()
                .saturating_add(lineage.allocated_bytes()),
        )?;
        captured.lineage.insert(read, Arc::new(lineage));
        Ok(())
    }

    pub(super) fn share_lineage(&self, from: usize, read: usize) -> Result<()> {
        let mut captured = self
            .captured
            .lock()
            .map_err(|_| DataFusionError::Internal("source lineage lock is poisoned".into()))?;
        let captured = captured
            .as_mut()
            .ok_or_else(|| DataFusionError::Internal("source capture is absent".into()))?;
        if let Some(lineage) = captured.lineage.get(&from).cloned() {
            if let Some(prior) = captured.lineage.get(&read) {
                if !prior.matches(&lineage) {
                    return Err(DataFusionError::Execution(
                        "shared source lineage differs".into(),
                    ));
                }
            } else {
                captured
                    ._memory
                    .try_grow(std::mem::size_of::<(usize, Arc<PortLineage>)>())?;
                captured.lineage.insert(read, lineage);
            }
        }
        Ok(())
    }

    pub(crate) fn attribute_input(
        &self,
        call: u64,
        plan: &Arc<dyn ExecutionPlan>,
        owner: &crate::definition::CallContext,
    ) -> Result<()> {
        let Some(view) = self.source_view()? else {
            return Ok(());
        };
        let lineage = self.lineage(std::slice::from_ref(plan), owner)?;
        let reads = self
            .reads
            .lock()
            .map_err(|_| DataFusionError::Internal("source read lock is poisoned".into()))?;
        let count = lineage
            .reads
            .iter()
            .filter_map(|id| reads.get(id))
            .filter(|read| matches!(read.image, SourceImage::After | SourceImage::Inserted))
            .map(|read| read.rows.len())
            .sum::<usize>();
        let bytes = count
            .checked_add(lineage.derived.len())
            .ok_or_else(|| DataFusionError::ResourcesExhausted("source lineage memory".into()))?
            .checked_mul(4 * std::mem::size_of::<Arc<ManagedSourceRows>>())
            .and_then(|bytes| bytes.checked_add(8 * std::mem::size_of::<usize>()))
            .ok_or_else(|| {
                DataFusionError::ResourcesExhausted("source call lineage memory".into())
            })?;
        let memory = Arc::new(self.memory.reserve_input(bytes)?);
        let mut rows = Vec::with_capacity(count);
        for id in lineage.reads {
            if let Some(read) = reads
                .get(&id)
                .filter(|read| matches!(read.image, SourceImage::After | SourceImage::Inserted))
            {
                rows.extend(read.rows.iter().map(Arc::clone));
            }
        }
        drop(reads);
        let derived = lineage.derived.into_values().collect::<Vec<_>>();
        let scratch =
            araphor_data::ManagedSourceFrame::attribution_bytes(&rows).ok_or_else(|| {
                DataFusionError::ResourcesExhausted("source attribution memory".into())
            })?;
        let _scratch = self.memory.reserve_input(scratch)?;
        view.frame()
            .attribute_input(call, &rows, &derived, memory)
            .map_err(Self::data_error)
    }
}
