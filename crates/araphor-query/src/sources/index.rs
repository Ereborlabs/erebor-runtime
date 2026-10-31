use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use araphor_data::{
    AnalysisStreamIdentityV1, ManagedSourceBlock, ManagedSourceFrame, ManagedSourceRead,
    ManagedSourceRef, ManagedSourceRows,
};
use datafusion::arrow::array::{Array, RecordBatch, UInt64Array};
use datafusion::arrow::compute::take;
use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatchOptions;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::physical_expr::PhysicalExpr;
use datafusion::physical_plan::joins::HashExpr;

use super::SourceSnapshot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceImage {
    Before,
    After,
    Inserted,
    Removed,
}

#[derive(Clone, Debug)]
pub(crate) struct SourceKey {
    pub(crate) id: usize,
    pub(crate) table: String,
    pub(crate) columns: Vec<usize>,
    pub(crate) hash: Arc<HashExpr>,
}

#[derive(Debug)]
pub(crate) struct SourceIndex {
    keys: Vec<SourceKey>,
    state: Mutex<IndexState>,
    memory: Arc<crate::memory::Memory>,
    _metadata: MemoryReservation,
}

#[derive(Debug, Default)]
struct IndexState {
    head: Option<ManagedSourceRef>,
    next: u64,
    tables: BTreeMap<String, IndexedTable>,
    leases: BTreeMap<u64, usize>,
    retired: VecDeque<(u64, String, RowAddress)>,
}

#[derive(Debug)]
struct IndexedTable {
    columns: Vec<usize>,
    schema: SchemaRef,
    blocks: BTreeMap<u64, Arc<SourceBlock>>,
    live: BTreeMap<u64, usize>,
    removed: BTreeMap<RowAddress, u64>,
    buckets: BTreeMap<usize, BTreeMap<u64, BTreeSet<RowAddress>>>,
    cursors: BTreeMap<AnalysisStreamIdentityV1, BTreeMap<u64, BTreeSet<RowAddress>>>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RowAddress {
    block: u64,
    row: usize,
}

#[derive(Debug)]
struct SourceBlock {
    batch: RecordBatch,
    handles: ManagedSourceBlock,
    born: u64,
    hashes: Arc<BTreeMap<usize, Arc<UInt64Array>>>,
    _memory: Arc<MemoryReservation>,
}

pub(crate) struct SourceView {
    index: Arc<SourceIndex>,
    parent: Option<ManagedSourceRef>,
    frame: Arc<ManagedSourceFrame>,
    tables: BTreeMap<String, IndexedTable>,
    removed: BTreeMap<String, BTreeSet<RowAddress>>,
    next: u64,
    control: araphor_data::AnalysisReadControl,
    _staging: MemoryReservation,
}

pub(crate) struct SourceRows {
    pub(crate) batches: Vec<RecordBatch>,
    pub(crate) origins: Vec<ManagedSourceRows>,
}

impl SourceIndex {
    pub(crate) fn new(
        keys: Vec<SourceKey>,
        memory: Arc<crate::memory::Memory>,
    ) -> Result<Arc<Self>> {
        let bytes = size_of::<Self>()
            .saturating_add(keys.capacity().saturating_mul(size_of::<SourceKey>()))
            .saturating_add(
                keys.iter()
                    .map(|key| {
                        key.table.capacity().saturating_add(
                            key.columns.capacity().saturating_mul(size_of::<usize>()),
                        )
                    })
                    .sum::<usize>(),
            );
        let metadata = memory.reserve_input(bytes)?;
        Ok(Arc::new(Self {
            keys,
            state: Mutex::new(IndexState::default()),
            memory,
            _metadata: metadata,
        }))
    }

    fn lock(&self) -> Result<MutexGuard<'_, IndexState>> {
        self.state
            .lock()
            .map_err(|_| DataFusionError::Internal("the retained source index is poisoned".into()))
    }

    pub(crate) fn reference(&self) -> Result<Option<ManagedSourceRef>> {
        Ok(self.lock()?.head.clone())
    }

    pub(crate) fn committed(&self, frame: &ManagedSourceFrame) -> Result<bool> {
        let Some(proof) = frame.proof() else {
            return Ok(false);
        };
        Ok(self.lock()?.head.as_ref()
            == Some(&ManagedSourceRef {
                result: proof.result.clone(),
                position: frame.position(),
            }))
    }

    pub(crate) fn discard_restore(&self) -> Result<()> {
        let mut state = self.lock()?;
        if !state.leases.is_empty() {
            return Err(Self::conflict());
        }
        *state = IndexState::default();
        Ok(())
    }

    pub(crate) fn stage(
        self: &Arc<Self>,
        frame: Arc<ManagedSourceFrame>,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<Arc<SourceView>> {
        control.check().map_err(SourceSnapshot::data_error)?;
        let control = control.within(None).map_err(SourceSnapshot::data_error)?;
        let staging = self.memory.reserve_input(size_of::<SourceView>())?;
        let mut state = self.lock()?;
        let parent = match frame.read() {
            ManagedSourceRead::Initial if state.head.is_none() => None,
            ManagedSourceRead::Changes(parent) if state.head.as_ref() == Some(parent) => {
                Some(parent.clone())
            }
            _ => return Err(Self::conflict()),
        };
        let version = parent
            .as_ref()
            .map_or(0, |parent| parent.result.commit_revision);
        let mut next = state.next;
        for data in frame.datasets() {
            if let Some(table) = state.tables.get(&data.name) {
                let columns = frame
                    .projection()
                    .get(&data.name)
                    .and_then(Option::as_ref)
                    .ok_or_else(SourceIndex::conflict)?
                    .iter()
                    .copied()
                    .collect::<Vec<_>>();
                if table.columns != columns {
                    return Err(Self::conflict());
                }
            }
        }
        *state.leases.entry(version).or_default() += 1;
        drop(state);
        let mut view = SourceView {
            index: Arc::clone(self),
            parent,
            frame,
            tables: BTreeMap::new(),
            removed: BTreeMap::new(),
            next,
            control,
            _staging: staging,
        };
        let frame = &view.frame;
        for data in frame.datasets() {
            if !matches!(data.name.as_str(), "events" | "context_versions") {
                return Err(DataFusionError::NotImplemented(format!(
                    "retained source changes for {}",
                    data.name,
                )));
            }
            let columns = frame
                .projection()
                .get(&data.name)
                .and_then(Option::as_ref)
                .ok_or_else(|| DataFusionError::Internal("the source projection is absent".into()))?
                .iter()
                .copied()
                .collect::<Vec<_>>();
            let schema = Arc::new(
                SourceSnapshot::schemas()
                    .get(&data.name)
                    .ok_or_else(|| DataFusionError::Internal("the source schema is absent".into()))?
                    .project(&columns)?,
            );
            let mut table = IndexedTable::new(columns, schema);
            for key in self.keys.iter().filter(|key| key.table == data.name) {
                table.buckets.insert(key.id, BTreeMap::new());
            }
            for (slot, batch) in data.batches.iter().enumerate() {
                view.control.check().map_err(SourceSnapshot::data_error)?;
                let count = self
                    .keys
                    .iter()
                    .filter(|key| key.table == data.name)
                    .count();
                let entries = size_of::<RowAddress>()
                    .saturating_add(size_of::<(u64, BTreeSet<RowAddress>)>())
                    .saturating_mul(count)
                    .saturating_add(size_of::<(u64, BTreeSet<RowAddress>)>());
                let bytes = size_of::<SourceBlock>()
                    .saturating_add(batch.num_rows().saturating_mul(entries));
                let memory = self.memory.reserve_input(bytes)?;
                view._staging
                    .try_grow(batch.num_rows().saturating_mul(entries))?;
                self.memory.retain_input(batch, &memory)?;
                let mut block = SourceBlock {
                    batch: batch.clone(),
                    handles: frame
                        .row_handles(&data.name, slot)
                        .map_err(SourceSnapshot::data_error)?,
                    born: 0,
                    hashes: Arc::default(),
                    _memory: Arc::new(memory),
                };
                for key in self.keys.iter().filter(|key| key.table == data.name) {
                    let projection = key
                        .columns
                        .iter()
                        .map(|column| {
                            table.columns.binary_search(column).map_err(|_| {
                                DataFusionError::Internal(
                                    "a source index column was not captured".into(),
                                )
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let batch = batch.project(&projection)?;
                    block
                        ._memory
                        .try_grow(batch.num_rows().saturating_mul(size_of::<u64>()))?;
                    let values = key.hash.evaluate(&batch)?.into_array(batch.num_rows())?;
                    let hashes =
                        values
                            .as_any()
                            .downcast_ref::<UInt64Array>()
                            .ok_or_else(|| {
                                DataFusionError::Internal(
                                    "the native source hash type is invalid".into(),
                                )
                            })?;
                    Arc::make_mut(&mut block.hashes).insert(key.id, Arc::new(hashes.clone()));
                }
                table.insert(next, Arc::new(block));
                next = next.checked_add(1).ok_or_else(|| {
                    DataFusionError::Execution("source block identifiers are exhausted".into())
                })?;
            }
            view.tables.insert(data.name.clone(), table);
        }
        let state = self.lock()?;
        let mut removed = BTreeMap::<String, BTreeSet<RowAddress>>::new();
        for (identity, ranges) in frame.removals() {
            for (name, table) in &state.tables {
                if let Some(cursors) = table.cursors.get(identity) {
                    for range in ranges {
                        for (_, addresses) in cursors.range(range.first_cursor..=range.last_cursor)
                        {
                            removed.entry(name.clone()).or_default().extend(
                                addresses
                                    .iter()
                                    .copied()
                                    .filter(|address| table.visible(*address, version)),
                            );
                        }
                    }
                }
            }
        }
        drop(state);
        view.removed = removed;
        view.next = next;
        Ok(Arc::new(view))
    }

    pub(crate) fn restore(
        self: &Arc<Self>,
        frame: ManagedSourceFrame,
        control: &araphor_data::AnalysisReadControl,
    ) -> Result<()> {
        let reference = frame
            .proof()
            .ok_or_else(|| {
                DataFusionError::Execution("the restored source proof is absent".into())
            })?
            .result
            .clone();
        let view = self.stage(Arc::new(frame), control)?;
        view.commit(&reference)
    }

    fn conflict() -> DataFusionError {
        DataFusionError::Execution("the committed source basis differs".into())
    }
}

impl IndexedTable {
    fn new(columns: Vec<usize>, schema: SchemaRef) -> Self {
        Self {
            columns,
            schema,
            blocks: BTreeMap::new(),
            live: BTreeMap::new(),
            removed: BTreeMap::new(),
            buckets: BTreeMap::new(),
            cursors: BTreeMap::new(),
        }
    }

    fn insert(&mut self, id: u64, block: Arc<SourceBlock>) {
        for (index, hashes) in block.hashes.iter() {
            let buckets = self.buckets.entry(*index).or_default();
            for (row, hash) in hashes.values().iter().enumerate() {
                buckets
                    .entry(*hash)
                    .or_default()
                    .insert(RowAddress { block: id, row });
            }
        }
        for row in 0..block.batch.num_rows() {
            if let Some(witness) = block.handles.witness(row) {
                self.cursors
                    .entry(witness.identity.clone())
                    .or_default()
                    .entry(witness.cursor)
                    .or_default()
                    .insert(RowAddress { block: id, row });
            }
        }
        self.live.insert(id, block.batch.num_rows());
        self.blocks.insert(id, block);
    }

    fn visible(&self, address: RowAddress, version: u64) -> bool {
        self.blocks.get(&address.block).is_some_and(|block| {
            block.born <= version
                && self
                    .removed
                    .get(&address)
                    .is_none_or(|removed| *removed > version)
        })
    }

    fn lookup(&self, index: usize, hashes: &BTreeSet<u64>) -> Result<BTreeSet<RowAddress>> {
        let buckets = self.buckets.get(&index).ok_or_else(|| {
            DataFusionError::Internal("the retained source key index is absent".into())
        })?;
        Ok(hashes
            .iter()
            .flat_map(|hash| buckets.get(hash).into_iter().flatten().copied())
            .collect())
    }

    fn reclaim(&mut self, address: RowAddress) {
        let Some(block) = self.blocks.get(&address.block) else {
            return;
        };
        for (id, hashes) in block.hashes.iter() {
            if let Some(buckets) = self.buckets.get_mut(id) {
                let hash = hashes.value(address.row);
                if let Some(bucket) = buckets.get_mut(&hash) {
                    bucket.remove(&address);
                    if bucket.is_empty() {
                        buckets.remove(&hash);
                    }
                }
            }
        }
        if let Some(witness) = block.handles.witness(address.row) {
            if let Some(cursors) = self.cursors.get_mut(&witness.identity) {
                if let Some(rows) = cursors.get_mut(&witness.cursor) {
                    rows.remove(&address);
                    if rows.is_empty() {
                        cursors.remove(&witness.cursor);
                    }
                }
                if cursors.is_empty() {
                    self.cursors.remove(&witness.identity);
                }
            }
        }
        self.removed.remove(&address);
        if let Some(live) = self.live.get_mut(&address.block) {
            *live -= 1;
            if *live == 0 {
                self.live.remove(&address.block);
                self.blocks.remove(&address.block);
            }
        }
    }
}

impl SourceView {
    fn version(&self) -> u64 {
        self.parent
            .as_ref()
            .map_or(0, |parent| parent.result.commit_revision)
    }

    pub(crate) fn frame(&self) -> &Arc<ManagedSourceFrame> {
        &self.frame
    }

    pub(crate) fn commit(
        &self,
        reference: &araphor_data::analysis::PackageResultRefV1,
    ) -> Result<()> {
        self.frame
            .proof()
            .filter(|proof| &proof.result == reference)
            .ok_or_else(|| {
                DataFusionError::Execution("the source acknowledgement differs".into())
            })?;
        if self
            .parent
            .as_ref()
            .is_some_and(|parent| parent.result.commit_revision >= reference.commit_revision)
        {
            return Err(DataFusionError::Execution(
                "the source acknowledgement differs".into(),
            ));
        }
        let mut state = self.index.lock()?;
        let next = ManagedSourceRef {
            result: reference.clone(),
            position: self.frame.position(),
        };
        if state.head.as_ref() == Some(&next) {
            return Ok(());
        }
        if state.head != self.parent {
            return Err(SourceIndex::conflict());
        }
        for (name, addresses) in &self.removed {
            let table = state
                .tables
                .get_mut(name)
                .ok_or_else(SourceIndex::conflict)?;
            for address in addresses {
                table.removed.insert(*address, reference.commit_revision);
            }
            state.retired.extend(
                addresses
                    .iter()
                    .map(|address| (reference.commit_revision, name.clone(), *address)),
            );
        }
        for (name, pending) in &self.tables {
            let table = state.tables.entry(name.clone()).or_insert_with(|| {
                IndexedTable::new(pending.columns.clone(), Arc::clone(&pending.schema))
            });
            for id in pending.buckets.keys() {
                table.buckets.entry(*id).or_default();
            }
            for (id, block) in &pending.blocks {
                let block = Arc::new(SourceBlock {
                    batch: block.batch.clone(),
                    handles: block.handles.clone(),
                    born: reference.commit_revision,
                    hashes: block.hashes.clone(),
                    _memory: Arc::clone(&block._memory),
                });
                table.insert(*id, block);
            }
        }
        state.next = self.next;
        state.head = Some(next);
        Ok(())
    }

    pub(crate) fn read(
        &self,
        name: &str,
        image: SourceImage,
        key: Option<(usize, &BTreeSet<u64>)>,
        columns: &[usize],
        schema: &SchemaRef,
    ) -> Result<SourceRows> {
        self.control.check().map_err(SourceSnapshot::data_error)?;
        let state = self.index.lock()?;
        let pending = self
            .tables
            .get(name)
            .ok_or_else(|| DataFusionError::Execution("the source image table is absent".into()))?;
        let prior = state.tables.get(name);
        let mut addresses = BTreeSet::new();
        if matches!(
            image,
            SourceImage::Before | SourceImage::After | SourceImage::Removed
        ) {
            if let Some(prior) = prior {
                let selected = match key {
                    Some((index, hashes)) => prior.lookup(index, hashes)?,
                    None if image == SourceImage::Removed => {
                        self.removed.get(name).cloned().unwrap_or_default()
                    }
                    None => {
                        return Err(DataFusionError::NotImplemented(
                            "a retained source scan requires native join keys".into(),
                        ))
                    }
                };
                addresses.extend(selected.into_iter().filter(|address| {
                    prior.visible(*address, self.version())
                        && match image {
                            SourceImage::After => !self
                                .removed
                                .get(name)
                                .is_some_and(|rows| rows.contains(address)),
                            SourceImage::Removed => self
                                .removed
                                .get(name)
                                .is_some_and(|rows| rows.contains(address)),
                            _ => true,
                        }
                }));
            }
        }
        if matches!(image, SourceImage::After | SourceImage::Inserted) {
            let selected = match key {
                Some((index, hashes)) if !pending.blocks.is_empty() => {
                    pending.lookup(index, hashes)?
                }
                Some(_) => BTreeSet::new(),
                None => pending
                    .blocks
                    .iter()
                    .flat_map(|(id, block)| {
                        (0..block.batch.num_rows()).map(move |row| RowAddress { block: *id, row })
                    })
                    .collect(),
            };
            addresses.extend(selected);
        }
        let projection = columns
            .iter()
            .map(|column| {
                pending.columns.binary_search(column).map_err(|_| {
                    DataFusionError::Internal(
                        "the indexed source projection was not captured".into(),
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if pending.schema.project(&projection)? != **schema {
            return Err(DataFusionError::Internal(
                "the indexed source schema differs".into(),
            ));
        }
        let mut grouped = BTreeMap::<u64, Vec<usize>>::new();
        for address in addresses {
            grouped.entry(address.block).or_default().push(address.row);
        }
        let blocks = grouped
            .into_iter()
            .map(|(id, rows)| {
                let block = pending
                    .blocks
                    .get(&id)
                    .or_else(|| prior.and_then(|prior| prior.blocks.get(&id)))
                    .ok_or_else(SourceIndex::conflict)?;
                Ok((Arc::clone(block), rows))
            })
            .collect::<Result<Vec<_>>>()?;
        drop(state);
        let mut result = SourceRows {
            batches: Vec::new(),
            origins: Vec::new(),
        };
        for (block, rows) in blocks {
            self.control.check().map_err(SourceSnapshot::data_error)?;
            let indices = UInt64Array::from(rows.iter().map(|row| *row as u64).collect::<Vec<_>>());
            let arrays = projection
                .iter()
                .map(|column| take(block.batch.column(*column).as_ref(), &indices, None))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            result.batches.push(RecordBatch::try_new_with_options(
                Arc::clone(schema),
                arrays,
                &RecordBatchOptions::new().with_row_count(Some(rows.len())),
            )?);
            result.origins.push(
                block
                    .handles
                    .select(&rows)
                    .map_err(SourceSnapshot::data_error)?,
            );
        }
        Ok(result)
    }
}

impl Drop for SourceView {
    fn drop(&mut self) {
        let Ok(mut state) = self.index.lock() else {
            return;
        };
        let version = self.version();
        if let Some(count) = state.leases.get_mut(&version) {
            *count -= 1;
            if *count == 0 {
                state.leases.remove(&version);
            }
        }
        let oldest = state.leases.keys().next().copied().unwrap_or(u64::MAX);
        while state
            .retired
            .front()
            .is_some_and(|(removed, _, _)| *removed <= oldest)
        {
            if let Some((_, name, address)) = state.retired.pop_front() {
                if let Some(table) = state.tables.get_mut(&name) {
                    table.reclaim(address);
                }
            }
        }
    }
}
