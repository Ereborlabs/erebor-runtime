use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use arrow_buffer::{Buffer, MemoryPool as ArrowPool, MemoryReservation as ArrowReservation};
use datafusion::arrow::array::RecordBatch;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::{
    GreedyMemoryPool, MemoryConsumer, MemoryLimit, MemoryPool, MemoryReservation,
    UnboundedMemoryPool,
};
use tokio::sync::watch;

#[derive(Debug)]
struct Pool {
    native: GreedyMemoryPool,
    capacity: Arc<Capacity>,
    resource: &'static str,
}

#[derive(Debug)]
struct Capacity {
    released: Mutex<Releases>,
    changes: watch::Sender<()>,
}

#[derive(Debug, Default)]
struct Releases {
    total: u64,
    consumers: HashMap<usize, Consumer>,
}

#[derive(Debug)]
struct Consumer {
    released: Arc<AtomicU64>,
    bytes: usize,
    scoped: bool,
}

impl MemoryPool for Pool {
    fn unregister(&self, consumer: &MemoryConsumer) {
        self.capacity
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .consumers
            .remove(&consumer.id());
    }

    fn grow(&self, reservation: &MemoryReservation, bytes: usize) {
        let mut released = self
            .capacity
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.native.grow(reservation, bytes);
        if let Some(consumer) = released.consumers.get_mut(&reservation.consumer().id()) {
            consumer.bytes += bytes;
        }
    }

    fn shrink(&self, reservation: &MemoryReservation, bytes: usize) {
        let mut released = self
            .capacity
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.native.shrink(reservation, bytes);
        if let Some(consumer) = released.consumers.get_mut(&reservation.consumer().id()) {
            consumer.bytes -= bytes;
            if bytes != 0 {
                consumer.released.fetch_add(1, Ordering::Relaxed);
            }
        }
        if bytes != 0 {
            released.total = released.total.wrapping_add(1);
            drop(released);
            self.capacity.changes.send_replace(());
        }
    }

    fn try_grow(&self, reservation: &MemoryReservation, bytes: usize) -> Result<()> {
        let mut released = self
            .capacity
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let consumer = released
            .consumers
            .get_mut(&reservation.consumer().id())
            .ok_or_else(|| DataFusionError::Internal("memory consumer is absent".into()))?;
        let owned = if consumer.scoped {
            consumer.bytes
        } else {
            reservation.size()
        };
        match self.native.try_grow(reservation, bytes) {
            Err(source)
                if matches!(self.native.memory_limit(), MemoryLimit::Finite(limit)
                    if owned.saturating_add(bytes) <= limit) =>
            {
                Err(DataFusionError::External(Box::new(
                    crate::Error::Capacity {
                        resource: self.resource,
                        source,
                    },
                )))
            }
            Ok(()) => {
                consumer.bytes += bytes;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn reserved(&self) -> usize {
        self.native.reserved()
    }

    fn memory_limit(&self) -> MemoryLimit {
        self.native.memory_limit()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct BufferKey {
    address: usize,
    capacity: usize,
}

#[derive(Debug, Default)]
struct Registry {
    buffers: Mutex<HashMap<BufferKey, Weak<Allocation>>>,
}

static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();

#[derive(Debug)]
struct Allocation {
    key: BufferKey,
    registry: Weak<Registry>,
    charges: Mutex<HashMap<usize, MemoryReservation>>,
}

impl Drop for Allocation {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let mut buffers = registry
                .buffers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if buffers
                .get(&self.key)
                .is_some_and(|owner| std::ptr::eq(owner.as_ptr(), self))
            {
                buffers.remove(&self.key);
            }
        }
    }
}

#[derive(Debug)]
struct Claim(Arc<Allocation>);

impl ArrowReservation for Claim {
    fn size(&self) -> usize {
        self.0.key.capacity
    }

    fn resize(&mut self, size: usize) {
        let charges = self
            .0
            .charges
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        for reservation in charges.values() {
            reservation.resize(size);
        }
    }
}

impl ArrowPool for Claim {
    fn reserve(&self, size: usize) -> Box<dyn ArrowReservation> {
        assert_eq!(size, self.0.key.capacity);
        Box::new(Self(Arc::clone(&self.0)))
    }

    fn available(&self) -> isize {
        0
    }

    fn used(&self) -> usize {
        self.0.key.capacity
    }

    fn capacity(&self) -> usize {
        self.0.key.capacity
    }
}

#[derive(Debug)]
pub struct Memory {
    released: Arc<AtomicU64>,
    capacity: Arc<Capacity>,
    family: [usize; 2],
    registry: Arc<Registry>,
    input: MemoryReservation,
    input_pool: Arc<dyn MemoryPool>,
    output: MemoryReservation,
    output_pool: Arc<dyn MemoryPool>,
    input_capacity: Option<usize>,
    output_capacity: Option<usize>,
}

impl Memory {
    pub fn new(input_capacity: Option<usize>, output_capacity: Option<usize>) -> Arc<Self> {
        let (changes, _) = watch::channel(());
        let capacity = Arc::new(Capacity {
            released: Mutex::default(),
            changes,
        });
        let pool = |bytes: Option<usize>, resource| -> Arc<dyn MemoryPool> {
            match bytes {
                Some(bytes) => Arc::new(Pool {
                    native: GreedyMemoryPool::new(bytes),
                    capacity: Arc::clone(&capacity),
                    resource,
                }),
                None => Arc::new(UnboundedMemoryPool::default()),
            }
        };
        let input = pool(input_capacity, "shared input");
        let output = pool(output_capacity, "shared output");
        let released = Arc::default();
        let input_reservation =
            Self::consumer("araphor input", &input, &capacity, &released, false);
        let output_reservation =
            Self::consumer("araphor output", &output, &capacity, &released, false);
        Arc::new(Self {
            released,
            capacity,
            family: [
                input_reservation.consumer().id(),
                output_reservation.consumer().id(),
            ],
            registry: Arc::clone(REGISTRY.get_or_init(Arc::default)),
            input: input_reservation,
            input_pool: input,
            output: output_reservation,
            output_pool: output,
            input_capacity,
            output_capacity,
        })
    }

    fn consumer(
        name: &str,
        pool: &Arc<dyn MemoryPool>,
        capacity: &Arc<Capacity>,
        released: &Arc<AtomicU64>,
        scoped: bool,
    ) -> MemoryReservation {
        let consumer = MemoryConsumer::new(name);
        if matches!(pool.memory_limit(), MemoryLimit::Finite(_)) {
            capacity
                .released
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .consumers
                .insert(
                    consumer.id(),
                    Consumer {
                        released: Arc::clone(released),
                        bytes: 0,
                        scoped,
                    },
                );
        }
        consumer.register(pool)
    }

    pub fn scope(&self) -> Arc<Self> {
        self.scoped(Arc::default())
    }

    pub fn child(&self) -> Arc<Self> {
        self.scoped(Arc::clone(&self.released))
    }

    fn scoped(&self, released: Arc<AtomicU64>) -> Arc<Self> {
        Arc::new(Self {
            input: Self::consumer(
                "araphor input",
                &self.input_pool,
                &self.capacity,
                &released,
                true,
            ),
            output: Self::consumer(
                "araphor output",
                &self.output_pool,
                &self.capacity,
                &released,
                true,
            ),
            released,
            capacity: Arc::clone(&self.capacity),
            family: self.family,
            registry: Arc::clone(&self.registry),
            input_pool: Arc::clone(&self.input_pool),
            output_pool: Arc::clone(&self.output_pool),
            input_capacity: self.input_capacity,
            output_capacity: self.output_capacity,
        })
    }

    pub(crate) fn same_family(&self, other: &Self) -> bool {
        self.family == other.family
    }

    pub fn capacity_epoch(&self) -> u64 {
        let released = self
            .capacity
            .released
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        released
            .total
            .wrapping_sub(self.released.load(Ordering::Relaxed))
    }

    pub async fn capacity_changed(&self, epoch: u64) -> crate::Result<()> {
        let mut changes = self.capacity.changes.subscribe();
        loop {
            changes.borrow_and_update();
            if self.capacity_epoch() != epoch {
                return Ok(());
            }
            changes
                .changed()
                .await
                .map_err(|source| crate::Error::Sql {
                    source: DataFusionError::External(Box::new(source)),
                })?;
        }
    }

    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn input_reserved(&self) -> usize {
        self.input_pool.reserved()
    }

    pub fn reserve_input(&self, bytes: usize) -> Result<MemoryReservation> {
        Self::reserve(&self.input, bytes, self.input_capacity)
    }

    pub fn reserve_output(&self, bytes: usize) -> Result<MemoryReservation> {
        Self::reserve(&self.output, bytes, self.output_capacity)
    }

    pub(crate) fn input_capacity(&self) -> Option<usize> {
        self.input_capacity
    }

    pub(crate) fn output_capacity(&self) -> Option<usize> {
        self.output_capacity
    }

    pub(crate) fn prepare_output(&self, bytes: usize) -> Result<MemoryReservation> {
        let Some(capacity) = self.output_capacity else {
            return self.reserve_output(0);
        };
        let bytes = if bytes == usize::MAX { capacity } else { bytes };
        if bytes > capacity {
            return self.reserve_output(bytes);
        }
        let available = capacity.saturating_sub(self.output_pool.reserved());
        self.reserve_output(bytes.min(available).max(usize::from(bytes != 0)))
    }

    pub(crate) fn prepare_input(&self, bytes: usize) -> Result<MemoryReservation> {
        let Some(capacity) = self.input_capacity else {
            return self.reserve_input(if bytes == usize::MAX { 0 } else { bytes });
        };
        let bytes = if bytes == usize::MAX { capacity } else { bytes };
        if bytes > capacity {
            return self.reserve_input(bytes);
        }
        let available = capacity.saturating_sub(self.input_pool.reserved());
        self.reserve_input(bytes.min(available).max(usize::from(bytes != 0)))
    }

    pub fn retain_input(&self, batch: &RecordBatch, reservation: &MemoryReservation) -> Result<()> {
        self.retain(batch, reservation, true)
    }

    pub fn retain_output(
        &self,
        batch: &RecordBatch,
        reservation: &MemoryReservation,
    ) -> Result<()> {
        self.retain(batch, reservation, false)
    }

    fn reserve(
        anchor: &MemoryReservation,
        bytes: usize,
        capacity: Option<usize>,
    ) -> Result<MemoryReservation> {
        if let Some(capacity) = capacity.filter(|capacity| bytes > *capacity) {
            return Err(DataFusionError::ResourcesExhausted(format!(
                "{} requires {bytes} bytes, capacity is {capacity}",
                anchor.consumer().name(),
            )));
        }
        let reservation = anchor.new_empty();
        reservation.try_grow(bytes)?;
        Ok(reservation)
    }

    fn retain(
        &self,
        batch: &RecordBatch,
        reservation: &MemoryReservation,
        input: bool,
    ) -> Result<()> {
        let (anchor, capacity, resource) = if input {
            (&self.input, self.input_capacity, "shared input")
        } else {
            (&self.output, self.output_capacity, "shared output")
        };
        if reservation.consumer().id() != anchor.consumer().id() {
            return Err(DataFusionError::Internal(
                "Arrow reservation category changed".into(),
            ));
        }
        let Some(capacity) = capacity else {
            return Ok(());
        };
        let columns = batch
            .columns()
            .iter()
            .map(|column| column.to_data())
            .collect::<Vec<_>>();
        let mut pending = columns.iter().collect::<Vec<_>>();
        let mut buffers = Vec::new();
        while let Some(data) = pending.pop() {
            for buffer in data
                .buffers()
                .iter()
                .chain(data.nulls().map(|nulls| nulls.buffer()))
            {
                let key = BufferKey {
                    address: buffer.data_ptr().as_ptr() as usize,
                    capacity: buffer.capacity(),
                };
                if key.capacity > 0 {
                    buffers.push((key, buffer.clone()));
                }
            }
            pending.extend(data.child_data());
        }
        for (key, buffer) in buffers {
            self.retain_buffer(key, buffer, reservation, capacity, resource)?;
        }
        Ok(())
    }

    fn retain_buffer(
        &self,
        key: BufferKey,
        buffer: Buffer,
        reservation: &MemoryReservation,
        capacity: usize,
        resource: &'static str,
    ) -> Result<()> {
        if key.capacity > capacity {
            return Err(DataFusionError::ResourcesExhausted(format!(
                "{resource} allocation requires {} bytes, capacity is {capacity}",
                key.capacity
            )));
        }
        let mut registry = self.registry.buffers.lock().map_err(|_| {
            DataFusionError::Internal("Arrow allocation registry lock failed".into())
        })?;
        let previous = registry.get(&key).and_then(Weak::upgrade);
        let allocation = previous.as_ref().map(Arc::clone).unwrap_or_else(|| {
            Arc::new(Allocation {
                key,
                registry: Arc::downgrade(&self.registry),
                charges: Mutex::default(),
            })
        });
        let result = allocation
            .charges
            .lock()
            .map_err(|_| {
                DataFusionError::Internal("Arrow allocation reservation lock failed".into())
            })
            .and_then(|mut charges| {
                if let std::collections::hash_map::Entry::Vacant(charge) = charges.entry(
                    if reservation.consumer().id() == self.input.consumer().id() {
                        self.family[0]
                    } else {
                        self.family[1]
                    },
                ) {
                    reservation.try_grow(key.capacity.saturating_sub(reservation.size()))?;
                    charge.insert(reservation.split(key.capacity));
                }
                Ok(())
            });
        if result.is_ok() && previous.is_none() {
            registry.insert(key, Arc::downgrade(&allocation));
        }
        drop(registry);
        result?;
        buffer.claim(&Claim(allocation));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datafusion::arrow::array::{Array, ArrayRef, Int64Array, ListArray, StringViewArray};
    use datafusion::arrow::datatypes::Int64Type;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn unbounded_pools_skip_quota() -> TestResult {
        let limits = crate::execution::Limits::default();
        assert_eq!(limits.input_capacity, None);
        assert_eq!(limits.output_capacity, None);
        let memory = Memory::new(limits.input_capacity, limits.output_capacity);
        assert!(matches!(
            memory.input_pool.memory_limit(),
            MemoryLimit::Infinite
        ));
        assert!(matches!(
            memory.output_pool.memory_limit(),
            MemoryLimit::Infinite
        ));
        let scope = memory.scope();
        let bytes = 256 * 1024 * 1024;
        let input = scope.prepare_input(bytes)?;
        let prepared = scope.prepare_output(bytes)?;
        assert_eq!(input.size(), bytes);
        assert_eq!(prepared.size(), 0);
        let output = scope.reserve_output(bytes)?;
        let concurrent = memory.scope().prepare_output(bytes)?;
        assert_eq!(concurrent.size(), 0);
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1, 2]));
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        scope.retain_input(&batch, &input)?;
        scope.retain_output(&batch, &output)?;
        assert!(allocations(&memory).is_empty());
        assert!(scope.retain_input(&batch, &prepared).is_err());
        assert_eq!(memory.input_pool.reserved(), bytes);
        assert_eq!(memory.output_pool.reserved(), bytes);
        drop((input, output, prepared, concurrent, scope));
        assert_eq!(memory.input_pool.reserved(), 0);
        assert_eq!(memory.output_pool.reserved(), 0);
        assert!(memory
            .capacity
            .released
            .lock()
            .map_err(|_| "capacity lock")?
            .consumers
            .is_empty());
        drop(batch);
        Ok(())
    }

    #[test]
    fn optional_categories_stay_independent() -> TestResult {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1, 2]));
        let capacity = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let alias = Arc::clone(batch.column(0));
        let memory = Memory::new(None, Some(capacity));
        let input = memory.reserve_input(capacity * 2)?;
        memory.retain_input(&batch, &input)?;
        assert!(allocations(&memory).is_empty());
        let output = memory.prepare_output(capacity)?;
        memory.retain_output(&batch, &output)?;
        assert!(memory.reserve_output(1).is_err());
        drop((input, output, batch));
        assert_eq!(memory.input_pool.reserved(), 0);
        assert_eq!(memory.output_pool.reserved(), capacity);
        assert!(memory.reserve_output(1).is_err());
        drop(alias);
        drop(memory.reserve_output(capacity)?);
        assert_eq!(memory.output_pool.reserved(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn scoped_releases_ignore_self() -> TestResult {
        let memory = Memory::new(Some(64), Some(64));
        let first = memory.scope();
        let other = memory.scope();
        let epoch = first.capacity_epoch();
        drop(first.reserve_input(16)?);
        drop(first.reserve_output(16)?);
        assert_eq!(first.capacity_epoch(), epoch);
        let pending = first.capacity_changed(epoch);
        tokio::pin!(pending);
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        let held = other.reserve_output(64)?;
        assert!(first.reserve_output(1).is_err());
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(1), pending).await??;
        assert_ne!(first.capacity_epoch(), epoch);
        drop(first.reserve_output(64)?);
        let before = first.capacity_epoch();
        drop(other.reserve_input(8)?);
        first.capacity_changed(before).await?;
        assert_eq!(memory.input_pool.reserved(), 0);
        assert_eq!(memory.output_pool.reserved(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn children_share_wake_group() -> TestResult {
        let memory = Memory::new(Some(64), Some(64));
        let owner = memory.scope();
        let before = owner.capacity_epoch();
        let previous = owner.child();
        let held = previous.reserve_output(64)?;
        let next = owner.child();
        assert!(matches!(next.reserve_output(1),
            Err(DataFusionError::External(error))
                if matches!(error.downcast_ref::<crate::Error>(),
                    Some(crate::Error::Capacity { resource: "shared output", .. }))));
        drop((held, previous, next));
        assert_eq!(owner.capacity_epoch(), before);
        let waiting = owner.capacity_changed(before);
        tokio::pin!(waiting);
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        drop(memory.reserve_input(1)?);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiting).await??;
        drop(owner.child().reserve_output(64)?);
        Ok(())
    }

    #[test]
    fn scoped_aliases_share_charge() -> TestResult {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1, 2]));
        let bytes = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let memory = Memory::new(Some(bytes), Some(bytes));
        let first = memory.scope();
        let other = memory.scope();
        let input = first.reserve_input(bytes)?;
        first.retain_input(&batch, &input)?;
        other.retain_input(&batch, &other.reserve_input(0)?)?;
        assert_eq!(memory.input_pool.reserved(), bytes);
        let output = other.reserve_output(bytes)?;
        other.retain_output(&batch, &output)?;
        first.retain_output(&batch, &first.reserve_output(0)?)?;
        assert_eq!(memory.output_pool.reserved(), bytes);
        let alias = Arc::clone(batch.column(0));
        drop((input, output, batch, first, other));
        assert!(memory.reserve_input(1).is_err());
        assert!(memory.reserve_output(1).is_err());
        drop(alias);
        drop(memory.reserve_input(bytes)?);
        drop(memory.reserve_output(bytes)?);
        let live = memory
            .capacity
            .released
            .lock()
            .map_err(|_| "capacity lock")?;
        assert_eq!(live.consumers.len(), 2);
        Ok(())
    }

    #[test]
    fn native_resize_preserves_capacity() -> TestResult {
        let memory = Memory::new(Some(64), Some(64));
        let scope = memory.scope();
        let hold = memory.reserve_input(64)?;
        let pending = scope.reserve_input(0)?;
        let error = pending.try_resize(16).err().ok_or("capacity must fail")?;
        assert!(matches!(error, DataFusionError::External(error)
            if matches!(error.downcast_ref::<crate::Error>(),
                Some(crate::Error::Capacity { resource: "shared input", .. }))));
        assert_eq!(pending.size(), 0);
        assert!(matches!(
            pending.try_resize(65),
            Err(DataFusionError::ResourcesExhausted(_))
        ));
        drop(hold);
        pending.try_resize(64)?;
        assert_eq!(memory.input_pool.reserved(), 64);
        Ok(())
    }

    #[test]
    fn retained_working_set_limit() -> TestResult {
        let memory = Memory::new(Some(64), Some(64));
        let scope = memory.scope();
        let held = scope.reserve_input(64)?;
        let retained = held.split(40);
        drop(held);
        assert!(matches!(
            scope.reserve_input(32),
            Err(DataFusionError::ResourcesExhausted(_))
        ));
        assert!(matches!(
            memory.reserve_input(32),
            Err(DataFusionError::External(error))
                if matches!(error.downcast_ref::<crate::Error>(),
                    Some(crate::Error::Capacity { resource: "shared input", .. }))
        ));
        drop(retained);
        drop(scope.reserve_input(64)?);
        let output = scope.reserve_output(40)?;
        assert!(matches!(
            scope.reserve_output(32),
            Err(DataFusionError::ResourcesExhausted(_))
        ));
        drop(output);
        drop(scope.reserve_output(64)?);
        assert_eq!(memory.input_pool.reserved(), 0);
        assert_eq!(memory.output_pool.reserved(), 0);
        Ok(())
    }

    #[test]
    fn prepay_keeps_existing_charges() {
        let memory = Memory::new(Some(1024), Some(1024));
        let batch = RecordBatch::try_from_iter([(
            "value",
            Arc::new(Int64Array::from(vec![1])) as ArrayRef,
        )])
        .unwrap();
        let reservation = memory.reserve_output(0).unwrap();
        memory.retain_output(&batch, &reservation).unwrap();
        let retained = memory.output_pool.reserved();
        assert!(retained > 0 && retained < 1024);
        let prepared = memory.prepare_output(1024).unwrap();
        assert_eq!(prepared.size(), 1024 - retained);
        assert!(memory.prepare_output(1).is_err());
        drop(prepared);
        assert_eq!(memory.output_pool.reserved(), retained);
        assert!(memory.prepare_output(1025).is_err());
        drop(batch);
        assert_eq!(memory.output_pool.reserved(), 0);
        assert!(memory.reserve_output(1024).is_ok());
    }

    fn allocations(memory: &Memory) -> Vec<(BufferKey, Weak<Allocation>)> {
        let entries = memory
            .registry
            .buffers
            .lock()
            .unwrap()
            .iter()
            .map(|(key, owner)| (*key, Weak::clone(owner)))
            .collect::<Vec<_>>();
        entries
            .into_iter()
            .filter(|(_, owner)| {
                owner.upgrade().is_some_and(|allocation| {
                    let charges = allocation.charges.lock().unwrap();
                    charges.contains_key(&memory.input.consumer().id())
                        || charges.contains_key(&memory.output.consumer().id())
                })
            })
            .collect()
    }

    fn released(memory: &Memory, owners: Vec<(BufferKey, Weak<Allocation>)>) {
        for (key, owner) in owners {
            assert!(owner.upgrade().is_none());
            assert!(memory
                .registry
                .buffers
                .lock()
                .unwrap()
                .get(&key)
                .is_none_or(|current| !Weak::ptr_eq(current, &owner)));
        }
    }

    #[test]
    fn aliases_keep_both_charges() -> Result<()> {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1, 2, 3]));
        let capacity = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let memory = Memory::new(Some(capacity), Some(capacity));
        let input = memory.reserve_input(capacity)?;
        memory.retain_input(&batch, &input)?;
        assert_eq!(input.size(), 0);
        let slice = batch.slice(1, 1);
        let output = memory.reserve_output(capacity)?;
        memory.retain_output(&slice, &output)?;
        memory.retain_output(&slice.clone(), &output)?;
        let owners = allocations(&memory);
        assert_eq!(output.size(), 0);
        assert!(memory.reserve_input(1).is_err());
        assert!(memory.reserve_output(1).is_err());
        let consumer = slice.column(0).clone();
        drop(batch);
        drop(slice);
        assert!(memory.reserve_input(capacity).is_err());
        assert!(memory.reserve_output(capacity).is_err());
        drop(consumer);
        assert!(memory.reserve_input(capacity).is_ok());
        assert!(memory.reserve_output(capacity).is_ok());
        released(&memory, owners);
        Ok(())
    }

    #[test]
    fn nested_buffer_charges() -> Result<()> {
        let nested: ArrayRef = Arc::new(ListArray::from_iter_primitive::<Int64Type, _, _>([
            Some(vec![Some(1), None]),
            None,
            Some(vec![Some(2)]),
        ]));
        let views: ArrayRef = Arc::new(StringViewArray::from(vec![
            Some("a value outside the inline view"),
            None,
            Some("another value outside the inline view"),
        ]));
        let capacity = nested.get_buffer_memory_size() + views.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("nested", nested), ("views", views)])?;
        let memory = Memory::new(Some(capacity), Some(capacity));
        let input = memory.reserve_input(capacity)?;
        memory.retain_input(&batch, &input)?;
        let owners = allocations(&memory);
        assert_eq!(input.size(), 0);
        let child = batch.column(0).to_data().child_data()[0].buffers()[0].clone();
        let validity = batch.column(1).to_data().nulls().unwrap().buffer().clone();
        let values = batch.column(1).to_data().buffers().last().unwrap().clone();
        drop(batch);
        assert!(memory.reserve_input(capacity).is_err());
        drop(child);
        assert!(memory.reserve_input(capacity).is_err());
        drop(validity);
        assert!(memory.reserve_input(capacity).is_err());
        drop(values);
        assert!(memory.reserve_input(capacity).is_ok());
        released(&memory, owners);
        Ok(())
    }

    #[test]
    fn rejected_claim_releases_registry() -> Result<()> {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1]));
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let memory = Memory::new(Some(0), Some(0));
        let input = memory.reserve_input(0)?;
        let buffer = batch.column(0).to_data().buffers()[0].clone();
        let key = BufferKey {
            address: buffer.data_ptr().as_ptr() as usize,
            capacity: buffer.capacity(),
        };
        assert!(memory.retain_input(&batch, &input).is_err());
        assert_eq!(input.size(), 0);
        assert!(!memory.registry.buffers.lock().unwrap().contains_key(&key));
        assert!(memory.reserve_input(0).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn consumer_survives_producer_abort() -> Result<()> {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1]));
        let capacity = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let memory = Memory::new(Some(capacity), Some(capacity));
        let producer_memory = Arc::clone(&memory);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let producer = tokio::spawn(async move {
            let input = producer_memory.reserve_input(capacity).unwrap();
            producer_memory.retain_input(&batch, &input).unwrap();
            sender.send(batch.column(0).clone()).unwrap();
            std::future::pending::<()>().await;
            drop(batch);
        });
        let consumer = receiver.await.unwrap();
        let owners = allocations(&memory);
        producer.abort();
        assert!(producer.await.unwrap_err().is_cancelled());
        assert!(memory.reserve_input(capacity).is_err());
        drop(consumer);
        assert!(memory.reserve_input(capacity).is_ok());
        released(&memory, owners);
        Ok(())
    }

    #[test]
    fn cross_owner_charges() -> Result<()> {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1, 2, 3]));
        let capacity = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let first = Memory::new(Some(0), Some(capacity));
        let second = Memory::new(Some(capacity), Some(0));
        assert!(Arc::ptr_eq(&first.registry, &second.registry));
        let output = first.reserve_output(capacity)?;
        first.retain_output(&batch, &output)?;
        let slice = batch.slice(1, 1);
        let input = second.reserve_input(capacity)?;
        second.retain_input(&slice, &input)?;
        first.retain_output(&slice, &output)?;
        assert_eq!((input.size(), output.size()), (0, 0));
        let owners = allocations(&first);
        assert!(!owners.is_empty());
        assert!(first.reserve_output(1).is_err());
        assert!(second.reserve_input(1).is_err());
        let consumer = slice.column(0).clone();
        drop(batch);
        drop(slice);
        assert!(first.reserve_output(capacity).is_err());
        assert!(second.reserve_input(capacity).is_err());
        drop(consumer);
        assert!(first.reserve_output(capacity).is_ok());
        assert!(second.reserve_input(capacity).is_ok());
        released(&first, owners);
        Ok(())
    }

    #[test]
    fn pressure_keeps_native_source() -> Result<()> {
        let column: ArrayRef = Arc::new(Int64Array::from(vec![1]));
        let capacity = column.get_buffer_memory_size();
        let batch = RecordBatch::try_from_iter([("value", column)])?;
        let memory = Memory::new(Some(capacity), Some(0));
        let held = memory.reserve_input(capacity)?;
        let input = memory.reserve_input(0)?;
        let error = memory.retain_input(&batch, &input).unwrap_err();
        assert!(matches!(error,
            DataFusionError::External(source) if matches!(source.downcast_ref::<crate::Error>(),
                Some(crate::Error::Capacity { resource: "shared input", source: DataFusionError::ResourcesExhausted(_) }))));
        drop(held);
        memory.retain_input(&batch, &input)?;
        let owners = allocations(&memory);
        drop(batch);
        assert!(memory.reserve_input(capacity).is_ok());
        released(&memory, owners);
        Ok(())
    }
}
