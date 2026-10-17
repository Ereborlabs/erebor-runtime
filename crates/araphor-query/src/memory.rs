use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use arrow_buffer::{Buffer, MemoryPool as ArrowPool, MemoryReservation as ArrowReservation};
use datafusion::arrow::array::RecordBatch;
use datafusion::common::{DataFusionError, Result};
use datafusion::execution::memory_pool::{
    GreedyMemoryPool, MemoryConsumer, MemoryPool, MemoryReservation,
};

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
    registry: Arc<Registry>,
    input: MemoryReservation,
    input_pool: Arc<dyn MemoryPool>,
    output: MemoryReservation,
    output_pool: Arc<dyn MemoryPool>,
    input_capacity: usize,
    output_capacity: usize,
}

impl Memory {
    pub fn new(input_capacity: usize, output_capacity: usize) -> Arc<Self> {
        let input: Arc<dyn MemoryPool> = Arc::new(GreedyMemoryPool::new(input_capacity));
        let output: Arc<dyn MemoryPool> = Arc::new(GreedyMemoryPool::new(output_capacity));
        Arc::new(Self {
            registry: Arc::clone(REGISTRY.get_or_init(Arc::default)),
            input: MemoryConsumer::new("araphor input").register(&input),
            input_pool: input,
            output: MemoryConsumer::new("araphor output").register(&output),
            output_pool: output,
            input_capacity,
            output_capacity,
        })
    }

    pub fn reserve_input(&self, bytes: usize) -> Result<MemoryReservation> {
        Self::reserve(&self.input, bytes, self.input_capacity, "shared input")
    }

    pub fn reserve_output(&self, bytes: usize) -> Result<MemoryReservation> {
        Self::reserve(&self.output, bytes, self.output_capacity, "shared output")
    }

    pub(crate) fn prepare_output(&self, bytes: usize) -> Result<MemoryReservation> {
        if bytes > self.output_capacity {
            return self.reserve_output(bytes);
        }
        let available = self
            .output_capacity
            .saturating_sub(self.output_pool.reserved());
        self.reserve_output(bytes.min(available).max(usize::from(bytes != 0)))
    }

    pub(crate) fn prepare_input(&self, bytes: usize) -> Result<MemoryReservation> {
        if bytes > self.input_capacity {
            return self.reserve_input(bytes);
        }
        let available = self
            .input_capacity
            .saturating_sub(self.input_pool.reserved());
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
        capacity: usize,
        resource: &'static str,
    ) -> Result<MemoryReservation> {
        if bytes > capacity {
            return Err(DataFusionError::ResourcesExhausted(format!(
                "{} requires {bytes} bytes, capacity is {capacity}",
                anchor.consumer().name(),
            )));
        }
        let reservation = anchor.new_empty();
        Self::grow(&reservation, bytes, resource)?;
        Ok(reservation)
    }

    fn grow(reservation: &MemoryReservation, bytes: usize, resource: &'static str) -> Result<()> {
        reservation.try_grow(bytes).map_err(|source| {
            DataFusionError::External(Box::new(crate::Error::Capacity { resource, source }))
        })
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
                if let std::collections::hash_map::Entry::Vacant(charge) =
                    charges.entry(reservation.consumer().id())
                {
                    Self::grow(
                        reservation,
                        key.capacity.saturating_sub(reservation.size()),
                        resource,
                    )?;
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

    #[test]
    fn prepay_keeps_existing_charges() {
        let memory = Memory::new(1024, 1024);
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
        let memory = Memory::new(capacity, capacity);
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
        let memory = Memory::new(capacity, capacity);
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
        let memory = Memory::new(0, 0);
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
        let memory = Memory::new(capacity, capacity);
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
        let first = Memory::new(0, capacity);
        let second = Memory::new(capacity, 0);
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
        let memory = Memory::new(capacity, 0);
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
