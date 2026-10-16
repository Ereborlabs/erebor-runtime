use std::mem::size_of;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use datafusion::arrow::array::{make_array, ArrayData, RecordBatchOptions};
use datafusion::arrow::buffer::{BooleanBuffer, Buffer, MutableBuffer, NullBuffer};
use snafu::ResultExt as _;

use super::QueryLease;
use crate::Result;

impl QueryLease {
    pub(in crate::query) fn batch_overhead(batch: &sdk::RecordBatch) -> usize {
        fn owners(data: &ArrayData) -> usize {
            let buffers = data.buffers().len() + usize::from(data.nulls().is_some());
            let children = data.child_data();
            let owner = size_of::<MutableBuffer>()
                + size_of::<Buffer>()
                + size_of::<(Buffer, QueryLease)>()
                + 4 * size_of::<usize>();
            children.iter().fold(
                2 * size_of::<usize>()
                    + children.len() * size_of::<sdk::arrow_array::ArrayRef>()
                    + buffers.saturating_mul(owner),
                |bytes, child| bytes.saturating_add(owners(child)),
            )
        }
        batch.columns().iter().fold(
            size_of::<sdk::RecordBatch>()
                + batch.num_columns() * size_of::<sdk::arrow_array::ArrayRef>(),
            |bytes, array| {
                bytes
                    .saturating_add(
                        array
                            .get_array_memory_size()
                            .saturating_sub(array.get_buffer_memory_size()),
                    )
                    .saturating_add(owners(&array.to_data()))
            },
        )
    }

    pub(in crate::query) fn index_overhead(rows: usize) -> usize {
        let owner = size_of::<MutableBuffer>() + size_of::<Buffer>() + 2 * size_of::<usize>();
        rows.saturating_mul(size_of::<u64>()).saturating_add(
            2 * size_of::<sdk::arrow_array::UInt64Array>()
                + 2 * size_of::<sdk::arrow_array::ArrayRef>()
                + size_of::<[usize; 8]>()
                + 2 * owner
                + size_of::<(Buffer, Self)>(),
        )
    }

    pub(in crate::query) fn retain_batch(
        &self,
        batch: &sdk::RecordBatch,
    ) -> Result<sdk::RecordBatch> {
        let columns = batch
            .columns()
            .iter()
            .map(|array| self.retain_array(array.to_data()).map(make_array))
            .collect::<Result<Vec<_>>>()?;
        sdk::RecordBatch::try_new_with_options(
            batch.schema(),
            columns,
            &RecordBatchOptions::new().with_row_count(Some(batch.num_rows())),
        )
        .map_err(sdk::Error::from)
        .context(crate::AnalysisContractSnafu)
    }

    fn retain_array(&self, data: ArrayData) -> Result<ArrayData> {
        let buffers = data
            .buffers()
            .iter()
            .map(|buffer| self.retain_buffer(buffer))
            .collect();
        let children = data
            .child_data()
            .iter()
            .cloned()
            .map(|child| self.retain_array(child))
            .collect::<Result<Vec<_>>>()?;
        let nulls = data.nulls().map(|nulls| {
            let bits = nulls.inner();
            NullBuffer::new(BooleanBuffer::new(
                self.retain_buffer(bits.inner()),
                bits.offset(),
                bits.len(),
            ))
        });
        data.into_builder()
            .buffers(buffers)
            .child_data(children)
            .nulls(nulls)
            .build()
            .map_err(sdk::Error::from)
            .context(crate::AnalysisContractSnafu)
    }

    #[allow(unsafe_code)]
    fn retain_buffer(&self, buffer: &Buffer) -> Buffer {
        let owner = Arc::new((buffer.clone(), self.clone()));
        // The owner retains the original allocation and its lease for this pointer range.
        let retained =
            unsafe { Buffer::from_custom_allocation(buffer.data_ptr(), buffer.capacity(), owner) };
        retained.slice_with_length(buffer.ptr_offset(), buffer.len())
    }
}

#[cfg(test)]
mod buffer_tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use datafusion::arrow::array::{Array as _, ListArray, StructArray, UInt64Array};
    use datafusion::arrow::datatypes::Int32Type;

    use super::super::{QueryBudget, QueryLimits};
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    #[test]
    fn query_buffer_slice_lease() -> TestResult {
        let field = sdk::Field::new("value", sdk::DataType::UInt64, false)
            .with_metadata(HashMap::from([("unit".into(), "count".into())]));
        let schema = Arc::new(
            sdk::Schema::new(vec![field])
                .with_metadata(HashMap::from([("owner".into(), "fixture".into())])),
        );
        let source = sdk::RecordBatch::try_new(
            schema.clone(),
            vec![Arc::new(UInt64Array::from_iter_values(0..8192))],
        )?;
        let bytes = source.get_array_memory_size();
        let output_bytes = std::mem::size_of::<u64>();
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: bytes,
            input_capacity: bytes,
            output_bytes,
            output_capacity: output_bytes,
            ..Default::default()
        });
        let mut lease = budget.evaluate([1; 16])?;
        let weak = Arc::downgrade(&lease.charge);
        let sliced = source.slice(4096, 1);
        let before = sliced.column(0).to_data();
        let pointer = before.buffers()[0].as_ptr();
        let capacity = before.buffers()[0].capacity();
        let offset = before.buffers()[0].ptr_offset();
        let length = before.buffers()[0].len();
        let array_offset = before.offset();
        drop(before);
        let mut retained = lease.retain_batch(&sliced)?;
        let output = lease.split(output_bytes)?;
        let output_weak = Arc::downgrade(&output.charge);
        retained = output.retain_batch(&retained)?;
        drop(lease.retained_output(0)?);
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .evaluations,
            0
        );
        assert_eq!(retained, sliced);
        assert!(Arc::ptr_eq(&schema, &retained.schema()));
        let after = retained.column(0).to_data();
        assert_eq!(after.buffers()[0].as_ptr(), pointer);
        assert_eq!(after.buffers()[0].capacity(), capacity);
        assert_eq!(after.buffers()[0].ptr_offset(), offset);
        assert_eq!(after.buffers()[0].len(), length);
        assert_eq!(after.offset(), array_offset);
        drop(after);
        drop(source);
        drop(sliced);
        drop(output);
        let last = retained.column(0).slice(0, 1);
        drop(retained);
        assert!(weak.upgrade().is_some());
        assert!(output_weak.upgrade().is_some());
        assert!(budget.retained_input(1).is_err());
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .input_bytes,
            bytes
        );
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .output_bytes,
            output_bytes
        );
        assert_eq!(
            last.as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("retained value type")?
                .value(0),
            4096,
        );
        drop(last);
        assert!(weak.upgrade().is_none());
        assert!(output_weak.upgrade().is_none());
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(
            (usage.evaluations, usage.input_bytes, usage.output_bytes),
            (0, 0, 0)
        );
        assert!(usage.tenants.is_empty());
        Ok(())
    }

    #[test]
    fn query_buffer_nested_lease() -> TestResult {
        let lists = ListArray::from_iter_primitive::<Int32Type, _, _>([
            Some(vec![Some(10), None]),
            None,
            Some(vec![Some(30), Some(40)]),
            Some(vec![None, Some(60)]),
        ]);
        let field = Arc::new(
            sdk::Field::new("items", lists.data_type().clone(), true)
                .with_metadata(HashMap::from([("unit".into(), "count".into())])),
        );
        let records = StructArray::try_new(
            vec![field].into(),
            vec![Arc::new(lists)],
            Some(NullBuffer::from(vec![true, false, true, true])),
        )?;
        let schema = Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "record",
            records.data_type().clone(),
            true,
        )]));
        let source = sdk::RecordBatch::try_new(schema, vec![Arc::new(records)])?;
        let bytes = source.get_array_memory_size();
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: bytes,
            input_capacity: bytes,
            ..Default::default()
        });
        let lease = budget.retained_input(bytes)?;
        let weak = Arc::downgrade(&lease.charge);
        let sliced = source.slice(1, 2);
        let retained = lease.retain_batch(&sliced)?;
        assert_eq!(retained, sliced);
        let data = retained.column(0).to_data();
        let validity = data.nulls().ok_or("retained validity")?.inner().clone();
        assert_eq!(validity.offset(), 1);
        assert_eq!(validity.len(), 2);
        let child = data.child_data()[0].child_data()[0].buffers()[0].clone();
        drop(data);
        drop(source);
        drop(sliced);
        drop(retained);
        drop(lease);
        assert!(weak.upgrade().is_some());
        assert!(budget.retained_input(1).is_err());
        drop(child);
        assert!(weak.upgrade().is_some());
        drop(validity);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .input_bytes,
            0
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn query_buffer_cancelled_child() -> TestResult {
        let source = sdk::RecordBatch::try_new(
            Arc::new(sdk::Schema::new(vec![sdk::Field::new(
                "value",
                sdk::DataType::UInt64,
                false,
            )])),
            vec![Arc::new(UInt64Array::from(vec![7]))],
        )?;
        let bytes = source.get_array_memory_size();
        let budget = QueryBudget::new(QueryLimits {
            input_bytes: bytes,
            input_capacity: bytes,
            global_evaluations: 1,
            ..Default::default()
        });
        let lease = budget.model([1; 16], 0)?;
        let weak = Arc::downgrade(&lease.charge);
        let retained = lease.retain_batch(&source)?;
        let alias = retained.column(0).clone();
        let control = crate::AnalysisReadControl::default();
        let (entered, entering) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let child = tokio::spawn(async move {
            let _ = entered.send(());
            let _ = released.await;
            assert_eq!(alias.to_data(), UInt64Array::from(vec![7]).to_data());
        });
        tokio::time::timeout(Duration::from_secs(2), entering).await??;
        control.cancel()?;
        assert!(matches!(
            control.check(),
            Err(crate::Error::AnalysisReadCancelled { .. }),
        ));
        drop(source);
        drop(retained);
        drop(lease);
        assert!(weak.upgrade().is_some());
        assert!(budget.retained_input(1).is_err());
        assert!(matches!(
            budget.component([2; 16], 0, 0),
            Err(crate::Error::AnalysisBusy {
                resource: "query evaluation capacity",
                ..
            }),
        ));
        assert_eq!(
            budget
                .usage
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .evaluations,
            1
        );
        release.send(()).map_err(|_| "child release closed")?;
        tokio::time::timeout(Duration::from_secs(2), child).await??;
        assert!(weak.upgrade().is_none());
        let usage = budget
            .usage
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(usage.evaluations, 0);
        assert_eq!(usage.input_bytes, 0);
        assert_eq!(usage.output_bytes, 0);
        Ok(())
    }
}
