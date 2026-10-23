use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::*;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::logical_expr::{lit, LogicalPlanBuilder};
use datafusion::physical_plan::empty::EmptyExec;

#[derive(Debug)]
struct Port;

impl PortSource for Port {
    fn plan(&self, _: usize, _: &[Arc<dyn ExecutionPlan>]) -> Result<Arc<dyn ExecutionPlan>> {
        Ok(Arc::new(EmptyExec::new(Arc::new(Schema::empty()))))
    }
}

fn port(role: &str, field: &str, value: i64) -> SourcePort {
    SourcePort::new(
        role.into(),
        Arc::new(Schema::new(vec![Field::new(field, DataType::Int64, false)])),
        vec![LogicalPlanBuilder::empty(true)
            .project([lit(value).alias("input")])
            .unwrap()
            .build()
            .unwrap()],
        Arc::new(Port),
    )
    .unwrap()
}

fn fingerprint(port: &SourcePort) -> u64 {
    let mut hasher = DefaultHasher::new();
    port.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn role_keeps_native_binding() {
    let first = port("records", "value", 1);
    let rebuilt = port("records", "value", 1);
    assert_ne!(first.slot, rebuilt.slot);
    assert_ne!(first, rebuilt);
    assert_ne!(first.partial_cmp(&rebuilt), Some(Ordering::Equal));
    assert_eq!(fingerprint(&first), fingerprint(&rebuilt));
    assert_eq!(first, first.clone());
    assert_eq!(fingerprint(&first), fingerprint(&first.clone()));
    for changed in [
        port("facts", "value", 1),
        port("records", "other", 1),
        port("records", "value", 2),
    ] {
        assert_ne!(first, changed);
        assert_ne!(fingerprint(&first), fingerprint(&changed));
    }
    let inputs = first.inputs.clone();
    let rewritten = first.with_exprs_and_inputs(Vec::new(), inputs).unwrap();
    assert_eq!(rewritten, first);
    assert_eq!(fingerprint(&rewritten), fingerprint(&first));
}
