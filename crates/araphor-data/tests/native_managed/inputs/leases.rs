use super::*;

struct Budget(Arc<()>);

impl araphor_data::ManagedBudget for Budget {
    fn limit(&self) -> usize {
        usize::MAX
    }

    fn check(&self) -> araphor_data::Result<()> {
        Ok(())
    }

    fn reserve(&self, _: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
        Ok(Box::new(Arc::clone(&self.0)))
    }
}

#[test]
fn live_handles_release_budget() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let instance = instance(&store)?;
    let budget = Budget(Arc::new(()));
    let control = AnalysisReadControl::default();
    let subscribe = || {
        store.subscribe_managed_inputs(
            &instance,
            &instance.grant.selection,
            &requests(),
            None,
            &control,
            &budget,
        )
    };
    let first = subscribe()?;
    let handles = Arc::strong_count(&budget.0);
    assert!(handles > 1);
    let second = first.clone();
    let before = saved(&store)?;
    let meta = store.meta()?;
    drop(first);
    assert_eq!(Arc::strong_count(&budget.0), handles);
    drop(second);
    assert_eq!(Arc::strong_count(&budget.0), 1);
    assert_eq!(saved(&store)?, before);
    assert_eq!(store.meta()?, meta);
    super::super::attempts::append(&store, 1)?;
    let revived = subscribe()?;
    assert_eq!(
        revived.position(),
        StorePositionV1 {
            commit_revision: store.meta()?.commit_revision,
            ordinal: 0,
        }
    );
    assert_eq!(saved(&store)?, before);
    drop(revived);
    assert_eq!(Arc::strong_count(&budget.0), 1);
    Ok(())
}
