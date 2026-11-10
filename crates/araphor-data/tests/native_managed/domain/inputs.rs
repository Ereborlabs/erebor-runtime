use super::*;
use araphor_data::Selection;
use std::time::Duration;

async fn changed(
    subscription: &mut araphor_data::InputSubscription,
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(
        tokio::time::timeout(Duration::from_secs(5), subscription.changed())
            .await??
            .commit_revision,
    )
}

async fn unchanged(subscription: &mut araphor_data::InputSubscription) -> TestResult {
    assert!(
        tokio::time::timeout(Duration::from_millis(20), subscription.changed())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn graph_publications_route_by_actual_producer_witnesses_and_replay() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = fixture(&store)?;
    let control = AnalysisReadControl::default();
    let requests: AnalysisTableRequests = [("findings".into(), None)].into();
    let mut scope = AnalysisSelectionV1::new([1; 16], vec![source.clone()]);
    scope.select_graphs(Selection::All, None)?;
    let mut other_source = source;
    other_source.node_id = "other-node".into();
    let mut other = AnalysisSelectionV1::new([1; 16], vec![other_source]);
    other.select_graphs(Selection::All, None)?;
    let foreign = AnalysisSelectionV1::tenant([2; 16]);
    let mut matching = store.subscribe_inputs(&scope, &requests, None, &control, &graph::Budget)?;
    let mut unrelated =
        store.subscribe_inputs(&other, &requests, None, &control, &graph::Budget)?;
    let mut tenant = store.subscribe_inputs(&foreign, &requests, None, &control, &graph::Budget)?;
    let before = store.view()?;
    commit(&store, &model, &observation, 0)?;
    let first = store.view()?.revision();
    assert_eq!(changed(&mut matching).await?, first);
    unchanged(&mut unrelated).await?;
    unchanged(&mut tenant).await?;
    let saved = store.view()?;
    store.commit_context(&super::super::attempts::context(100))?;
    unchanged(&mut matching).await?;
    commit(&store, &model, &observation, 1)?;
    let second = store.view()?.revision();
    assert_eq!(changed(&mut matching).await?, second);
    unchanged(&mut unrelated).await?;
    let mut lagging =
        store.subscribe_inputs_at(&before, &scope, &requests, None, &control, &graph::Budget)?;
    assert_eq!(changed(&mut lagging).await?, second);
    unchanged(&mut matching).await?;
    let saved_revision = saved.revision();
    drop((matching, unrelated, tenant, lagging, before, saved));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let saved = store.read_at(saved_revision)?;
    let mut resumed =
        store.subscribe_inputs_at(&saved, &scope, &requests, None, &control, &graph::Budget)?;
    assert_eq!(changed(&mut resumed).await?, second);
    unchanged(&mut resumed).await?;
    Ok(())
}
