use super::*;
use araphor_data::Selection;
use std::time::Duration;

#[derive(serde::Deserialize)]
struct Stored {
    body: Body,
}
#[derive(serde::Deserialize)]
enum Body {
    Call(Call),
}
#[derive(serde::Deserialize)]
struct Call {
    call: u64,
    witnesses: Vec<araphor_data::AnalysisWitnessV1>,
}

#[tokio::test]
async fn empty_graph_witnesses_fall_back_only_when_all_heads_are_empty() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let mut fixture = Fixture::new(&store, [1; 16], "input-fallback", true)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    fixture
        .spec
        .manifest
        .calls
        .insert(20, fixture.spec.manifest.calls[&10].clone());
    assert!(fixture
        .spec
        .manifest
        .calls
        .values()
        .all(|call| call.dependencies.is_empty()));
    let admitted = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], &admitted.spec.id, admitted.lifecycle, true, || {
            Ok(())
        })?;
    let control = AnalysisReadControl::default();
    let package = &instance.spec.manifest.calls[&10].package;
    let descriptor = store
        .view()?
        .package_revision([1; 16], &package.package_id, &package.revision, &control)?
        .ok_or("package")?;
    let descriptor: sdk::Package = serde_json::from_slice(&descriptor.descriptor)?;
    let model = &descriptor.exports[0];
    let mut scope = AnalysisSelectionV1::tenant([1; 16]);
    scope.nodes = vec!["other-node".into()];
    scope.select_graphs(Selection::All, None)?;
    let requests: AnalysisTableRequests = [("graph_manifest".into(), None)].into();
    let mut subscription = store.subscribe_inputs(
        &scope,
        &requests,
        None,
        &control,
        &super::super::graph::Budget,
    )?;
    let mut matching = store.subscribe_inputs(
        &AnalysisSelectionV1::tenant([1; 16]),
        &requests,
        None,
        &control,
        &super::super::graph::Budget,
    )?;
    for step in 0..2 {
        let page = if step == 0 {
            super::super::attempts::capture(&store, &instance, false)?
        } else {
            super::super::attempts::append(&store, 1)?;
            let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
            capture(&store, &resume)?
        };
        if step == 1 {
            let frame = page.state.source().ok_or("source frame")?;
            let batch = page.page.tables["events"]
                .iter()
                .position(|batch| batch.num_rows() > 0)
                .ok_or("event batch")?;
            let rows = Arc::new(
                frame
                    .row_handles("events", batch)?
                    .select(&[0], Arc::new(()))?,
            );
            frame.record_rows(&rows)?;
            frame.attribute_rows(10, &[rows], Arc::new(()))?;
        }
        let attempt = Arc::new(store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request(&format!("fallback-{step}"), true),
            || Ok(()),
        )?);
        let mut journals = Vec::new();
        for call in [10, 20] {
            let graph = ManagedGraphTransaction::new(
                &store,
                Arc::clone(&attempt),
                call,
                model,
                Vec::new(),
                Arc::new(super::super::graph::Budget),
                &control,
            )?;
            if call == 10 {
                let batch = super::super::graph::node(
                    &graph,
                    if step == 0 { b"task-a" } else { b"task-b" },
                )?;
                graph.stage(&store, "task", batch, Arc::new(()), &control)?;
            }
            journals.push(graph.freeze(&store, &control)?);
        }
        let journals = journals.try_into().map_err(|_| "journals")?;
        let receipt = publish(&store, &attempt, model, &journals, false)?;
        let view = store.view()?;
        let publication = view
            .managed_graph_publication([1; 16], &receipt.selected, &control)?
            .ok_or("publication")?;
        assert_eq!(publication.heads.len(), 2);
        let mut calls = std::collections::BTreeSet::new();
        for (id, _) in publication.heads.values() {
            let key = [b"\0data/X".as_slice(), &id.to_be_bytes()].concat();
            let bytes = view.snapshot().get(key)?.ok_or("producer")?;
            let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
            let Body::Call(call) = stored.body;
            assert!(calls.insert(call.call));
            assert_eq!(
                call.witnesses.len(),
                usize::from(step == 1 && call.call == 10)
            );
            if let Some(witness) = call.witnesses.first() {
                assert_eq!(witness.cursor, 1);
                assert!(
                    matches!(&witness.identity, araphor_data::AnalysisStreamIdentityV1::Evidence(source) if source.node_id == "node-a")
                );
            }
        }
        assert_eq!(calls, [10, 20].into());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), matching.changed())
                .await??
                .commit_revision,
            receipt.commit_revision
        );
        if step == 0 {
            let position =
                tokio::time::timeout(Duration::from_secs(5), subscription.changed()).await??;
            assert_eq!(position.commit_revision, receipt.commit_revision);
        } else {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), subscription.changed())
                    .await
                    .is_err()
            );
        }
    }
    Ok(())
}
