use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    AnalysisStore, ContextSensitivityV1, Selection,
};
use datafusion::arrow::array::BinaryArray;
use futures_util::TryStreamExt as _;

use super::ArrowSnapshot;
use crate::execution::{Engine, Limits, Read};
use crate::parser::Parser;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn witnesses_keep_source_receipt() -> TestResult {
    use araphor_data::{AnalysisExtractLimits, AnalysisStreamIdentityV1, AnalysisWitnessV1};

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let source = araphor_data::EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        observed_boottime_ns: 1,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        source.clone(),
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    let context = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "witness-test".into(),
            entity_key: vec![4],
            lifetime_key: vec![5],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![6],
    };
    let revision = store.commit_context(&context)?;
    let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
    selection.contexts = Selection::Exact(vec![context.key.clone()]);
    let capacity = 32 * 1024;
    let memory = crate::memory::Memory::new(capacity, 1024);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let snapshot = super::SourceSnapshot::new(
        store,
        selection,
        AnalysisExtractLimits {
            input_bytes: 16 * 1024,
            ..Default::default()
        },
        control.within(control.remaining()?)?,
        Duration::from_secs(30),
        1,
        Arc::clone(&memory),
    );
    let mut captured = snapshot.read(
        &BTreeSet::from(["events".to_owned(), "context_versions".to_owned()]),
        &BTreeMap::new(),
        None,
        super::ReadMode::Snapshot,
        &control,
    )?;
    let previous = captured.receipt._metadata.size();
    let old = captured.receipt.witnesses.capacity() * std::mem::size_of::<AnalysisWitnessV1>()
        + captured
            .receipt
            .witnesses
            .iter()
            .map(|witness| match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
            })
            .sum::<usize>();
    let mut witnesses = Vec::with_capacity(7);
    let mut witness = captured.receipt.witnesses[0].clone();
    if let AnalysisStreamIdentityV1::Evidence(identity) = &mut witness.identity {
        identity.node_id.reserve_exact(64);
    }
    witnesses.push(witness);
    let mut node = String::with_capacity(96);
    node.push_str("node-b");
    witnesses.push(AnalysisWitnessV1 {
        identity: AnalysisStreamIdentityV1::Diagnostic(araphor_data::TraceIdentityV1 {
            tenant_id: [1; 16],
            node_id: node,
            node_boot_id: [2; 16],
            request_id: [3; 16],
            execution_id: [4; 16],
            source_sha256: [5; 32],
        }),
        cursor: 2,
        expires_utc_ns: 0,
    });
    let added = witnesses.capacity() * std::mem::size_of::<AnalysisWitnessV1>()
        + witnesses
            .iter()
            .map(|witness| match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
            })
            .sum::<usize>();
    captured.set_witnesses(witnesses)?;
    let expected = previous - old + added;
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(captured.receipt.witnesses.len(), 2);
    assert_eq!(captured.receipt.contexts[0].key, context.key);
    assert_eq!(captured.receipt.contexts[0].commit_revision, revision);
    assert_eq!(captured.receipt.page.extraction.sources.len(), 1);
    let shared = Arc::clone(&captured.receipt);
    assert!(matches!(
        captured.set_witnesses(Vec::new()),
        Err(datafusion::common::DataFusionError::Internal(_))
    ));
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(shared.witnesses.len(), 2);
    drop(shared);
    let held = memory.reserve_input(capacity - expected)?;
    let mut larger = Vec::with_capacity(64);
    larger.extend(captured.receipt.witnesses.iter().cloned());
    let error = captured
        .set_witnesses(larger)
        .expect_err("shared input is exhausted");
    assert!(
        matches!(error, datafusion::common::DataFusionError::External(source)
        if matches!(source.downcast_ref::<crate::Error>(), Some(crate::Error::Capacity { resource: "shared input", .. })))
    );
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(captured.receipt.witnesses.len(), 2);
    drop(held);
    captured.set_witnesses(Vec::new())?;
    assert_eq!(captured.receipt._metadata.size(), previous - old);
    assert!(captured.receipt.witnesses.is_empty());
    assert_eq!(captured.receipt.contexts[0].key, context.key);
    drop(captured);
    assert!(memory.reserve_input(capacity).is_ok());
    Ok(())
}

#[tokio::test]
async fn receipt_releases_binary_scratch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let context = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "receipt-test".into(),
            entity_key: vec![2; 16],
            lifetime_key: vec![3; 16],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![7; 24 * 1024],
    };
    let revision = store.commit_context(&context)?;
    let engine = Engine::new(
        Arc::clone(&store),
        Limits {
            input_bytes: 2 * 1024 * 1024,
            input_capacity: 2 * 1024 * 1024,
            output_capacity: 2 * 1024 * 1024,
            extract_timeout: Duration::from_secs(5),
            evaluate_timeout: Duration::from_secs(5),
            ..Default::default()
        },
    )?;
    let state = engine.catalog(BTreeMap::new())?;
    let statement = Parser::parse("SELECT body FROM context_versions")?;
    let sources: BTreeSet<String> = state
        .resolve_table_references(&statement)?
        .into_iter()
        .map(|source| source.table().to_owned())
        .collect();
    let plan = engine.plan(&state, statement, vec![])?;
    let mut selection = AnalysisSelectionV1::new(context.key.tenant_id, vec![]);
    selection.contexts = Selection::Exact(vec![context.key.clone()]);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
    let session = engine.session(selection, &control, 1)?;
    let (receipt, mut stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
    let batch = stream.try_next().await?.ok_or("context batch is absent")?;
    let body = batch
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("context body is not native binary")?;
    assert_eq!(body.value(0), context.body);
    let payload = batch.column(0).to_data().buffers()[1].clone();
    assert!(stream.try_next().await?.is_none());
    assert_eq!(receipt.contexts.len(), 1);
    assert_eq!(receipt.contexts[0].key, context.key);
    assert_eq!(receipt.contexts[0].commit_revision, revision);
    let metadata = receipt._metadata.size();
    assert!(
        metadata
            >= std::mem::size_of::<ArrowSnapshot>()
                + std::mem::size_of::<AnalysisContextRefV1>()
                + context.key.owner_id.capacity()
                + context.key.entity_key.capacity()
                + context.key.lifetime_key.capacity()
    );
    assert!(metadata < context.body.len());
    assert!(receipt.page.extraction.input_bytes > context.body.len() * 2);
    drop(batch);
    drop(stream);
    drop(session);
    let capacity = engine.limits().input_capacity;
    assert!(engine.memory().reserve_input(capacity - metadata).is_err());
    drop(payload);
    let available = engine.memory().reserve_input(capacity - metadata)?;
    assert!(engine.memory().reserve_input(1).is_err());
    drop(available);
    assert!(engine.memory().reserve_input(capacity).is_err());
    assert!(engine
        .memory()
        .reserve_output(engine.limits().output_capacity)
        .is_ok());
    drop(receipt);
    assert!(engine.memory().reserve_input(capacity).is_ok());
    Ok(())
}
