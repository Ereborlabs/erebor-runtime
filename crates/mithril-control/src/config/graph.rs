use super::*;
use araphor_data::{AnalysisReadControl, DiscoveryInputManifestV1, EvidenceIntakeIdentityV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn records() -> TestResult<Vec<araphor_data::DiscoveryRecordV1>> {
    Ok(DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?
    .records
    .into_iter()
    .take(3)
    .collect())
}

pub(super) fn configuration(
    path: &Path,
    graph: bool,
    discovery: bool,
) -> TestResult<ControlConfig> {
    let records = records()?;
    let source = &records.first().ok_or("Control Graph source")?.id.stream;
    let config: ControlConfig = serde_json::from_value(serde_json::json!({
        "listen": "127.0.0.1:0",
        "tls": {
            "certificate_path": path.join("control.pem"),
            "private_key_path": path.join("control-key.pem"),
            "node_ca_path": path.join("node-ca.pem")
        },
        "allowed_nodes": [{
            "node_id": source.node_id,
            "certificate_sha256": "a".repeat(64),
            "tenant_id": uuid::Uuid::from_bytes(source.tenant_id).to_string()
        }],
        "trust": {
            "generation": 1, "bundle_digest": "b".repeat(64),
            "policy_issuer_sequence_epoch": 0, "policy_signers": []
        },
        "client": null, "evidence_directory": path,
        "graph_enabled": graph, "discovery": discovery
    }))?;
    Ok(config)
}

fn configured(path: &Path, graph: bool, discovery: bool) -> TestResult<ControlRuntimeParts> {
    Ok(configuration(path, graph, discovery)?.into_parts()?)
}

fn append(
    data: &araphor_data::AnalysisStore,
    source: &EvidenceIntakeIdentityV1,
    records: &[araphor_data::DiscoveryRecordV1],
) -> TestResult {
    for record in records {
        data.accept_validated_batch(
            source.clone(),
            araphor_data::ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: record.id.durable_cursor,
                last_cursor: record.id.durable_cursor,
                intake_utc_ns: record.id.durable_cursor,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
    }
    Ok(())
}

#[test]
fn graph_flag_is_independent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let parts = configured(directory.path(), true, false)?;
    assert!(parts.graph.is_some());
    assert!(parts.discovery.is_none());
    assert!(parts.instances.is_some());
    assert!(parts
        .control
        .analysis_store()
        .ok_or("Graph data")?
        .graph_enabled());
    assert!(!parts
        .control
        .analysis_store()
        .ok_or("Graph data")?
        .discovery_enabled());
    drop(parts);
    let directory = tempfile::tempdir()?;
    let parts = configured(directory.path(), false, true)?;
    assert!(parts.graph.is_none());
    assert!(parts.discovery.is_some());
    assert!(!parts
        .control
        .analysis_store()
        .ok_or("Discovery data")?
        .graph_enabled());
    drop(parts);
    let directory = tempfile::tempdir()?;
    let parts = configured(directory.path(), false, false)?;
    assert!(parts.graph.is_none());
    assert!(parts.instances.is_none());
    assert!(!parts
        .control
        .analysis_store()
        .ok_or("idle data")?
        .graph_enabled());
    Ok(())
}

#[test]
fn graph_definitions_stay_inert() -> TestResult {
    let directory = tempfile::tempdir()?;
    let parts = configured(directory.path(), true, false)?;
    let records = records()?;
    let source = &records[0].id.stream;
    let data = parts.control.analysis_store().ok_or("Graph data")?;
    let control = AnalysisReadControl::default();
    let definition = data
        .definition(source.tenant_id, "mithril-control-graph", None, &control)?
        .ok_or("configured Graph definition")?;
    assert_eq!(definition.images.len(), 3);
    assert!(data
        .definition(source.tenant_id, "graph-expiry", None, &control)?
        .ok_or("configured expiry definition")?
        .images
        .is_empty());
    append(&data, source, &records)?;
    let scope = araphor_data::ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    let health = data
        .processor_health(&scope)?
        .ok_or("required Graph processor")?;
    assert_eq!(health.class, araphor_data::ProcessorClassV1::Required);
    assert_eq!(health.consumed_cursor, 0);
    assert!(data.graph_snapshot(source)?.is_none());
    for operation in [
        araphor_data::ManagedGraphOperation::Evaluate,
        araphor_data::ManagedGraphOperation::Expire,
    ] {
        assert!(data
            .managed_instance(source.tenant_id, &operation.instance_id(source), &control)?
            .is_none());
    }
    Ok(())
}

async fn join_task(
    mut task: tokio::task::JoinHandle<araphor_analysis::Result<()>>,
    stage: &str,
) -> TestResult {
    match tokio::time::timeout(std::time::Duration::from_secs(90), &mut task).await {
        Ok(result) => {
            result??;
            Ok(())
        }
        Err(error) => {
            let _joined = task.await;
            Err(format!("{stage}: {error}").into())
        }
    }
}

#[tokio::test]
async fn graph_sources_use_host() -> TestResult {
    let directory = tempfile::tempdir()?;
    let parts = configured(directory.path(), true, false)?;
    let data = parts.control.analysis_store().ok_or("Graph data")?;
    let records = records()?;
    let source = records[0].id.stream.clone();
    let graph = parts.graph.clone().ok_or("configured Graph feed")?;
    let host = parts.instances.clone().ok_or("shared Instance Host")?;
    let query = Arc::clone(&parts.control.analysis_packages(None)?.query);
    let components = [
        araphor_analysis_builtins::components::PROCESS,
        araphor_analysis_builtins::components::CREDENTIALS,
        araphor_analysis_builtins::components::KUBERNETES,
    ];
    for component in components {
        assert!(!query.guest_cached(component)?);
    }
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(Arc::clone(&host).serve(stopped.clone(), u64::MAX));
    let feed = tokio::spawn(graph.run(stopped));
    let mut changes = data.subscribe_revision();
    let mut sources = Vec::new();
    let produced = async {
        for source in [
            source.clone(),
            EvidenceIntakeIdentityV1 {
                source_id: [231; 16],
                ..source.clone()
            },
        ] {
            append(&data, &source, &records)?;
            tokio::time::timeout(std::time::Duration::from_secs(90), async {
                loop {
                    if data
                        .graph_snapshot(&source)?
                        .is_some_and(|graph| graph.last_cursor == 3)
                    {
                        return Ok::<_, crate::Error>(());
                    }
                    changes.changed().await.map_err(|_| {
                        crate::error::InvalidConfigurationSnafu {
                            reason: "Graph source revision watch closed",
                        }
                        .build()
                    })?;
                }
            })
            .await
            .map_err(|error| {
                format!(
                    "Graph publication for source {:?}: {error}",
                    source.source_id
                )
            })??;
            for component in components {
                assert!(query.guest_cached(component)?);
            }
            let graph = data
                .graph_snapshot(&source)?
                .ok_or("native configured Graph")?;
            assert_eq!(graph.input_manifest.evidence.len(), 3);
            assert_eq!(graph.input_positions.len(), 3);
            assert_eq!(graph.packages.len(), 3);
            let job = data
                .managed_instance(
                    source.tenant_id,
                    &araphor_data::ManagedGraphOperation::Evaluate.instance_id(&source),
                    &AnalysisReadControl::default(),
                )?
                .ok_or("shared managed Graph job")?;
            assert!(job.running);
            assert_eq!(
                job.grant.selection.nodes,
                std::slice::from_ref(&source.node_id)
            );
            assert_eq!(
                job.spec
                    .destination
                    .selection(&job.grant.selection)?
                    .sources
                    .as_slice(),
                std::slice::from_ref(&source)
            );
            assert!(!data
                .managed_history(
                    &job.grant.selection,
                    &job.spec.id,
                    &AnalysisReadControl::default()
                )?
                .is_empty());
            sources.push((source, graph));
        }
        let foreign = EvidenceIntakeIdentityV1 {
            node_id: "unconfigured-node".into(),
            source_id: [233; 16],
            ..source.clone()
        };
        append(&data, &foreign, &records)?;
        assert!(data
            .processor_health(&araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: foreign.clone(),
            })?
            .is_none());
        assert!(data.graph_snapshot(&foreign)?.is_none());
        for operation in [
            araphor_data::ManagedGraphOperation::Evaluate,
            araphor_data::ManagedGraphOperation::Expire,
        ] {
            assert!(data
                .managed_instance(
                    foreign.tenant_id,
                    &operation.instance_id(&foreign),
                    &AnalysisReadControl::default()
                )?
                .is_none());
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    let stopping = stop.send(true);
    let (joined_feed, joined_host) = tokio::join!(
        join_task(feed, "Graph source feed join"),
        join_task(serving, "shared Instance Host join"),
    );
    produced?;
    stopping?;
    joined_feed?;
    joined_host?;
    let before = data.meta()?;
    changes.borrow_and_update();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), changes.changed())
            .await
            .is_err()
    );
    assert_eq!(data.meta()?, before);
    for (source, graph) in sources {
        assert_eq!(data.graph_snapshot(&source)?, Some(graph));
        assert!(data
            .processor_health(&araphor_data::ProcessorScopeV1 {
                processor_id: araphor_data::GRAPH_PROCESSOR.into(),
                method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
                identity: source,
            })?
            .is_some());
    }
    let late = EvidenceIntakeIdentityV1 {
        source_id: [232; 16],
        ..source
    };
    append(&data, &late, &records)?;
    assert!(data.graph_snapshot(&late)?.is_none());
    assert!(data
        .managed_instance(
            late.tenant_id,
            &araphor_data::ManagedGraphOperation::Evaluate.instance_id(&late),
            &AnalysisReadControl::default()
        )?
        .is_none());
    Ok(())
}
