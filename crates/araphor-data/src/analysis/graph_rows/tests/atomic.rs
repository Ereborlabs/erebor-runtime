use std::collections::BTreeMap;

use super::*;
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, PackageBundle};

fn proposed(
    fixture: &mut CommitFixture,
) -> std::result::Result<Vec<AnalysisContextVersionV1>, Box<dyn std::error::Error>> {
    use araphor_analysis_sdk as sdk;
    let tenant = fixture.request.scope.identity.tenant_id;
    let fact = crate::GraphFactV1 {
        record_id: fixture.snapshot.input_manifest.evidence[0].clone(),
        value: crate::GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: false,
            reviewed_policy_revision: "retained-policy".into(),
        },
    };
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: tenant,
            owner_id: "graph-fixture-v1".into(),
            entity_key: b"fact".to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: fact.encode_context()?,
    };
    fixture
        .snapshot
        .input_manifest
        .context
        .push(context.key.clone());

    fixture.snapshot.graph.facts.push(fact);
    let descriptor = sdk::Package::new(
        "graph-image",
        "r1",
        vec![sdk::Model::new(
            "count",
            Vec::new(),
            vec![sdk::Port::new(
                "rows",
                sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
            )],
        )],
    );
    let artifact = crate::PackageArtifactV1 {
        descriptor,
        implementations: vec![crate::PackageImplementationV1::Sql {
            export: "count".into(),
            program: crate::SqlModelV1 {
                outputs: BTreeMap::from([(
                    "rows".into(),
                    "SELECT CAST(1 AS BIGINT UNSIGNED) AS count".into(),
                )]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let bundle = crate::PackageBundleV1 {
        schema_version: 1,
        root: artifact.reference(),
        artifacts: vec![artifact],
    };
    let bundle = PackageBundle::try_from(bundle)?;
    fixture
        .store
        .install_package_image(tenant, &bundle, || Ok(()))?;
    let pin = crate::AnalysisContextVersionV1::from_package(
        &bundle,
        tenant,
        &bundle.bundle().root,
        "count",
        "rows",
    )?;
    let mut rows = vec![context, pin];
    rows.sort_by(|left, right| left.key.cmp(&right.key));
    fixture.request.body.clear();
    Ok(rows)
}

fn proof(
    fixture: &CommitFixture,
) -> std::result::Result<crate::AnalysisContextRefV1, Box<dyn std::error::Error>> {
    let context = AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: fixture.request.scope.identity.tenant_id,
            owner_id: "control-fixture-v1".into(),
            entity_key: b"candidate".to_vec(),
            lifetime_key: b"control".to_vec(),
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: br#"{"candidate":1}"#.to_vec(),
    };
    let commit_revision = fixture.store.commit_context(&context)?;
    Ok(crate::AnalysisContextRefV1 {
        key: context.key,
        commit_revision,
    })
}

#[test]
fn context_failure_rolls_back() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let rows = proposed(&mut fixture)?;
    let captured = proof(&fixture)?;
    assert!(!fixture.snapshot.input_manifest.evidence.is_empty());
    let original: String = {
        let writer = fixture.store.writer_access()?;
        writer.get()?.query_row(
            "SELECT sql FROM duckdb_tables() WHERE table_name = 'context_refs'",
            [],
            |row| row.get(0),
        )?
    };
    let rejecting = original.replacen("PRIMARY KEY", "CHECK (false), PRIMARY KEY", 1);
    assert_ne!(rejecting, original);
    fixture
        .store
        .fault_write(&format!("DROP TABLE context_refs; {rejecting}"), &[])?;
    let before = fixture.store.meta()?;
    let sources = vec![("context_versions".into(), before.commit_revision)];
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisDatabase {
            operation: "flush exact result context",
            ..
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture.store.context_version(&captured.key)?.is_some());
    for context in &rows {
        assert!(fixture.store.context_version(&context.key)?.is_none());
    }
    assert!(fixture
        .store
        .read_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id,
        )?
        .is_none());
    assert!(fixture
        .store
        .graph_snapshot(&fixture.request.scope.identity)?
        .is_none());
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.request.scope)?
            .ok_or("graph progress")?
            .consumed_cursor,
        0
    );
    {
        let writer = fixture.store.writer_access()?;
        for table in [
            "graph_sources",
            "graph_evidence",
            "graph_producer_scopes",
            "graph_producer_versions",
            "graph_producer_members",
            "graph_result_producers",
            "graph_versions",
            "graph_subject_values",
            "graph_edge_values",
            "graph_edge_properties",
            "graph_progress_values",
            "graph_position_values",
            "graph_branch_values",
            "graph_fact_values",
            "graph_finding_values",
            "evidence_refs",
            "context_refs",
        ] {
            let count: u64 =
                writer
                    .get()?
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            assert_eq!(count, 0, "retained rows in {table}");
        }
    }
    fixture
        .store
        .fault_write(&format!("DROP TABLE context_refs; {original}"), &[])?;
    let receipt = fixture.store.commit_graph_snapshot(
        fixture.request.clone(),
        CanonicalGraph::new(fixture.snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        true,
        || Ok(()),
    )?;
    assert_eq!(receipt.commit_revision, before.commit_revision + 1);
    let (witnesses, references) = fixture.store.package_evidence(
        fixture.request.scope.identity.tenant_id,
        std::slice::from_ref(&fixture.request.result_id),
    )?;
    assert_eq!(
        witnesses.len(),
        fixture.snapshot.input_manifest.evidence.len()
    );
    assert_eq!(references.len(), rows.len() + 1);
    assert!(references.contains(&captured));
    Ok(())
}

#[test]
fn graph_contexts_commit_atomically() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let rows = proposed(&mut fixture)?;
    let captured = proof(&fixture)?;
    let before = fixture.store.meta()?;
    let sources = vec![("context_versions".into(), before.commit_revision)];
    let mut malformed = fixture.request.clone();
    malformed.context_revision += 1;
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            malformed.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    let denied = fixture.store.commit_graph_snapshot(
        fixture.request.clone(),
        CanonicalGraph::new(fixture.snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        true,
        || Err(crate::PackageErrorCodeV1::Denied.error("graph final authority")),
    );
    assert!(matches!(
        denied,
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    for context in &rows {
        assert!(fixture.store.context_version(&context.key)?.is_none());
    }
    assert!(fixture
        .store
        .read_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id
        )?
        .is_none());
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.request.scope)?
            .ok_or("graph progress")?
            .consumed_cursor,
        0
    );
    let receipt = fixture.store.commit_graph_snapshot(
        fixture.request.clone(),
        CanonicalGraph::new(fixture.snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        true,
        || Ok(()),
    )?;
    assert_eq!(receipt.commit_revision, before.commit_revision + 1);
    for context in &rows {
        assert_eq!(
            fixture.store.context_version(&context.key)?,
            Some(context.clone())
        );
    }
    let (_, refs) = fixture.store.package_evidence(
        fixture.request.scope.identity.tenant_id,
        std::slice::from_ref(&fixture.request.result_id),
    )?;
    assert_eq!(refs.len(), 3);
    assert!(refs.contains(&captured));
    for context in &rows {
        assert!(refs.contains(&crate::AnalysisContextRefV1 {
            key: context.key.clone(),
            commit_revision: receipt.commit_revision
        }));
    }
    let after = fixture.store.meta()?;
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            malformed,
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.store.meta()?, after);
    assert_eq!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            true,
            || Ok(()),
        )?,
        receipt
    );
    assert_eq!(fixture.store.meta()?, after);
    let mut stale = captured.clone();
    stale.commit_revision += 1;
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            &[stale],
            &sources,
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.store.meta()?, after);
    let CommitFixture {
        store,
        snapshot,
        request,
        _graph,
        _directory,
    } = fixture;
    let path = _directory.path().join("analysis");
    drop(_graph);
    drop(store);
    let store = crate::AnalysisStore::open(path)?;
    assert_eq!(
        store.commit_graph_snapshot(
            request.clone(),
            CanonicalGraph::new(snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            true,
            || Ok(()),
        )?,
        receipt
    );
    assert_eq!(
        store.graph_result(request.scope.identity.tenant_id, &request.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        store
            .package_evidence(
                request.scope.identity.tenant_id,
                std::slice::from_ref(&request.result_id)
            )?
            .1,
        refs
    );
    Ok(())
}

#[test]
fn graph_context_union_matches() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let rows = proposed(&mut fixture)?;
    let captured = proof(&fixture)?;
    let before = fixture.store.meta()?;
    let mut request = fixture.request.clone();
    request.context_revision = captured.commit_revision;
    request.context_refs = vec![captured.clone()];
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            request,
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            &[],
            &[],
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &[],
            std::slice::from_ref(&captured),
            &[],
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisState { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    for context in &rows {
        assert!(fixture.store.context_version(&context.key)?.is_none());
    }
    assert!(fixture
        .store
        .read_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id
        )?
        .is_none());
    Ok(())
}

#[test]
fn unchanged_refresh_keeps_receipt() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let rows = proposed(&mut fixture)?;
    let captured = proof(&fixture)?;
    let sources = vec![(
        "context_versions".into(),
        fixture.store.meta()?.commit_revision,
    )];
    let first = fixture.store.commit_graph_snapshot(
        fixture.request.clone(),
        CanonicalGraph::new(fixture.snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        true,
        || Ok(()),
    )?;
    let original_sources = sources;
    let committed = fixture.store.meta()?;
    let sources = vec![("context_versions".into(), committed.commit_revision)];
    let mut request = fixture.request.clone();
    request.result_id = "graph:unchanged".into();
    request.expected_cursor = first.consumed_cursor;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some(fixture.request.result_id.clone());
    snapshot.context_notice_revision = captured.commit_revision;
    let denied = fixture.store.commit_graph_snapshot(
        request.clone(),
        CanonicalGraph::new(snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        false,
        || Err(crate::PackageErrorCodeV1::Denied.error("unchanged graph authority")),
    );
    assert!(matches!(
        denied,
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Denied,
            ..
        })
    ));
    assert_eq!(fixture.store.meta()?, committed);
    let receipt = fixture.store.commit_graph_snapshot(
        request.clone(),
        CanonicalGraph::new(snapshot.clone())?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        false,
        || Ok(()),
    )?;
    assert_eq!(receipt, first);
    assert_eq!(fixture.store.meta()?, committed);
    assert!(fixture
        .store
        .graph_result(request.scope.identity.tenant_id, &request.result_id)?
        .is_none());
    assert_eq!(
        fixture.store.commit_graph_snapshot(
            request.clone(),
            CanonicalGraph::new(snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            false,
            || Ok(()),
        )?,
        first
    );
    let mut changed = snapshot.clone();
    changed.packages[0].state = crate::GraphPackageStateV1::CoverageInsufficient;
    let mut changed_request = request.clone();
    changed_request.result_id = "graph:changed".into();
    let changed_receipt = fixture.store.commit_graph_snapshot(
        changed_request.clone(),
        CanonicalGraph::new(changed)?,
        &rows,
        std::slice::from_ref(&captured),
        &sources,
        false,
        || Ok(()),
    )?;
    assert!(changed_receipt.commit_revision > first.commit_revision);
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            request,
            CanonicalGraph::new(snapshot)?,
            &rows,
            std::slice::from_ref(&captured),
            &sources,
            false,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            std::slice::from_ref(&captured),
            &original_sources,
            true,
            || Ok(()),
        )?,
        first
    );
    Ok(())
}

#[test]
fn absent_context_cut_fenced() -> TestResult {
    let mut fixture = CommitFixture::new()?;
    let rows = proposed(&mut fixture)?;
    let sources = vec![(
        "context_versions".into(),
        fixture.store.meta()?.commit_revision,
    )];
    let _new_candidate = proof(&fixture)?;
    let before = fixture.store.meta()?;
    assert!(matches!(
        fixture.store.commit_graph_snapshot(
            fixture.request.clone(),
            CanonicalGraph::new(fixture.snapshot.clone())?,
            &rows,
            &[],
            &sources,
            true,
            || Ok(()),
        ),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    for context in &rows {
        assert!(fixture.store.context_version(&context.key)?.is_none());
    }
    assert!(fixture
        .store
        .read_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id
        )?
        .is_none());
    Ok(())
}

#[test]
fn unchanged_requires_live_witness() -> TestResult {
    let fixture = CommitFixture::new()?;
    let first = fixture
        .store
        .commit_graph(&fixture.request, true, || Ok(()))?;
    let before = fixture.store.meta()?;
    let deadline = fixture.snapshot.witness_deadline_utc_ns;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some(fixture.request.result_id.clone());
    let mut request = fixture.request.clone();
    request.result_id = "graph:time-only".into();
    request.expected_cursor = request.consumed_cursor;
    request.created_utc_ns = deadline - 1;
    snapshot.witness_deadline_utc_ns = request.created_utc_ns + crate::GRAPH_WITNESS_TTL_NS;
    request.witnesses[0].expires_utc_ns = snapshot.witness_deadline_utc_ns;
    request.body = serde_json::to_vec(&snapshot)?;
    assert_eq!(
        fixture.store.commit_graph(&request, false, || Ok(()))?,
        first
    );
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture
        .store
        .graph_result(request.scope.identity.tenant_id, &request.result_id)?
        .is_none());
    assert_eq!(
        fixture.store.graph_result(
            fixture.request.scope.identity.tenant_id,
            &fixture.request.result_id
        )?,
        Some(fixture.snapshot.clone())
    );
    request.result_id = "graph:renewed-witness".into();
    request.created_utc_ns = deadline;
    snapshot.witness_deadline_utc_ns = request.created_utc_ns + crate::GRAPH_WITNESS_TTL_NS;
    request.witnesses[0].expires_utc_ns = snapshot.witness_deadline_utc_ns;
    request.body = serde_json::to_vec(&snapshot)?;
    let renewed = fixture.store.commit_graph(&request, false, || Ok(()))?;
    assert!(renewed.commit_revision > first.commit_revision);
    assert_eq!(renewed.consumed_cursor, first.consumed_cursor);
    assert_eq!(
        fixture
            .store
            .graph_result(request.scope.identity.tenant_id, &request.result_id)?,
        Some(snapshot)
    );
    assert_eq!(
        fixture
            .store
            .commit_graph(&fixture.request, true, || Ok(()))?,
        first
    );
    Ok(())
}
