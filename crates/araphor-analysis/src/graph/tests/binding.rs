use super::super::*;
use super::fixture::*;
use super::{derive, TestResult};

#[test]
fn input_binding_accepts_batches() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let mut evaluation = graph.evaluation_for(model)?;
    for input in &mut evaluation.inputs {
        let original = input.data.batches.remove(0);
        input.data.batches = (0..original.num_rows())
            .map(|row| original.slice(row, 1))
            .collect();
        input.data.batches.push(original.slice(0, 0));
    }
    graph.check_inputs(model, &evaluation)?;
    evaluation.inputs.reverse();
    graph.check_inputs(model, &evaluation)?;
    Ok(())
}

#[test]
fn input_binding_preserves_order() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let mut evaluation = graph.evaluation_for(model)?;
    let mut records = algorithm::Observation::decode(&graph.projection()?[0])?;
    records.swap(0, 1);
    evaluation.inputs[0].data = algorithm::Observation::encode(&records)?;
    assert!(matches!(
        graph.check_inputs(model, &evaluation),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph input binding",
            ..
        })
    ));
    let mut evaluation = graph.evaluation_for(model)?;
    let mut facts = algorithm::Fact::decode(&graph.projection()?[1])?;
    let value = facts
        .iter_mut()
        .find_map(|fact| match &mut fact.value {
            GraphFactValueV1::Credential {
                expected_access, ..
            } => Some(expected_access),
            _ => None,
        })
        .ok_or("credential fact")?;
    *value = !*value;
    evaluation.inputs[1].data = algorithm::Fact::encode(&facts)?;
    assert!(graph.check_inputs(model, &evaluation).is_err());
    let mut evaluation = graph.evaluation_for(model)?;
    evaluation.inputs.pop();
    assert!(graph.check_inputs(model, &evaluation).is_err());
    Ok(())
}

#[test]
fn input_normalizes_record_order() -> TestResult {
    let mut input = credential_input()?;
    input.records.reverse();
    let normalized = input.normalized()?;
    let left = Graph::new(&input)?;
    let right = Graph::new(&normalized)?;
    for (actual, expected) in left.projection()?.iter().zip(right.projection()?) {
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.batches, expected.batches);
    }
    Ok(())
}

#[test]
fn input_positions_bind_exact_records() -> TestResult {
    let input = credential_input()?;
    for case in 0..3 {
        let mut invalid = input.clone();
        match case {
            0 => {
                invalid.input_positions.pop();
            }
            1 => invalid.input_positions[1].1 = invalid.input_positions[0].1,
            _ => invalid.input_positions[1].0 = invalid.input_positions[0].0.clone(),
        }
        assert!(matches!(
            Graph::new(&invalid),
            Err(araphor_data::Error::GraphInvalid {
                field: "replay input position",
                ..
            })
        ));
    }
    let graph = Graph::new(&input)?;
    let model = &algorithm::Detector::Credentials.descriptor().exports[0];
    let mut evaluation = graph.evaluation_for(model)?;
    let mut records = algorithm::Observation::decode(&evaluation.inputs[0].data)?;
    records[0].position.ordinal += 1;
    evaluation.inputs[0].data = algorithm::Observation::encode(&records)?;
    assert!(matches!(
        graph.check_inputs(model, &evaluation),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph input binding",
            ..
        })
    ));
    Ok(())
}

#[tokio::test]
async fn result_requires_exact_image() -> TestResult {
    use araphor_data::{AnalysisReadControl, AnalysisSelectionV1, AnalysisStore};
    use araphor_discovery_definition::{Definition, Program, Source};
    use araphor_package::{
        PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1,
    };
    use araphor_query::definition::Invocation;
    use araphor_query::execution::Engine;
    use datafusion::common::tree_node::TreeNodeRecursion;
    use datafusion::logical_expr::LogicalPlan;
    use std::sync::Arc;

    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Process.descriptor();
    let model = &package.exports[0];
    let evaluation = graph.evaluation_for(model)?;
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let engine = Engine::new(Arc::clone(&store), Default::default())?;
    let mut session = engine.session(
        AnalysisSelectionV1::tenant(input.source.tenant_id),
        &AnalysisReadControl::default(),
        10,
    )?;
    for input in &evaluation.inputs {
        session.register(
            &format!("origin_{}", input.data.name),
            input.data.batches[0].schema(),
            &input.data.batches,
        )?;
    }
    let expected = algorithm::Detector::Process.evaluate(&evaluation)?;
    let mut returns = Vec::new();
    for revision in ["1", "2"] {
        let mut descriptor = package.clone();
        descriptor.revision = revision.into();
        let returned = expected.clone();
        let prior_checkpoint = returned.checkpoint.clone().ok_or("complete checkpoint")?;
        let prior_outputs = super::execution::normalized_prior(&returned, &descriptor.id)?;
        let sql = super::execution::Fixture::sql(&returned)?;
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: descriptor.id.clone(),
                revision: revision.into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor,
                implementations: vec![PackageImplementationV1::Sql {
                    export: "detect".into(),
                    program: sql.clone(),
                }],
                fixtures: Vec::new(),
            }],
        };
        store.install_package_image(
            input.source.tenant_id,
            &araphor_package::PackageBundle::try_from(bundle)?,
            || Ok(()),
        )?;
        let definition = Definition {
            name: "graph-origin".into(),
            description: String::new(),
            labels: Default::default(),
            program: Program::Sql {
                source: Source::Inline {
                    inline: format!(
                        r#"SELECT * FROM "HF-PROC-001"."{revision}".detect('subjects',
                    records => (SELECT * FROM origin_records),
                    facts => (SELECT * FROM origin_facts),
                    manifest => (SELECT * FROM origin_manifest))"#,
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition).await?;
        let mut call = None;
        prepared.plan.apply_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = plan {
                if let Some(node) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    call = Some(node.clone());
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let call = call.ok_or("package call")?;
        let invocation = Invocation {
            checkpoints: BTreeMap::from([(call.id(), prior_checkpoint)]),
            previous_outputs: if prior_outputs.is_empty() {
                BTreeMap::new()
            } else {
                BTreeMap::from([(call.id(), prior_outputs)])
            },
            ..Default::default()
        };
        let output = session.execute_definition(&prepared, invocation).await?;
        let result = Arc::clone(output.calls.get(&call.id()).ok_or("package return")?);
        assert!(result.belongs_to(&call));
        Graph::new(&input)?.apply(&call, &result)?.finish()?;
        returns.push((call, result));
    }
    let [(first, first_result), (second, second_result)] = returns.as_slice() else {
        return Err("two package returns required".into());
    };
    assert_eq!(first.id(), second.id());
    assert_eq!(first.export(), second.export());
    assert_ne!(first.image(), second.image());
    for (call, result) in [(first, second_result), (second, first_result)] {
        assert!(!result.belongs_to(call));
        assert!(matches!(
            Graph::new(&input)?.apply(call, result),
            Err(araphor_data::Error::GraphInvalid {
                field: "graph package call",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn expiry_downgrades_all_proofs() -> TestResult {
    let input = credential_input()?;
    let mut previous = derive(&input)?;
    previous.witness_deadline_utc_ns = 100;
    let original = previous.clone();
    let expired = Graph::expire(&previous, "graph:previous", 7)?;
    assert_eq!(previous, original);
    assert_eq!(
        expired.previous_result_id.as_deref(),
        Some("graph:previous")
    );
    assert_eq!(expired.context_notice_revision, 7);
    assert_eq!(expired.witness_deadline_utc_ns, 100);
    assert_eq!(
        expired.input_manifest.evidence,
        previous.input_manifest.evidence
    );
    assert_eq!(
        expired.input_manifest.context,
        previous.input_manifest.context
    );
    assert!(expired
        .missing_ranges
        .contains(&(previous.first_cursor, previous.last_cursor)));
    assert!(expired.graph.edges.iter().all(|edge| {
        edge.key.cause == GraphCauseV1::Superseded
            && edge.proof_quality.temporal_coverage == TemporalCoverageV1::Unknown
    }));
    assert!(expired.graph.branches.iter().all(|branch| {
        branch.state == GraphBranchStateV1::CoverageUnknown
            && branch
                .missing_fields
                .contains(&"RETAINED_INPUT_EXPIRED".into())
    }));
    assert!(expired.findings.iter().all(|finding| {
        finding.state == FindingStateV1::CoverageInsufficient
            && finding.limits.contains(&"RETAINED_INPUT_EXPIRED".into())
            && finding
                .limits
                .contains(&"LATE_EVIDENCE_UNSUPPORTED_AFTER_RETENTION".into())
            && finding
                .effects
                .iter()
                .all(|effect| effect.proof_quality.temporal_coverage == TemporalCoverageV1::Unknown)
    }));
    assert!(expired
        .packages
        .iter()
        .all(|package| { package.state == GraphPackageStateV1::CoverageInsufficient }));
    assert_eq!(expired, Graph::expire(&previous, "graph:previous", 7)?);
    expired.validate()?;
    Ok(())
}

#[test]
fn owned_input_preserves_semantic_binding() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::try_from(input)?;
    let pointers = graph
        .projection()?
        .each_ref()
        .map(|rows| rows.batches.as_ptr());
    for detector in [
        algorithm::Detector::Process,
        algorithm::Detector::Credentials,
        algorithm::Detector::Kubernetes,
    ] {
        let package = detector.descriptor();
        let model = &package.exports[0];
        let mut evaluation = graph.evaluation_for(model)?;
        for input in &mut evaluation.inputs {
            let batch = input.data.batches.remove(0);
            input.data.batches = (0..batch.num_rows())
                .map(|row| batch.slice(row, 1))
                .collect();
            input.data.batches.push(batch.slice(0, 0));
        }
        graph.check_inputs(model, &evaluation)?;
        assert_eq!(
            graph
                .projection()?
                .each_ref()
                .map(|rows| rows.batches.as_ptr()),
            pointers
        );
    }
    Ok(())
}
