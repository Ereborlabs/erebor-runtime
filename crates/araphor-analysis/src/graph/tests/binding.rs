use super::super::*;
use super::fixture::*;
use super::{derive, TestResult};

#[test]
fn selection_keeps_affected_roots() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let current = graph
        .observations
        .first()
        .ok_or("current observation")?
        .id
        .clone();
    let mut retired = current.clone();
    retired.durable_cursor = graph
        .observations
        .iter()
        .map(|row| row.id.durable_cursor)
        .max()
        .ok_or("current cursor")?
        .checked_add(1)
        .ok_or("retired cursor")?;
    let unit = |record| algorithm::Unit {
        record,
        window_ns: GRAPH_WINDOW_NS,
        restricted: false,
        support: Vec::new(),
    };
    graph.check_selection(
        std::slice::from_ref(&current),
        &[],
        &[unit(current.clone())],
    )?;
    graph.check_selection(
        std::slice::from_ref(&retired),
        &[unit(retired.clone())],
        &[],
    )?;
    graph.check_selection(
        std::slice::from_ref(&current),
        &[unit(current.clone())],
        &[unit(current.clone())],
    )?;
    for (keys, before, after) in [
        (vec![current.clone()], vec![], vec![]),
        (vec![retired.clone()], vec![], vec![]),
        (
            vec![current.clone(), current.clone()],
            vec![],
            vec![unit(current.clone())],
        ),
        (
            vec![retired.clone()],
            vec![unit(retired.clone()), unit(retired.clone())],
            vec![],
        ),
        (
            vec![current.clone()],
            vec![],
            vec![unit(current.clone()), unit(current.clone())],
        ),
        (vec![], vec![], vec![unit(current.clone())]),
        (vec![retired.clone()], vec![], vec![unit(retired.clone())]),
    ] {
        assert!(graph.check_selection(&keys, &before, &after).is_err());
    }
    let mut foreign = retired.clone();
    foreign.stream.source_epoch += 1;
    assert!(graph
        .check_selection(
            std::slice::from_ref(&foreign),
            &[unit(foreign.clone())],
            &[]
        )
        .is_err());
    retired.durable_cursor = 0;
    assert!(graph
        .check_selection(
            std::slice::from_ref(&retired),
            &[unit(retired.clone())],
            &[]
        )
        .is_err());
    Ok(())
}

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
fn input_binding_preserves_links() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let mut evaluation = graph.evaluation_for(model)?;
    let mut records = algorithm::Observation::decode(&graph.projection()?[0])?;
    records.swap(0, 1);
    evaluation.inputs[3].data = algorithm::Observation::encode(&records)?;
    assert!(matches!(
        graph.check_inputs(model, &evaluation),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph unit lookup facts",
            ..
        })
    ));
    let mut evaluation = graph.evaluation_for(model)?;
    let mut facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
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
    evaluation.inputs[4].data = algorithm::Fact::encode(&facts)?;
    assert!(graph.check_inputs(model, &evaluation).is_err());
    let mut evaluation = graph.evaluation_for(model)?;
    evaluation.inputs.pop();
    assert!(graph.check_inputs(model, &evaluation).is_err());
    Ok(())
}

#[test]
fn input_binding_accepts_permutations() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let mut evaluation = graph.evaluation_for(model)?;
    let original = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
    let mut records = original.clone();
    records.reverse();
    let positions = records
        .iter()
        .enumerate()
        .map(|(row, record)| (&record.id, row as u32))
        .collect::<BTreeMap<_, _>>();
    let mut facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
    for fact in &mut facts {
        fact.record = positions[&original[fact.record as usize].id];
    }
    facts.reverse();
    let mut units = algorithm::Unit::decode(&evaluation.input("units")?.data)?;
    units.reverse();
    for data in [
        algorithm::Observation::encode(&records)?,
        algorithm::Fact::encode(&facts)?,
        algorithm::Unit::encode(&units)?,
    ] {
        let input = evaluation
            .inputs
            .iter_mut()
            .find(|input| input.data.name == data.name)
            .ok_or("input")?;
        input.data = data;
    }
    graph.check_inputs(model, &evaluation)?;
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
    let mut records = algorithm::Observation::decode(&evaluation.inputs[3].data)?;
    records[0].position.ordinal += 1;
    evaluation.inputs[3].data = algorithm::Observation::encode(&records)?;
    assert!(matches!(
        graph.check_inputs(model, &evaluation),
        Err(araphor_data::Error::GraphInvalid {
            field: "graph unit lookup record",
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
    let facts = algorithm::Fact::encode_source(
        &algorithm::Fact::decode(&evaluation.input("facts")?.data)?,
        &algorithm::Observation::decode(&evaluation.input("records")?.data)?,
    )?;
    for (table, data) in [
        ("graph_records", &evaluation.input("records")?.data),
        ("graph_facts", &facts),
        ("graph_dirty", &evaluation.input("affected")?.data),
        ("graph_window", &evaluation.input("window")?.data),
    ] {
        session.register(table, data.batches[0].schema(), &data.batches)?;
    }
    let settings = algorithm::Manifest::encode(&[algorithm::Manifest {
        window_ns: GRAPH_WINDOW_NS,
    }])?;
    let mut fields = settings.batches[0].schema().fields().to_vec();
    fields.push(Arc::new(sdk::Field::new(
        "restricted",
        sdk::DataType::Boolean,
        false,
    )));
    let mut columns = settings.batches[0].columns().to_vec();
    columns.push(Arc::new(sdk::arrow_array::BooleanArray::from(vec![
        graph.restricted,
    ])));
    let settings = sdk::RecordBatch::try_new(Arc::new(sdk::Schema::new(fields)), columns)?;
    session.register("graph_settings", settings.schema(), &[settings])?;
    let expected = algorithm::Detector::Process.evaluate(&evaluation)?;
    let mut returns = Vec::new();
    for revision in ["1", "2"] {
        let mut descriptor = package.clone();
        descriptor.revision = revision.into();
        let returned = expected.clone();
        let sql = super::execution::Fixture::sql(&evaluation, &returned)?;
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
                    units => (SELECT * FROM origin_units))"#,
                    ),
                },
            },
        };
        let prepared = session.prepare_definition(&definition, None).await?;
        let mut call = None;
        prepared.plan().apply_with_subqueries(|plan| {
            if let LogicalPlan::Extension(extension) = plan {
                if let Some(node) = extension.node.as_any().downcast_ref::<PackageCall>() {
                    call = Some(node.clone());
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let call = call.ok_or("package call")?;
        let invocation = Invocation::default();
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
