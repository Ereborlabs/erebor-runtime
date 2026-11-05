use super::*;
use std::collections::BTreeMap;
use std::sync::Arc;

#[tokio::test]
async fn policy_support_preserves_sets() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Process.descriptor();
    let model = &package.exports[0];
    let evaluation = graph.evaluation_for(model)?;
    let records = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
    let facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
    let policy = facts
        .iter()
        .find(|fact| matches!(fact.value, GraphFactValueV1::Policy(_)))
        .ok_or("policy support fixture")?;
    let mut missing = records[0].id.clone();
    missing.durable_cursor = 99;
    let mut selected = Vec::new();
    for (row, observations) in [
        (
            0,
            vec![records[1].id.clone(), records[1].id.clone(), missing],
        ),
        (0, vec![records[2].id.clone(), records[0].id.clone()]),
        (1, vec![]),
    ] {
        let mut fact = policy.clone();
        fact.record = row;
        fact.key.entity_key = (selected.len() as u64).to_be_bytes().to_vec();
        let GraphFactValueV1::Policy(value) = &mut fact.value else {
            return Err("policy support fixture kind".into());
        };
        value.observations = observations;
        selected.push(fact);
    }
    let context = datafusion::prelude::SessionContext::new();
    for (name, data) in [
        ("graph_records", algorithm::Observation::encode(&records)?),
        (
            "graph_facts",
            algorithm::Fact::encode_source(&selected, &records)?,
        ),
        ("graph_window", evaluation.input("window")?.data.clone()),
    ] {
        context.register_batch(name, data.batches[0].clone())?;
    }
    context
        .sql("CREATE VIEW graph_settings AS SELECT window_ns, true AS restricted FROM graph_window")
        .await?
        .collect()
        .await?;
    let sdk::InputSource::Query(sql) = &model.inputs[0].source else {
        return Err("policy unit query".into());
    };
    let schema = Arc::new(model.inputs[0].port.schema.clone());
    let batches = context
        .sql(sql)
        .await?
        .collect()
        .await?
        .into_iter()
        .map(|batch| sdk::Dataset::normalize_batch(batch, Arc::clone(&schema)))
        .collect::<sdk::Result<Vec<_>>>()?;
    let units = algorithm::Unit::decode(&sdk::Dataset {
        name: "units".into(),
        batches,
    })?;
    let actual = units
        .iter()
        .map(|unit| {
            assert_eq!(unit.window_ns, GRAPH_WINDOW_NS);
            assert!(unit.restricted);
            for support in &unit.support {
                let record = records
                    .iter()
                    .find(|record| record.id == support.record)
                    .unwrap();
                assert_eq!(support.proof, record.proof_quality);
                let mut keys = selected
                    .iter()
                    .filter(|fact| records[fact.record as usize].id == support.record)
                    .map(|fact| fact.key.clone())
                    .collect::<Vec<_>>();
                keys.sort();
                assert_eq!(support.facts, keys);
            }
            (
                unit.record.durable_cursor,
                unit.support
                    .iter()
                    .map(|support| support.record.durable_cursor)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual,
        BTreeMap::from([(1, vec![1, 2, 3]), (2, vec![2]), (3, vec![3])])
    );
    Ok(())
}
