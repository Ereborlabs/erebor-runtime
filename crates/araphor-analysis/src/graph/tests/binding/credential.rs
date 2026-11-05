use super::*;
use std::collections::BTreeMap;

#[tokio::test]
async fn credential_support_keeps_matches() -> TestResult {
    let input = credential_input()?.normalized()?;
    let graph = Graph::new(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let model = &package.exports[0];
    let evaluation = graph.evaluation_for(model)?;
    let original = algorithm::Observation::decode(&evaluation.input("records")?.data)?;
    let facts = algorithm::Fact::decode(&evaluation.input("facts")?.data)?;
    let records = [100, 800, 500, GRAPH_WINDOW_NS + 2_000, 500, 500]
        .into_iter()
        .enumerate()
        .map(|(index, time)| {
            let mut record = original[0].clone();
            record.id.durable_cursor = index as u64 + 1;
            record.position.commit_revision = index as u64 + 1;
            record.position.ordinal = 0;
            record.observed_boottime_ns = time;
            record.effect.task_cookie = 0;
            record.process_instance_id = Some([if index < 4 { 8 } else { 9 }; 16]);
            record
        })
        .collect::<Vec<_>>();
    let mut selected = Vec::new();
    for (row, tag) in [(0, 0), (1, 1), (1, 1), (2, 2), (3, 2), (4, 2)] {
        let mut fact = facts
            .iter()
            .find(|fact| {
                matches!(
                    (&fact.value, tag),
                    (GraphFactValueV1::Credential { .. }, 0)
                        | (GraphFactValueV1::AuthorityUse { .. }, 1)
                        | (GraphFactValueV1::Channel { .. }, 2)
                )
            })
            .ok_or("credential support fixture fact")?
            .clone();
        fact.record = row;
        fact.key.entity_key = (selected.len() as u64).to_be_bytes().to_vec();
        match &mut fact.value {
            GraphFactValueV1::Credential { completion, .. } => *completion = None,
            GraphFactValueV1::AuthorityUse {
                task_cookie,
                process_instance_id,
                credential_object_id,
                socket_object_id,
                ..
            } => {
                *task_cookie = Some(0);
                *process_instance_id = Some([9; 16]);
                *credential_object_id = None;
                *socket_object_id = Some([0; 16]);
            }
            GraphFactValueV1::Channel {
                task_cookie,
                process_instance_id,
                socket_object_id,
                ..
            } => {
                *task_cookie = 0;
                *process_instance_id = records[row as usize]
                    .process_instance_id
                    .ok_or("channel process")?;
                *socket_object_id = [0; 16];
            }
            _ => return Err("credential support fixture kind".into()),
        }
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
        .sql(
            "CREATE VIEW graph_settings AS SELECT window_ns, false AS restricted FROM graph_window",
        )
        .await?
        .collect()
        .await?;
    let sdk::InputSource::Query(sql) = &model.inputs[0].source else {
        return Err("credential unit query".into());
    };
    let schema = std::sync::Arc::new(model.inputs[0].port.schema.clone());
    let batches = context
        .sql(sql)
        .await?
        .collect()
        .await?
        .into_iter()
        .map(|batch| sdk::Dataset::normalize_batch(batch, std::sync::Arc::clone(&schema)))
        .collect::<sdk::Result<Vec<_>>>()?;
    let units = algorithm::Unit::decode(&sdk::Dataset {
        name: "units".into(),
        batches,
    })?;
    let actual = units
        .iter()
        .map(|unit| {
            assert_eq!(unit.window_ns, GRAPH_WINDOW_NS);
            assert!(!unit.restricted);
            (
                unit.record.durable_cursor,
                unit.support
                    .iter()
                    .map(|row| row.record.durable_cursor)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        actual,
        BTreeMap::from([
            (1, vec![1]),
            (2, vec![1, 2]),
            (3, vec![1, 2, 3]),
            (4, vec![4]),
            (5, vec![5]),
            (6, vec![6]),
        ])
    );
    Ok(())
}
