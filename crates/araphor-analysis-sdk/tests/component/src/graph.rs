use super::{sdk, Arc, RuntimeFixture};
use sdk::arrow_array::{
    cast::AsArray as _, types::UInt64Type, BinaryArray, StructArray, UInt8Array,
};

pub(super) struct GraphFixture;

impl GraphFixture {
    pub(super) fn model() -> sdk::Model {
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, true)]);
        let mut model = sdk::Model::new(
            "index",
            vec![
                sdk::Port::new("after", schema.clone()),
                sdk::Port::new("before", schema.clone()),
                sdk::Port::new("affected", schema.clone()),
                sdk::ChangeInputs::reset_port("reset"),
            ],
            vec![sdk::Port::new("frontier", schema.clone())],
        );
        model.input_mode = sdk::InputMode::Resolved;
        let query = |image: &str| {
            format!(
            "SELECT owner_revision AS value FROM {image}context_versions WHERE owner_id = 'graph-fixture'"
        )
        };
        for (input, query) in model.inputs.iter_mut().zip([
            query(""),
            format!(
                "SELECT source.* FROM ({}) source JOIN affected USING (value)",
                query("before.")
            ),
            "SELECT value FROM inserted.after UNION SELECT value FROM removed.after".into(),
        ]) {
            input.source = sdk::InputSource::Query(query);
        }
        model.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                affected: "affected".into(),
                before: "before".into(),
                after: "after".into(),
                current: Some(format!(
                    "SELECT source.* FROM ({}) source JOIN affected USING (value)",
                    query("after.")
                )),
            }],
        });
        model.graph = Some(sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations: vec![
                sdk::GraphRelation {
                    name: "nodes".into(),
                    kind: sdk::GraphKind::Node,
                    properties: schema.clone(),
                },
                sdk::GraphRelation {
                    name: "links".into(),
                    kind: sdk::GraphKind::Edge {
                        from: "nodes".into(),
                        to: "nodes".into(),
                    },
                    properties: schema,
                },
            ],
        });
        model
    }
}

impl sdk::Guest for GraphFixture {
    fn package() -> sdk::Package {
        RuntimeFixture::package()
    }

    fn compute(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let contract = input
            .model()
            .graph
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "fixture Graph"))?;
        let graph = input.graph()?;
        let failed = |_| sdk::Error::contract(sdk::ErrorCode::Failed, "fixture Graph stage");
        let evaluation = input.evaluation();
        if input
            .model()
            .change_inputs
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "fixture changes"))?
            .is_reset(evaluation)?
        {
            graph.clear_scope().map_err(failed)?;
        } else {
            for batch in &evaluation.input("affected")?.data.batches {
                for value in batch.column(0).as_primitive::<UInt64Type>().values() {
                    graph.clear_owner(&value.to_be_bytes()).map_err(failed)?;
                }
            }
        }
        for batch in &evaluation.input("after")?.data.batches {
            for value in batch.column(0).as_primitive::<UInt64Type>().values() {
                let owner = value.to_be_bytes();
                for (relation, count) in [("nodes", 4), ("links", 3)] {
                    let keys = (0..count)
                        .map(|index| [owner.as_slice(), &[index]].concat())
                        .collect::<Vec<_>>();
                    let mut columns: Vec<sdk::arrow_array::ArrayRef> = vec![
                        Arc::new(BinaryArray::from_iter_values((0..count).map(|_| owner))),
                        Arc::new(BinaryArray::from_iter_values(&keys)),
                        Arc::new(UInt8Array::from(vec![0; count as usize])),
                    ];
                    if relation == "links" {
                        columns.extend([
                            Arc::new(BinaryArray::from_iter_values(&keys))
                                as sdk::arrow_array::ArrayRef,
                            Arc::new(BinaryArray::from_iter_values(
                                (1..=count).map(|index| [owner.as_slice(), &[index]].concat()),
                            )),
                            Arc::new(BinaryArray::from_iter_values((0..count).map(|_| b"next"))),
                        ]);
                    }
                    let properties = sdk::RecordBatch::try_new(
                        Arc::new(contract.relation(relation)?.properties.clone()),
                        vec![Arc::new(sdk::arrow_array::UInt64Array::from(
                            vec![*value; count as usize],
                        ))],
                    )?;
                    columns.push(Arc::new(StructArray::from(properties)));
                    input.host()?.stage(&sdk::Dataset {
                        name: relation.into(),
                        batches: vec![sdk::RecordBatch::try_new(
                            Arc::new(contract.command_schema(relation)?),
                            columns,
                        )?],
                    })?;
                }
            }
        }
        let mut data = evaluation.input("after")?.data.clone();
        data.name = "frontier".into();
        Ok(sdk::Output {
            datasets: vec![data],
            ..Default::default()
        })
    }
}
