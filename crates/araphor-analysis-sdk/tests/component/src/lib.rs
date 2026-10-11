use std::cell::Cell;
use std::sync::Arc;

use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{cast::AsArray as _, types::UInt64Type, StringArray, UInt64Array};
use sdk::guest::bindings::{araphor::analysis::types, exports::araphor::analysis::analysis::Guest};

thread_local! { static CALLS: Cell<u64> = const { Cell::new(0) }; }

pub struct RuntimeFixture;

impl Guest for RuntimeFixture {
    fn evaluate(
        input: types::Evaluation,
    ) -> std::result::Result<types::Output, types::EvaluationError> {
        Self::execute(input.into())
            .map(Into::into)
            .map_err(|error| sdk::wire::EvaluationError::from(error).into())
    }
}

#[cfg(target_arch = "wasm32")]
sdk::guest::bindings::export!(RuntimeFixture with_types_in sdk::guest::bindings);

impl RuntimeFixture {
    fn execute(input: sdk::wire::Evaluation) -> sdk::Result<sdk::wire::Output> {
        if input.export_name == "echo-inputs" {
            return Self::echo_inputs(input);
        }
        let package = Self::package();
        let evaluation = input.decode(&package)?;
        if evaluation.export == "accumulate" {
            return Self::accumulate(&package, &evaluation);
        }
        let parameters = evaluation
            .parameters
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "parameters"))?;
        let mode = parameters.column(0).as_string::<i32>().value(0);
        let amount = parameters.column(1).as_primitive::<UInt64Type>().value(0);
        let value = match mode {
            "echo" => amount,
            "sum-input" => Self::sum(&evaluation.input("input")?.data)?,
            "clock" => evaluation.context.time_utc_ns as u64,
            "seed" => evaluation.context.seed.unwrap_or_default(),
            "recurse" => Self::recurse(amount),
            "isolation" => CALLS.with(|calls| {
                let value = calls.get() + 1;
                calls.set(value);
                value
            }),
            "denied" => {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Unauthorized,
                    "fixture-denied",
                ));
            }
            "limit" => return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "fixture-limit")),
            "trap" => Self::trap()?,
            "loop" => loop {
                std::hint::black_box(amount);
            },
            "hostcalls" => loop {
                sdk::guest::bindings::araphor::analysis::host::cancelled();
            },
            "cancel" => {
                while !sdk::guest::bindings::araphor::analysis::host::cancelled() {
                    for value in 0..100_000 {
                        std::hint::black_box(value);
                    }
                }
                1
            }
            "memory" => {
                let mut memory = vec![0_u8; amount as usize];
                for value in memory.iter_mut().step_by(4096) {
                    *value = 1;
                }
                std::hint::black_box(&memory);
                memory.len() as u64
            }
            "oversized" => {
                return Ok(sdk::wire::Output {
                    datasets: vec![sdk::wire::Dataset {
                        name: "data".into(),
                        arrow_ipc: vec![0; amount as usize],
                    }],
                    ..Default::default()
                });
            }
            "invalid-name" | "invalid-evidence" => amount,
            _ => return Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "mode")),
        };
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "export"))?;
        let data = sdk::Dataset {
            name: if mode == "invalid-name" {
                "undeclared"
            } else {
                "data"
            }
            .into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(model.outputs[0].schema.clone()),
                vec![Arc::new(UInt64Array::from(vec![value]))],
            )?],
        };
        Ok(sdk::wire::Output {
            datasets: vec![sdk::wire::Dataset::encode(
                &data,
                &model.outputs[0].schema,
                model.limits,
            )?],
            evidence: if mode == "invalid-evidence" {
                vec![sdk::EvidenceLink {
                    output: sdk::RowRef {
                        dataset: "data".into(),
                        row: 1,
                    },
                    input: sdk::RowRef {
                        dataset: "input".into(),
                        row: 1,
                    },
                }]
            } else {
                Vec::new()
            },
            ..Default::default()
        })
    }

    fn echo_inputs(input: sdk::wire::Evaluation) -> sdk::Result<sdk::wire::Output> {
        let limits = input.context.limits;
        let maximum = sdk::Limits::default();
        if limits.max_bytes > maximum.max_bytes
            || limits.max_rows > maximum.max_rows
            || limits.max_batches > maximum.max_batches
            || limits.max_checkpoint_bytes > maximum.max_checkpoint_bytes
        {
            return Err(sdk::Error::contract(sdk::ErrorCode::Limit, "echo limits"));
        }
        let mut ports = Vec::new();
        for source in &input.inputs {
            let typed = (source.data.name == "context")
                .then(|| builtin::Discovery::port::<builtin::ContextSelection>("context"));
            let data = sdk::wire::Dataset::decode_ipc(
                &source.data.name,
                &source.data.arrow_ipc,
                typed.as_ref().map(|port| &port.schema),
                limits,
            )?;
            if let Some(port) = typed {
                let _: Vec<builtin::ContextSelection> = Rows::decode(&port, &data, limits)?;
            }
            let schema = data
                .batches
                .first()
                .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Incomplete, "echo schema"))?
                .schema();
            ports.push(sdk::Port::new(&source.data.name, schema.as_ref().clone()));
        }
        let metadata = Self::metadata_port();
        let mut outputs = ports.clone();
        outputs.push(metadata.clone());
        let package = sdk::Package::new(
            "runtime-fixture",
            "1",
            vec![sdk::Model::new("echo-inputs", ports, outputs)],
        );
        let evaluation = input.decode(&package)?;
        let encode = |value| {
            serde_json::to_string(value)
                .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Failed, "echo metadata"))
        };
        let revisions = evaluation
            .inputs
            .iter()
            .map(|input| encode(&input.revision))
            .collect::<sdk::Result<Vec<_>>>()?;
        let coverage = evaluation
            .inputs
            .iter()
            .map(|input| {
                serde_json::to_string(&input.coverage)
                    .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Failed, "echo metadata"))
            })
            .collect::<sdk::Result<Vec<_>>>()?;
        let mut datasets: Vec<_> = evaluation
            .inputs
            .iter()
            .map(|input| input.data.clone())
            .collect();
        datasets.push(sdk::Dataset {
            name: metadata.name.clone(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(metadata.schema),
                vec![
                    Arc::new(StringArray::from_iter_values(
                        evaluation.inputs.iter().map(|input| &input.data.name),
                    )),
                    Arc::new(StringArray::from(revisions)),
                    Arc::new(StringArray::from(coverage)),
                ],
            )?],
        });
        sdk::wire::Output::encode(
            &package,
            &evaluation,
            &sdk::Output {
                datasets,
                ..Default::default()
            },
        )
    }

    fn metadata_port() -> sdk::Port {
        sdk::Port::new(
            "metadata",
            sdk::Schema::new(vec![
                sdk::Field::new("dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("revision", sdk::DataType::Utf8, false),
                sdk::Field::new("coverage", sdk::DataType::Utf8, false),
            ]),
        )
    }

    fn sum(data: &sdk::Dataset) -> sdk::Result<u64> {
        data.batches
            .iter()
            .flat_map(|batch| batch.column(0).as_primitive::<UInt64Type>().values())
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(*value)
                    .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "input sum"))
            })
    }

    fn accumulate(
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
    ) -> sdk::Result<sdk::wire::Output> {
        let prior = evaluation
            .checkpoint
            .as_ref()
            .map(|checkpoint| Self::sum(&checkpoint.datasets[0]))
            .transpose()?
            .unwrap_or_default();
        let total = prior
            .checked_add(Self::sum(&evaluation.input("input")?.data)?)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "checkpoint sum"))?;
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "export"))?;
        let schema = Arc::new(model.outputs[0].schema.clone());
        let data = |name: &str| -> sdk::Result<sdk::Dataset> {
            Ok(sdk::Dataset {
                name: name.into(),
                batches: vec![sdk::RecordBatch::try_new(
                    schema.clone(),
                    vec![Arc::new(UInt64Array::from(vec![total]))],
                )?],
            })
        };
        sdk::wire::Output::encode(
            package,
            evaluation,
            &sdk::Output {
                datasets: vec![data("data")?],
                checkpoint: Some(sdk::Checkpoint {
                    version: 1,
                    datasets: vec![data("state")?],
                }),
                ..Default::default()
            },
        )
    }

    #[inline(never)]
    fn recurse(amount: u64) -> u64 {
        if amount == 0 {
            return 0;
        }
        std::hint::black_box(Self::recurse(amount - 1)).saturating_add(1)
    }

    fn trap() -> sdk::Result<u64> {
        #[cfg(target_arch = "wasm32")]
        core::arch::wasm32::unreachable();
        #[cfg(not(target_arch = "wasm32"))]
        Err(sdk::Error::contract(sdk::ErrorCode::Failed, "trap"))
    }

    fn package() -> sdk::Package {
        let mut model = sdk::Model::new(
            "evaluate",
            Vec::new(),
            vec![sdk::Port::new(
                "data",
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
            )],
        );
        model.parameters = sdk::Schema::new(vec![
            sdk::Field::new("mode", sdk::DataType::Utf8, false),
            sdk::Field::new("amount", sdk::DataType::UInt64, false),
        ]);
        let mut count = model.clone();
        count.name = "count-input".into();
        count.inputs = vec![sdk::Port::new("input", model.outputs[0].schema.clone())];
        let mut accumulate = count.clone();
        accumulate.name = "accumulate".into();
        accumulate.parameters = sdk::Schema::empty();
        accumulate.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", model.outputs[0].schema.clone())],
        });
        sdk::Package::new("runtime-fixture", "1", vec![model, count, accumulate])
    }
}

#[cfg(test)]
mod tests;
