use std::cell::Cell;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::{cast::AsArray as _, types::UInt64Type, UInt64Array};
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
        let package = Self::package();
        let evaluation = input.decode(&package)?;
        let parameters = evaluation
            .parameters
            .as_ref()
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "parameters"))?;
        let mode = parameters.column(0).as_string::<i32>().value(0);
        let amount = parameters.column(1).as_primitive::<UInt64Type>().value(0);
        let value = match mode {
            "echo" => amount,
            "sum-input" => evaluation
                .input("input")?
                .data
                .batches
                .iter()
                .flat_map(|batch| batch.column(0).as_primitive::<UInt64Type>().values())
                .try_fold(0_u64, |sum, value| {
                    sum.checked_add(*value)
                        .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Limit, "input sum"))
                })?,
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
                ))
            }
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
                })
            }
            "invalid-name" => amount,
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
            ..Default::default()
        })
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
        sdk::Package::new("runtime-fixture", "1", vec![model, count])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sdk::arrow_array::StringArray;

    #[test]
    fn sum_keeps_all_input_batches() -> sdk::Result<()> {
        let package = RuntimeFixture::package();
        let model = &package.exports[1];
        let batch = |values| {
            sdk::RecordBatch::try_new(
                Arc::new(model.inputs[0].schema.clone()),
                vec![Arc::new(UInt64Array::from(values))],
            )
        };
        let evaluation = sdk::Evaluation {
            export: model.name.clone(),
            inputs: vec![sdk::Input {
                data: sdk::Dataset {
                    name: "input".into(),
                    batches: vec![
                        batch(vec![2, 3])?,
                        batch(Vec::<u64>::new())?,
                        batch(vec![5])?,
                    ],
                },
                revision: sdk::Revision {
                    owner: "sql".into(),
                    id: "1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            }],
            parameters: Some(sdk::RecordBatch::try_new(
                Arc::new(model.parameters.clone()),
                vec![
                    Arc::new(StringArray::from(vec!["sum-input"])),
                    Arc::new(UInt64Array::from(vec![0])),
                ],
            )?),
            context: sdk::EvaluationContext {
                id: "sum".into(),
                time_utc_ns: 1,
                seed: None,
                limits: model.limits,
            },
            checkpoint: None,
        };
        let input = sdk::wire::Evaluation::encode(&package, &evaluation)?;
        let output = RuntimeFixture::execute(input)?.decode(&package, &evaluation)?;
        assert_eq!(
            output.datasets[0].batches[0]
                .column(0)
                .as_primitive::<UInt64Type>()
                .value(0),
            10
        );
        Ok(())
    }
}
