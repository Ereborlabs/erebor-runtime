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

#[cfg(not(target_arch = "wasm32"))]
impl sdk::Guest for RuntimeFixture {
    fn package() -> sdk::Package {
        Self::package()
    }

    fn compute(input: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        let evaluation = input.evaluation();
        Self::native_fault()?;
        Self::execute(input.encode()?)?.decode(input.package(), evaluation)
    }
}

#[cfg(not(target_arch = "wasm32"))]
sdk::export_native!(RuntimeFixture);

impl RuntimeFixture {
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::panic)]
    fn native_fault() -> sdk::Result<()> {
        let Some(mode) = std::env::var_os("ARAPHOR_NATIVE_FIXTURE_FAULT") else {
            return Ok(());
        };
        let marker = std::env::var_os("ARAPHOR_NATIVE_FIXTURE_MARKER")
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "fault marker"))?;
        let marker = std::path::PathBuf::from(marker);
        if marker.exists() {
            return Ok(());
        }
        let mode = mode
            .to_str()
            .filter(|mode| matches!(*mode, "panic" | "abort"))
            .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "fault mode"))?;
        std::fs::write(marker, mode)
            .map_err(|_| sdk::Error::contract(sdk::ErrorCode::Failed, "fault marker"))?;
        match mode {
            "panic" => panic!("native fixture panic"),
            "abort" => std::process::abort(),
            _ => Err(sdk::Error::contract(sdk::ErrorCode::Invalid, "fault mode")),
        }
    }

    fn execute(input: sdk::wire::Evaluation) -> sdk::Result<sdk::wire::Output> {
        if input.export_name == "echo-inputs" {
            return Self::echo_inputs(input);
        }
        let package = Self::package();
        let evaluation = input.decode(&package)?;
        if matches!(
            evaluation.export.as_str(),
            "accumulate" | "continue-input" | "changes"
        ) {
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
                Self::cancelled();
            },
            mode if mode == "cancel"
                || cfg!(all(unix, not(target_arch = "wasm32"))) && mode.starts_with("cancel:") =>
            {
                #[cfg(all(unix, not(target_arch = "wasm32")))]
                let mut peer = mode
                    .strip_prefix("cancel:")
                    .map(|path| {
                        use std::io::{Read as _, Write as _};
                        let failure = |_| {
                            sdk::Error::contract(sdk::ErrorCode::Failed, "fixture cancellation IPC")
                        };
                        let mut peer =
                            std::os::unix::net::UnixStream::connect(path).map_err(failure)?;
                        peer.write_all(b"E").map_err(failure)?;
                        let size = u32::try_from(evaluation.context.id.len()).map_err(|_| {
                            sdk::Error::contract(
                                sdk::ErrorCode::Invalid,
                                "fixture cancellation identity",
                            )
                        })?;
                        peer.write_all(&size.to_le_bytes()).map_err(failure)?;
                        peer.write_all(evaluation.context.id.as_bytes())
                            .map_err(failure)?;
                        let mut release = [0];
                        peer.read_exact(&mut release).map_err(failure)?;
                        if release != *b"R" {
                            return Err(sdk::Error::contract(
                                sdk::ErrorCode::Invalid,
                                "fixture cancellation release",
                            ));
                        }
                        Ok(peer)
                    })
                    .transpose()?;
                while !Self::cancelled() {
                    for value in 0..100_000 {
                        std::hint::black_box(value);
                    }
                }
                #[cfg(all(unix, not(target_arch = "wasm32")))]
                if let Some(peer) = &mut peer {
                    use std::io::Write as _;
                    peer.write_all(b"D").map_err(|_| {
                        sdk::Error::contract(
                            sdk::ErrorCode::Failed,
                            "fixture cancellation completion",
                        )
                    })?;
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
            datasets: vec![sdk::wire::Dataset::encode(&data, &model.outputs[0].schema)?],
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
        let mut ports = Vec::new();
        for source in &input.inputs {
            let typed = (source.data.name == "context")
                .then(|| builtin::Discovery::port::<builtin::ContextSelection>("context"));
            let data = sdk::wire::Dataset::decode_ipc(
                &source.data.name,
                &source.data.arrow_ipc,
                typed.as_ref().map(|port| &port.schema),
            )?;
            if let Some(port) = typed {
                let _: Vec<builtin::ContextSelection> = Rows::decode(&port, &data)?;
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

    fn cancelled() -> bool {
        #[cfg(target_arch = "wasm32")]
        {
            sdk::guest::bindings::araphor::analysis::host::cancelled()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            sdk::native::cancelled()
        }
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
        let prior = if matches!(evaluation.export.as_str(), "continue-input" | "changes")
            && evaluation.checkpoint.is_some()
        {
            let previous = evaluation.previous_outputs.first().ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Incomplete, "previous output")
            })?;
            let previous = Self::sum(previous)?;
            if previous != prior {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "previous output state",
                ));
            }
            previous
        } else {
            prior
        };
        let total = if evaluation.export == "changes" {
            let added = evaluation.input("input")?.data.rows();
            let removed = evaluation.input("removed")?.data.rows();
            prior
                .checked_add(added)
                .and_then(|total| total.checked_sub(removed))
        } else {
            prior.checked_add(Self::sum(&evaluation.input("input")?.data)?)
        }
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
        count.inputs = vec![sdk::Port::new("input", model.outputs[0].schema.clone()).into()];
        let mut accumulate = count.clone();
        accumulate.name = "accumulate".into();
        accumulate.parameters = sdk::Schema::empty();
        accumulate.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: false,
            version: 1,
            datasets: vec![sdk::Port::new("state", model.outputs[0].schema.clone())],
        });
        let mut continuation = accumulate.clone();
        continuation.name = "continue-input".into();
        continuation.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: true,
            version: 1,
            datasets: vec![sdk::Port::new("state", model.outputs[0].schema.clone())],
        });
        let mut changes = continuation.clone();
        changes.name = "changes".into();
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, true)]);
        changes.inputs = vec![
            sdk::Port::new("input", schema.clone()).into(),
            sdk::Port::new("removed", schema).into(),
            sdk::ChangeInputs::reset_port("reset").into(),
        ];
        changes.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                before: "removed".into(),
                after: "input".into(),
            }],
        });
        sdk::Package::new(
            "runtime-fixture",
            "1",
            vec![model, count, accumulate, continuation, changes],
        )
    }
}

#[cfg(test)]
mod tests;
