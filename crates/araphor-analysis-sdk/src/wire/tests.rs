use std::sync::Arc;

use crate::arrow_array::UInt64Array;
use crate::{DataType, ErrorCode, Field, Limits, RecordBatch, Schema};

use super::Dataset;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod buffers;

#[test]
fn ipc_preflights_schema_allocation() -> TestResult {
    let stream = |schema: &Schema| -> TestResultWithBytes {
        let mut bytes = Vec::new();
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut bytes, schema)?;
        writer.finish()?;
        drop(writer);
        Ok(bytes)
    };
    let schema = Schema::new(
        (0..1024)
            .map(|index| Field::new(format!("value-{index}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    let ipc = stream(&schema)?;
    let tight = Limits {
        max_bytes: ipc.len() as u64,
        ..Limits::default()
    };
    assert_eq!(
        Dataset::decode_ipc("data", &ipc, None, tight)
            .err()
            .ok_or("schema storage accepted")?
            .code(),
        ErrorCode::Limit
    );
    assert!(Dataset::decode_ipc("data", &ipc, None, Limits::default()).is_ok());
    let schema = Schema::new(
        (0..1025)
            .map(|index| Field::new(format!("value-{index}"), DataType::UInt64, false))
            .collect::<Vec<_>>(),
    );
    assert_eq!(
        Dataset::decode_ipc("data", &stream(&schema)?, None, Limits::default())
            .err()
            .ok_or("schema fields accepted")?
            .code(),
        ErrorCode::Limit
    );
    let schema = Schema::new(vec![Field::new(
        "value",
        DataType::Dictionary(Box::new(DataType::Int64), Box::new(DataType::Utf8)),
        false,
    )]);
    assert_eq!(
        Dataset::decode_ipc("data", &stream(&schema)?, None, Limits::default())
            .err()
            .ok_or("dictionary schema accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    Ok(())
}

type TestResultWithBytes = std::result::Result<Vec<u8>, Box<dyn std::error::Error>>;

#[test]
fn ipc_round_trip_and_bounds() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: "values".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![1, 2, 3]))],
        )?],
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let decoded = encoded.decode(&schema, Limits::default())?;
    assert_eq!(decoded.batches, data.batches);
    assert_eq!(
        encoded
            .decode(
                &schema,
                Limits {
                    max_rows: 2,
                    ..Limits::default()
                }
            )
            .err()
            .ok_or("row bound")?
            .code(),
        ErrorCode::Limit
    );
    assert_eq!(
        encoded
            .decode(
                &schema,
                Limits {
                    max_bytes: 1,
                    ..Limits::default()
                }
            )
            .err()
            .ok_or("byte bound")?
            .code(),
        ErrorCode::Limit
    );
    assert_eq!(
        Dataset::encode(
            &data,
            &schema,
            Limits {
                max_bytes: 1,
                ..Limits::default()
            }
        )
        .err()
        .ok_or("encode byte bound")?
        .code(),
        ErrorCode::Limit
    );
    let wrong = Schema::new(vec![Field::new("other", DataType::UInt64, false)]);
    assert!(encoded.decode(&wrong, Limits::default()).is_err());
    let truncated = Dataset {
        name: encoded.name,
        arrow_ipc: encoded.arrow_ipc[..8].to_vec(),
    };
    assert!(truncated.decode_any(Limits::default()).is_err());
    Ok(())
}

#[test]
fn ipc_keeps_empty_schema() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: "empty".into(),
        batches: Vec::new(),
    };
    let encoded = Dataset::encode(&data, &schema, Limits::default())?;
    let decoded = encoded.decode(&schema, Limits::default())?;
    assert_eq!(decoded.batches.len(), 1);
    assert_eq!(decoded.batches[0].num_rows(), 0);
    assert_eq!(decoded.batches[0].schema().as_ref(), &schema);
    Ok(())
}

#[test]
fn wire_validates_evidence() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: "values".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![1]))],
        )?],
    };
    let mut port = crate::Port::new("values", schema);
    port.evidence_required = true;
    let package = crate::Package::new(
        "test",
        "1",
        vec![crate::Model::new("run", Vec::new(), vec![port])],
    );
    let evaluation = crate::Evaluation {
        export: "run".into(),
        inputs: Vec::new(),
        parameters: None,
        context: crate::EvaluationContext {
            id: "test.1".into(),
            time_utc_ns: 17,
            seed: Some(3),
            limits: Limits::default(),
        },
        checkpoint: None,
    };
    let wire = super::Evaluation::encode(&package, &evaluation)?;
    let decoded = wire.decode(&package)?;
    assert_eq!(decoded.context, evaluation.context);
    let output = crate::Output {
        datasets: vec![data],
        ..Default::default()
    };
    assert_eq!(
        super::Output::encode(&package, &evaluation, &output)
            .err()
            .ok_or("missing evidence accepted")?
            .code(),
        ErrorCode::Incomplete
    );
    Ok(())
}

#[test]
fn allocation_counts_schema_metadata() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: "data".into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![1]))],
        )?],
    };
    let mut output = crate::Output {
        datasets: vec![data],
        ..Default::default()
    };
    let initial = output.allocated_bytes();
    output.datasets[0].batches[0] = RecordBatch::try_new(
        Arc::new(schema.with_metadata(std::collections::HashMap::from([(
            "description".into(),
            "x".repeat(2048),
        )]))),
        output.datasets[0].batches[0].columns().to_vec(),
    )?;
    assert!(output.allocated_bytes() >= initial + 2048);
    Ok(())
}

#[test]
fn allocation_counts_input_state() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let batch = RecordBatch::try_new(Arc::new(schema), vec![Arc::new(UInt64Array::from(vec![1]))])?;
    let mut evaluation = crate::Evaluation {
        export: "run".into(),
        inputs: Vec::new(),
        parameters: None,
        context: crate::EvaluationContext {
            id: "memory".into(),
            time_utc_ns: 1,
            seed: None,
            limits: Limits::default(),
        },
        checkpoint: None,
    };
    let initial = evaluation.allocated_bytes();
    evaluation.inputs.push(crate::Input {
        data: crate::Dataset {
            name: "data".into(),
            batches: vec![batch.clone()],
        },
        revision: crate::Revision {
            owner: "owner".into(),
            id: "1".into(),
            window: Some(crate::SourceWindow {
                source: vec![1; 1024],
                start_utc_ns: 0,
                end_utc_ns: 1,
            }),
        },
        coverage: crate::Coverage {
            state: crate::CoverageState::Gapped,
            limits: vec!["x".repeat(2048)],
        },
    });
    let input = evaluation.allocated_bytes();
    assert!(input >= initial + 3072 + batch.get_array_memory_size());
    evaluation.parameters = Some(batch.clone());
    assert!(evaluation.allocated_bytes() > input);
    let parameters = evaluation.allocated_bytes();
    evaluation.checkpoint = Some(crate::Checkpoint {
        version: 1,
        datasets: vec![crate::Dataset {
            name: "state".into(),
            batches: vec![batch],
        }],
    });
    assert!(evaluation.allocated_bytes() > parameters);
    Ok(())
}

#[test]
fn wire_rejects_compressed_batch() -> TestResult {
    let mut builder = flatbuffers::FlatBufferBuilder::new();
    let compression = arrow_ipc::BodyCompression::create(
        &mut builder,
        &arrow_ipc::BodyCompressionArgs::default(),
    );
    let batch = arrow_ipc::RecordBatch::create(
        &mut builder,
        &arrow_ipc::RecordBatchArgs {
            length: 1,
            compression: Some(compression),
            ..Default::default()
        },
    );
    let message = arrow_ipc::Message::create(
        &mut builder,
        &arrow_ipc::MessageArgs {
            header_type: arrow_ipc::MessageHeader::RecordBatch,
            header: Some(batch.as_union_value()),
            ..Default::default()
        },
    );
    builder.finish(message, None);
    let metadata = builder.finished_data();
    let mut bytes = (metadata.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(metadata);
    let data = Dataset {
        name: "compressed".into(),
        arrow_ipc: bytes,
    };
    assert_eq!(
        data.decode_any(Limits::default())
            .err()
            .ok_or("compressed stream accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    Ok(())
}

#[cfg(feature = "guest")]
#[test]
fn generated_types_preserve_context() -> TestResult {
    let context = crate::EvaluationContext {
        id: "recorded".into(),
        time_utc_ns: 123,
        seed: Some(42),
        limits: Limits::default(),
    };
    let wire = super::Evaluation {
        export_name: "run".into(),
        inputs: Vec::new(),
        parameters: None,
        context: context.clone(),
        checkpoint: None,
    };
    let generated: crate::guest::bindings::araphor::analysis::types::Evaluation = wire.into();
    let decoded: super::Evaluation = generated.into();
    assert_eq!(decoded.context, context);
    assert_eq!(decoded.export_name, "run");
    Ok(())
}
