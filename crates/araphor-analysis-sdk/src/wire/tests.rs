use std::sync::Arc;

use crate::arrow_array::UInt64Array;
use crate::{DataType, ErrorCode, Field, RecordBatch, Schema};

use super::Dataset;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod buffers;
mod output;

fn values(name: &str, values: Vec<u64>) -> crate::Result<(Schema, crate::Dataset)> {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: name.into(),
        batches: vec![RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(values))],
        )?],
    };
    Ok((schema, data))
}

#[test]
fn ipc_validates_schema_layout() -> TestResult {
    let stream = |schema: &Schema| -> TestResultWithBytes {
        let mut bytes = Vec::new();
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut bytes, schema)?;
        writer.finish()?;
        drop(writer);
        Ok(bytes)
    };
    for fields in [1024, 1025] {
        let schema = Schema::new(
            (0..fields)
                .map(|index| Field::new(format!("value-{index}"), DataType::UInt64, false))
                .collect::<Vec<_>>(),
        );
        let ipc = stream(&schema)?;
        assert!(Dataset::decoding_bytes(&ipc)? >= ipc.len());
        let data = Dataset::decode_ipc("data", &ipc, None)?;
        assert_eq!(data.batches[0].schema().as_ref(), &schema);
    }
    let schema = Schema::new(vec![Field::new(
        "value",
        DataType::Dictionary(Box::new(DataType::Int64), Box::new(DataType::Utf8)),
        false,
    )]);
    assert_eq!(
        Dataset::decode_ipc("data", &stream(&schema)?, None)
            .err()
            .ok_or("dictionary schema accepted")?
            .code(),
        ErrorCode::Incompatible
    );
    Ok(())
}

type TestResultWithBytes = std::result::Result<Vec<u8>, Box<dyn std::error::Error>>;

#[test]
fn ipc_preserves_schema() -> TestResult {
    let (schema, data) = values("values", vec![1, 2, 3])?;
    let encoded = Dataset::encode(&data, &schema)?;
    let decoded = encoded.decode(&schema)?;
    assert_eq!(decoded.batches, data.batches);
    assert_eq!(encoded.batch_count()?, 1);
    let wrong = Schema::new(vec![Field::new("other", DataType::UInt64, false)]);
    assert!(encoded.decode(&wrong).is_err());
    assert!(Dataset::encode(&data, &wrong).is_err());
    assert_eq!(encoded.decode_any()?.batches, data.batches);
    let truncated = Dataset {
        name: encoded.name,
        arrow_ipc: encoded.arrow_ipc[..8].to_vec(),
    };
    assert!(truncated.decode_any().is_err());
    assert!(truncated.batch_count().is_err());
    Ok(())
}

#[test]
fn ipc_keeps_empty_schema() -> TestResult {
    let schema = Schema::new(vec![Field::new("value", DataType::UInt64, false)]);
    let data = crate::Dataset {
        name: "empty".into(),
        batches: Vec::new(),
    };
    let encoded = Dataset::encode(&data, &schema)?;
    let decoded = encoded.decode(&schema)?;
    assert_eq!(decoded.batches.len(), 1);
    assert_eq!(decoded.batches[0].num_rows(), 0);
    assert_eq!(decoded.batches[0].schema().as_ref(), &schema);
    assert_eq!(encoded.batch_count()?, 0);
    let batch = crate::Dataset {
        name: data.name,
        batches: vec![RecordBatch::new_empty(Arc::new(schema.clone()))],
    };
    let with_batch = Dataset::encode(&batch, &schema)?;
    assert_eq!(with_batch.batch_count()?, 1);
    assert_eq!(with_batch.decode(&schema)?.batches, decoded.batches);
    Ok(())
}

#[test]
fn wire_validates_evidence() -> TestResult {
    let (schema, data) = values("values", vec![1])?;
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
        },
        checkpoint: None,
    };
    let wire = package.check_evaluation(&evaluation)?.encode()?;
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
    let (schema, data) = values("data", vec![1])?;
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
        data.decode_any()
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

#[test]
fn output_budget_includes_checkpoint() -> TestResult {
    let (schema, data) = values("data", vec![7; 4096])?;
    let mut model = crate::Model::new(
        "stateful",
        Vec::new(),
        vec![crate::Port::new("data", schema.clone())],
    );
    model.checkpoint = Some(crate::CheckpointSpec {
        version: 1,
        datasets: vec![crate::Port::new("state", schema)],
    });
    let package = crate::Package::new("fixture", "1", vec![model]);
    let evaluation = crate::Evaluation {
        export: "stateful".into(),
        inputs: Vec::new(),
        parameters: None,
        checkpoint: None,
        context: crate::EvaluationContext {
            id: "bounded-output".into(),
            time_utc_ns: 1,
            seed: None,
        },
    };
    let mut state = data.clone();
    state.name = "state".into();
    let output = crate::Output {
        datasets: vec![data],
        checkpoint: Some(crate::Checkpoint {
            version: 1,
            datasets: vec![state],
        }),
        ..Default::default()
    };
    let encoded = super::Output::encode(&package, &evaluation, &output)?;
    encoded.decode(&package, &evaluation)?;
    let tight = 48 * 1024;
    assert!(encoded.datasets[0].arrow_ipc.len() < tight);
    assert!(
        encoded.checkpoint.as_ref().ok_or("checkpoint")?.datasets[0]
            .arrow_ipc
            .len()
            < tight
    );
    assert_eq!(
        encoded
            .decode_bounded(&package, &evaluation, tight)
            .err()
            .ok_or("combined output exceeded its budget")?
            .code(),
        ErrorCode::Limit
    );
    let decoded = encoded.decode_bounded(&package, &evaluation, 256 * 1024)?;
    assert_eq!(decoded.datasets[0].batches, output.datasets[0].batches);
    assert_eq!(
        decoded.checkpoint.ok_or("decoded checkpoint")?.datasets[0].batches,
        output.checkpoint.ok_or("original checkpoint")?.datasets[0].batches
    );
    Ok(())
}
