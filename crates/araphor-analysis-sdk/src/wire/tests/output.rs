use super::*;
use crate::wire::Output;

#[test]
fn model_wire_keeps_bounds() -> TestResult {
    let (schema, data) = values("values", vec![1, u64::MAX])?;
    let limits = Limits::default();
    let encoded = Dataset::encode(&data, &schema, limits)?;
    assert_eq!(encoded.decode(&schema, limits)?.batches, data.batches);
    assert!(encoded
        .decode(
            &schema,
            Limits {
                max_rows: 1,
                ..limits
            }
        )
        .is_err());
    assert!(Dataset::encode(
        &data,
        &schema,
        Limits {
            max_bytes: 8,
            ..limits
        }
    )
    .is_err());
    let malicious = Dataset {
        name: "values".into(),
        arrow_ipc: vec![255, 255, 255, 255, 255, 255, 255, 127],
    };
    assert!(malicious.decode(&schema, limits).is_err());
    let mut truncated = encoded.clone();
    truncated.arrow_ipc.truncate(truncated.arrow_ipc.len() / 2);
    assert!(truncated.decode(&schema, limits).is_err());
    let bytes = encoded.arrow_ipc.len() as u64 * 2;
    let mut model = crate::Model::new(
        "policy",
        Vec::new(),
        vec![
            crate::Port::new("values", schema.clone()),
            crate::Port::new("other", schema.clone()),
        ],
    );
    model.limits = Limits {
        max_rows: 2,
        max_batches: 1,
        max_bytes: bytes,
        max_checkpoint_bytes: bytes,
    };
    model.checkpoint = Some(crate::CheckpointSpec {
        version: 7,
        datasets: model.outputs.clone(),
    });
    let mut other = data.clone();
    other.name = "other".into();
    let output = crate::Output {
        datasets: vec![data.clone(), other],
        checkpoint: Some(crate::Checkpoint {
            version: 7,
            datasets: vec![
                data.clone(),
                crate::Dataset {
                    name: "other".into(),
                    batches: data.batches.clone(),
                },
            ],
        }),
        ..Default::default()
    };
    let mut packet = Output::encode_model(&output, &model, model.limits)?;
    assert_eq!(
        serde_json::from_slice::<Output>(&serde_json::to_vec(&packet)?)?,
        packet
    );
    let decoded = packet.decode_model(&model)?;
    assert_eq!(decoded.datasets[1].batches, data.batches);
    assert_eq!(decoded.checkpoint.ok_or("checkpoint")?.datasets.len(), 2);
    let package = crate::Package::new("codec", "1", vec![model.clone()]);
    let evaluation = crate::Evaluation {
        export: model.name.clone(),
        inputs: Vec::new(),
        parameters: None,
        context: crate::EvaluationContext {
            id: "codec.bounds".into(),
            time_utc_ns: 0,
            seed: None,
            limits: model.limits,
        },
        checkpoint: None,
    };
    assert_eq!(
        packet
            .decode(&package, &evaluation)
            .err()
            .ok_or("aggregate limits")?
            .code(),
        ErrorCode::Limit
    );
    packet.datasets[1].name = "unknown".into();
    let mut limited = model.clone();
    limited.limits.max_bytes -= 1;
    assert!(
        matches!(packet.decode_model(&limited), Err(crate::Error::Contract {
        code: ErrorCode::Limit, field, ..
    }) if field == "encoded datasets")
    );
    assert!(
        matches!(packet.decode_model(&model), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "dataset name")
    );
    packet.datasets[1].name = "other".into();
    packet.checkpoint.as_mut().ok_or("checkpoint")?.version = 8;
    assert!(
        matches!(packet.decode_model(&model), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "checkpoint version")
    );
    let checkpoint = packet.checkpoint.as_ref().ok_or("checkpoint")?;
    assert!(
        matches!(checkpoint.decode_model(&model), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "checkpoint version")
    );
    let mut absent = model.clone();
    absent.checkpoint = None;
    assert!(
        matches!(checkpoint.decode_model(&absent), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "checkpoint declaration")
    );
    assert!(
        matches!(Output::encode_model(&output, &absent, absent.limits), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "checkpoint declaration")
    );
    limited = model.clone();
    limited.limits.max_checkpoint_bytes -= 1;
    assert!(Output::encode_model(&output, &limited, limited.limits).is_err());
    model.reasons.push(crate::Reason {
        code: "known".into(),
        details: schema.clone(),
    });
    let reason = crate::ReasonValue {
        output: crate::RowRef {
            dataset: "values".into(),
            row: 0,
        },
        code: "known".into(),
        details: data.batches[0].slice(0, 1),
    };
    let mut reasons = Output::encode_model(
        &crate::Output {
            reasons: vec![reason.clone(), reason],
            ..Default::default()
        },
        &model,
        model.limits,
    )?;
    model.limits.max_bytes = reasons.reasons[0].details.len() as u64;
    assert_eq!(reasons.decode_model(&model)?.reasons.len(), 2);
    model.limits.max_bytes = model.limits.max_bytes.max(encoded.arrow_ipc.len() as u64);
    reasons.reasons[0].details = encoded.arrow_ipc;
    assert!(
        matches!(reasons.decode_model(&model), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "reason details")
    );
    reasons.reasons[0].code = "unknown".into();
    assert!(
        matches!(reasons.decode_model(&model), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "reason code")
    );
    Ok(())
}
