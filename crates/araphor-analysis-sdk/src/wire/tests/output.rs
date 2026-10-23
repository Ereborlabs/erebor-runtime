use super::*;
use crate::wire::Output;

#[test]
fn model_wire_keeps_contract() -> TestResult {
    let (schema, data) = values("values", vec![1, u64::MAX])?;
    let encoded = Dataset::encode(&data, &schema)?;
    assert_eq!(encoded.decode(&schema)?.batches, data.batches);
    let malicious = Dataset {
        name: "values".into(),
        arrow_ipc: vec![255, 255, 255, 255, 255, 255, 255, 127],
    };
    assert!(malicious.decode(&schema).is_err());
    let mut truncated = encoded.clone();
    truncated.arrow_ipc.truncate(truncated.arrow_ipc.len() / 2);
    assert!(truncated.decode(&schema).is_err());
    let mut model = crate::Model::new(
        "policy",
        Vec::new(),
        vec![
            crate::Port::new("values", schema.clone()),
            crate::Port::new("other", schema.clone()),
        ],
    );
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
    let mut packet = Output::encode_model(&output, &model)?;
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
        },
        checkpoint: None,
    };
    assert_eq!(
        packet.decode(&package, &evaluation)?.datasets[1].batches,
        data.batches
    );
    packet.datasets[1].name = "unknown".into();
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
        matches!(Output::encode_model(&output, &absent), Err(crate::Error::Contract {
        code: ErrorCode::Invalid, field, ..
    }) if field == "checkpoint declaration")
    );
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
    )?;
    assert_eq!(reasons.decode_model(&model)?.reasons.len(), 2);
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
