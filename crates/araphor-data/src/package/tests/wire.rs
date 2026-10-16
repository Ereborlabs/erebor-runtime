use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::UInt64Array;

use super::TestResult;
use crate::{AnalysisPackageOwner, PackageErrorCodeV1};

#[test]
fn package_ipc_limits() -> TestResult {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let data = sdk::Dataset {
        name: "values".into(),
        batches: vec![sdk::RecordBatch::try_new(
            Arc::new(schema.clone()),
            vec![Arc::new(UInt64Array::from(vec![1, u64::MAX]))],
        )?],
    };
    let limits = sdk::Limits::default();
    let encoded = sdk::wire::Dataset::encode(&data, &schema, limits)?;
    let decoded = encoded.decode(&schema, limits)?;
    assert_eq!(decoded.batches, data.batches);
    assert!(encoded
        .decode(
            &schema,
            sdk::Limits {
                max_rows: 1,
                ..limits
            }
        )
        .is_err());
    assert!(sdk::wire::Dataset::encode(
        &data,
        &schema,
        sdk::Limits {
            max_bytes: 8,
            ..limits
        }
    )
    .is_err());
    let malicious = sdk::wire::Dataset {
        name: "values".into(),
        arrow_ipc: vec![255, 255, 255, 255, 255, 255, 255, 127],
    };
    assert!(malicious.decode(&schema, limits).is_err());
    let mut truncated = encoded.clone();
    truncated.arrow_ipc.truncate(truncated.arrow_ipc.len() / 2);
    assert!(truncated.decode(&schema, limits).is_err());
    let mut model = sdk::Model::new(
        "policy",
        Vec::new(),
        vec![
            sdk::Port::new("values", schema.clone()),
            sdk::Port::new("other", schema.clone()),
        ],
    );
    model.limits.max_rows = 2;
    model.limits.max_batches = 1;
    model.limits.max_bytes = encoded.arrow_ipc.len() as u64 * 2;
    model.limits.max_checkpoint_bytes = model.limits.max_bytes;
    model.checkpoint = Some(sdk::CheckpointSpec {
        version: 7,
        datasets: model.outputs.clone(),
    });
    let mut other = data.clone();
    other.name = "other".into();
    let output = sdk::Output {
        datasets: vec![data.clone(), other],
        checkpoint: Some(sdk::Checkpoint {
            version: 7,
            datasets: vec![
                data.clone(),
                sdk::Dataset {
                    name: "other".into(),
                    batches: data.batches.clone(),
                },
            ],
        }),
        ..Default::default()
    };
    let mut packet = AnalysisPackageOwner::encode_output(&output, &model)?;
    assert_eq!(
        serde_json::from_slice::<sdk::wire::Output>(&serde_json::to_vec(&packet)?)?,
        packet
    );
    let decoded = AnalysisPackageOwner::decode_output(&packet, &model)?;
    assert_eq!(decoded.datasets[1].batches, data.batches);
    assert_eq!(decoded.checkpoint.ok_or("checkpoint")?.datasets.len(), 2);
    let package = sdk::Package::new("codec", "1", vec![model.clone()]);
    let evaluation = sdk::Evaluation {
        export: model.name.clone(),
        inputs: Vec::new(),
        parameters: None,
        context: sdk::EvaluationContext {
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
        sdk::ErrorCode::Limit
    );
    packet.datasets[1].name = "unknown".into();
    let mut limited = model.clone();
    limited.limits.max_bytes -= 1;
    assert!(
        matches!(AnalysisPackageOwner::decode_output(&packet, &limited), Err(crate::Error::Package {
        code: PackageErrorCodeV1::Limit, field, ..
    }) if field == "encoded datasets")
    );
    packet.datasets[1].name = "other".into();
    packet.checkpoint.as_mut().ok_or("checkpoint")?.version = 8;
    assert!(
        matches!(AnalysisPackageOwner::decode_output(&packet, &model), Err(crate::Error::Package {
        code: PackageErrorCodeV1::Invalid, field, ..
    }) if field == "checkpoint version")
    );
    limited = model.clone();
    limited.limits.max_checkpoint_bytes -= 1;
    assert!(AnalysisPackageOwner::encode_output(&output, &limited).is_err());
    model.reasons.push(sdk::Reason {
        code: "known".into(),
        details: schema.clone(),
    });
    let reason = sdk::ReasonValue {
        output: sdk::RowRef {
            dataset: "values".into(),
            row: 0,
        },
        code: "known".into(),
        details: data.batches[0].slice(0, 1),
    };
    let mut reasons = AnalysisPackageOwner::encode_output(
        &sdk::Output {
            reasons: vec![reason.clone(), reason],
            ..Default::default()
        },
        &model,
    )?;
    model.limits.max_bytes = reasons.reasons[0].details.len() as u64;
    assert_eq!(
        AnalysisPackageOwner::decode_output(&reasons, &model)?
            .reasons
            .len(),
        2
    );
    model.limits.max_bytes = model.limits.max_bytes.max(encoded.arrow_ipc.len() as u64);
    reasons.reasons[0].details = encoded.arrow_ipc;
    assert!(
        matches!(AnalysisPackageOwner::decode_output(&reasons, &model), Err(crate::Error::Package {
        code: PackageErrorCodeV1::Invalid, field, ..
    }) if field == "reason details")
    );
    reasons.reasons[0].code = "unknown".into();
    assert!(
        matches!(AnalysisPackageOwner::decode_output(&reasons, &model), Err(crate::Error::Package {
        code: PackageErrorCodeV1::Invalid, field, ..
    }) if field == "reason code")
    );
    Ok(())
}
