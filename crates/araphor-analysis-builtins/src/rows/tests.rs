use super::*;

#[derive(Debug, Eq, PartialEq, serde::Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Sample {
    cursor: u64,
    time_ns: i64,
    identity: Vec<u8>,
    missing: Option<u32>,
}

#[test]
fn exact_rows() -> sdk::Result<()> {
    let port = Rows::port::<Sample>("samples", "test.sample.v1");
    let expected = vec![Sample {
        cursor: u64::MAX,
        time_ns: i64::MIN,
        identity: vec![0, 255],
        missing: None,
    }];
    let bounds = sdk::Limits::default();
    let mut data = Rows::encode(&port, &expected, bounds)?;
    data.batches.push(data.batches[0].clone());
    let decoded: Vec<Sample> = Rows::decode(&port, &data, bounds)?;
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0], expected[0]);
    assert_eq!(decoded[1], expected[0]);
    let metadata = port.schema.field(0).metadata();
    assert_eq!(metadata["araphor.type"], "test.sample.v1");
    let schema: serde_json::Value = serde_json::from_str(&metadata["araphor.json_schema"])
        .map_err(|source| sdk::Error::Encoding {
            source,
            location: snafu::location!(),
        })?;
    assert_eq!(schema["properties"]["cursor"]["type"], "integer");
    Ok(())
}

#[test]
fn invalid_rows() -> sdk::Result<()> {
    let port = Rows::port::<Sample>("samples", "test.sample.v1");
    let bounds = sdk::Limits::default();
    for values in [
        vec![None],
        vec![Some(b"{}".as_slice())],
        vec![Some(b"{".as_slice())],
    ] {
        let batch = sdk::RecordBatch::try_new(
            Arc::new(port.schema.clone()),
            vec![Arc::new(BinaryArray::from(values))],
        );
        if let Ok(batch) = batch {
            let data = sdk::Dataset {
                name: port.name.clone(),
                batches: vec![batch],
            };
            assert!(Rows::decode::<Sample>(&port, &data, bounds).is_err());
        }
    }
    let mut data = Rows::encode::<Sample>(&port, &[], bounds)?;
    assert!(Rows::decode::<Sample>(&port, &data, bounds)?.is_empty());
    data.name = "other".into();
    assert!(Rows::decode::<Sample>(&port, &data, bounds).is_err());
    let wrong = sdk::Port::new("samples", sdk::Schema::empty());
    assert!(Rows::encode::<Sample>(&wrong, &[], bounds).is_err());
    Ok(())
}

#[test]
fn declared_row_limits() -> sdk::Result<()> {
    let port = Rows::port::<Sample>("samples", "test.sample.v1");
    let values = [Sample {
        cursor: 1,
        time_ns: 2,
        identity: vec![3],
        missing: None,
    }];
    let normal = sdk::Limits::default();
    let data = Rows::encode(&port, &values, normal)?;
    for bounds in [
        sdk::Limits {
            max_rows: 0,
            ..normal
        },
        sdk::Limits {
            max_bytes: 1,
            ..normal
        },
        sdk::Limits {
            max_batches: 0,
            ..normal
        },
    ] {
        assert!(matches!(
            Rows::encode(&port, &values, bounds),
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Limit,
                ..
            })
        ));
        assert!(matches!(
            Rows::decode::<Sample>(&port, &data, bounds),
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Limit,
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn row_byte_limit() -> std::io::Result<()> {
    let mut remaining = 3;
    let mut buffer = RowBuffer {
        bytes: Vec::new(),
        remaining: &mut remaining,
        limited: false,
    };
    buffer.write_all(b"abc")?;
    assert!(buffer.write_all(b"d").is_err());
    assert_eq!(buffer.bytes, b"abc");
    assert!(buffer.limited);
    Ok(())
}
