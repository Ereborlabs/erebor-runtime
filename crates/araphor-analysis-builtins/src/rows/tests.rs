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
        for result in [
            Rows::encode(&port, &values, bounds).map(|_| ()),
            Rows::decode::<Sample>(&port, &data, bounds).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(sdk::Error::Contract {
                    code: sdk::ErrorCode::Limit,
                    ..
                })
            ));
        }
    }
    Ok(())
}

#[test]
fn rows_fit_payload_bound() -> sdk::Result<()> {
    let port = Rows::port::<String>("strings", "test.string.v1");
    let values = vec!["\\\"".repeat(8193); 3];
    let bounds = sdk::Limits {
        max_bytes: 128 * 1024,
        ..sdk::Limits::default()
    };
    let data = Rows::encode(&port, &values, bounds)?;
    assert_eq!(Rows::decode::<String>(&port, &data, bounds)?, values);
    assert!(data.batches[0].get_array_memory_size() as u64 <= bounds.max_bytes);
    let rows = data.batches[0]
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or_else(|| sdk::Error::contract(sdk::ErrorCode::Invalid, "row type"))?;
    for (index, value) in values.iter().enumerate() {
        let expected = serde_json::to_vec(value).map_err(|source| sdk::Error::Encoding {
            source,
            location: snafu::location!(),
        })?;
        assert_eq!(rows.value(index), expected);
    }
    let small = sdk::Limits {
        max_bytes: 1024,
        ..bounds
    };
    for result in [
        Rows::encode(&port, &values, small).map(|_| ()),
        Rows::decode::<String>(&port, &data, small).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(sdk::Error::Contract {
                code: sdk::ErrorCode::Limit,
                ..
            })
        ));
    }
    Ok(())
}

struct FailedString<'a>(&'a str);

impl Serialize for FailedString<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)?;
        Err(serde::ser::Error::custom("test serialization failure"))
    }
}

#[test]
fn row_error_precedence() -> sdk::Result<()> {
    let port = Rows::port::<String>("strings", "test.string.v1");
    let value = "\\".repeat(20);
    let values = [FailedString(&value)];
    let normal = sdk::Limits::default();
    assert!(matches!(
        Rows::encode(&port, &values, normal),
        Err(sdk::Error::Encoding { .. })
    ));
    let small = sdk::Limits {
        max_bytes: 32,
        ..normal
    };
    assert!(matches!(
        Rows::encode(&port, &values, small),
        Err(sdk::Error::Contract {
            code: sdk::ErrorCode::Limit,
            ..
        })
    ));
    let expected = ["complete".to_owned()];
    let data = Rows::encode(&port, &expected, normal)?;
    assert_eq!(Rows::decode::<String>(&port, &data, normal)?, expected);
    Ok(())
}

#[test]
fn row_byte_limit() -> std::io::Result<()> {
    let mut remaining = 5;
    let mut builder = BinaryBuilder::new();
    let mut buffer = RowBuffer {
        builder: &mut builder,
        remaining: &mut remaining,
        limited: false,
    };
    buffer.write_all(b"")?;
    assert!(buffer.builder.values_slice().is_empty());
    assert_eq!(*buffer.remaining, 5);
    assert!(!buffer.limited);
    buffer.write_all(b"abc")?;
    assert_eq!(buffer.builder.values_slice(), b"abc");
    assert_eq!(*buffer.remaining, 2);
    assert!(!buffer.limited);
    buffer.write_all(b"")?;
    assert_eq!(*buffer.remaining, 2);
    assert!(buffer.write_all(b"def").is_err());
    assert_eq!(buffer.builder.values_slice(), b"abc");
    assert_eq!(*buffer.remaining, 2);
    assert!(buffer.limited);
    buffer.builder.append_value(b"");
    let rows = buffer.builder.finish();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.value(0), b"abc");
    Ok(())
}
