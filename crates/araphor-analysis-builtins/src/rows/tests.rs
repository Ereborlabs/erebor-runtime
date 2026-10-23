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
    let mut data = Rows::encode(&port, &expected)?;
    data.batches.push(data.batches[0].clone());
    let decoded: Vec<Sample> = Rows::decode(&port, &data)?;
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
            assert!(Rows::decode::<Sample>(&port, &data).is_err());
        }
    }
    let mut data = Rows::encode::<Sample>(&port, &[])?;
    assert!(Rows::decode::<Sample>(&port, &data)?.is_empty());
    data.name = "other".into();
    assert!(Rows::decode::<Sample>(&port, &data).is_err());
    let wrong = sdk::Port::new("samples", sdk::Schema::empty());
    assert!(Rows::encode::<Sample>(&wrong, &[]).is_err());
    Ok(())
}

#[test]
fn rows_preserve_payload() -> sdk::Result<()> {
    let port = Rows::port::<String>("strings", "test.string.v1");
    let values = vec!["\\\"".repeat(8193); 3];
    let data = Rows::encode(&port, &values)?;
    assert_eq!(Rows::decode::<String>(&port, &data)?, values);
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
    assert!(matches!(
        Rows::encode(&port, &values),
        Err(sdk::Error::Encoding { .. })
    ));
    let expected = ["complete".to_owned()];
    let data = Rows::encode(&port, &expected)?;
    assert_eq!(Rows::decode::<String>(&port, &data)?, expected);
    Ok(())
}

#[test]
fn row_byte_limit() -> std::io::Result<()> {
    let mut builder = BinaryBuilder::new();
    for (bytes, expected, remaining, limited) in [
        (b"".as_slice(), b"".as_slice(), 5, false),
        (b"abc".as_slice(), b"abc".as_slice(), 2, false),
        (b"".as_slice(), b"abc".as_slice(), 2, false),
        (b"def".as_slice(), b"abc".as_slice(), 2, true),
    ] {
        let available = 5 - builder.values_slice().len();
        let mut buffer = sdk::wire::BoundedBuffer::from_writer(&mut builder, available as u64);
        let result = buffer.write_all(bytes);
        let builder = buffer.finish();
        assert_eq!(builder.values_slice(), expected);
        assert_eq!(5 - builder.values_slice().len(), remaining);
        if limited {
            assert_eq!(
                result.err().map(|source| source.kind()),
                Some(std::io::ErrorKind::FileTooLarge)
            );
        } else {
            result?;
        }
    }
    builder.append_value(b"");
    let rows = builder.finish();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows.value(0), b"abc");
    Ok(())
}
