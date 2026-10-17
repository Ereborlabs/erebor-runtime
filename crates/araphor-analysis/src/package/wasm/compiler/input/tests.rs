use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn request_checks_framing() -> TestResult {
    for fuel in [false, true] {
        let mut bytes = Vec::new();
        CompilerInput::write(fuel, b"component source", &mut bytes).await?;
        let input = CompilerInput::read(bytes.as_slice())?;
        let request = input.request()?;
        assert_eq!(request.fuel, fuel);
        assert_eq!(request.source, b"component source");
        bytes.push(0);
        assert!(CompilerInput::read(bytes.as_slice())?.request().is_err());
    }
    let wrong_version = minicbor::to_vec(CompilerRequest {
        version: 2,
        fuel: false,
        source: &[],
    })?;
    for bytes in [Vec::new(), vec![0], vec![0x83, 1, 0, 0x40], wrong_version] {
        assert!(CompilerInput::read(bytes.as_slice())?.request().is_err());
    }
    Ok(())
}

#[tokio::test]
async fn request_bounds_source() -> TestResult {
    let mut source = vec![0; MAX_SOURCE_BYTES];
    let mut bytes = Vec::new();
    CompilerInput::write(false, &source, &mut bytes).await?;
    let input = CompilerInput::read(bytes.as_slice())?;
    assert_eq!(input.request()?.source.len(), MAX_SOURCE_BYTES);
    source.push(0);
    assert!(CompilerInput::write(false, &source, tokio::io::sink())
        .await
        .is_err());
    let bytes = minicbor::to_vec(CompilerRequest {
        version: 1,
        fuel: false,
        source: &source,
    })?;
    assert!(CompilerInput::read(bytes.as_slice())?.request().is_err());
    assert!(CompilerInput::read(std::io::repeat(0).take((MAX_REQUEST_BYTES + 1) as u64)).is_err());
    Ok(())
}

#[tokio::test]
async fn request_matches_codec() -> TestResult {
    for length in [0, 1, 23, 24, 255, 256, 65535, 65536, MAX_SOURCE_BYTES] {
        let source = vec![0x81; length];
        for fuel in [false, true] {
            let expected = minicbor::to_vec(CompilerRequest {
                version: 1,
                fuel,
                source: &source,
            })?;
            let mut actual = Vec::new();
            CompilerInput::write(fuel, &source, &mut actual).await?;
            assert_eq!(actual, expected);
        }
    }
    let (writer, reader) = tokio::io::duplex(1);
    drop(reader);
    assert!(matches!(
        CompilerInput::write(false, b"source", writer).await,
        Err(crate::Error::PackageWasm {
            code: Code::Incomplete,
            operation: "component compiler request write",
            ..
        })
    ));
    Ok(())
}
