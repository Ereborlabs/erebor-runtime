use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn request_checks_framing() -> TestResult {
    for fuel in [false, true] {
        let mut bytes = Vec::new();
        CompilerInput::write(fuel, b"component source", &mut bytes)?;
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

#[test]
fn request_bounds_source() -> TestResult {
    let mut source = vec![0; MAX_SOURCE_BYTES];
    let mut bytes = Vec::new();
    CompilerInput::write(false, &source, &mut bytes)?;
    let input = CompilerInput::read(bytes.as_slice())?;
    assert_eq!(input.request()?.source.len(), MAX_SOURCE_BYTES);
    source.push(0);
    assert!(CompilerInput::write(false, &source, std::io::sink()).is_err());
    let bytes = minicbor::to_vec(CompilerRequest {
        version: 1,
        fuel: false,
        source: &source,
    })?;
    assert!(CompilerInput::read(bytes.as_slice())?.request().is_err());
    assert!(CompilerInput::read(std::io::repeat(0).take((MAX_REQUEST_BYTES + 1) as u64)).is_err());
    Ok(())
}
