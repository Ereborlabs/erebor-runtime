use std::error::Error;

use crate::control_fixture::MtlsFixture;

use super::transfer::GrpcTransfer;

#[tokio::test]
async fn transfer_keeps_complete_file() -> Result<(), Box<dyn Error>> {
    let tls = MtlsFixture::new(false)?;
    let bytes = 6 * 1_024 * 1_024 + 7;
    let (elapsed, rate) = GrpcTransfer::new(None).measure(&tls.files, bytes).await?;
    assert!(!elapsed.is_zero() && rate > 0.0);
    let path = tls.path().join("received.bin");
    GrpcTransfer::new(Some(path.clone()))
        .measure(&tls.files, bytes)
        .await?;
    let contents = std::fs::read(&path)?;
    assert_eq!(contents.len() as u64, bytes);
    assert!(contents.iter().all(|byte| *byte == 0xa5));

    let blocked = tls.path().join("absent/received.bin");
    let result = GrpcTransfer::new(Some(blocked))
        .measure(&tls.files, bytes)
        .await;
    let error = result.err().ok_or("transfer ignored its failed receiver")?;
    assert!(
        error.to_string().contains("create transfer file"),
        "{error}"
    );
    assert!(!path.parent().ok_or("no parent")?.join("absent").exists());
    Ok(())
}
