use std::path::PathBuf;

use erebor_runtime_error::{ErrorExt, RetryHint, StatusCode};
use snafu::Location;

use super::FilesystemError;

#[test]
fn filesystem_errors_have_status_and_retry_hints() {
    let invalid = FilesystemError::InvalidVolumeId {
        id: String::from("bad/id"),
        reason: String::from("must be a safe path component"),
        location: Location::default(),
    };
    assert_eq!(invalid.status_code(), StatusCode::InvalidArguments);
    assert_eq!(invalid.retry_hint(), RetryHint::NonRetryable);

    let io_error = FilesystemError::CreateStorageDir {
        path: PathBuf::from("/tmp/erebor"),
        source: std::io::Error::from(std::io::ErrorKind::TimedOut),
        location: Location::default(),
    };
    assert_eq!(io_error.status_code(), StatusCode::External);
    assert_eq!(io_error.retry_hint(), RetryHint::Retryable);
}
