use erebor_runtime_e2e::E2eError;

use crate::support::{allow_all_policy, create_governed_session_with_mini_upstream};

#[tokio::test]
async fn browser_session_manager_creates_governed_session_with_public_endpoint(
) -> Result<(), E2eError> {
    let session = create_governed_session_with_mini_upstream(allow_all_policy()?).await?;

    assert!(!session.owns_browser());
    assert!(session.public_endpoint().starts_with("ws://127.0.0.1:"));
    assert!(!session.public_endpoint().contains('?'));
    assert_eq!(
        session.metadata().public_endpoint,
        session.public_endpoint()
    );
    assert_eq!(session.metadata().session_id.as_str(), "e2e-cdp-session");
    Ok(())
}
