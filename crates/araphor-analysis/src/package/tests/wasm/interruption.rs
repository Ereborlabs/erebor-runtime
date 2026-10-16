use std::time::Duration;

use super::*;
use crate::AnalysisReadControl;

#[tokio::test]
async fn wasm_running_stop_releases_capacity() -> TestResult {
    for cause in ["cancel", "revoke"] {
        let fixture = Fixture::new()?;
        let package = component("1");
        fixture.owner.admit_artifact(
            &package.artifacts[0],
            &AnalysisReadControl::with_timeout(Duration::from_secs(60))?,
        )?;
        super::super::interruption::running_guest(fixture, package, cause).await?;
    }
    Ok(())
}
