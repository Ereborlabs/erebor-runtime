#[path = "support/codex_linux_v1.rs"]
mod codex_linux_v1;

use std::path::Path;

use codex_linux_v1::{CodexLinuxV1ProfileProbe, CodexLinuxV1RequirementsArtifact, V1_HOOK_EVENTS};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn requirements_artifact_has_the_complete_v1_event_family() -> TestResult<()> {
    let root = tempfile::tempdir()?;
    let artifact = CodexLinuxV1RequirementsArtifact::create(
        root.path(),
        Path::new(env!("CARGO_BIN_EXE_codex-linux-v1-test-hook")),
    )?;

    artifact.assert_complete()?;
    assert_eq!(V1_HOOK_EVENTS.len(), 8);
    assert_eq!(artifact.requirements_sha256().len(), 64);
    assert_eq!(artifact.hook_sha256().len(), 64);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn profile_and_ordering() -> TestResult<()> {
    CodexLinuxV1ProfileProbe::run_if_required(Path::new(env!(
        "CARGO_BIN_EXE_codex-linux-v1-test-hook"
    )))
}

#[cfg(not(target_os = "linux"))]
#[test]
fn profile_and_ordering() {
    eprintln!("skipping Codex Linux V1 lifecycle probe on a non-Linux host");
}
