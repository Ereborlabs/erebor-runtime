#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn linux_process_guard_unit_tests_pass() -> Result<(), Box<dyn std::error::Error>> {
    use std::{env, fs, path::Path, process, process::Command};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = manifest_dir.join("src/os/linux/process_guard.rs");
    let out_dir = env::temp_dir().join(format!(
        "erebor-linux-process-guard-tests-{}",
        process::id()
    ));
    fs::create_dir_all(&out_dir)?;
    let test_binary = out_dir.join("process_guard_tests");

    let compile = Command::new("rustc")
        .arg("--edition=2021")
        .arg("--test")
        .arg(&source)
        .arg("-o")
        .arg(&test_binary)
        .output()?;
    assert!(
        compile.status.success(),
        "failed to compile Linux process guard unit tests\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    let run = Command::new(&test_binary)
        .arg("--test-threads=1")
        .output()?;
    assert!(
        run.status.success(),
        "Linux process guard unit tests failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );

    fs::remove_dir_all(out_dir)?;
    Ok(())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[test]
fn linux_process_guard_unit_tests_are_host_specific() {
    eprintln!("skipping Linux process guard unit tests on non-x86_64 Linux host");
}
