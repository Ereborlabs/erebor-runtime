use std::{fs, io, path::Path};

#[test]
fn supported_tree_has_no_legacy_framed_ipc_or_guard_launcher() -> Result<(), io::Error> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let forbidden = [
        concat!("Async", "FrameCodec"),
        concat!("Sync", "FrameCodec"),
        concat!("Erebor", "IpcFrame"),
        concat!("Ipc", "ProtocolError"),
        concat!("DAEMON_CONTROL_", "PROTOCOL_", "VERSION"),
        concat!("KIND_", "GUARD_"),
        concat!("KIND_", "DAEMON_"),
        concat!("KIND_", "INTERCEPTION_"),
        concat!("Envelope", "::wrap_message"),
        concat!("erebor-linux-process", "-guard"),
        concat!("envelope", ".proto"),
        concat!("guard", ".proto"),
    ];
    let mut violations = Vec::new();

    for root in ["crates", "examples", ".github", "packaging"] {
        let root = repository.join(root);
        if root.exists() {
            scan(&repository, &root, &forbidden, &mut violations)?;
        }
    }

    assert!(
        violations.is_empty(),
        "legacy IPC references remain:\n{}",
        violations.join("\n")
    );
    Ok(())
}

fn scan(
    repository: &Path,
    path: &Path,
    forbidden: &[&str],
    violations: &mut Vec<String>,
) -> Result<(), io::Error> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            scan(repository, &entry?.path(), forbidden, violations)?;
        }
        return Ok(());
    }
    if path.extension().and_then(|extension| extension.to_str()) == Some("jsonl") {
        return Ok(());
    }

    let Ok(source) = fs::read_to_string(path) else {
        return Ok(());
    };
    let relative = path.strip_prefix(repository).unwrap_or(path);
    for pattern in forbidden {
        if source.contains(pattern) {
            violations.push(format!("{} contains `{pattern}`", relative.display()));
        }
    }
    if relative.starts_with("crates/erebor-runtime-ipc")
        && source.contains(concat!("PROTOCOL_", "VERSION"))
    {
        violations.push(format!(
            "{} contains a transport protocol version",
            relative.display()
        ));
    }
    Ok(())
}
