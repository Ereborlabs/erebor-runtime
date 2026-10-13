use std::ffi::OsStr;

use super::*;

#[test]
fn workspace_command_isolated() {
    let root = Path::new("/workspace");
    let target = Path::new("/guest-target");
    let command = ComponentBuilder::workspace_command(root, target);
    assert_eq!(command.get_current_dir(), Some(root));
    let arguments = command.get_args().collect::<Vec<_>>();
    let expected = [
        "build",
        "--locked",
        "--lib",
        "--release",
        "--target",
        "wasm32-unknown-unknown",
        "--jobs",
        "1",
        "--target-dir",
        "/guest-target",
        "--package",
        "araphor-discovery-component",
        "--package",
        "araphor-process-component",
        "--package",
        "araphor-credentials-component",
        "--package",
        "araphor-kubernetes-component",
        "--package",
        "araphor-detector-example",
        "--package",
        "araphor-component-fixture",
    ]
    .map(OsStr::new);
    assert_eq!(arguments, expected);
    let environment = command.get_envs().collect::<Vec<_>>();
    for key in [
        "CARGO_MAKEFLAGS",
        "MAKEFLAGS",
        "MFLAGS",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_BUILD_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "CLIPPY_ARGS",
    ] {
        assert!(environment.contains(&(OsStr::new(key), None)));
    }
    assert!(environment.contains(&(OsStr::new("CARGO_INCREMENTAL"), Some(OsStr::new("0")))));
    assert!(environment.contains(&(
        OsStr::new("CONST_RANDOM_SEED"),
        Some(OsStr::new("araphor-analysis-v1"))
    )));
    assert_eq!(
        ComponentBuilder::workspace_path(root, Path::new("guest-target")),
        Path::new("/workspace/guest-target")
    );
    assert_eq!(ComponentBuilder::workspace_path(root, target), target);
}

#[test]
fn workspace_inputs_complete() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let inputs = ComponentBuilder::inputs(&root);
    assert!(inputs.len() >= 22);
    assert!(inputs.iter().all(|path| path.exists()));
    assert!(inputs.contains(&root.join("Cargo.toml")));
    assert!(inputs.contains(&root.join("Cargo.lock")));
    for directory in [
        "crates/araphor-analysis-builtins/components/discovery",
        "crates/araphor-analysis-builtins/components/process",
        "crates/araphor-analysis-builtins/components/credentials",
        "crates/araphor-analysis-builtins/components/kubernetes",
        "crates/araphor-detector-example",
        "crates/araphor-analysis-sdk/tests/component",
    ] {
        assert!(inputs.contains(&root.join(directory).join("Cargo.toml")));
        assert!(inputs.contains(&root.join(directory).join("src")));
        let build = root.join(directory).join("build.rs");
        if build.is_file() {
            assert!(inputs.contains(&build));
        }
    }
    let wit = root.join("crates/araphor-analysis-sdk/src/bindings/analysis.wit");
    assert!(wit.exists());
    assert!(inputs.iter().any(|path| wit.starts_with(path)));
    assert!(inputs
        .iter()
        .all(|path| path.extension() != Some(OsStr::new("wasm"))));
}

#[test]
fn native_command_uses_host() {
    let command = ComponentBuilder::target_command(
        Path::new("/workspace"),
        Path::new("/native"),
        "x86_64-unknown-linux-gnu",
    );
    let args = command.get_args().collect::<Vec<_>>();
    assert!(args.windows(2).any(|pair| pair
        == [
            OsStr::new("--target"),
            OsStr::new("x86_64-unknown-linux-gnu")
        ]));
    assert!(args.contains(&OsStr::new("--locked")));
    assert!(args.contains(&OsStr::new("--release")));
    assert!(!args.contains(&OsStr::new(TARGET)));
}
