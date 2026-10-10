use std::collections::HashMap;
use std::io::Write as _;
use std::process::{Command, Stdio};

use super::*;
use crate::{CoverageState, DataType, ErrorCode, Field, Model, Port, Schema};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn package() -> Package {
    let schema = Schema::new(vec![Field::new("count", DataType::UInt64, false)]);
    Package::new(
        "contract.fixture",
        "revision.1",
        vec![Model::new(
            "files.count",
            Vec::new(),
            vec![Port::new("counts", schema)],
        )],
    )
}

#[test]
fn declarations_share_descriptor() -> TestResult {
    let mut package = package();
    let metadata = HashMap::from([
        (
            "description".into(),
            "Metadata with */ and a newline\n#include <unknown>".into(),
        ),
        ("unit".into(), "count".into()),
    ]);
    package.exports[0].outputs[0].schema = package.exports[0].outputs[0]
        .schema
        .clone()
        .with_metadata(metadata);
    let declarations = package.interfaces()?;
    let expected = serde_json::to_value(&package)?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&declarations.descriptor_json)?,
        expected
    );
    for source in [&declarations.wit, &declarations.native_header] {
        let descriptor = source
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("// descriptor-json: "))
            .ok_or("descriptor comment is absent")?;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(descriptor)?,
            expected
        );
    }
    let decoded = serde_json::from_str::<Package>(&declarations.descriptor_json)?;
    assert_eq!(decoded.interfaces()?, declarations);
    let mut invalid = package;
    invalid.contract_version += 1;
    assert!(invalid.interfaces().is_err());
    Ok(())
}

#[test]
fn descriptor_size_is_bounded() -> TestResult {
    let mut package = package();
    let metadata = HashMap::from([("description".into(), String::new())]);
    package.exports[0].outputs[0].schema = package.exports[0].outputs[0]
        .schema
        .clone()
        .with_metadata(metadata);
    let limit = crate::descriptor::MAX_DESCRIPTOR_BYTES;
    let overhead = serde_json::to_string_pretty(&package)?.len();
    package.exports[0].outputs[0]
        .schema
        .metadata
        .insert("description".into(), "a".repeat(limit - overhead));
    package.validate()?;
    assert_eq!(package.inspect()?.len(), limit);
    let directory = tempfile::tempdir()?;
    package.build(directory.path())?;
    assert_eq!(
        std::fs::metadata(directory.path().join("descriptor.json"))?.len(),
        limit as u64
    );
    package.exports[0].outputs[0]
        .schema
        .metadata
        .get_mut("description")
        .ok_or("description is absent")?
        .push('a');
    let rejected = directory.path().join("rejected");
    for result in [
        package.validate(),
        package.inspect().map(|_| ()),
        package.build(&rejected),
    ] {
        assert_eq!(
            result.err().ok_or("limit error is absent")?.code(),
            ErrorCode::Limit
        );
    }
    assert!(!rejected.exists());
    Ok(())
}

#[test]
fn wit_declaration_parses() -> TestResult {
    let declarations = package().interfaces()?;
    let mut resolve = wit_parser::Resolve::default();
    let package = resolve.push_str("analysis.wit", &declarations.wit)?;
    let world = resolve.packages[package]
        .worlds
        .get("analysis-package")
        .ok_or("analysis world is absent")?;
    let mut imports = Vec::new();
    for item in resolve.worlds[*world].imports.values() {
        let wit_parser::WorldItem::Interface { id, .. } = item else {
            return Err("unexpected world import".into());
        };
        let interface = &resolve.interfaces[*id];
        match interface.name.as_deref() {
            Some("types") => assert!(interface.functions.is_empty()),
            Some("host") => imports.extend(interface.functions.keys().map(String::as_str)),
            _ => return Err("unexpected interface import".into()),
        }
    }
    assert_eq!(imports, ["cancelled"]);
    let exports: Vec<_> = resolve.worlds[*world].exports.values().collect();
    let [wit_parser::WorldItem::Interface { id, .. }] = exports.as_slice() else {
        return Err("unexpected world export".into());
    };
    let interface = &resolve.interfaces[*id];
    assert_eq!(interface.name.as_deref(), Some("analysis"));
    assert_eq!(
        interface
            .functions
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["evaluate"]
    );
    Ok(())
}

#[test]
fn native_declaration_compiles() -> TestResult {
    let declarations = package().interfaces()?;
    let mut compiler = Command::new("cc")
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-x",
            "c",
            "-fsyntax-only",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = compiler.stdin.take().ok_or("compiler input is absent")?;
    stdin.write_all(declarations.native_header.as_bytes())?;
    writeln!(
        stdin,
        "_Static_assert(ARAPHOR_ANALYSIS_CONTRACT_VERSION == {}, \"version mismatch\");",
        crate::CONTRACT_VERSION
    )?;
    for (name, code) in [
        ("INVALID", ErrorCode::Invalid as u32),
        ("INCOMPATIBLE", ErrorCode::Incompatible as u32),
        ("UNAUTHORIZED", ErrorCode::Unauthorized as u32),
        ("INCOMPLETE", ErrorCode::Incomplete as u32),
        ("FAILED", ErrorCode::Failed as u32),
        ("LIMIT", ErrorCode::Limit as u32),
        ("COMPLETE", CoverageState::Complete as u32),
        ("GAPPED", CoverageState::Gapped as u32),
        ("UNKNOWN", CoverageState::Unknown as u32),
    ] {
        writeln!(
            stdin,
            "_Static_assert(ARAPHOR_ANALYSIS_{name} == {code}, \"code mismatch\");"
        )?;
    }
    stdin.write_all(
        br#"
static uint32_t evaluate(const araphor_analysis_request_v1 *request,
                         araphor_analysis_response_v1 *response) {
    response->error.code = request->context.limits.max_rows
        ? ARAPHOR_ANALYSIS_OK : ARAPHOR_ANALYSIS_LIMIT;
    return response->error.code;
}
static void release(araphor_analysis_response_v1 *response) {
    response->private_data = 0;
}
int main(void) {
    araphor_analysis_api_v1 api = {
        ARAPHOR_ANALYSIS_CONTRACT_VERSION, sizeof(araphor_analysis_api_v1),
        evaluate, release
    };
    araphor_analysis_request_v1 request = {0};
    araphor_analysis_response_v1 response = {0};
    uint32_t code = api.evaluate(&request, &response);
    api.release(&response);
    return code == ARAPHOR_ANALYSIS_LIMIT ? 0 : 1;
}
"#,
    )?;
    drop(stdin);
    let result = compiler.wait_with_output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}
