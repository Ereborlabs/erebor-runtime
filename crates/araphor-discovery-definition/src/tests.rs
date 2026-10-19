use std::collections::BTreeMap;
use std::path::PathBuf;

use araphor_package::PackageRefV1;
use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};
use serde_json::json;

use crate::{Definition, Error, ImagePin, Program, ResolvedDefinition, Source};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn definition() -> Definition {
    Definition {
        name: "sample".into(),
        description: String::new(),
        labels: BTreeMap::new(),
        program: Program::Sql {
            source: Source::Inline {
                inline: "SELECT 1".into(),
            },
        },
    }
}

fn pin(package: &str) -> ImagePin {
    ImagePin {
        image: PackageRefV1 {
            package_id: package.into(),
            revision: "1".into(),
        },
        digest: format!("sha256:{}", "a".repeat(64)),
    }
}

#[test]
fn definition_forms_are_strict() -> TestResult {
    for program in [
        json!({"kind":"sql","source":{"inline":"SELECT 1"}}),
        json!({"kind":"prql","source":{"inline":"from events"}}),
        json!({"kind":"package","call":{"image":{"package_id":"example","revision":"1"},"export":"detect"}}),
    ] {
        let parsed: Definition =
            serde_json::from_value(json!({"name":"sample","program":program}))?;
        parsed.validate_captured()?;
        assert!(parsed.description.is_empty());
        assert!(parsed.labels.is_empty());
        if let Program::Package { call } = parsed.program {
            assert_eq!(call.parameters, json!({}));
            assert!(call.inputs.is_empty());
            assert_eq!(call.window, None);
            assert_eq!(call.output, None);
        }
    }
    for value in [
        json!({"name":"sample","extra":true,"program":{"kind":"sql","source":{"inline":"SELECT 1"}}}),
        json!({"name":"sample","program":{"kind":"sql","source":{"inline":"SELECT 1"},"call":{}}}),
        json!({"name":"sample","program":{"kind":"sql","source":{"inline":"SELECT 1","file":"query.sql"}}}),
        json!({"name":"sample","program":{"kind":"sql","source":{"inline":"SELECT 1","extra":true}}}),
        json!({"name":"sample","program":{"kind":"sql","source":{}}}),
        json!({"name":"sample","program":{"kind":"package","call":{"image":{"package_id":"example","revision":"1"},"export":"detect","extra":true}}}),
        json!({"name":"sample","program":{"kind":"package","call":{"image":{"package_id":"example","revision":"1","latest":true},"export":"detect"}}}),
        json!({"name":"sample","program":{"kind":"sql","source":{"inline":"SELECT 1"}},"sql":"SELECT 2","images":[]}),
    ] {
        assert!(
            serde_json::from_value::<Definition>(value.clone()).is_err(),
            "{value}"
        );
    }
    Ok(())
}

#[test]
fn source_file_is_captured() -> TestResult {
    let directory = tempfile::tempdir()?;
    let source = directory.path().join("query.sql");
    let path = directory.path().join("definition.json");
    let text = "SELECT source_cursor\nFROM events\n";
    std::fs::write(&source, text)?;
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "name":"sample","description":"retained metadata","labels":{"team":"security"},
            "program":{"kind":"sql","source":{"file":"query.sql"}}
        }))?,
    )?;
    let captured = Definition::read(&path)?;
    assert_eq!(
        captured
            .program
            .source()
            .ok_or("source is absent")?
            .inline()?,
        text
    );
    assert_eq!(captured.description, "retained metadata");
    assert_eq!(
        captured.labels.get("team").map(String::as_str),
        Some("security")
    );
    std::fs::write(&source, "SELECT 2")?;
    assert_eq!(
        captured
            .program
            .source()
            .ok_or("source is absent")?
            .inline()?,
        text
    );
    let updated = Definition::read(&path)?;
    assert_eq!(
        updated
            .program
            .source()
            .ok_or("source is absent")?
            .inline()?,
        "SELECT 2"
    );
    std::fs::remove_file(&source)?;
    captured.validate_captured()?;
    assert_eq!(
        captured
            .program
            .source()
            .ok_or("source is absent")?
            .inline()?,
        text
    );
    assert!(matches!(Definition::read(&path), Err(Error::Io { .. })));

    std::fs::write(&source, "from events")?;
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "name":"sample","program":{"kind":"prql","source":{"file":source}}
        }))?,
    )?;
    let absolute = Definition::read(&path)?;
    assert_eq!(
        absolute
            .program
            .source()
            .ok_or("source is absent")?
            .inline()?,
        "from events"
    );
    Ok(())
}

#[test]
fn source_errors_are_structured() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("definition.json");
    std::fs::write(&path, "{")?;
    let Err(error) = Definition::read(&path) else {
        return Err("invalid JSON must fail".into());
    };
    assert!(matches!(error, Error::Json { .. }));
    assert_eq!(error.status_code(), StatusCode::InvalidArguments);
    assert_eq!(error.retry_hint(), RetryHint::NonRetryable);
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({
            "name":"sample","program":{"kind":"sql","source":{"file":"query.sql"}}
        }))?,
    )?;
    let Err(error) = Definition::read(&path) else {
        return Err("absent source must fail".into());
    };
    assert!(
        matches!(&error, Error::Io { path, .. } if path == &directory.path().join("query.sql"))
    );
    assert_eq!(error.status_code(), StatusCode::External);
    std::fs::write(directory.path().join("query.sql"), [0xff])?;
    assert!(matches!(Definition::read(&path), Err(Error::Io { .. })));
    std::fs::write(directory.path().join("query.sql"), " \n\t")?;
    assert!(matches!(
        Definition::read(&path),
        Err(Error::Invalid {
            field: "source",
            ..
        })
    ));
    Ok(())
}

#[test]
fn definition_values_are_checked() -> TestResult {
    let mut value = definition();
    value.name = " \t".into();
    assert!(value.validate().is_err());
    value = definition();
    value.program = Program::Sql {
        source: Source::Inline {
            inline: "\n".into(),
        },
    };
    assert!(value.validate().is_err());
    value.program = Program::Prql {
        source: Source::File {
            file: PathBuf::new(),
        },
    };
    assert!(value.validate().is_err());
    value.program = Program::Sql {
        source: Source::File {
            file: "query.sql".into(),
        },
    };
    value.validate()?;
    assert!(value.validate_captured().is_err());
    assert!(value
        .program
        .source()
        .ok_or("source is absent")?
        .inline()
        .is_err());
    for change in [
        json!({"image":{"package_id":"","revision":"1"}}),
        json!({"image":{"package_id":"example","revision":""}}),
        json!({"export":" "}),
        json!({"inputs":{"":"SELECT 1"}}),
        json!({"inputs":{"events":" "}}),
        json!({"window":" "}),
        json!({"output":" "}),
    ] {
        let mut call = json!({"image":{"package_id":"example","revision":"1"},"export":"detect"});
        call.as_object_mut()
            .ok_or("call is not an object")?
            .extend(change.as_object().ok_or("change is not an object")?.clone());
        let parsed: Definition = serde_json::from_value(
            json!({"name":"sample","program":{"kind":"package","call":call}}),
        )?;
        assert!(parsed.validate().is_err(), "{change}");
    }
    for parameters in [json!(null), json!([]), json!({"threshold": 2})] {
        let parsed: Definition = serde_json::from_value(json!({
            "name":"sample","program":{"kind":"package","call":{
                "image":{"package_id":"example","revision":"1"},
                "export":"detect","parameters":parameters
            }}
        }))?;
        parsed.validate()?;
        let Program::Package { call } = parsed.program else {
            return Err("package call is absent".into());
        };
        assert_eq!(call.parameters, parameters);
    }
    Ok(())
}

#[test]
fn snapshot_digest_covers_content() -> TestResult {
    let resolved = ResolvedDefinition::new(definition(), "SELECT 1".into(), Vec::new())?;
    assert_eq!(
        resolved.digest()?,
        "sha256:4b191b5382565395b0a38e699e33dc36c28fbee79236c1adf39fb3152565b8cb"
    );
    let original = resolved.digest()?;
    let mut changed = resolved.clone();
    changed.definition.description = "new description".into();
    assert_ne!(changed.digest()?, original);
    changed = resolved.clone();
    changed
        .definition
        .labels
        .insert("team".into(), "security".into());
    assert_ne!(changed.digest()?, original);
    changed = resolved.clone();
    changed.definition.program = Program::Sql {
        source: Source::Inline {
            inline: "SELECT 2".into(),
        },
    };
    assert_ne!(changed.digest()?, original);
    changed = resolved.clone();
    changed.sql = "SELECT 2".into();
    assert_ne!(changed.digest()?, original);
    changed = resolved.clone();
    changed.images.push(pin("example"));
    assert_ne!(changed.digest()?, original);
    let ordered =
        ResolvedDefinition::new(definition(), "SELECT 1".into(), vec![pin("a"), pin("b")])?;
    let reversed =
        ResolvedDefinition::new(definition(), "SELECT 1".into(), vec![pin("b"), pin("a")])?;
    assert_eq!(ordered.digest()?, reversed.digest()?);
    let retained: ResolvedDefinition = serde_json::from_slice(&serde_json::to_vec(&ordered)?)?;
    assert_eq!(retained.digest()?, ordered.digest()?);
    Ok(())
}

#[test]
fn snapshot_requires_captured_sources() -> TestResult {
    let mut file = definition();
    file.program = Program::Sql {
        source: Source::File {
            file: "query.sql".into(),
        },
    };
    assert!(ResolvedDefinition::new(file, "SELECT 1".into(), Vec::new()).is_err());
    assert!(ResolvedDefinition::new(definition(), " ".into(), Vec::new()).is_err());
    assert!(
        ResolvedDefinition::new(definition(), "SELECT 1".into(), vec![pin("a"), pin("a")]).is_err()
    );
    for digest in [
        "sha256:short".into(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha512:{}", "a".repeat(64)),
    ] {
        let mut image = pin("example");
        image.digest = digest;
        assert!(image.validate().is_err());
    }
    let package: Definition = serde_json::from_value(json!({
        "name":"sample","program":{"kind":"package","call":{
            "image":{"package_id":"example","revision":"1"},"export":"detect",
            "inputs":{"events":"SELECT * FROM events"},"parameters":{"threshold":2},
            "window":"received_at > now() - interval '1 minute'","output":"findings"
        }}
    }))?;
    assert!(ResolvedDefinition::new(package.clone(), "SELECT 1".into(), Vec::new()).is_err());
    let resolved = ResolvedDefinition::new(package, "SELECT 1".into(), vec![pin("example")])?;
    resolved.validate()?;
    let original = resolved.digest()?;
    let mut changed = resolved.clone();
    changed.images[0].digest = format!("sha256:{}", "b".repeat(64));
    assert_ne!(changed.digest()?, original);
    let mut value = serde_json::to_value(&resolved)?;
    value["images"][0]["extra"] = json!(true);
    assert!(serde_json::from_value::<ResolvedDefinition>(value).is_err());
    Ok(())
}
