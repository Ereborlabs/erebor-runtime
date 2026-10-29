use super::super::*;
use super::TestResult;

#[test]
fn descriptor_preserves_owners() -> TestResult {
    for id in FindingV1::PACKAGES {
        let package = algorithm::Detector::from_id(id)?.descriptor();
        package.validate()?;
        assert_eq!(package.id, id);
        assert_eq!(package.revision, "1");
        assert_eq!(package.exports.len(), 1);
        let model = &package.exports[0];
        assert!(Graph::supports(model));
        assert_eq!(model.name, "detect");
        let expected: &[&str] = match id {
            "HF-PROC-001" => &[
                "UNEXPECTED_EFFECT",
                "AUDITED_ROLE_DEVIATION",
                "LINEAGE_COVERAGE_GAP",
                "CONTRADICTION",
                "OUTSIDE_AUTHORITY",
                "IN_MEMORY_ONLY",
                "PAYLOAD_UNOBSERVABLE",
            ],
            "HF-DW-001" => &[
                "CREDENTIAL_PIVOT",
                "CONTEXTUAL_CREDENTIAL_PIVOT",
                "MISSING_AUTHORITY_PROOF",
                "CONTRADICTION",
            ],
            "HF-XNODE-001" => &["KUBERNETES_PROOF_MISSING"],
            _ => return Err("unknown host package".into()),
        };
        assert_eq!(
            model
                .reasons
                .iter()
                .map(|reason| reason.code.as_str())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(|reason| format!("{id}.{reason}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            model
                .inputs
                .iter()
                .map(|input| input.port.name.as_str())
                .collect::<Vec<_>>(),
            ["records", "facts", "manifest"]
        );
        assert_eq!(
            model
                .outputs
                .iter()
                .map(|port| port.name.as_str())
                .collect::<Vec<_>>(),
            [
                "subjects",
                "subject_removals",
                "relationships",
                "relationship_removals",
                "findings",
                "finding_removals",
                "progress",
                "progress_removals",
            ]
        );
        assert_eq!(model.outputs[0].kind, sdk::OutputKind::Subjects);
        assert_eq!(model.outputs[2].kind, sdk::OutputKind::Relationships);
        assert_eq!(model.outputs[4].kind, sdk::OutputKind::Findings);
        let subject = &model.outputs[0].schema;
        assert_eq!(subject.fields().len(), 2);
        assert_eq!(subject.field(0).name(), "anchor");
        assert!(matches!(
            subject.field(0).data_type(),
            sdk::DataType::Struct(_)
        ));
        let key = subject.field(1);
        assert_eq!(key.name(), "key");
        assert!(!key.is_nullable());
        let sdk::DataType::Struct(fields) = key.data_type() else {
            return Err("native subject key is not a Struct".into());
        };
        assert_eq!(
            fields
                .iter()
                .map(|field| field.name().as_str())
                .collect::<Vec<_>>(),
            ["tenant_id", "authority", "kind", "identity"]
        );
        assert!(fields.iter().all(|field| !field.is_nullable()));
        assert_eq!(fields[0].data_type(), &sdk::DataType::Binary);
        assert!(matches!(fields[1].data_type(), sdk::DataType::Struct(_)));
        assert_eq!(fields[2].data_type(), &sdk::DataType::Utf8);
        assert_eq!(fields[3].data_type(), &sdk::DataType::Binary);
        let findings = model
            .outputs
            .iter()
            .find(|port| port.name == "findings")
            .ok_or("finding port")?;
        assert!(findings.evidence_required);
        let details = sdk::Schema::new(vec![
            sdk::Field::new("record", sdk::DataType::UInt32, false),
            sdk::Field::new("context", sdk::DataType::UInt32, true),
            sdk::Field::new("reason", sdk::DataType::Utf8, false),
            sdk::Field::new("confirmed", sdk::DataType::Boolean, false),
            sdk::Field::new(
                "evidence",
                sdk::DataType::List(std::sync::Arc::new(sdk::Field::new(
                    "item",
                    sdk::DataType::UInt32,
                    false,
                ))),
                false,
            ),
            sdk::Field::new(
                "limits",
                sdk::DataType::List(std::sync::Arc::new(sdk::Field::new(
                    "item",
                    sdk::DataType::Utf8,
                    false,
                ))),
                false,
            ),
        ]);
        for reason in &model.reasons {
            assert_eq!(reason.details, details);
        }
        assert_eq!(model.checkpoint.as_ref().ok_or("checkpoint")?.version, 1);
        assert_eq!(
            model
                .checkpoint
                .as_ref()
                .ok_or("checkpoint")?
                .datasets
                .len(),
            1
        );
        assert!(
            model
                .checkpoint
                .as_ref()
                .ok_or("checkpoint")?
                .resume_input_changes
        );
        let inspected = package.inspect()?;
        assert!(!inspected.contains("GraphSnapshotV1"));
    }
    let error = algorithm::Detector::from_id("outside-package")
        .err()
        .ok_or("unknown detector accepted")?;
    assert_eq!(error.code(), sdk::ErrorCode::Incompatible);
    Ok(())
}

#[test]
fn support_requires_exact_ports() -> TestResult {
    let package = algorithm::Detector::Process.descriptor();
    let model = &package.exports[0];
    for change in 0..8 {
        let mut altered = model.clone();
        match change {
            0 => altered.inputs.swap(0, 1),
            1 => altered.inputs[0].port.name = "other".into(),
            2 => altered.outputs.reverse(),
            3 => altered.outputs[4].evidence_required = false,
            4 => altered.checkpoint = None,
            5 => altered.checkpoint.as_mut().ok_or("checkpoint")?.version += 1,
            6 => {
                altered.checkpoint.as_mut().ok_or("checkpoint")?.datasets[0].name = "other".into();
            }
            7 => {
                altered.checkpoint.as_mut().ok_or("checkpoint")?.datasets[0].schema =
                    sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::Utf8, false)]);
            }
            _ => return Err("contract mutation".into()),
        }
        assert!(!Graph::supports(&altered), "accepted mutation {change}");
    }
    Ok(())
}

#[test]
fn support_keeps_native_state() -> TestResult {
    let mut package = algorithm::Detector::Process.descriptor();
    let checkpoint = package.exports[0].checkpoint.as_mut().ok_or("checkpoint")?;
    checkpoint.datasets.truncate(1);
    checkpoint.resume_input_changes = false;
    let state = checkpoint.datasets[0].clone();
    package.validate()?;
    assert!(Graph::supports(&package.exports[0]));
    package.exports[0]
        .checkpoint
        .as_mut()
        .ok_or("checkpoint")?
        .datasets
        .push(state);
    assert!(Graph::supports(&package.exports[0]));
    assert!(package.validate().is_err());
    Ok(())
}
