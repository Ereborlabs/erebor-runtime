use std::fmt::Write as _;

use araphor_data::PackageResponseV1;
use snafu::ResultExt as _;

use super::*;
use crate::cli::araphor::error::PackageSnafu;

impl Output {
    pub(in crate::cli::araphor) fn package(&self, response: PackageResponseV1) -> Result<Vec<u8>> {
        match &response {
            PackageResponseV1::Definition(definition) => {
                let revision = definition
                    .digest()
                    .map_err(araphor_data::Error::from)
                    .context(PackageSnafu)?;
                let document = serde_json::json!({"revision": revision, "snapshot": definition});
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("definition", &document);
                }
                serde_json::to_vec_pretty(&document).context(EncodeSnafu)
            }
            PackageResponseV1::Image(image) => {
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("image", image);
                }
                let mut text = format!(
                    "image\t{}\nrevision\t{}\ndigest\t{}\n",
                    Self::text(&image.root.package_id),
                    Self::text(&image.root.revision),
                    Self::text(&image.digest)
                );
                for artifact in &image.artifacts {
                    let descriptor =
                        serde_json::to_string(&artifact.descriptor).context(EncodeSnafu)?;
                    let _ = writeln!(text, "descriptor\t{}", Self::text(&descriptor));
                    for implementation in &artifact.implementations {
                        let metadata =
                            serde_json::to_string(implementation).context(EncodeSnafu)?;
                        let _ = writeln!(text, "implementation\t{}", Self::text(&metadata));
                    }
                    for fixture in &artifact.fixtures {
                        let _ = writeln!(text, "fixture\t{}", Self::text(fixture));
                    }
                }
                Ok(text.into_bytes())
            }
            PackageResponseV1::Uninstalled(image) => {
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("image_uninstalled", image);
                }
                Ok(format!(
                    "image\t{}\nrevision\t{}\ndigest\t{}\ninstalled\tfalse\n",
                    Self::text(&image.image.package_id),
                    Self::text(&image.image.revision),
                    Self::text(&image.digest),
                )
                .into_bytes())
            }
            PackageResponseV1::Tests(tests) => {
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("image_tests", tests);
                }
                let mut text = String::from("fixture\tpassed\n");
                for test in tests {
                    let _ = writeln!(text, "{}\t{}", Self::text(&test.fixture), test.passed);
                }
                Ok(text.into_bytes())
            }
            PackageResponseV1::Instance(instance) => {
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("instance", instance);
                }
                serde_json::to_vec_pretty(instance).context(EncodeSnafu)
            }
            PackageResponseV1::History(history) => {
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("instance_history", history);
                }
                serde_json::to_vec_pretty(history).context(EncodeSnafu)
            }
            PackageResponseV1::Output(output) => {
                let document = serde_json::json!({
                    (&output.name): Self::dataset_rows(&output.name, &output.arrow_ipc)?
                });
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("instance_result", &document);
                }
                serde_json::to_vec_pretty(&document).context(EncodeSnafu)
            }
            PackageResponseV1::Result(result) => {
                let reasons = result
                    .output
                    .reasons
                    .iter()
                    .map(|reason| {
                        Ok(serde_json::json!({
                            "output": &reason.output,
                            "code": &reason.code,
                            "details": Self::dataset_rows(&reason.code, &reason.details)?
                        }))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let checkpoint = result
                    .output
                    .checkpoint
                    .as_ref()
                    .map(|state| -> Result<_> {
                        Ok(serde_json::json!({
                            "version": state.version,
                            "datasets": Self::output_rows(&state.datasets)?
                        }))
                    })
                    .transpose()?;
                let document = serde_json::json!({
                    "instance_id": &result.instance_id,
                    "result_id": &result.result_id,
                    "image": &result.image,
                    "package": &result.package,
                    "export": &result.export,
                    "context": &result.context,
                    "commit_revision": result.commit_revision,
                    "current": result.current,
                    "output": {
                        "datasets": Self::output_rows(&result.output.datasets)?,
                        "evidence": &result.output.evidence,
                        "reasons": reasons,
                        "checkpoint": checkpoint
                    }
                });
                if matches!(self.mode, OutputMode::Jsonl) {
                    return Self::json("instance_output", &document);
                }
                serde_json::to_vec_pretty(&document).context(EncodeSnafu)
            }
        }
    }

    fn output_rows(data: &[araphor_analysis_sdk::wire::Dataset]) -> Result<serde_json::Value> {
        let rows = data
            .iter()
            .map(|data| {
                Ok((
                    data.name.clone(),
                    Self::dataset_rows(&data.name, &data.arrow_ipc)?,
                ))
            })
            .collect::<Result<serde_json::Map<String, serde_json::Value>>>()?;
        Ok(serde_json::Value::Object(rows))
    }

    fn dataset_rows(name: &str, ipc: &[u8]) -> Result<serde_json::Value> {
        let data = araphor_analysis_sdk::wire::Dataset::decode_ipc(name, ipc, None)
            .context(araphor_data::AnalysisContractSnafu)
            .context(PackageSnafu)?;
        let mut writer = arrow_json::ArrayWriter::new(Vec::new());
        for batch in &data.batches {
            writer
                .write(batch)
                .map_err(araphor_analysis_sdk::Error::from)
                .context(araphor_data::AnalysisContractSnafu)
                .context(PackageSnafu)?;
        }
        writer
            .finish()
            .map_err(araphor_analysis_sdk::Error::from)
            .context(araphor_data::AnalysisContractSnafu)
            .context(PackageSnafu)?;
        serde_json::from_slice(&writer.into_inner()).context(EncodeSnafu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definition_output_revision() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_discovery_definition::{Definition, ResolvedDefinition};
        let definition: Definition = serde_json::from_value(serde_json::json!({
            "name":"counts", "labels":{"team":"security"},
            "program":{"kind":"sql", "source":{"inline":"SELECT 1"}}
        }))?;
        let definition = ResolvedDefinition::new(definition, "SELECT 1".into(), Vec::new())?;
        let response = PackageResponseV1::Definition(definition.clone());
        for mode in [OutputMode::Jsonl, OutputMode::Table] {
            let bytes = Output::new(Some(mode), false).package(response.clone())?;
            let document: serde_json::Value = serde_json::from_slice(&bytes)?;
            let frame = document.get("frame").unwrap_or(&document);
            assert_eq!(frame["revision"], definition.digest()?);
            assert_eq!(frame["snapshot"], serde_json::to_value(&definition)?);
        }
        Ok(())
    }

    #[tokio::test]
    async fn image_output_metadata() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let image = araphor_analysis::Package::discovery_bundle()?.metadata()?;
        let response = PackageResponseV1::Image(image.clone());
        let bytes = Output::new(Some(OutputMode::Jsonl), false).package(response.clone())?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(document["kind"], "image");
        assert_eq!(document["frame"], serde_json::to_value(&image)?);
        let bytes = Output::new(Some(OutputMode::Table), false).package(response)?;
        let text = String::from_utf8(bytes)?;
        assert!(text.contains(&format!("image\t{}\n", image.root.package_id)));
        assert!(text.contains(&format!("revision\t{}\n", image.root.revision)));
        assert!(text.contains(&format!("digest\t{}\n", image.digest)));
        assert!(text.contains("descriptor\t"));
        assert!(text.contains("implementation\t"));
        assert!(!text.contains("\nactive\t"));
        Ok(())
    }
    #[test]
    fn instance_output_keeps_fields() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let status = araphor_data::InstanceStatusV1 {
            id: "counts".into(),
            definition_revision: "sha256:exact".into(),
            generation: 10,
            lifecycle: 14,
            running: false,
            removed: false,
            progress: 12,
            readiness: araphor_data::PackageReadinessV1::Failed {
                code: araphor_data::PackageErrorCodeV1::Invalid,
                field: "model evaluation".into(),
            },
            status_progress: 12,
        };
        let response = PackageResponseV1::Instance(status.clone());
        for mode in [OutputMode::Jsonl, OutputMode::Table] {
            let bytes = Output::new(Some(mode), false).package(response.clone())?;
            let document: serde_json::Value = serde_json::from_slice(&bytes)?;
            let frame = document.get("frame").unwrap_or(&document);
            assert_eq!(frame, &serde_json::to_value(&status)?);
            assert!(frame.get("grant").is_none());
        }
        Ok(())
    }

    #[test]
    fn retained_output_keeps_rows() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_analysis_sdk as sdk;
        let schema = sdk::Schema::new(vec![
            sdk::Field::new("value", sdk::DataType::UInt64, false),
            sdk::Field::new("text", sdk::DataType::Utf8, true),
        ]);
        let row = serde_json::json!({"value":u64::MAX,"text":"quoted \"value\"\n\u{03bb}"});
        let batch = araphor_data::decode_parameters(&schema, Some(&row))?.ok_or("row batch")?;
        for batches in [
            vec![batch.clone(), batch],
            vec![sdk::RecordBatch::new_empty(std::sync::Arc::new(
                schema.clone(),
            ))],
        ] {
            let empty = batches[0].num_rows() == 0;
            let data = sdk::Dataset {
                name: "query".into(),
                batches,
            };
            let response = PackageResponseV1::try_from(&data)?;
            for mode in [OutputMode::Jsonl, OutputMode::Table] {
                let bytes = Output::new(Some(mode), false).package(response.clone())?;
                let document: serde_json::Value = serde_json::from_slice(&bytes)?;
                let frame = document.get("frame").unwrap_or(&document);
                assert_eq!(
                    frame,
                    &serde_json::json!({"query":if empty { Vec::new() } else { vec![row.clone(),row.clone()] }})
                );
            }
        }
        let mut response = PackageResponseV1::try_from(&sdk::Dataset {
            name: "query".into(),
            batches: vec![sdk::RecordBatch::new_empty(std::sync::Arc::new(schema))],
        })?;
        let PackageResponseV1::Output(output) = &mut response else {
            return Err("wire output variant".into());
        };
        output.arrow_ipc.truncate(3);
        assert!(Output::new(Some(OutputMode::Jsonl), false)
            .package(response)
            .is_err());
        Ok(())
    }
    #[test]
    fn raw_output_keeps_auxiliaries() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_analysis_sdk as sdk;
        let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
        let details = sdk::Schema::new(vec![sdk::Field::new("detail", sdk::DataType::Utf8, false)]);
        let mut model = sdk::Model::new(
            "read",
            vec![sdk::Port::new("source", schema.clone())],
            vec![
                sdk::Port::new("rows", schema.clone()),
                sdk::Port::new("other", schema.clone()),
            ],
        );
        model.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: false,
            version: 7,
            datasets: vec![sdk::Port::new("state", schema.clone())],
        });
        model.reasons.push(sdk::Reason {
            code: "fixture.reason".into(),
            details: details.clone(),
        });
        let mut datasets = Vec::new();
        for (name, value) in [("rows", 1), ("other", 2)] {
            let batch = araphor_data::decode_parameters(
                &schema,
                Some(&serde_json::json!({"value":value})),
            )?
            .ok_or("output batch")?;
            datasets.push(sdk::Dataset {
                name: name.into(),
                batches: vec![batch],
            });
        }
        let text = "quoted \"reason\"\n\u{03bb}";
        let detail =
            araphor_data::decode_parameters(&details, Some(&serde_json::json!({"detail":text})))?
                .ok_or("details batch")?;
        let evaluation = sdk::Evaluation {
            previous_outputs: Vec::new(),
            export: "read".into(),
            inputs: vec![sdk::Input {
                data: sdk::Dataset {
                    name: "source".into(),
                    batches: datasets[0].batches.clone(),
                },
                revision: sdk::Revision {
                    owner: "fixture".into(),
                    id: "source-1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Complete,
                    limits: Vec::new(),
                },
            }],
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "first".into(),
                time_utc_ns: 10,
                seed: Some(7),
            },
        };
        let output = sdk::Output {
            datasets: datasets.clone(),
            evidence: ["rows", "other"]
                .into_iter()
                .map(|name| sdk::EvidenceLink {
                    output: sdk::RowRef {
                        dataset: name.into(),
                        row: 0,
                    },
                    input: sdk::RowRef {
                        dataset: "source".into(),
                        row: 0,
                    },
                })
                .collect(),
            reasons: ["rows", "other"]
                .into_iter()
                .map(|name| sdk::ReasonValue {
                    output: sdk::RowRef {
                        dataset: name.into(),
                        row: 0,
                    },
                    code: "fixture.reason".into(),
                    details: detail.clone(),
                })
                .collect(),
            checkpoint: Some(sdk::Checkpoint {
                version: 7,
                datasets: vec![sdk::Dataset {
                    name: "state".into(),
                    batches: datasets[0].batches.clone(),
                }],
            }),
        };
        let package = sdk::Package::new("fixture", "r1", vec![model.clone()]);
        let packet = sdk::wire::Output::encode(&package, &evaluation, &output)?;
        let mut context = araphor_data::ResultContext::new("first", 10, &evaluation.inputs);
        context.context = evaluation.context.clone();
        let image = araphor_data::PackageRefV1 {
            package_id: "fixture".into(),
            revision: "r1".into(),
        };
        let result = araphor_data::InstanceResultV1 {
            instance_id: "counts".into(),
            result_id: "exact-result".into(),
            image: araphor_discovery_definition::ImagePin {
                image: image.clone(),
                digest: format!("sha256:{}", "0".repeat(64)),
            },
            package: image,
            export: "read".into(),
            context,
            commit_revision: 17,
            current: false,
            output: packet,
        };
        for mode in [OutputMode::Jsonl, OutputMode::Table] {
            let response = PackageResponseV1::Result(Box::new(result.clone()));
            let bytes = Output::new(Some(mode), false).package(response)?;
            let document: serde_json::Value = serde_json::from_slice(&bytes)?;
            let frame = document.get("frame").unwrap_or(&document);
            assert_eq!(frame["instance_id"], "counts");
            assert_eq!(frame["result_id"], "exact-result");
            assert_eq!(frame["image"], serde_json::to_value(&result.image)?);
            assert_eq!(frame["package"], serde_json::to_value(&result.package)?);
            assert_eq!(frame["export"], "read");
            assert_eq!(frame["commit_revision"], 17);
            assert_eq!(frame["current"], false);
            assert_eq!(frame["context"], serde_json::to_value(&result.context)?);
            assert_eq!(
                frame["output"]["datasets"],
                serde_json::json!({"rows":[{"value":1}],"other":[{"value":2}]})
            );
            assert_eq!(
                frame["output"]["evidence"],
                serde_json::to_value(&output.evidence)?
            );
            assert_eq!(
                frame["output"]["checkpoint"],
                serde_json::json!({"version":7,"datasets":{"state":[{"value":1}]}})
            );
            let reasons = frame["output"]["reasons"].as_array().ok_or("reason rows")?;
            assert_eq!(reasons.len(), 2);
            for (reason, expected) in reasons.iter().zip(&output.reasons) {
                assert_eq!(reason["output"], serde_json::to_value(&expected.output)?);
                assert_eq!(reason["code"], "fixture.reason");
                assert_eq!(reason["details"], serde_json::json!([{"detail":text}]));
            }
        }
        for role in ["reason", "checkpoint"] {
            let mut invalid = result.clone();
            if role == "reason" {
                invalid.output.reasons[0].details.truncate(3);
            } else {
                invalid
                    .output
                    .checkpoint
                    .as_mut()
                    .ok_or("checkpoint")?
                    .datasets[0]
                    .arrow_ipc
                    .truncate(3);
            }
            assert!(Output::new(Some(OutputMode::Jsonl), false)
                .package(PackageResponseV1::Result(Box::new(invalid)))
                .is_err());
        }
        Ok(())
    }
    #[test]
    fn history_output_keeps_receipts() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let reference = araphor_data::analysis::PackageResultRefV1 {
            result_id: "exact-result".into(),
            commit_revision: 17,
        };
        let receipt = araphor_data::ManagedReceipt {
            frontier: Some(araphor_data::ManagedFrontier {
                pending: false,
                cursor: vec![1, 2, 255],
                next_change: Some(99),
            }),
            instance: "counts".into(),
            attempt: "original".into(),
            commit_revision: 17,
            selected: reference.clone(),
            results: std::collections::BTreeMap::from([(10, reference)]),
        };
        for history in [Vec::new(), vec![receipt]] {
            for mode in [OutputMode::Jsonl, OutputMode::Table] {
                let bytes = Output::new(Some(mode), false)
                    .package(PackageResponseV1::History(history.clone()))?;
                let document: serde_json::Value = serde_json::from_slice(&bytes)?;
                assert_eq!(
                    document.get("frame").unwrap_or(&document),
                    &serde_json::to_value(&history)?
                );
            }
        }
        Ok(())
    }

    #[test]
    fn fixture_output_keeps_results() -> std::result::Result<(), Box<dyn std::error::Error>> {
        for tests in [
            Vec::new(),
            vec![
                araphor_data::FixtureResult {
                    fixture: "equal".into(),
                    passed: true,
                },
                araphor_data::FixtureResult {
                    fixture: "different".into(),
                    passed: false,
                },
            ],
        ] {
            let json = Output::new(Some(OutputMode::Jsonl), false)
                .package(PackageResponseV1::Tests(tests.clone()))?;
            let document: serde_json::Value = serde_json::from_slice(&json)?;
            assert_eq!(
                document.get("frame").unwrap_or(&document),
                &serde_json::to_value(&tests)?
            );
            let table = Output::new(Some(OutputMode::Table), false)
                .package(PackageResponseV1::Tests(tests.clone()))?;
            let expected = if tests.is_empty() {
                "fixture\tpassed\n"
            } else {
                "fixture\tpassed\nequal\ttrue\ndifferent\tfalse\n"
            };
            assert_eq!(String::from_utf8(table)?, expected);
        }
        Ok(())
    }
    #[test]
    fn uninstall_output_is_exact() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let image = araphor_discovery_definition::ImagePin {
            image: araphor_data::PackageRefV1 {
                package_id: "example".into(),
                revision: "1".into(),
            },
            digest: format!("sha256:{}", "1".repeat(64)),
        };
        let response = PackageResponseV1::Uninstalled(image.clone());
        let bytes = Output::new(Some(OutputMode::Jsonl), false).package(response.clone())?;
        let document: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(document["kind"], "image_uninstalled");
        assert_eq!(document["frame"], serde_json::to_value(&image)?);
        let bytes = Output::new(Some(OutputMode::Table), false).package(response)?;
        assert_eq!(
            String::from_utf8(bytes)?,
            format!(
                "image\texample\nrevision\t1\ndigest\t{}\ninstalled\tfalse\n",
                image.digest
            )
        );
        Ok(())
    }
}
