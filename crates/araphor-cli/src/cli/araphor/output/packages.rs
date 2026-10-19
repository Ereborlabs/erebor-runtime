use std::fmt::Write as _;

use araphor_data::PackageResponseV1;
use snafu::ResultExt as _;

use super::*;
use crate::cli::araphor::error::{AnalysisSnafu, PackageSnafu};

impl Output {
    pub(in crate::cli::araphor) fn package(
        &self,
        mut response: PackageResponseV1,
    ) -> Result<Vec<u8>> {
        if let Some(definition) = &response.definition {
            let revision = definition
                .digest()
                .map_err(araphor_data::Error::from)
                .context(PackageSnafu)?;
            let document = serde_json::json!({"revision": revision, "snapshot": definition});
            if matches!(self.mode, OutputMode::Jsonl) {
                return Self::json("definition", &document);
            }
            return serde_json::to_vec_pretty(&document).context(EncodeSnafu);
        }
        if let Some(image) = &response.image {
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
                    let metadata = serde_json::to_string(implementation).context(EncodeSnafu)?;
                    let _ = writeln!(text, "implementation\t{}", Self::text(&metadata));
                }
                for fixture in &artifact.fixtures {
                    let _ = writeln!(text, "fixture\t{}", Self::text(fixture));
                }
            }
            return Ok(text.into_bytes());
        }
        let output = response
            .output
            .take()
            .map(|output| {
                araphor_analysis_back::AnalysisPackageOwner::output_rows(&output)
                    .context(AnalysisSnafu)
            })
            .transpose()?;
        if matches!(self.mode, OutputMode::Jsonl) {
            let mut document = serde_json::to_value(&response).context(EncodeSnafu)?;
            if let Some(output) = output {
                document["output"] = output;
            }
            return Self::json("package", &document);
        }
        let mut text = format!(
            "package\t{}\nscope\t{}\nexport\trevision\tactive\treadiness\n",
            Self::text(&response.package_id),
            Self::text(&response.scope_id)
        );
        for export in response.exports {
            let readiness = serde_json::to_string(&export.readiness).context(EncodeSnafu)?;
            let _ = writeln!(
                text,
                "{}\t{}\t{}\t{}",
                Self::text(&export.descriptor.name),
                Self::text(&export.revision),
                export.active,
                Self::text(&readiness)
            );
            for result in export.results {
                let coverage = serde_json::to_string(&result.coverage).context(EncodeSnafu)?;
                let _ = writeln!(
                    text,
                    "result\t{}\ttarget={}\tartifact={}\tstale={}\tcoverage={}",
                    Self::text(&result.result_id),
                    Self::text(&result.target),
                    result
                        .artifact
                        .as_ref()
                        .map_or("", |artifact| artifact.digest.as_str()),
                    result.stale,
                    Self::text(&coverage)
                );
            }
        }
        if let Some(serde_json::Value::Object(datasets)) = output {
            for (name, rows) in datasets {
                let _ = writeln!(text, "dataset\t{}", Self::text(&name));
                if let Some(rows) = rows.as_array() {
                    for row in rows {
                        let value = serde_json::to_string(row).context(EncodeSnafu)?;
                        let _ = writeln!(text, "{}", Self::text(&value));
                    }
                }
            }
        }
        for fixture in response.tests {
            let _ = writeln!(
                text,
                "test\t{}\tpassed={}",
                Self::text(&fixture.fixture),
                fixture.passed
            );
        }
        Ok(text.into_bytes())
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
        let response = PackageResponseV1 {
            definition: Some(definition.clone()),
            image: None,
            scope_id: String::new(),
            package_id: String::new(),
            exports: Vec::new(),
            tests: Vec::new(),
            output: None,
        };
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
        let image = araphor_analysis_back::AnalysisPackageOwner::required_bundles()
            .into_iter()
            .next()
            .ok_or("package fixture absent")?
            .metadata()?;
        let response = PackageResponseV1 {
            definition: None,
            image: Some(image.clone()),
            scope_id: String::new(),
            package_id: image.root.package_id.clone(),
            exports: Vec::new(),
            tests: Vec::new(),
            output: Some(Default::default()),
        };
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
}
