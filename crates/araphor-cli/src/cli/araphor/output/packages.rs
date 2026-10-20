use std::fmt::Write as _;

use araphor_data::PackageResponseV1;
use snafu::ResultExt as _;

use super::*;
use crate::cli::araphor::error::{PackageSnafu, ProtocolSnafu};

impl Output {
    pub(in crate::cli::araphor) fn package(&self, response: PackageResponseV1) -> Result<Vec<u8>> {
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
        ProtocolSnafu {
            field: "image or definition response",
        }
        .fail()
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
        let image = araphor_analysis::Package::discovery_bundle()?.metadata()?;
        let response = PackageResponseV1 {
            definition: None,
            image: Some(image.clone()),
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
