use std::fmt::Write as _;

use araphor_data::PackageResponseV1;
use snafu::ResultExt as _;

use super::*;
use crate::cli::araphor::error::PackageSnafu;

impl Output {
    pub(in crate::cli::araphor) fn package(
        &self,
        mut response: PackageResponseV1,
    ) -> Result<Vec<u8>> {
        let output = response
            .output
            .take()
            .map(|output| output.json_rows())
            .transpose()
            .context(PackageSnafu)?;
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
