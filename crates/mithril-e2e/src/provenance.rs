use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{CommandSnafu, InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::{ArchitectureClosure, DigestV1, Result};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionDossierV1 {
    schema_version: u32,
    dossier_id: String,
    snapshots: Vec<SourceSnapshotV1>,
    records: Vec<AdoptionRecordV1>,
    explicit_rejections: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceSnapshotV1 {
    project: String,
    directory: String,
    repository: String,
    commit: String,
    license_path: String,
    license_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionRecordV1 {
    adoption_id: String,
    project: String,
    classification: String,
    source: String,
    source_sha256: String,
    license_decision: String,
    transitive_dependencies: Vec<String>,
    local_owner: String,
    semantic_differences: String,
    hostile_fixture_id: String,
}

pub struct ProvenanceVerifier {
    repo_root: PathBuf,
    spec_root: PathBuf,
}

impl ProvenanceVerifier {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        let repo_root = repo_root.into();
        Self {
            spec_root: repo_root.join("spec"),
            repo_root,
        }
    }

    pub fn load_and_verify(&self) -> Result<AdoptionDossierV1> {
        let path = self.spec_root.join("provenance/v1/upstream-adoption.json");
        let bytes = fs::read(&path).context(IoSnafu { path: path.clone() })?;
        let dossier: AdoptionDossierV1 =
            serde_json::from_slice(&bytes).context(JsonSnafu { path: path.clone() })?;
        self.verify_schema(&path, &dossier)?;
        Ok(dossier)
    }

    pub fn verify_checked_sources(&self) -> Result<AdoptionDossierV1> {
        let dossier = self.load_and_verify()?;
        for snapshot in &dossier.snapshots {
            self.verify_snapshot(snapshot)?;
        }
        for record in dossier
            .records
            .iter()
            .filter(|record| record.project == "META_BPFJAILER_DECK")
        {
            self.verify_primary_source(record, &self.repo_root)?;
        }
        for record in dossier
            .records
            .iter()
            .filter(|record| record.project != "META_BPFJAILER_DECK")
        {
            let Some(snapshot) = dossier
                .snapshots
                .iter()
                .find(|snapshot| snapshot.project == record.project)
            else {
                return InvalidInputSnafu {
                    path: self.repo_root.clone(),
                    reason: format!("no snapshot for `{}`", record.project),
                }
                .fail();
            };
            self.verify_primary_source(record, &self.repo_root.join(&snapshot.directory))?;
        }
        Ok(dossier)
    }

    fn verify_schema(&self, path: &Path, dossier: &AdoptionDossierV1) -> Result<()> {
        ensure!(
            dossier.schema_version == 1 && dossier.dossier_id == "UPSTREAM-ADOPTION-V1",
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "unexpected provenance schema or dossier ID"
            }
        );
        let fixture_ids = ArchitectureClosure::new(&self.spec_root)
            .verify()?
            .fixtures
            .into_iter()
            .map(|fixture| fixture.fixture_id)
            .collect::<BTreeSet<_>>();
        let record_ids = dossier
            .records
            .iter()
            .map(|record| record.adoption_id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            record_ids.len() == dossier.records.len(),
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "duplicate adoption dossier ID"
            }
        );
        ensure!(
            dossier.records.iter().all(|record| {
                matches!(
                    record.classification.as_str(),
                    "context_only" | "reimplemented" | "do_not_inherit"
                ) && record.source_sha256.len() == 64
                    && !record.source.is_empty()
                    && !record.license_decision.is_empty()
                    && !record.local_owner.is_empty()
                    && !record.semantic_differences.is_empty()
                    && fixture_ids.contains(&record.hostile_fixture_id)
            }),
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "an adoption record is incomplete or references an unknown fixture"
            }
        );
        let required_rejections = [
            "INDEPENDENT_JAILER_PENDING_PID_ENROLLMENT",
            "INDEPENDENT_JAILER_DENTRY_ONLY_INODE_CACHE_AUTHORITY",
            "UPSTREAM_DAEMONS_AS_PRODUCT_CHASSIS",
            "INDEPENDENT_RUNTIME_BPF_LOADER_AFTER_SHARED_OWNER",
        ];
        ensure!(
            required_rejections.iter().all(|required| dossier
                .explicit_rejections
                .iter()
                .any(|item| item == required)),
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "the required rejected upstream contracts are not closed"
            }
        );
        ensure!(
            dossier
                .records
                .iter()
                .all(|record| record.transitive_dependencies.is_empty()),
            InvalidInputSnafu {
                path: path.to_path_buf(),
                reason: "Phase 0 clean-room prototypes must not add upstream runtime dependencies"
            }
        );
        Ok(())
    }

    fn verify_snapshot(&self, snapshot: &SourceSnapshotV1) -> Result<()> {
        let directory = self.repo_root.join(&snapshot.directory);
        let head = command_output(
            "git",
            [
                "-C",
                directory.to_string_lossy().as_ref(),
                "rev-parse",
                "HEAD",
            ],
        )?;
        ensure!(
            head.trim() == snapshot.commit,
            InvalidInputSnafu {
                path: directory.clone(),
                reason: format!(
                    "expected commit {}, observed {}",
                    snapshot.commit,
                    head.trim()
                )
            }
        );
        let remote = command_output(
            "git",
            [
                "-C",
                directory.to_string_lossy().as_ref(),
                "remote",
                "get-url",
                "origin",
            ],
        )?;
        ensure!(
            remote.trim().trim_end_matches(".git") == snapshot.repository.trim_end_matches(".git"),
            InvalidInputSnafu {
                path: directory.clone(),
                reason: "source repository URL does not match the dossier"
            }
        );
        let license = directory.join(&snapshot.license_path);
        let bytes = fs::read(&license).context(IoSnafu {
            path: license.clone(),
        })?;
        ensure!(
            DigestV1::of(bytes).to_hex() == snapshot.license_sha256,
            InvalidInputSnafu {
                path: license,
                reason: "license digest does not match the dossier"
            }
        );
        Ok(())
    }

    fn verify_primary_source(&self, record: &AdoptionRecordV1, root: &Path) -> Result<()> {
        let path_text = record
            .source
            .split(';')
            .next()
            .unwrap_or(record.source.as_str())
            .rsplit_once(':')
            .filter(|(_, suffix)| suffix.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .map_or_else(
                || record.source.split(';').next().unwrap_or_default(),
                |(path, _)| path,
            );
        let path = root.join(path_text);
        let bytes = fs::read(&path).context(IoSnafu { path: path.clone() })?;
        ensure!(
            DigestV1::of(bytes).to_hex() == record.source_sha256,
            InvalidInputSnafu {
                path,
                reason: format!("source digest for `{}` does not match", record.adoption_id)
            }
        );
        Ok(())
    }
}

fn command_output<'a>(
    program: &str,
    arguments: impl IntoIterator<Item = &'a str>,
) -> Result<String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .context(IoSnafu {
            path: PathBuf::from(program),
        })?;
    ensure!(
        output.status.success(),
        CommandSnafu {
            program: program.to_owned(),
            reason: String::from_utf8_lossy(&output.stderr).into_owned()
        }
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ProvenanceVerifier;

    #[test]
    fn dossier_closes_sources_licenses_owners_and_hostile_fixtures() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let dossier = ProvenanceVerifier::new(root).load_and_verify()?;
        assert_eq!(dossier.records.len(), 17);
        assert_eq!(dossier.snapshots.len(), 3);
        Ok(())
    }
}
