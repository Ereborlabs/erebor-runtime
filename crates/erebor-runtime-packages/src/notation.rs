use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde::Deserialize;
use snafu::{ensure, ResultExt};

use crate::{
    error::{
        InspectVerifierSnafu, InvalidVerifierConfigurationSnafu, InvalidVerifierResultSnafu,
        VerificationRejectedSnafu, VerifierDigestMismatchSnafu,
    },
    ContentDigest, Result, VerificationReceipt, VerificationReceiptInput,
};

const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const OCI_LAYOUT_VERSION: &str = "1.0.0";

/// Root-owned configuration for one exact Notation verifier artifact.
#[derive(Clone, Debug)]
pub struct NotationVerifierConfig {
    program: PathBuf,
    version: String,
    program_digest: ContentDigest,
    home: PathBuf,
}

impl NotationVerifierConfig {
    pub fn new(
        program: impl Into<PathBuf>,
        version: impl Into<String>,
        program_digest: ContentDigest,
        home: impl Into<PathBuf>,
    ) -> Result<Self> {
        let config = Self {
            program: program.into(),
            version: version.into(),
            program_digest,
            home: home.into(),
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.program.is_absolute()
                && self.home.is_absolute()
                && !self.version.trim().is_empty(),
            InvalidVerifierConfigurationSnafu {
                reason: String::from(
                    "program and Notation home must be absolute and a pinned version must be declared"
                )
            }
        );
        require_safe_directory(&self.home, "Notation home")?;
        self.program_digest.validate()
    }
}

/// Daemon-owned facts for one local OCI-layout verification.
#[derive(Clone, Debug)]
pub struct NotationVerificationRequest {
    layout_dir: PathBuf,
    subject_reference: String,
    trust_policy_scope: String,
    subject_digest: ContentDigest,
    trust_policy_digest: ContentDigest,
    verified_at_unix_ms: u64,
    revocation_snapshot_digest: Option<ContentDigest>,
}

impl NotationVerificationRequest {
    pub fn new(
        layout_dir: impl Into<PathBuf>,
        subject_reference: impl Into<String>,
        trust_policy_scope: impl Into<String>,
        subject_digest: ContentDigest,
        trust_policy_digest: ContentDigest,
        verified_at_unix_ms: u64,
        revocation_snapshot_digest: Option<ContentDigest>,
    ) -> Result<Self> {
        let request = Self {
            layout_dir: layout_dir.into(),
            subject_reference: subject_reference.into(),
            trust_policy_scope: trust_policy_scope.into(),
            subject_digest,
            trust_policy_digest,
            verified_at_unix_ms,
            revocation_snapshot_digest,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.layout_dir.is_absolute()
                && !self.subject_reference.trim().is_empty()
                && !self.trust_policy_scope.trim().is_empty(),
            InvalidVerifierConfigurationSnafu {
                reason: String::from(
                    "local layout, subject reference, and trust-policy scope must be daemon-owned values"
                )
            }
        );
        let reference_digest = Self::reference_digest(&self.subject_reference)?;
        ensure!(
            reference_digest == self.subject_digest,
            InvalidVerifierConfigurationSnafu {
                reason: String::from(
                    "Notation subject reference must bind the declared SHA-256 subject digest"
                )
            }
        );
        require_safe_directory(&self.layout_dir, "OCI layout")?;
        self.subject_digest.validate()?;
        self.trust_policy_digest.validate()?;
        if let Some(digest) = &self.revocation_snapshot_digest {
            digest.validate()?;
        }
        Ok(())
    }

    fn reference_digest(reference: &str) -> Result<ContentDigest> {
        let Some((repository, digest)) = reference.rsplit_once("@sha256:") else {
            return InvalidVerifierConfigurationSnafu {
                reason: String::from(
                    "Notation subject reference must be a repository followed by @sha256:<digest>",
                ),
            }
            .fail();
        };
        ensure!(
            !repository.is_empty()
                && !repository.chars().any(char::is_whitespace)
                && !repository.contains('\0'),
            InvalidVerifierConfigurationSnafu {
                reason: String::from("Notation subject repository is invalid")
            }
        );
        ContentDigest::new(digest)
    }
}

/// The approved non-shell verifier boundary.
pub struct NotationVerifier {
    config: NotationVerifierConfig,
}

impl NotationVerifier {
    #[must_use]
    pub fn new(config: NotationVerifierConfig) -> Self {
        Self { config }
    }

    pub fn verify(&self, request: &NotationVerificationRequest) -> Result<VerificationReceipt> {
        request.validate()?;
        self.require_pinned_program()?;
        self.require_held_layout_subject(request)?;

        let output = Command::new(&self.config.program)
            .arg("verify")
            .arg("--oci-layout")
            .arg(&request.subject_reference)
            .arg("--scope")
            .arg(&request.trust_policy_scope)
            .current_dir(&request.layout_dir)
            .env_clear()
            .env("HOME", &self.config.home)
            .env("NOTATION_EXPERIMENTAL", "1")
            .output()
            .map_err(|source| crate::PackageError::InvokeVerifier {
                path: self.config.program.clone(),
                source,
                location: snafu::Location::default(),
            })?;
        if !output.status.success() {
            return VerificationRejectedSnafu {
                subject: request.subject_reference.clone(),
                reason: Self::diagnostic(&output.stdout, &output.stderr),
            }
            .fail();
        }
        self.require_valid_result(&output, request)?;
        VerificationReceipt::new(VerificationReceiptInput {
            subject_digest: request.subject_digest.clone(),
            subject_reference: request.subject_reference.clone(),
            trust_policy_digest: request.trust_policy_digest.clone(),
            trust_policy_scope: request.trust_policy_scope.clone(),
            verifier_version: self.config.version.clone(),
            verifier_digest: self.config.program_digest.clone(),
            verified_at_unix_ms: request.verified_at_unix_ms,
            revocation_snapshot_digest: request.revocation_snapshot_digest.clone(),
        })
    }

    fn require_pinned_program(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.config.program).map_err(|source| {
            crate::PackageError::InspectVerifier {
                path: self.config.program.clone(),
                source,
                location: snafu::Location::default(),
            }
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return InvalidVerifierConfigurationSnafu {
                reason: String::from(
                    "pinned Notation program must be a non-symlink regular file that is not group/world writable",
                ),
            }
            .fail();
        }
        let bytes = fs::read(&self.config.program).context(InspectVerifierSnafu {
            path: &self.config.program,
        })?;
        let actual = ContentDigest::from_canonical_bytes(&bytes);
        if actual != self.config.program_digest {
            return VerifierDigestMismatchSnafu {
                path: self.config.program.clone(),
            }
            .fail();
        }
        Ok(())
    }

    fn require_held_layout_subject(&self, request: &NotationVerificationRequest) -> Result<()> {
        let oci_layout = request.layout_dir.join("oci-layout");
        let index = request.layout_dir.join("index.json");
        let oci_layout_bytes = read_regular_file(&oci_layout)?;
        let marker: OciLayoutMarker =
            serde_json::from_slice(&oci_layout_bytes).map_err(|source| {
                crate::PackageError::InvalidVerifierResult {
                    subject: request.subject_reference.clone(),
                    reason: format!("OCI layout marker is not valid JSON: {source}"),
                    location: snafu::Location::default(),
                }
            })?;
        if marker.image_layout_version != OCI_LAYOUT_VERSION {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: format!(
                    "OCI layout version `{}` is not supported",
                    marker.image_layout_version
                ),
            }
            .fail();
        }
        let index_bytes = read_regular_file(&index)?;
        let index: OciIndex = serde_json::from_slice(&index_bytes).map_err(|source| {
            crate::PackageError::InvalidVerifierResult {
                subject: request.subject_reference.clone(),
                reason: format!("OCI layout index is not valid JSON: {source}"),
                location: snafu::Location::default(),
            }
        })?;
        if index.schema_version != 2 {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: String::from("OCI layout index schemaVersion must be 2"),
            }
            .fail();
        }
        let expected_descriptor = format!("sha256:{}", request.subject_digest.as_str());
        if !index
            .manifests
            .iter()
            .any(|descriptor| descriptor.digest == expected_descriptor)
        {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: String::from(
                    "OCI layout index does not contain the held subject descriptor",
                ),
            }
            .fail();
        }
        let blob = request
            .layout_dir
            .join("blobs")
            .join("sha256")
            .join(request.subject_digest.as_str());
        let bytes = read_regular_file(&blob)?;
        if ContentDigest::from_canonical_bytes(&bytes) != request.subject_digest {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: String::from(
                    "OCI subject descriptor does not match its held SHA-256 digest",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn require_valid_result(
        &self,
        output: &Output,
        request: &NotationVerificationRequest,
    ) -> Result<()> {
        if !output.stderr.is_empty() {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: String::from(
                    "Notation emitted diagnostics while claiming verification success",
                ),
            }
            .fail();
        }
        let expected = format!(
            "Successfully verified signature for {}\n",
            request.subject_reference
        );
        if output.stdout != expected.as_bytes() {
            return InvalidVerifierResultSnafu {
                subject: request.subject_reference.clone(),
                reason: String::from(
                    "Notation success result did not match the pinned v1 machine contract",
                ),
            }
            .fail();
        }
        Ok(())
    }

    fn diagnostic(stdout: &[u8], stderr: &[u8]) -> String {
        let source = if stderr.is_empty() { stdout } else { stderr };
        let bounded = &source[..source.len().min(MAX_DIAGNOSTIC_BYTES)];
        String::from_utf8_lossy(bounded).trim().to_owned()
    }
}

fn require_safe_directory(path: &Path, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| crate::PackageError::InspectVerifier {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.is_dir()
            && metadata.permissions().mode() & 0o022 == 0,
        InvalidVerifierConfigurationSnafu {
            reason: format!(
                "{label} must be a non-symlink directory that is not group/world writable"
            )
        }
    );
    Ok(())
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| crate::PackageError::InspectVerifier {
            path: path.to_path_buf(),
            source,
            location: snafu::Location::default(),
        })?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_file(),
        InvalidVerifierConfigurationSnafu {
            reason: format!("{} must be a non-symlink regular file", path.display())
        }
    );
    fs::read(path).map_err(|source| crate::PackageError::InspectVerifier {
        path: path.to_path_buf(),
        source,
        location: snafu::Location::default(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciLayoutMarker {
    image_layout_version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciIndex {
    schema_version: u32,
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::{
        ContentDigest, NotationVerificationRequest, NotationVerifier, NotationVerifierConfig,
    };

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn digest() -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(DIGEST)?)
    }

    #[test]
    fn verifier_rejects_a_binary_that_does_not_match_its_pin(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("erebor-notation-test-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let home = root.join("home");
        let layout = root.join("layout");
        fs::create_dir_all(&home)?;
        fs::create_dir_all(&layout)?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&layout, fs::Permissions::from_mode(0o700))?;
        let program = root.join("notation");
        fs::write(&program, "#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
        let verifier = NotationVerifier::new(NotationVerifierConfig::new(
            &program,
            "v1.3.2",
            digest()?,
            &home,
        )?);
        let request = NotationVerificationRequest::new(
            &layout,
            format!("local/example@sha256:{DIGEST}"),
            "local/example",
            digest()?,
            digest()?,
            1,
            None,
        )?;
        assert!(verifier.verify(&request).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn verifier_accepts_only_the_pinned_success_contract_and_held_subject(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let layout = root.path().join("layout");
        let home = root.path().join("home");
        fs::create_dir_all(layout.join("blobs/sha256"))?;
        fs::create_dir_all(&home)?;
        fs::set_permissions(&layout, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::write(
            layout.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )?;
        let subject = b"held OCI subject descriptor";
        let subject_digest = ContentDigest::from_canonical_bytes(subject);
        fs::write(
            layout.join("blobs/sha256").join(subject_digest.as_str()),
            subject,
        )?;
        fs::write(
            layout.join("index.json"),
            format!(
                r#"{{"schemaVersion":2,"manifests":[{{"digest":"sha256:{}"}}]}}"#,
                subject_digest.as_str()
            ),
        )?;
        let reference = format!("local/example@sha256:{}", subject_digest.as_str());
        let program = root.path().join("notation");
        fs::write(
            &program,
            format!(
                "#!/bin/sh\n[ \"$NOTATION_EXPERIMENTAL\" = 1 ] || exit 20\n[ \"$HOME\" = \"{}\" ] || exit 21\n[ \"$1\" = verify ] || exit 22\n[ \"$2\" = --oci-layout ] || exit 23\n[ \"$3\" = \"{}\" ] || exit 24\n[ \"$4\" = --scope ] || exit 25\n[ \"$5\" = local/example ] || exit 26\nprintf '%s\\n' 'Successfully verified signature for {}'\n",
                home.display(), reference, reference
            ),
        )?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
        let program_digest = ContentDigest::from_canonical_bytes(&fs::read(&program)?);
        let verifier = NotationVerifier::new(NotationVerifierConfig::new(
            &program,
            "v1.3.2",
            program_digest,
            &home,
        )?);
        let request = NotationVerificationRequest::new(
            &layout,
            reference,
            "local/example",
            subject_digest.clone(),
            digest()?,
            1,
            None,
        )?;
        let receipt = verifier.verify(&request)?;
        assert_eq!(receipt.subject_digest(), &subject_digest);
        assert_eq!(receipt.subject_reference(), request.subject_reference);
        Ok(())
    }

    #[test]
    fn verifier_rejects_a_success_result_with_unexpected_output(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let layout = root.path().join("layout");
        let home = root.path().join("home");
        fs::create_dir_all(layout.join("blobs/sha256"))?;
        fs::create_dir_all(&home)?;
        fs::set_permissions(&layout, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;
        fs::write(
            layout.join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )?;
        let subject = b"held OCI subject descriptor";
        let subject_digest = ContentDigest::from_canonical_bytes(subject);
        fs::write(
            layout.join("blobs/sha256").join(subject_digest.as_str()),
            subject,
        )?;
        fs::write(
            layout.join("index.json"),
            format!(
                r#"{{"schemaVersion":2,"manifests":[{{"digest":"sha256:{}"}}]}}"#,
                subject_digest.as_str()
            ),
        )?;
        let program = root.path().join("notation");
        fs::write(&program, "#!/bin/sh\nprintf '%s\\n' 'unexpected success'\n")?;
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
        let program_digest = ContentDigest::from_canonical_bytes(&fs::read(&program)?);
        let verifier = NotationVerifier::new(NotationVerifierConfig::new(
            &program,
            "v1.3.2",
            program_digest,
            &home,
        )?);
        let request = NotationVerificationRequest::new(
            &layout,
            format!("local/example@sha256:{}", subject_digest.as_str()),
            "local/example",
            subject_digest,
            digest()?,
            1,
            None,
        )?;
        assert!(verifier.verify(&request).is_err());
        Ok(())
    }
}
