//! Immutable OCI-package, policy, installation, alias, and verification models.

mod error;
mod model;
mod notation;

pub use error::{PackageError, Result};
pub use model::{
    AgentPackageManifest, CanonicalEncoding, ContentDigest, DigestAlias, InstallationRecord,
    PolicyPackageManifest, PolicySetRevision, VerificationReceipt, VerificationReceiptInput,
    CANONICAL_FORMAT_VERSION,
};
pub use notation::{NotationVerificationRequest, NotationVerifier, NotationVerifierConfig};

#[cfg(test)]
mod tests {
    use super::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, PolicySetRevision,
        VerificationReceipt, VerificationReceiptInput,
    };

    const FIRST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SECOND: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn digest(value: &str) -> Result<ContentDigest, Box<dyn std::error::Error>> {
        Ok(ContentDigest::new(value)?)
    }

    #[test]
    fn canonical_models_have_stable_digest_identity() -> Result<(), Box<dyn std::error::Error>> {
        let manifest = AgentPackageManifest::new(
            "example.agent",
            "generic-process-v1",
            "0.1.0",
            vec![String::from("example")],
            digest(FIRST)?,
            vec![digest(SECOND)?],
        )?;
        assert_eq!(manifest.canonical_digest()?, manifest.canonical_digest()?);
        Ok(())
    }

    #[test]
    fn receipt_cannot_be_reused_after_trust_policy_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let receipt = VerificationReceipt::new(VerificationReceiptInput {
            subject_digest: digest(FIRST)?,
            subject_reference: format!("example/package@sha256:{FIRST}"),
            trust_policy_digest: digest(FIRST)?,
            trust_policy_scope: String::from("example/package"),
            verifier_version: String::from("notation-v1.3.2"),
            verifier_digest: digest(SECOND)?,
            verified_at_unix_ms: 1,
            revocation_snapshot_digest: None,
        })?;
        assert!(receipt.validates_current_trust(&digest(FIRST)?));
        assert!(!receipt.validates_current_trust(&digest(SECOND)?));
        Ok(())
    }

    #[test]
    fn policy_set_rejects_duplicate_package_digests() -> Result<(), Box<dyn std::error::Error>> {
        assert!(PolicySetRevision::new(
            digest(FIRST)?,
            vec![digest(SECOND)?, digest(SECOND)?],
            None
        )
        .is_err());
        Ok(())
    }
}
