//! Immutable local package, policy, installation, and alias models.

mod error;
mod model;

pub use error::{PackageError, Result};
pub use model::{
    AgentPackageManifest, CanonicalEncoding, ContentDigest, DigestAlias, InstallationRecord,
    PolicyPackageManifest, PolicySetRevision, CANONICAL_FORMAT_VERSION,
};

#[cfg(test)]
mod tests {
    use super::{AgentPackageManifest, CanonicalEncoding, ContentDigest, PolicySetRevision};

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
