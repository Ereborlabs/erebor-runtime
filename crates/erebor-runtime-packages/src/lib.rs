//! Immutable local package, policy, installation, and alias models.

mod codex;
mod error;
mod model;

pub use codex::{
    CodexArtifact, CodexChildDelegationContract, CodexChildProfile, CodexCommandDispatch,
    CodexEntrypoint, CodexFrozenContextMode, CodexHookContract, CodexHookEventName,
    CodexHookEventSchema, CodexHookExec, CodexHookShell, CodexManagedArtifacts,
    CodexPackageDefinition, CodexSupportedPlatform,
};
pub use error::{PackageError, Result};
pub use model::{
    AgentPackageManifest, CanonicalEncoding, ContentDigest, DigestAlias, InstallationRecord,
    LocalArtifactProvider, PolicyPackageManifest, PolicyPackageRevision, PolicySetRevision,
    VerifiedLocalArtifact, CANONICAL_FORMAT_VERSION,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        AgentPackageManifest, CanonicalEncoding, ContentDigest, PolicyPackageRevision,
        PolicySetRevision,
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
    fn policy_set_rejects_duplicate_package_digests() -> Result<(), Box<dyn std::error::Error>> {
        assert!(PolicySetRevision::new(
            digest(FIRST)?,
            vec![digest(SECOND)?, digest(SECOND)?],
            None
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn policy_revision_binds_manifest_to_complete_immutable_contents(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let revision = PolicyPackageRevision::new(
            "host-minimum",
            b"name = \"host-minimum\"\n".to_vec(),
            BTreeMap::from([(String::from("terminal.json"), br#"{\"rules\":[]}"#.to_vec())]),
            BTreeMap::new(),
            BTreeMap::from([(String::from("terminal.json"), br#"{}"#.to_vec())]),
            b"# Host minimum\n".to_vec(),
        )?;
        revision.validate()?;
        assert_eq!(revision.canonical_digest()?, revision.canonical_digest()?);
        Ok(())
    }
}
