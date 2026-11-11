use snafu::ResultExt as _;

use super::{AnalysisResultCommitV1, MAX_RESULT_BYTES};
use crate::{DiscoveryEncodingSnafu, DiscoveryProfileV1, Result};

mod replay;

pub use replay::DiscoveryProducer;

pub struct PreparedProfile {
    pub(in crate::analysis) profile: DiscoveryProfileV1,
    pub(in crate::analysis) body: Vec<u8>,
    pub(in crate::analysis) contexts: Vec<crate::AnalysisContextVersionV1>,
}

pub struct ProfileCommit {
    pub request: AnalysisResultCommitV1,
    pub profile: PreparedProfile,
    pub previous: Option<super::super::PackageResultRefV1>,
    pub head: Option<super::super::PackageResultRefV1>,
    pub notice: Option<(u64, u64)>,
}

impl PreparedProfile {
    pub(in crate::analysis) fn check_transition(
        profile: &DiscoveryProfileV1,
        previous: &DiscoveryProfileV1,
        historical: bool,
        root: &std::path::Path,
    ) -> Result<()> {
        if profile.profile_id == previous.profile_id
            || profile.scope != previous.scope
            || profile.updated_utc_ns < previous.updated_utc_ns
            || if historical {
                !profile.sealed
                    || Some(profile.revision) != previous.revision.checked_add(1)
                    || profile.created_utc_ns != previous.created_utc_ns
                    || profile.facts_revision < previous.facts_revision
                    || profile.coverage_revision < previous.coverage_revision
                    || profile.input_bytes != previous.input_bytes
                    || profile.incomplete != previous.incomplete
                    || profile.gaps != previous.gaps
                    || !previous
                        .context_refs
                        .iter()
                        .all(|reference| profile.context_refs.contains(reference))
            } else if previous.sealed {
                profile.interval_id == previous.interval_id
                    || profile.revision != 1
                    || profile.created_utc_ns < previous.updated_utc_ns
            } else {
                profile.interval_id != previous.interval_id
                    || Some(profile.revision) != previous.revision.checked_add(1)
                    || profile.created_utc_ns != previous.created_utc_ns
            }
        {
            return crate::Error::reject_path(root, "the immutable profile transition is invalid");
        }
        Ok(())
    }

    pub fn new(profile: DiscoveryProfileV1) -> Result<Self> {
        profile.validate()?;
        let body = Self::encode(&profile)?;
        Ok(Self {
            profile,
            body,
            contexts: Vec::new(),
        })
    }

    pub fn captured(
        profile: DiscoveryProfileV1,
        contexts: Vec<crate::AnalysisContextVersionV1>,
    ) -> Result<Self> {
        profile.validate()?;
        if contexts.is_empty() {
            return Self::new(profile);
        }
        Ok(Self {
            profile,
            body: Vec::new(),
            contexts,
        })
    }

    pub(in crate::analysis) fn encode(profile: &DiscoveryProfileV1) -> Result<Vec<u8>> {
        Self::encode_charged(profile, &mut |_| Ok(()))
    }

    pub(in crate::analysis) fn encode_charged(
        profile: &DiscoveryProfileV1,
        charge: &mut dyn FnMut(usize) -> Result<()>,
    ) -> Result<Vec<u8>> {
        struct Buffer<'a> {
            bytes: Vec<u8>,
            charge: &'a mut dyn FnMut(usize) -> Result<()>,
            error: Option<crate::Error>,
        }
        impl std::io::Write for Buffer<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let next = self
                    .bytes
                    .len()
                    .checked_add(bytes.len())
                    .ok_or_else(|| std::io::Error::other("profile capacity"))?;
                if next > self.bytes.capacity() {
                    let capacity = self.bytes.capacity().saturating_mul(2).max(next);
                    if let Err(error) = (self.charge)(
                        capacity
                            .saturating_sub(self.bytes.capacity())
                            .saturating_mul(2),
                    ) {
                        self.error = Some(error);
                        return Err(std::io::Error::other("profile memory"));
                    }
                    self.bytes
                        .try_reserve_exact(capacity - self.bytes.len())
                        .map_err(std::io::Error::other)?;
                }
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = araphor_analysis_sdk::wire::BoundedBuffer::from_writer(
            Buffer {
                bytes: Vec::new(),
                charge,
                error: None,
            },
            MAX_RESULT_BYTES as u64,
        );
        let result = serde_json::to_writer(&mut output, &profile);
        let output = output.finish();
        if let Some(error) = output.error {
            return Err(error);
        }
        if let Err(source) = result {
            if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                return crate::DiscoveryInvalidSnafu {
                    field: "profile bytes",
                }
                .fail();
            }
            return Err(source).context(DiscoveryEncodingSnafu);
        }
        Ok(output.bytes)
    }
}
