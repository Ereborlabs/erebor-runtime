use snafu::ResultExt as _;

use super::{AnalysisResultCommitV1, AnalysisResultReceiptV1, AnalysisStore, MAX_RESULT_BYTES};
use crate::{DiscoveryEncodingSnafu, DiscoveryProfileV1, Result};

pub struct PreparedProfile {
    profile: DiscoveryProfileV1,
    body: Vec<u8>,
}

impl PreparedProfile {
    pub fn new(profile: DiscoveryProfileV1) -> Result<Self> {
        profile.validate()?;
        let mut output = araphor_analysis_sdk::wire::BoundedBuffer::new(MAX_RESULT_BYTES as u64);
        if let Err(source) = serde_json::to_writer(&mut output, &profile) {
            if source.io_error_kind() == Some(std::io::ErrorKind::FileTooLarge) {
                return crate::DiscoveryInvalidSnafu {
                    field: "profile bytes",
                }
                .fail();
            }
            return Err(source).context(DiscoveryEncodingSnafu);
        }
        Ok(Self {
            profile,
            body: output.finish(),
        })
    }
}

impl AnalysisStore {
    pub fn commit_working_profile(
        &self,
        mut input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
        previous: Option<u64>,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR {
            return self.reject("the working result owner is invalid");
        }
        if !input.body.is_empty() {
            return self.reject("the typed profile commit contains independent body bytes");
        }
        input.body = prepared.body;
        self.commit_progress(&input, previous, true, Some(&prepared.profile), None, false)
    }

    pub fn commit_sealed_profile(
        &self,
        mut input: AnalysisResultCommitV1,
        prepared: PreparedProfile,
    ) -> Result<AnalysisResultReceiptV1> {
        if input.scope.processor_id != crate::DISCOVERY_PROCESSOR
            || input.expected_cursor != input.consumed_cursor
        {
            return self.reject("the historical profile cannot advance progress");
        }
        if !input.body.is_empty() {
            return self.reject("the typed profile commit contains independent body bytes");
        }
        if !prepared.profile.sealed {
            return self.reject("the historical profile is not sealed");
        }
        input.body = prepared.body;
        self.commit_progress(&input, None, false, Some(&prepared.profile), None, false)
    }
}

#[cfg(test)]
mod tests;
