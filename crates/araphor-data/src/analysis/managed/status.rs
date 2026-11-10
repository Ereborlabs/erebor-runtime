use super::codec::ManagedCodec;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;


use super::ManagedInstance;
use crate :: { PackageErrorCodeV1 as Code , Result } ;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::analysis) enum FailureOrigin {
    Admission,
    Attempt,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::analysis) struct Failure {
    pub origin: FailureOrigin,
    pub code: Code,
    pub progress: u64,
    pub revision: u64,
}

impl Failure {
    pub(in crate::analysis) fn decode(
        bytes: Option<Vec<u8>>,
        instance: &ManagedInstance,
        head: u64,
    ) -> Result<Option<Self>> {
        let failure: Option<Self> = bytes
            .map(|bytes| ManagedCodec::decode(&bytes).context(crate::ManagedDecodingSnafu))
            .transpose()?;
        if failure.as_ref().is_some_and(|failure| {
            failure.progress > instance.progress
                || failure.revision <= instance.generation
                || failure.revision <= failure.progress
                || failure.revision > head
        }) {
            return Err(Code::Invalid.error("managed failure status"));
        }
        Ok(failure)
    }
}


