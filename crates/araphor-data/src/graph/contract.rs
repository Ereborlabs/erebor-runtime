#[cfg(test)]
use super::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
#[cfg(test)]
use araphor_analysis_sdk as sdk;
#[cfg(test)]
mod tests;

#[cfg(test)]
fn validate(reason: &FindingReasonV1, package: &str) -> crate::Result<()> {
    crate::analysis::graph_rows::store::FindingRows::validate_reason(reason, package)
        .map_err(Into::into)
}

#[cfg(test)]
fn validate_declared(reason: &DeclaredFindingReasonV1, package: &str) -> crate::Result<()> {
    crate::analysis::graph_rows::store::FindingRows::validate_reason(
        &FindingReasonV1::Declared(reason.clone()),
        package,
    )
    .map_err(Into::into)
}
