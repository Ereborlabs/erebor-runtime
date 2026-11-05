use araphor_analysis_sdk as sdk;

mod claims;
mod coverage;
mod descriptor;
mod detect;
mod index;
mod io;
pub mod model;
mod state;

pub struct Causal;

impl Causal {
    pub fn compute(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        if checked.package() != Self::declaration() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "causal package contract",
            ));
        }
        match checked.model().name.as_str() {
            "index" => index::Index::compute(checked),
            "detect" => detect::Detect::compute(checked),
            _ => Err(model::Audit::invalid("causal package export")),
        }
    }
}
