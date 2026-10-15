use crate::{wire, CheckedEvaluation, Evaluation, Output, Package, Result};

#[allow(unsafe_code)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "src/bindings/analysis.wit",
        world: "analysis-package",
        pub_export_macro: true,
    });
}

crate::component_conversions!(bindings::araphor::analysis::types);

pub trait Guest {
    fn package() -> Package;
    fn evaluate(evaluation: &Evaluation) -> Result<Output>;

    /// Compute output from input that passed the package contract checks.
    fn evaluate_checked(checked: &CheckedEvaluation<'_>) -> Result<Output> {
        Self::evaluate(checked.evaluation())
    }
}

pub struct Component<G>(std::marker::PhantomData<G>);

impl<G: Guest> bindings::exports::araphor::analysis::analysis::Guest for Component<G> {
    fn evaluate(
        input: component_types::Evaluation,
    ) -> std::result::Result<component_types::Output, component_types::EvaluationError> {
        Self::evaluate(input.into())
            .map(Into::into)
            .map_err(|error| wire::EvaluationError::from(error).into())
    }
}

impl<G: Guest> Component<G> {
    fn evaluate(input: wire::Evaluation) -> Result<wire::Output> {
        Self::check_cancelled()?;
        let package = G::package();
        let (evaluation, validator) = input.decode_validated(&package)?;
        let checked = validator.checked(&evaluation);
        let output = G::evaluate_checked(&checked)?;
        Self::check_cancelled()?;
        wire::Output::encode_checked(&checked, &output)
    }

    pub fn cancelled() -> bool {
        bindings::araphor::analysis::host::cancelled()
    }

    fn check_cancelled() -> Result<()> {
        if Self::cancelled() {
            return Err(crate::Error::contract(
                crate::ErrorCode::Failed,
                "cancelled",
            ));
        }
        Ok(())
    }
}

/// Export an SDK guest through the pinned analysis WIT interface.
#[macro_export]
macro_rules! export_component {
    ($guest:ty) => {
        type AnalysisComponent = $crate::guest::Component<$guest>;
        $crate::guest::bindings::export!(AnalysisComponent with_types_in $crate::guest::bindings);
    };
}
