use crate::{wire, Guest, Result};

#[allow(unsafe_code)]
pub mod bindings {
    wit_bindgen::generate!({
        path: "src/bindings/analysis.wit",
        world: "analysis-package",
        pub_export_macro: true,
    });
}

crate::component_conversions!(bindings::araphor::analysis::types);

pub struct Component<G>(std::marker::PhantomData<G>);

impl<G: Guest> bindings::exports::araphor::analysis::analysis::Guest for Component<G> {
    fn evaluate(
        input: component_types::Evaluation,
        graph: Option<&bindings::araphor::analysis::graph::Transaction>,
    ) -> std::result::Result<component_types::Output, component_types::EvaluationError> {
        Self::evaluate(input.into(), graph)
            .map(Into::into)
            .map_err(|error| wire::EvaluationError::from(error).into())
    }
}

impl<G: Guest> Component<G> {
    fn evaluate(
        input: wire::Evaluation,
        graph: Option<&bindings::araphor::analysis::graph::Transaction>,
    ) -> Result<wire::Output> {
        Self::check_cancelled()?;
        let package = G::package();
        let (evaluation, model) = input.decode_validated(&package)?;
        let mut checked = crate::CheckedEvaluation::new(&package, model, &evaluation);
        let host = graph.map(GraphHost);
        if let Some(host) = &host {
            checked.bind_host(host)?;
        }
        let output = G::compute(&checked)?;
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

struct GraphHost<'a>(&'a bindings::araphor::analysis::graph::Transaction);

impl crate::InvocationHost for GraphHost<'_> {
    fn read(&self, name: &str, arguments: &crate::Dataset) -> Result<crate::Input> {
        let schema = arguments
            .batches
            .first()
            .ok_or_else(|| crate::Error::contract(crate::ErrorCode::Invalid, "Graph arguments"))?
            .schema();
        let arguments = wire::Dataset::encode(arguments, &schema)?;
        let input: wire::Input = self
            .0
            .read(name, &arguments.into())
            .map_err(|error| crate::Error::from(wire::EvaluationError::from(error)))?
            .into();
        Ok(crate::Input {
            data: input.data.decode_any()?,
            revision: input.revision,
            coverage: input.coverage,
        })
    }

    fn stage(&self, commands: &crate::Dataset) -> Result<()> {
        let schema = commands
            .batches
            .first()
            .ok_or_else(|| crate::Error::contract(crate::ErrorCode::Invalid, "Graph commands"))?
            .schema();
        let commands = wire::Dataset::encode(commands, &schema)?;
        self.0
            .stage(&commands.into())
            .map_err(|error| crate::Error::from(wire::EvaluationError::from(error)))
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
