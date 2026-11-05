use crate::{Dataset, Input, Result, Schema};

pub trait InvocationHost {
    fn read(&self, name: &str, arguments: &Dataset) -> Result<Input>;
    fn stage(&self, commands: &Dataset) -> Result<()>;
}

pub trait InvocationService: InvocationHost {
    fn argument_schema(&self, name: &str) -> Result<Schema>;
    fn command_schema(&self, name: &str) -> Result<Schema>;
    fn reserve_transfer(&self) -> Result<Transfer>;
}

pub struct Transfer {
    pub bytes: Option<usize>,
    pub lease: Box<dyn std::any::Any + Send>,
}

pub struct GraphTransport<'a> {
    host: &'a dyn InvocationHost,
}

impl<'a> crate::CheckedEvaluation<'a> {
    pub fn graph(&self) -> Result<araphor_graph::Transaction<GraphTransport<'_>>> {
        Ok(araphor_graph::Transaction::new(GraphTransport {
            host: self.host()?,
        }))
    }
}

impl araphor_graph::Transport for GraphTransport<'_> {
    fn read(
        &self,
        operation: &str,
        relation: &str,
        arguments: crate::RecordBatch,
    ) -> araphor_graph::Result<Vec<crate::RecordBatch>> {
        self.host
            .read(
                operation,
                &Dataset {
                    name: relation.into(),
                    batches: vec![arguments],
                },
            )
            .map(|input| input.data.batches)
            .map_err(araphor_graph::Error::backend)
    }

    fn stage(&self, relation: &str, commands: crate::RecordBatch) -> araphor_graph::Result<()> {
        self.host
            .stage(&Dataset {
                name: relation.into(),
                batches: vec![commands],
            })
            .map_err(araphor_graph::Error::backend)
    }
}
