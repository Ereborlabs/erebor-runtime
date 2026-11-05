use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::InvocationService as _;

pub(crate) struct HostAccess {
    pub(crate) service: Arc<dyn sdk::InvocationService + Send + Sync>,
    pub(crate) spec: sdk::GraphSpec,
}

impl sdk::InvocationHost for HostAccess {
    fn read(&self, name: &str, arguments: &sdk::Dataset) -> sdk::Result<sdk::Input> {
        let schema = self.spec.read_schema(name, &arguments.name)?;
        arguments.validate(&sdk::Port::new(
            &arguments.name,
            self.spec.argument_schema(name)?,
        ))?;
        let mut input = self.service.read(name, arguments)?;
        input
            .data
            .validate(&sdk::Port::new(&arguments.name, schema.clone()))?;
        if input.data.batches.is_empty() {
            input
                .data
                .batches
                .push(sdk::RecordBatch::new_empty(Arc::new(schema)));
        }
        Ok(input)
    }

    fn stage(&self, commands: &sdk::Dataset) -> sdk::Result<()> {
        commands.validate(&sdk::Port::new(
            &commands.name,
            self.command_schema(&commands.name)?,
        ))?;
        self.service.stage(commands)
    }
}

impl sdk::InvocationService for HostAccess {
    fn argument_schema(&self, name: &str) -> sdk::Result<sdk::Schema> {
        self.spec.argument_schema(name)
    }

    fn command_schema(&self, name: &str) -> sdk::Result<sdk::Schema> {
        self.spec.command_schema(name)
    }

    fn reserve_transfer(&self) -> sdk::Result<sdk::Transfer> {
        self.service.reserve_transfer()
    }
}
