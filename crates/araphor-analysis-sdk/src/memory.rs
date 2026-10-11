use std::mem::size_of;

use crate::{Coverage, Dependency, Model, Package, Port, Reason, Revision, Schema, wire};

impl Package {
    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self
            .id
            .capacity()
            .saturating_add(self.revision.capacity())
            .saturating_add(
                self.dependencies
                    .capacity()
                    .saturating_mul(size_of::<Dependency>()),
            )
            .saturating_add(self.exports.capacity().saturating_mul(size_of::<Model>()));
        for dependency in &self.dependencies {
            bytes = bytes
                .saturating_add(dependency.model.capacity())
                .saturating_add(dependency.input.capacity())
                .saturating_add(dependency.package.capacity())
                .saturating_add(dependency.revision.capacity())
                .saturating_add(dependency.export.capacity())
                .saturating_add(dependency.output.capacity());
        }
        for model in &self.exports {
            bytes = bytes.saturating_add(Memory::model(model));
        }
        bytes
    }
}

impl wire::Evaluation {
    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self
            .export_name
            .capacity()
            .saturating_add(self.context.id.capacity())
            .saturating_add(
                self.inputs
                    .capacity()
                    .saturating_mul(size_of::<wire::Input>()),
            );
        for input in &self.inputs {
            bytes = bytes
                .saturating_add(input.data.name.capacity())
                .saturating_add(input.data.arrow_ipc.capacity())
                .saturating_add(Memory::input_metadata(&input.revision, &input.coverage));
        }
        if let Some(parameters) = &self.parameters {
            bytes = bytes.saturating_add(parameters.capacity());
        }
        if let Some(checkpoint) = &self.checkpoint {
            bytes = bytes.saturating_add(
                checkpoint
                    .datasets
                    .capacity()
                    .saturating_mul(size_of::<wire::Dataset>()),
            );
            for data in &checkpoint.datasets {
                bytes = bytes
                    .saturating_add(data.name.capacity())
                    .saturating_add(data.arrow_ipc.capacity());
            }
        }
        bytes
    }
}

pub(crate) struct Memory;

impl Memory {
    fn model(model: &Model) -> usize {
        let mut bytes = model
            .name
            .capacity()
            .saturating_add(Self::ports(&model.inputs))
            .saturating_add(Self::ports(&model.outputs))
            .saturating_add(Self::schema_heap(&model.parameters))
            .saturating_add(model.reasons.capacity().saturating_mul(size_of::<Reason>()));
        for reason in &model.reasons {
            bytes = bytes
                .saturating_add(reason.code.capacity())
                .saturating_add(Self::schema_heap(&reason.details));
        }
        if let Some(checkpoint) = &model.checkpoint {
            bytes = bytes.saturating_add(Self::ports(&checkpoint.datasets));
        }
        bytes
    }

    fn ports(ports: &Vec<Port>) -> usize {
        let mut bytes = ports.capacity().saturating_mul(size_of::<Port>());
        for port in ports {
            bytes = bytes
                .saturating_add(port.name.capacity())
                .saturating_add(Self::schema_heap(&port.schema));
        }
        bytes
    }

    pub(crate) fn schema_heap(schema: &Schema) -> usize {
        // Use a second field charge for the nested Arc headers.
        let mut bytes = schema
            .fields()
            .size()
            .saturating_mul(2)
            .saturating_add(size_of::<[usize; 2]>());
        let capacity = schema.metadata().capacity();
        if capacity != 0 {
            // Allow space for unused hash buckets, control bytes, and alignment.
            let slots = capacity.saturating_mul(2);
            bytes = bytes
                .saturating_add(slots.saturating_mul(size_of::<(String, String)>() + 1))
                .saturating_add(size_of::<(String, String)>());
        }
        for (key, value) in schema.metadata() {
            bytes = bytes
                .saturating_add(key.capacity())
                .saturating_add(value.capacity());
        }
        bytes
    }

    pub(crate) fn input_metadata(revision: &Revision, coverage: &Coverage) -> usize {
        let mut bytes = revision
            .owner
            .capacity()
            .saturating_add(revision.id.capacity())
            .saturating_add(
                coverage
                    .limits
                    .capacity()
                    .saturating_mul(size_of::<String>()),
            );
        if let Some(window) = &revision.window {
            bytes = bytes.saturating_add(window.source.capacity());
        }
        for limit in &coverage.limits {
            bytes = bytes.saturating_add(limit.capacity());
        }
        bytes
    }
}

#[cfg(test)]
mod tests;
