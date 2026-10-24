use std::mem::size_of;

use crate::{
    wire, Coverage, InputPort, InputSource, Model, Package, Port, Reason, Revision, Schema,
    TableRef,
};

impl Package {
    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self
            .id
            .capacity()
            .saturating_add(self.revision.capacity())
            .saturating_add(self.exports.capacity().saturating_mul(size_of::<Model>()));
        for model in &self.exports {
            bytes = bytes.saturating_add(Memory::model(model));
        }
        bytes
    }
}

impl Port {
    pub fn allocated_bytes(&self) -> usize {
        self.name
            .capacity()
            .saturating_add(Memory::schema_heap(&self.schema))
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
            bytes = bytes.saturating_add(input.allocated_bytes());
        }
        if let Some(parameters) = &self.parameters {
            bytes = bytes.saturating_add(parameters.capacity());
        }
        if let Some(checkpoint) = &self.checkpoint {
            bytes = bytes.saturating_add(checkpoint.allocated_bytes());
        }
        bytes
    }
}

impl wire::Dataset {
    pub fn allocated_bytes(&self) -> usize {
        self.name
            .capacity()
            .saturating_add(self.arrow_ipc.capacity())
    }
}

impl wire::Input {
    pub fn allocated_bytes(&self) -> usize {
        self.data
            .allocated_bytes()
            .saturating_add(Memory::input_metadata(&self.revision, &self.coverage))
    }
}

impl wire::Checkpoint {
    pub fn allocated_bytes(&self) -> usize {
        self.datasets.iter().fold(
            self.datasets
                .capacity()
                .saturating_mul(size_of::<wire::Dataset>()),
            |bytes, data| bytes.saturating_add(data.allocated_bytes()),
        )
    }
}

impl wire::Output {
    pub fn allocated_bytes(&self) -> usize {
        let mut bytes = self
            .datasets
            .capacity()
            .saturating_mul(size_of::<wire::Dataset>())
            .saturating_add(
                self.evidence
                    .capacity()
                    .saturating_mul(size_of::<crate::EvidenceLink>()),
            )
            .saturating_add(
                self.reasons
                    .capacity()
                    .saturating_mul(size_of::<wire::ReasonValue>()),
            );
        for data in &self.datasets {
            bytes = bytes.saturating_add(data.allocated_bytes());
        }
        for link in &self.evidence {
            bytes = bytes
                .saturating_add(link.output.dataset.capacity())
                .saturating_add(link.input.dataset.capacity());
        }
        for reason in &self.reasons {
            bytes = bytes
                .saturating_add(reason.output.dataset.capacity())
                .saturating_add(reason.code.capacity())
                .saturating_add(reason.details.capacity());
        }
        if let Some(checkpoint) = &self.checkpoint {
            bytes = bytes.saturating_add(checkpoint.allocated_bytes());
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
            .saturating_add(
                model
                    .inputs
                    .capacity()
                    .saturating_mul(size_of::<InputPort>()),
            )
            .saturating_add(Self::ports(&model.outputs))
            .saturating_add(Self::schema_heap(&model.parameters))
            .saturating_add(model.reasons.capacity().saturating_mul(size_of::<Reason>()));
        for input in &model.inputs {
            bytes = bytes
                .saturating_add(input.port.name.capacity())
                .saturating_add(Self::schema_heap(&input.port.schema));
            bytes = bytes.saturating_add(match &input.source {
                InputSource::Query(value) | InputSource::Table(TableRef::Named(value)) => {
                    value.capacity()
                }
                InputSource::Table(TableRef::Output(output)) => output
                    .package
                    .capacity()
                    .saturating_add(output.revision.capacity())
                    .saturating_add(output.export.capacity())
                    .saturating_add(output.output.capacity()),
            });
        }
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
            bytes = bytes.saturating_add(port.allocated_bytes());
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
            .saturating_add(coverage.metadata_bytes());
        if let Some(window) = &revision.window {
            bytes = bytes.saturating_add(window.source.capacity());
        }
        bytes
    }
}

#[cfg(test)]
mod tests;
