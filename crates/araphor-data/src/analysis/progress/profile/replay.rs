

use crate::analysis::{ManagedDestination, ManagedSpec, PackageResultRefV1};

#[derive(Clone, Debug, PartialEq)]
pub struct DiscoveryProducer {
    pub result: PackageResultRefV1,
    pub generation: u64,
    pub call: u64,
    pub spec: ManagedSpec,
}

impl DiscoveryProducer {
    pub(in crate::analysis) fn matches(&self, current: &ManagedSpec) -> bool {
        matches!(&current.destination,
            ManagedDestination::DiscoveryProfile { source, call, output }
                if *call == self.call
                    && matches!(&self.spec.destination,
                        ManagedDestination::DiscoveryProfile { source: prior, call: selected, output: port }
                            if prior == source && selected == call && port == output)
                    && current.same_call(&self.spec, *call))
    }
}


