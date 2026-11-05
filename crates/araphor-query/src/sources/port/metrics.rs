use super::*;

const NAMES: [&str; 14] = [
    "output_rows",
    "output_batches",
    "elapsed_compute",
    "build_time",
    "join_time",
    "build_input_rows",
    "build_input_batches",
    "input_rows",
    "input_batches",
    "spill_count",
    "spilled_rows",
    "spilled_bytes",
    "build_mem_used",
    "mem_used",
];

pub(super) struct PortMetrics {
    values: BTreeMap<usize, [usize; NAMES.len()]>,
    _memory: MemoryReservation,
}

impl PortMetrics {
    pub(super) fn capture(plan: &Arc<dyn ExecutionPlan>, source: &SourceSnapshot) -> Result<Self> {
        let memory = source.memory.reserve_input(0)?;
        let mut values = BTreeMap::new();
        PortExec::apply(plan, &mut |node| {
            source
                .control
                .check()
                .map_err(|error| DataFusionError::External(Box::new(error)))?;
            let id = Arc::as_ptr(node) as *const () as usize;
            if values.contains_key(&id) {
                return Ok(TreeNodeRecursion::Jump);
            }
            memory.try_grow(
                12 * (std::mem::size_of::<(usize, [usize; NAMES.len()])>()
                    + std::mem::size_of::<usize>()),
            )?;
            values.insert(id, Self::read(node));
            Ok(TreeNodeRecursion::Continue)
        })?;
        Ok(Self {
            values,
            _memory: memory,
        })
    }

    fn read(node: &Arc<dyn ExecutionPlan>) -> [usize; NAMES.len()] {
        let metrics = node.metrics();
        std::array::from_fn(|index| {
            metrics
                .as_ref()
                .and_then(|metrics| metrics.sum(|metric| metric.value().name() == NAMES[index]))
                .map_or(0, |value| value.as_usize())
        })
    }

    pub(super) fn report(&self, port: &PortExec, source: &SourceSnapshot) -> Result<()> {
        let Ok(snapshot) = source.snapshot() else {
            return Ok(());
        };
        let cut = snapshot.page.extraction.meta.commit_revision;
        const REPORTED: usize = 12;
        self._memory.try_grow(
            2 * REPORTED * std::mem::size_of::<(usize, String, [usize; NAMES.len()])>(),
        )?;
        let mut top = Vec::<(usize, String, [usize; NAMES.len()])>::with_capacity(REPORTED);
        let mut nonzero = 0usize;
        let mut visited = BTreeSet::new();
        PortExec::apply(&port.inputs[1], &mut |node| {
            source
                .control
                .check()
                .map_err(|error| DataFusionError::External(Box::new(error)))?;
            let id = Arc::as_ptr(node) as *const () as usize;
            if !visited.insert(id) {
                return Ok(TreeNodeRecursion::Jump);
            }
            let before = self.values.get(&id).copied().unwrap_or([0; NAMES.len()]);
            let after = Self::read(node);
            let delta: [usize; NAMES.len()] =
                std::array::from_fn(|index| after[index].saturating_sub(before[index]));
            if delta.iter().any(|value| *value != 0) {
                nonzero += 1;
                let rank = |values: &[usize; NAMES.len()]| values[2].max(values[3]).max(values[4]);
                let position = top.partition_point(|(_, _, values)| rank(values) >= rank(&delta));
                if position < REPORTED {
                    if top.len() == REPORTED {
                        top.pop();
                    }
                    self._memory.try_grow(node.name().len())?;
                    top.insert(position, (visited.len() - 1, node.name().to_owned(), delta));
                }
            }
            Ok(TreeNodeRecursion::Continue)
        })?;
        let reported = top.len();
        for (ordinal, node, delta) in top {
            erebor_telemetry::debug!(
                stage = "source_native_metrics", role = %port.role,
                family_id = port.family, read_id = port.read, image = ?port.image,
                cut_revision = cut, ordinal, node = %node,
                output_rows = delta[0], output_batches = delta[1],
                compute_ns = delta[2], build_ns = delta[3], join_ns = delta[4],
                build_rows = delta[5], build_batches = delta[6],
                input_rows = delta[7], input_batches = delta[8],
                spill_count = delta[9], spilled_rows = delta[10], spilled_bytes = delta[11],
                build_memory_delta = delta[12], memory_delta = delta[13],
                "Native source header metric delta"
            );
        }
        erebor_telemetry::debug!(stage = "source_native_metrics", role = %port.role,
            family_id = port.family, read_id = port.read, image = ?port.image,
            cut_revision = cut, node_count = visited.len(), nonzero_count = nonzero,
            reported_count = reported, omitted_count = nonzero-reported,
            "Native source header metrics completed");
        Ok(())
    }
}
