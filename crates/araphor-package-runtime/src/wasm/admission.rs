use wasmparser::{Encoding, FunctionBody, Operator, Parser, Payload};
use wasmtime::{
    component::{types::ComponentItem, Component},
    Engine,
};

use crate::{AnalysisReadControl, Result, WasmLimits};

use super::Code;

const HOST: &str = "araphor:analysis/host@1.0.0";
const ANALYSIS: &str = "araphor:analysis/analysis@1.0.0";
const TYPES: &str = "araphor:analysis/types@1.0.0";

#[derive(Default)]
pub(super) struct CompileBudget {
    depth: usize,
    sections: usize,
    functions: usize,
    types: usize,
    operators: usize,
    instances: usize,
}

impl CompileBudget {
    pub(super) fn check_size(bytes: &[u8], quota: &WasmLimits) -> Result<()> {
        if quota
            .source_bytes
            .is_some_and(|maximum| bytes.len() > maximum)
        {
            return Err(Code::Limit.error("component source bytes").into());
        }
        if !Parser::is_component(bytes) {
            return Err(Code::Invalid.error("component binary").into());
        }
        Ok(())
    }

    pub(super) fn check(
        bytes: &[u8],
        control: &AnalysisReadControl,
        quota: &WasmLimits,
    ) -> Result<()> {
        Self::check_size(bytes, quota)?;
        let mut budget = Self::default();
        for payload in Parser::new(0).parse_all(bytes) {
            control.check()?;
            budget.sections += 1;
            budget.section(
                payload.map_err(|_| Code::Invalid.error("component structure"))?,
                control,
                quota,
            )?;
            if quota
                .compile_sections
                .is_some_and(|maximum| budget.sections > maximum)
                || quota
                    .compile_depth
                    .is_some_and(|maximum| budget.depth > maximum)
                || quota
                    .compile_functions
                    .is_some_and(|maximum| budget.functions > maximum)
                || quota
                    .compile_types
                    .is_some_and(|maximum| budget.types > maximum)
                || quota
                    .compile_operators
                    .is_some_and(|maximum| budget.operators > maximum)
                || quota
                    .compile_instances
                    .is_some_and(|maximum| budget.instances > maximum)
            {
                return Err(Code::Limit.error("component compilation work").into());
            }
        }
        Ok(())
    }

    fn section(
        &mut self,
        payload: Payload<'_>,
        control: &AnalysisReadControl,
        quota: &WasmLimits,
    ) -> Result<()> {
        match payload {
            Payload::Version { encoding, .. } => {
                if self.depth == 0 && encoding != Encoding::Component {
                    return Err(Code::Invalid.error("component encoding").into());
                }
                self.depth += 1;
            }
            Payload::End(_) => self.depth = self.depth.saturating_sub(1),
            Payload::TypeSection(types) => {
                self.types += types.count() as usize;
                let range = types.range();
                if quota
                    .compile_types
                    .is_some_and(|maximum| self.types > maximum)
                    || quota
                        .type_bytes
                        .is_some_and(|maximum| range.end - range.start > maximum as u64)
                {
                    return Err(Code::Limit.error("component core type bytes").into());
                }
                for function in types.into_iter_err_on_gc_types() {
                    let function =
                        function.map_err(|_| Code::Unsupported.error("component core types"))?;
                    if quota
                        .type_parameters
                        .is_some_and(|maximum| function.params().len() > maximum)
                        || quota
                            .type_results
                            .is_some_and(|maximum| function.results().len() > maximum)
                    {
                        return Err(Code::Limit.error("component function type").into());
                    }
                }
            }
            Payload::ComponentTypeSection(types) => {
                self.types += types.count() as usize;
                let range = types.range();
                if quota
                    .type_bytes
                    .is_some_and(|maximum| range.end - range.start > maximum as u64)
                {
                    return Err(Code::Limit.error("component interface type bytes").into());
                }
            }
            Payload::CoreTypeSection(types) => self.types += types.count() as usize,
            Payload::ModuleSection { .. } | Payload::ComponentSection { .. } if self.depth != 1 => {
                return Err(Code::Unsupported.error("nested component code").into());
            }
            Payload::InstanceSection(instances) => {
                if self.depth != 1 {
                    return Err(Code::Unsupported.error("nested core instantiation").into());
                }
                self.instances += instances.count() as usize;
            }
            Payload::ComponentInstanceSection(instances) => {
                if self.depth != 1 {
                    return Err(Code::Unsupported
                        .error("nested component instantiation")
                        .into());
                }
                self.instances += instances.count() as usize;
            }
            Payload::CodeSectionStart { count, .. } => self.functions += count as usize,
            Payload::CodeSectionEntry(body) => self.function(body, control, quota)?,
            Payload::UnknownSection { .. } => {
                return Err(Code::Unsupported.error("component section").into());
            }
            _ => {}
        }
        Ok(())
    }

    fn function(
        &mut self,
        body: FunctionBody<'_>,
        control: &AnalysisReadControl,
        quota: &WasmLimits,
    ) -> Result<()> {
        if quota
            .function_bytes
            .is_some_and(|maximum| body.as_bytes().len() > maximum)
        {
            return Err(Code::Limit.error("component function bytes").into());
        }
        let mut locals = 0u64;
        for local in body
            .get_locals_reader()
            .map_err(|_| Code::Invalid.error("component locals"))?
        {
            locals += u64::from(local.map_err(|_| Code::Invalid.error("component local"))?.0);
            if quota
                .function_locals
                .is_some_and(|maximum| locals > maximum)
            {
                return Err(Code::Limit.error("component function locals").into());
            }
        }
        let mut depth = 0usize;
        let mut count = 0usize;
        for operator in body
            .get_operators_reader()
            .map_err(|_| Code::Invalid.error("component operators"))?
        {
            count += 1;
            if count.is_multiple_of(256) {
                control.check()?;
            }
            match operator.map_err(|_| Code::Invalid.error("component operator"))? {
                Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => depth += 1,
                Operator::End => depth = depth.saturating_sub(1),
                _ => {}
            }
            if quota
                .function_operators
                .is_some_and(|maximum| count > maximum)
                || quota.function_depth.is_some_and(|maximum| depth > maximum)
            {
                return Err(Code::Limit.error("component function complexity").into());
            }
        }
        self.operators += count;
        Ok(())
    }

    pub(super) fn interface(
        engine: &Engine,
        component: &Component,
        quota: &WasmLimits,
    ) -> Result<()> {
        let interface = component.component_type();
        for (name, item) in interface.imports(engine) {
            if !matches!(name, HOST | TYPES)
                || item.implements.is_some()
                || item.external_id.is_some()
            {
                return Err(Code::Unsupported.error("component import").into());
            }
            Self::instance(engine, name, item.ty)?;
        }
        for (name, item) in interface.exports(engine) {
            if !matches!(name, ANALYSIS | TYPES)
                || item.implements.is_some()
                || item.external_id.is_some()
            {
                return Err(Code::Unsupported.error("component export").into());
            }
            Self::instance(engine, name, item.ty)?;
        }
        Self::resources(component, quota)
    }

    pub(super) fn resources(component: &Component, quota: &WasmLimits) -> Result<()> {
        let resources = component
            .resources_required()
            .ok_or_else(|| Code::Unsupported.error("component resources"))?;
        if quota
            .memories
            .is_some_and(|maximum| u64::from(resources.num_memories) > maximum as u64)
            || quota
                .tables
                .is_some_and(|maximum| u64::from(resources.num_tables) > maximum as u64)
            || quota.memory_bytes.is_some_and(|maximum| {
                resources
                    .max_initial_memory_size
                    .is_some_and(|pages| pages > maximum as u64 / 65_536)
            })
            || resources.max_initial_table_size.is_some_and(|elements| {
                quota
                    .table_elements
                    .is_some_and(|maximum| elements > maximum as u64)
            })
        {
            return Err(Code::Limit.error("component initial resources").into());
        }
        Ok(())
    }

    fn instance(engine: &Engine, name: &str, item: ComponentItem) -> Result<()> {
        let ComponentItem::ComponentInstance(instance) = item else {
            return Err(Code::Unsupported.error("component interface kind").into());
        };
        for (field, item) in instance.exports(engine) {
            match item.ty {
                ComponentItem::Type(_) if name != HOST => {}
                ComponentItem::ComponentFunc(_)
                    if (name == HOST && field == "cancelled")
                        || (name == ANALYSIS && field == "evaluate") => {}
                _ => return Err(Code::Unsupported.error("component interface member").into()),
            }
        }
        Ok(())
    }
}
