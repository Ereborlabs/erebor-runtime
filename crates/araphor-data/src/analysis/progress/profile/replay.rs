use duckdb::{params, OptionalExt as _};
use snafu::ResultExt as _;

use crate::analysis::{ManagedDestination, ManagedSpec, PackageResultRefV1};
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisSelectionV1, AnalysisStore,
    DiscoveryProfileV1, PackageErrorCodeV1 as Code, Result, DISCOVERY_PROCESSOR,
};

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

impl AnalysisStore {
    pub fn discovery_producer(
        &self,
        selection: &AnalysisSelectionV1,
        profile: &DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryProducer> {
        profile.validate()?;
        let source = &profile.scope.identity;
        if source.tenant_id != selection.tenant_id
            || !selection.sources.is_all() && !selection.sources.as_slice().contains(source)
            || !selection.nodes.is_empty() && !selection.nodes.contains(&source.node_id)
        {
            return Err(Code::Denied.error("discovery producer scope"));
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let stored = reader.query_row(
                "SELECT body, commit_revision FROM analysis_results WHERE tenant_id = ? AND result_id = ? AND processor_id = ? AND stream_key = ?",
                params![selection.tenant_id.as_slice(), profile.profile_id, DISCOVERY_PROCESSOR, source.key()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, u64>(1)?)),
            ).optional().context(AnalysisDatabaseSnafu { operation: "read discovery producer profile" })?
                .ok_or_else(|| Code::Missing.error("discovery producer profile"))?;
            if DiscoveryProfileV1::try_from(stored.0.as_slice())? != *profile {
                return Err(Code::Conflict.error("discovery retained profile"));
            }
            let producer = Self::discovery_producer_from(reader, selection, profile, stored.1)?;
            control.check()?;
            Ok(producer)
        })
    }

    pub(in crate::analysis) fn discovery_producer_from(
        reader: &duckdb::Connection,
        selection: &AnalysisSelectionV1,
        profile: &DiscoveryProfileV1,
        revision: u64,
    ) -> Result<DiscoveryProducer> {
        let source = &profile.scope.identity;
        let mut edges = Self::managed_edges(reader, selection.tenant_id, &profile.profile_id)?;
        if edges.len() != 1
            || !Self::managed_profile_version(reader, selection.tenant_id, &profile.profile_id)?
        {
            return Err(Code::Invalid.error("discovery producer edge"));
        }
        let result = edges
            .pop()
            .ok_or_else(|| Code::Missing.error("discovery producer edge"))?;
        if result.commit_revision > revision {
            return Err(Code::Invalid.error("discovery producer revision"));
        }
        let (spec, generation, call) = Self::managed_producer_from(reader, selection, &result)?;
        if !matches!(&spec.destination,
            ManagedDestination::DiscoveryProfile { source: owned, call: selected, .. }
                if owned == source && *selected == call)
        {
            return Err(Code::Invalid.error("discovery producer destination"));
        }
        Ok(DiscoveryProducer {
            result,
            generation,
            call,
            spec,
        })
    }
}
