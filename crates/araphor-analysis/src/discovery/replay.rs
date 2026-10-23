use std::sync::Arc;

use araphor_data::analysis::DiscoveryProducer;
use araphor_data::{
    AnalysisReadControl, DiscoveryProfileV1, DiscoveryReplayV1, ManagedDestination,
    PackageActionV1, PackageAuthorization, PackageErrorCodeV1 as Code, PackageGrantV1,
};
use araphor_query::execution::Engine;

use super::publication::Publication;
use super::DiscoveryOwner;
use crate::{Instance, Result};

impl DiscoveryOwner {
    pub async fn installed_refs(
        &self,
        profile: &DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryProducer> {
        let package = self.package(profile.scope.identity.tenant_id)?;
        package.selection(Some(&profile.scope.identity))?;
        Self::read_packages(
            Arc::clone(&package.query),
            Arc::clone(&package.authority),
            package.grant.clone(),
            profile,
            control,
        )
        .await
    }

    pub async fn read_packages(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        profile: &DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryProducer> {
        Instance::inspect(authority.as_ref(), &grant, control, |read| {
            Self::producer(&query, &grant, profile, read)
        })
        .await
    }

    async fn producer(
        query: &Arc<Engine>,
        grant: &PackageGrantV1,
        profile: &DiscoveryProfileV1,
        read: Arc<AnalysisReadControl>,
    ) -> Result<DiscoveryProducer> {
        let store = Arc::clone(query.store());
        let selected = grant.selection.clone();
        let profile = profile.clone();
        let stage = Arc::clone(&read);
        Ok(Engine::blocking(read, (), move || {
            Ok(store.discovery_producer(&selected, &profile, &stage)?)
        })
        .await?)
    }

    pub async fn replay(
        &self,
        profile: &DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryReplayV1> {
        let package = self.package(profile.scope.identity.tenant_id)?;
        package.selection(Some(&profile.scope.identity))?;
        Self::replay_profile(
            Arc::clone(&package.query),
            Arc::clone(&package.authority),
            package.grant.clone(),
            profile,
            control,
        )
        .await
    }

    pub async fn replay_profile(
        query: Arc<Engine>,
        authority: Arc<dyn PackageAuthorization>,
        grant: PackageGrantV1,
        profile: &DiscoveryProfileV1,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryReplayV1> {
        let (query, authority, grant) = (&query, &authority, &grant);
        let replayed = Instance::inspect(authority.as_ref(), grant, control, |read| async move {
            let producer = Self::producer(query, grant, profile, Arc::clone(&read)).await?;
            let ManagedDestination::DiscoveryProfile { output, .. } = &producer.spec.destination
            else {
                return Err(Code::Invalid.error("discovery replay destination").into());
            };
            let (replayed, prepared, saved) = Instance::replay_retained(
                query,
                authority.as_ref(),
                grant,
                &producer.spec.id,
                &producer.result.result_id,
                &read,
            )
            .await?;
            let returned = replayed
                .calls
                .get(&producer.call)
                .ok_or_else(|| Code::Invalid.error("discovery replay call"))?;
            let data = returned
                .output()
                .datasets
                .iter()
                .find(|data| data.name == *output)
                .ok_or_else(|| Code::Invalid.error("discovery replay output"))?;
            let decoded = query
                .memory()
                .reserve_input(
                    data.allocated_bytes()
                        .checked_mul(2)
                        .ok_or_else(|| Code::Limit.error("discovery replay decoded bytes"))?,
                )
                .map_err(|source| araphor_query::Error::Sql { source })?;
            let snapshot = Publication::replay_snapshot(data, &profile.scope.identity)?;
            if snapshot != profile.snapshot {
                return Err(Code::Conflict.error("discovery replay snapshot").into());
            }
            Ok((snapshot, prepared, saved, decoded))
        })
        .await;
        let (snapshot, prepared, _saved, _decoded) = match replayed {
            Ok(replayed) => replayed,
            Err(error) => {
                let reason = match &error {
                    crate::Error::Data { source }
                    | crate::Error::Query {
                        source: araphor_query::Error::Data { source },
                    } => match source {
                        araphor_data::Error::Package {
                            code: Code::Missing,
                            field,
                            ..
                        } => match *field {
                            "managed input payload"
                            | "managed evaluation payload"
                            | "managed prior payload" => "FROZEN_INPUT_UNAVAILABLE",
                            "managed SDK descriptor"
                            | "definition image"
                            | "retained definition image"
                            | "installed image artifact" => "FROZEN_PACKAGES_UNAVAILABLE",
                            _ => return Err(error),
                        },
                        _ => return Err(error),
                    },
                    _ => return Err(error),
                };
                return Self::unavailable(authority.as_ref(), grant, profile, reason, control);
            }
        };
        Instance::authorize_actions(
            authority.as_ref(),
            grant,
            &prepared,
            &[PackageActionV1::Run, PackageActionV1::Inspect],
            || {
                control.check()?;
                Ok(DiscoveryReplayV1::Available(Box::new(snapshot)))
            },
        )
        .map_err(Into::into)
    }

    fn unavailable(
        authority: &dyn PackageAuthorization,
        grant: &PackageGrantV1,
        profile: &DiscoveryProfileV1,
        reason: &str,
        control: &AnalysisReadControl,
    ) -> Result<DiscoveryReplayV1> {
        let mut checked = false;
        authority.commit_many(
            &[
                (grant, PackageActionV1::Run, None),
                (grant, PackageActionV1::Inspect, None),
            ],
            &mut || {
                grant.remaining()?;
                control.check()?;
                checked = true;
                Ok(())
            },
        )?;
        if !checked {
            return Err(Code::Denied.error("discovery replay authority").into());
        }
        Ok(DiscoveryReplayV1::Unavailable {
            first_cursor: profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.first_cursor)
                .min()
                .unwrap_or(0),
            last_cursor: profile
                .snapshot
                .coverage
                .iter()
                .map(|range| range.last_cursor)
                .max()
                .unwrap_or(0),
            reason: reason.into(),
        })
    }
}
