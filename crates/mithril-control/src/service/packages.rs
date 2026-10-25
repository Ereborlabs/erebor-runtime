use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use araphor_data::PackageAuthorization;
use araphor_data::{AnalysisSelectionV1, PackageActionV1, PackageGrantV1};
use araphor_query::execution::{Engine, Limits};

use super::ControlPlane;

mod graph;

pub(crate) struct ControlPackages {
    pub(crate) query: Arc<Engine>,
    pub(crate) instances: Arc<araphor_analysis::InstanceHost>,
    authority: Arc<ControlPackageAuthority>,
    facts: Option<Arc<dyn araphor_analysis::GraphFacts>>,
    limits: Limits,
}

struct ControlPackageAuthority {
    tenants: BTreeMap<[u8; 16], Vec<String>>,
    pins: BTreeSet<String>,
    client: RwLock<Option<Arc<crate::ClientAuth>>>,
    changes: tokio::sync::watch::Sender<u64>,
}

impl ControlPlane {
    pub(crate) fn analysis_packages(
        &self,
        limits: Option<Limits>,
    ) -> crate::Result<Arc<ControlPackages>> {
        self.configured_packages(limits, false)
    }

    pub(crate) fn configured_packages(
        &self,
        limits: Option<Limits>,
        notifications_enabled: bool,
    ) -> crate::Result<Arc<ControlPackages>> {
        let mut installed = self.packages.lock().map_err(|_| {
            crate::error::InvalidConfigurationSnafu {
                reason: "analysis package registry lock failed",
            }
            .build()
        })?;
        if let Some(installed) = installed.as_ref() {
            if limits
                .as_ref()
                .is_some_and(|limits| *limits != installed.limits)
            {
                return Err(crate::error::InvalidConfigurationSnafu {
                    reason: "analysis packages already use different query limits",
                }
                .build());
            }
            return Ok(installed.clone());
        }
        let data = self.analysis_store().ok_or_else(|| {
            crate::error::InvalidConfigurationSnafu {
                reason: "analysis packages require retained data storage",
            }
            .build()
        })?;
        let mut tenants = BTreeMap::<[u8; 16], Vec<String>>::new();
        for node in self.allowed_nodes.values() {
            let tenant = uuid::Uuid::parse_str(&node.tenant_id).map_err(|_| {
                crate::error::InvalidConfigurationSnafu {
                    reason: "analysis package tenant is invalid",
                }
                .build()
            })?;
            tenants
                .entry(*tenant.as_bytes())
                .or_default()
                .push(node.node_id.clone());
        }
        let mut bundles = araphor_analysis::GraphProgram::images();
        bundles.push(araphor_analysis::Package::discovery_bundle()?);
        let bundles = bundles
            .into_iter()
            .map(|bundle| {
                let digest = bundle.digest().map_err(araphor_data::Error::from)?;
                Ok((bundle, digest))
            })
            .collect::<araphor_data::Result<Vec<_>>>()?;
        let pins = bundles.iter().map(|(_, digest)| digest.clone()).collect();
        let authority = Arc::new(ControlPackageAuthority {
            tenants,
            pins,
            client: RwLock::new(None),
            changes: tokio::sync::watch::channel(1).0,
        });
        let limits = limits.unwrap_or_default();
        let mut query = Engine::new(data, limits.clone())?;
        Arc::get_mut(&mut query)
            .ok_or_else(|| {
                crate::error::InvalidConfigurationSnafu {
                    reason: "query engine is shared before package registration",
                }
                .build()
            })?
            .register_views(araphor_analysis_builtins::discovery::sql::VIEWS_SQL)?;
        let facts = self
            .policy_store
            .as_ref()
            .map(|store| {
                crate::ControlContextOwner::new(
                    store.clone(),
                    Arc::clone(query.store()),
                    &self.allowed_nodes.values().cloned().collect::<Vec<_>>(),
                )
                .map(|owner| Arc::new(owner) as Arc<dyn araphor_analysis::GraphFacts>)
            })
            .transpose()?;
        let instances = match (&facts, &self.notifications) {
            (_, Some(owner)) => araphor_analysis::InstanceHost::with_notifications(
                Arc::clone(&query),
                authority.clone(),
                facts.clone(),
                Arc::clone(&owner.router),
                Arc::clone(&owner.sink),
                notifications_enabled,
            ),
            (Some(facts), None) => araphor_analysis::InstanceHost::with_graph_facts(
                Arc::clone(&query),
                authority.clone(),
                Arc::clone(facts),
            ),
            (None, None) => {
                araphor_analysis::InstanceHost::new(Arc::clone(&query), authority.clone())
            }
        };
        let runtime = Arc::new(ControlPackages {
            query,
            instances,
            authority,
            facts,
            limits,
        });
        *installed = Some(runtime.clone());
        Ok(runtime)
    }
}

impl ControlPackages {
    pub(crate) fn discovery(&self) -> crate::Result<araphor_analysis::DiscoveryOwner> {
        let bundle = Arc::new(
            araphor_data::PackageBundle::try_from(araphor_analysis::Package::discovery_bundle()?)
                .map_err(araphor_data::Error::from)?,
        );
        let packages = self
            .authority
            .tenants
            .keys()
            .map(|tenant| {
                let grant = self.authority.grant(*tenant);
                self.authority.commit(
                    &grant,
                    PackageActionV1::Install,
                    bundle.as_ref(),
                    &mut || {
                        self.query
                            .store()
                            .install_package_image(*tenant, &bundle, || {
                                grant.remaining().map(|_| ())
                            })?;
                        Ok(())
                    },
                )?;
                araphor_analysis::Package::new(
                    self.query.clone(),
                    self.authority.clone(),
                    self.authority.grant(*tenant),
                    Arc::clone(&bundle),
                    "live",
                    "snapshot",
                )
            })
            .collect::<araphor_analysis::Result<Vec<_>>>()?;
        araphor_analysis::DiscoveryOwner::new(packages, Arc::clone(&self.instances))
            .map_err(Into::into)
    }

    pub(crate) fn notifications(
        self: &Arc<Self>,
        config: &crate::NotificationControlConfigV1,
    ) -> crate::Result<()> {
        let mut tenants = self
            .authority
            .tenants
            .keys()
            .copied()
            .chain(config.grants.iter().map(|grant| grant.tenant_id))
            .chain(config.routes.iter().map(|route| route.tenant_id))
            .collect::<BTreeSet<_>>();
        for owner in [
            None,
            Some(araphor_data::NOTIFICATION_ROUTE_OWNER),
            Some(araphor_data::NOTIFICATION_STATE_OWNER),
        ] {
            let mut after = None;
            loop {
                let page = match owner {
                    None => self.query.store().tenant_page(after)?,
                    Some(owner) => self.query.store().context_tenant_page(owner, after)?,
                };
                let Some(last) = page.last().copied() else {
                    break;
                };
                tenants.extend(page);
                after = Some(last);
            }
        }
        let owner = Arc::clone(self);
        let work = async move {
            let control = araphor_data::AnalysisReadControl::default();
            for tenant in tenants {
                if let Some(saved) =
                    owner
                        .query
                        .store()
                        .managed_instance(tenant, "notifications", &control)?
                {
                    if saved.spec.destination != araphor_data::ManagedDestination::Notification {
                        return Err(araphor_data::PackageErrorCodeV1::Conflict
                            .error("notification instance id")
                            .into());
                    }
                    continue;
                }
                let instance = owner
                    .instances
                    .admit_notifications(
                        ControlPackageAuthority::notification_grant(tenant),
                        &control,
                    )
                    .await?;
                let lifecycle = instance.admitted().lifecycle;
                owner.instances.start(instance, lifecycle, &control).await?;
            }
            Ok::<_, crate::Error>(())
        };
        self.query.wait(async move { Ok(work.await) })??;
        Ok(())
    }

    pub(crate) fn bind_client(&self, auth: Arc<crate::ClientAuth>) -> crate::Result<()> {
        let mut client = self.authority.client.write().map_err(|_| {
            crate::error::InvalidConfigurationSnafu {
                reason: "package client authority lock failed",
            }
            .build()
        })?;
        if client
            .as_ref()
            .is_some_and(|current| !Arc::ptr_eq(current, &auth))
        {
            return Err(crate::error::InvalidConfigurationSnafu {
                reason: "analysis packages already use another client authority",
            }
            .build());
        }
        *client = Some(auth);
        Ok(())
    }
}

impl ControlPackageAuthority {
    fn grant(&self, tenant: [u8; 16]) -> PackageGrantV1 {
        PackageGrantV1 {
            principal: "mithril-control".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(tenant),
            expires_utc_ns: None,
            authorization_id: None,
        }
    }

    fn graph_grant(&self, tenant: [u8; 16]) -> Option<PackageGrantV1> {
        let nodes = self
            .tenants
            .get(&tenant)
            .filter(|nodes| !nodes.is_empty())?;
        let mut grant = self.grant(tenant);
        grant.selection.nodes = nodes.clone();
        Some(grant)
    }

    fn notification_grant(tenant: [u8; 16]) -> PackageGrantV1 {
        PackageGrantV1 {
            principal: "mithril-control-notifications".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(tenant),
            expires_utc_ns: None,
            authorization_id: Some("notification-system-v1".into()),
        }
    }

    fn notification(grant: &PackageGrantV1) -> bool {
        grant.selection.tenant_id != [0; 16]
            && *grant == Self::notification_grant(grant.selection.tenant_id)
    }

    fn internal(&self, grant: &PackageGrantV1) -> bool {
        Self::notification(grant)
            || self.tenants.contains_key(&grant.selection.tenant_id)
                && (*grant == self.grant(grant.selection.tenant_id)
                    || self.graph_grant(grant.selection.tenant_id).as_ref() == Some(grant))
    }

    fn denied() -> araphor_data::Error {
        araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Denied,
            field: "package authority",
            location: snafu::Location::default(),
        }
    }
}

impl PackageAuthorization for ControlPackageAuthority {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if self.internal(grant) {
            return if action == PackageActionV1::Remove {
                Err(Self::denied())
            } else {
                Ok(())
            };
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .check(grant, action)
    }

    fn admit(
        &self,
        grant: &PackageGrantV1,
        bundle: &araphor_data::PackageBundle,
    ) -> araphor_data::Result<()> {
        if Self::notification(grant) {
            return Err(Self::denied());
        }
        if self.internal(grant) {
            return if self.pins.contains(bundle.digest()) {
                Ok(())
            } else {
                Err(Self::denied())
            };
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .admit(grant, bundle)
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &araphor_data::PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(&[(grant, action, Some(bundle))], operation)
    }

    fn commit_many(
        &self,
        grants: &[(
            &PackageGrantV1,
            PackageActionV1,
            Option<&araphor_data::PackageBundle>,
        )],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants.is_empty() {
            return Err(Self::denied());
        }
        let mut external = Vec::new();
        for (grant, action, bundle) in grants {
            if self.internal(grant) {
                self.check(grant, *action)?;
                if let Some(bundle) = bundle {
                    self.admit(grant, bundle)?;
                }
            } else {
                external.push((*grant, *action, *bundle));
            }
        }
        if external.is_empty() {
            return operation();
        }
        self.client
            .read()
            .map_err(|_| Self::denied())?
            .as_ref()
            .ok_or_else(Self::denied)?
            .commit_many(&external, operation)
    }

    fn changes_for(&self, grant: &PackageGrantV1) -> tokio::sync::watch::Receiver<u64> {
        if self.internal(grant) {
            self.changes.subscribe()
        } else {
            self.changes()
        }
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.client
            .read()
            .ok()
            .and_then(|client| client.as_ref().map(|client| client.changes()))
            .unwrap_or_else(|| self.changes.subscribe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notification_bootstrap_rejects_other_target(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use araphor_data::AnalysisReadControl;
        use araphor_discovery_definition::{Definition, Program, Source};

        let directory = tempfile::tempdir()?;
        let tenant = [1; 16];
        let control = ControlPlane::with_evidence_directory(
            vec![crate::AllowedNodeIdentity {
                node_id: "node".into(),
                certificate_sha256: "a".repeat(64),
                tenant_id: uuid::Uuid::from_bytes(tenant).to_string(),
            }],
            crate::TrustGenerationV1 {
                generation: 1,
                bundle_digest: "b".repeat(64),
                policy_issuer_sequence_epoch: 0,
                policy_signers: Vec::new(),
            },
            directory.path(),
        )?
        .with_notifications(crate::NotificationControlConfigV1::default())?;
        let packages = control.configured_packages(None, true)?;
        let read = AnalysisReadControl::default();
        let definition = packages
            .query
            .admit_definition(
                tenant,
                Definition {
                    name: "selected-job".into(),
                    description: String::new(),
                    labels: Default::default(),
                    program: Program::Sql {
                        source: Source::Inline {
                            inline: "SELECT 1 AS value".into(),
                        },
                    },
                },
                Arc::new(read.operation()?),
            )
            .await?;
        let data = packages.query.store();
        data.admit_definition(tenant, &definition, || read.check())?;
        let selected = araphor_analysis::Instance::admit(
            Arc::clone(&packages.query),
            packages.authority.clone(),
            packages.authority.grant(tenant),
            "notifications".into(),
            definition,
            &read,
        )
        .await?;
        let saved = selected.admitted().clone();
        assert_eq!(
            saved.spec.destination,
            araphor_data::ManagedDestination::Selected
        );
        let error = packages
            .notifications(&crate::NotificationControlConfigV1::default())
            .err()
            .ok_or("another target must not satisfy notification admission")?;
        assert!(matches!(
            error,
            crate::Error::DataStore { source, .. }
                if matches!(*source, araphor_data::Error::Package {
                    code: araphor_data::PackageErrorCodeV1::Conflict,
                    field: "notification instance id",
                    ..
                })
        ));
        assert_eq!(
            data.managed_instance(tenant, "notifications", &read)?
                .ok_or("retained selected job")?,
            saved
        );
        assert_eq!(
            data.managed_resume(tenant, "notifications", &read)?
                .completed,
            0
        );
        assert!(data
            .managed_history(&saved.grant.selection, "notifications", &read)?
            .is_empty());
        assert!(data
            .definition(tenant, "mithril-control-notifications", None, &read)?
            .is_none());
        Ok(())
    }

    #[test]
    fn notification_scope_is_exact() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let authority = ControlPackageAuthority {
            tenants: BTreeMap::from([([1; 16], vec!["new-node".into()])]),
            pins: BTreeSet::new(),
            client: RwLock::new(None),
            changes: tokio::sync::watch::channel(1).0,
        };
        let grant = ControlPackageAuthority::notification_grant([9; 16]);
        authority.check(&grant, PackageActionV1::Run)?;
        for field in 0..6 {
            let mut altered = grant.clone();
            match field {
                0 => altered.selection.nodes.push("node".into()),
                1 => altered.principal = "public-caller".into(),
                2 => altered.revision += 1,
                3 => altered.authorization_id = None,
                4 => altered.expires_utc_ns = Some(u64::MAX),
                _ => altered.selection.sources = araphor_data::Selection::Exact(Vec::new()),
            }
            assert!(authority.check(&altered, PackageActionV1::Run).is_err());
        }
        let bundle =
            araphor_data::PackageBundle::try_from(araphor_analysis::Package::discovery_bundle()?)?;
        assert!(authority.admit(&grant, &bundle).is_err());
        Ok(())
    }

    #[test]
    fn graph_scope_is_exact() {
        let authority = ControlPackageAuthority {
            tenants: BTreeMap::from([([1; 16], vec!["node-a".into()]), ([2; 16], Vec::new())]),
            pins: BTreeSet::new(),
            client: RwLock::new(None),
            changes: tokio::sync::watch::channel(1).0,
        };
        assert_eq!(
            authority
                .graph_grant([1; 16])
                .map(|grant| grant.selection.nodes),
            Some(vec!["node-a".to_owned()])
        );
        assert!(authority.graph_grant([2; 16]).is_none());
        assert!(authority.graph_grant([3; 16]).is_none());
    }

    #[test]
    fn package_notice_scope() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let client = crate::client_auth::tests::owner()?;
        client.replace_package_managers(vec![crate::InvestigateGrant {
            subject: "alice".into(),
            tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        }])?;
        let session = crate::client_auth::tests::session(&client)?;
        let access = client.browser(
            &session.token,
            [1; 16],
            "https://control.example",
            None,
            false,
        )?;
        let external =
            access.package_grant(AnalysisSelectionV1::tenant([1; 16]), PackageActionV1::Run)?;
        let authority = ControlPackageAuthority {
            tenants: BTreeMap::from([([1; 16], vec!["node-a".into()])]),
            pins: BTreeSet::new(),
            client: RwLock::new(Some(Arc::clone(&client))),
            changes: tokio::sync::watch::channel(1).0,
        };
        let internal = authority.grant([1; 16]);
        authority.check(&internal, PackageActionV1::Run)?;
        authority.check(&external, PackageActionV1::Run)?;
        let internal_notice = authority.changes_for(&internal);
        let external_notice = authority.changes_for(&external);
        assert!(!internal_notice.has_changed()?);
        assert!(!external_notice.has_changed()?);
        assert!(client.revoke_session(&session.token)?);
        assert!(!internal_notice.has_changed()?);
        assert!(external_notice.has_changed()?);
        authority.check(&internal, PackageActionV1::Run)?;
        assert!(matches!(
            authority.check(&external, PackageActionV1::Run),
            Err(araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Denied,
                ..
            })
        ));
        Ok(())
    }
}
