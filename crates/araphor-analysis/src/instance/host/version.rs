use std::collections::BTreeMap;
use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, ManagedDestination, ManagedInstance, ManagedSpec, PackageActionV1,
    PackageAuthorization, PackageGrantV1,
};
use araphor_discovery_definition::ResolvedDefinition;
use araphor_query::definition::PreparedDefinition;
use araphor_query::execution::{Engine, Session};
use araphor_query::follow::{Clock as _, SystemClock};
use datafusion::execution::memory_pool::MemoryReservation;
use datafusion::logical_expr::LogicalPlan;

use super::{Code, Instance, InstanceHost};
use crate::instance::sink;
use crate::Result;

pub(super) enum Target {
    Definition(ResolvedDefinition),
    Retained(u64),
}

impl Target {
    fn action(&self) -> PackageActionV1 {
        match self {
            Self::Definition(_) => PackageActionV1::Update,
            Self::Retained(_) => PackageActionV1::Rollback,
        }
    }
}

struct PreparedVersion {
    session: Session,
    prepared: PreparedDefinition,
    spec: ManagedSpec,
    calls: BTreeMap<u64, LogicalPlan>,
    graph: Option<Arc<crate::GraphPublication>>,
    metadata: MemoryReservation,
}

impl PreparedVersion {
    fn instantiate(
        self,
        authority: Arc<dyn PackageAuthorization>,
        admitted: ManagedInstance,
    ) -> Arc<Instance> {
        Arc::new(Instance {
            query: Arc::clone(self.session.engine()),
            authority,
            admitted,
            prepared: self.prepared,
            session: self.session,
            graph: self.graph,
            calls: self.calls,
            _metadata: self.metadata,
        })
    }
}

impl InstanceHost {
    pub async fn update(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        definition: ResolvedDefinition,
        rebuild: bool,
        witness_expiry: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        self.change_version(
            instance,
            expected_lifecycle,
            Target::Definition(definition),
            rebuild,
            witness_expiry,
            (control, None),
        )
        .await
    }

    pub async fn rollback(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        generation: u64,
        rebuild: bool,
        witness_expiry: u64,
        control: &AnalysisReadControl,
    ) -> Result<Arc<Instance>> {
        self.change_version(
            instance,
            expected_lifecycle,
            Target::Retained(generation),
            rebuild,
            witness_expiry,
            (control, None),
        )
        .await
    }

    pub(super) async fn change_version(
        self: &Arc<Self>,
        instance: Arc<Instance>,
        expected_lifecycle: u64,
        target: Target,
        rebuild: bool,
        witness_expiry: u64,
        authorization: (&AnalysisReadControl, Option<PackageGrantV1>),
    ) -> Result<Arc<Instance>> {
        let (control, caller) = authorization;
        if !Arc::ptr_eq(&instance.query, &self.query) {
            return Err(Code::Conflict.error("managed host query owner").into());
        }
        if instance.admitted.spec.destination == ManagedDestination::Notification {
            return Err(Code::Unsupported
                .error("notification managed version")
                .into());
        }
        let action = target.action();
        let actions: &'static [_] = if action == PackageActionV1::Rollback {
            &[
                PackageActionV1::Run,
                PackageActionV1::Update,
                PackageActionV1::Rollback,
            ]
        } else {
            &[PackageActionV1::Run, PackageActionV1::Update]
        };
        self.run_lifecycle(
            instance.admitted.grant.clone(),
            control,
            move |host, operation| async move {
                host.authority.check(&instance.admitted.grant, action)?;
                if action != PackageActionV1::Update {
                    host.authority
                        .check(&instance.admitted.grant, PackageActionV1::Update)?;
                }
                let current = Self::version_current(
                    Arc::clone(&instance),
                    expected_lifecycle,
                    Arc::clone(&operation),
                )
                .await?;
                let prepared = host
                    .prepare_version(&instance, &current, target, &operation)
                    .await?;
                let current = if prepared.spec == current.spec {
                    let selected = Arc::clone(&instance);
                    let stage = Arc::clone(&operation);
                    let authority = Arc::clone(&host.authority);
                    let actor = caller.clone();
                    let (prepared, current) =
                        Engine::blocking(Arc::clone(&operation), (), move || {
                            Instance::authorize_actions_for(
                                authority.as_ref(),
                                &selected.admitted.grant,
                                &prepared.prepared,
                                actions,
                                actor.as_ref().map(|grant| (grant, action, stage.as_ref())),
                                || selected.current_lifecycle(expected_lifecycle, &stage),
                            )
                            .map(|current| (prepared, current))
                            .map_err(Into::into)
                        })
                        .await?;
                    prepared.instantiate(Arc::clone(&host.authority), current)
                } else {
                    let pause = host
                        .pause_and_join(&current, Arc::clone(&operation))
                        .await?;
                    let result = async {
                        let expected = Self::version_current(
                            Arc::clone(&instance),
                            expected_lifecycle,
                            Arc::clone(&operation),
                        )
                        .await?;
                        let authority = Arc::clone(&host.authority);
                        let actor = caller.clone();
                        let stage = Arc::clone(&operation);
                        let store = Arc::clone(host.query.store());
                        let (prepared, admitted, expected) =
                            Engine::blocking(Arc::clone(&operation), (), move || {
                                let admitted = Instance::authorize_actions_for(
                                    authority.as_ref(),
                                    &expected.grant,
                                    &prepared.prepared,
                                    actions,
                                    actor.as_ref().map(|grant| (grant, action, stage.as_ref())),
                                    || {
                                        store.prepare_managed_version(
                                            &expected,
                                            &prepared.spec,
                                            || stage.check(),
                                        )
                                    },
                                )?;
                                Ok((prepared, admitted, expected))
                            })
                            .await?;
                        let candidate = prepared.instantiate(Arc::clone(&host.authority), admitted);
                        let time = SystemClock::default().now_ns()?;
                        candidate
                            .execute_step(
                                sink::Operation::Version {
                                    expected,
                                    rebuild,
                                    action,
                                    caller: caller.clone(),
                                },
                                time,
                                witness_expiry,
                                &operation,
                            )
                            .await?;
                        Self::version_result(candidate, Arc::clone(&operation)).await
                    }
                    .await;
                    if let Ok(retained) = &result {
                        let bound = retained.graph.as_ref().is_none_or(|graph| {
                            host.graph_facts
                                .as_ref()
                                .is_some_and(|facts| graph.uses_facts(facts))
                        });
                        if retained.admitted.running
                            && bound
                            && Arc::ptr_eq(&retained.authority, &host.authority)
                        {
                            pause.resume(Arc::clone(retained)).await;
                        } else {
                            pause.release(None).await;
                        }
                    } else {
                        drop(pause);
                    }
                    result?
                };
                Instance::authorize_actions_for(
                    host.authority.as_ref(),
                    &current.admitted.grant,
                    &current.prepared,
                    actions,
                    caller
                        .as_ref()
                        .map(|grant| (grant, action, operation.as_ref())),
                    || {
                        operation.check()?;
                        Ok(Arc::clone(&current))
                    },
                )
                .map_err(crate::Error::from)
            },
        )
        .await
    }

    async fn version_current(
        instance: Arc<Instance>,
        expected: u64,
        control: Arc<AnalysisReadControl>,
    ) -> Result<ManagedInstance> {
        let stage = Arc::clone(&control);
        Ok(Engine::blocking(control, (), move || {
            instance
                .current_lifecycle(expected, &stage)
                .map_err(Into::into)
        })
        .await?)
    }

    async fn prepare_version(
        &self,
        instance: &Instance,
        current: &ManagedInstance,
        target: Target,
        control: &Arc<AnalysisReadControl>,
    ) -> Result<PreparedVersion> {
        let retained = match target {
            Target::Retained(generation) => {
                let store = Arc::clone(self.query.store());
                let tenant = current.spec.tenant;
                let id = current.spec.id.clone();
                let stage = Arc::clone(control);
                Some(
                    Engine::blocking(Arc::clone(control), (), move || {
                        store
                            .managed_version(tenant, &id, generation, &stage)
                            .map_err(Into::into)
                    })
                    .await?,
                )
            }
            Target::Definition(_) => None,
        };
        let definition = match target {
            Target::Definition(definition) => definition,
            Target::Retained(_) => retained
                .as_ref()
                .ok_or_else(|| Code::Incomplete.error("managed retained target"))?
                .definition
                .clone(),
        };
        definition.validate().map_err(araphor_data::Error::from)?;
        let destination = retained
            .as_ref()
            .map_or(&current.spec.destination, |spec| &spec.destination)
            .clone();
        let (session, prepared, destination, graph) =
            if matches!(&destination, ManagedDestination::Graph { .. }) {
                crate::GraphPublication::prepare_managed(
                    Arc::clone(&self.query),
                    Arc::clone(&self.authority),
                    self.graph_facts.clone(),
                    &current.grant,
                    definition,
                    destination,
                    control,
                )
                .await?
            } else {
                let selection = destination.selection(&current.grant.selection)?;
                let session = if instance.session.selection() == &selection {
                    instance.session.operation(control, 0)?
                } else {
                    self.query
                        .session_on(selection, control, 0, self.query.memory().scope())?
                };
                let prepared = session.prepare_resolved(&definition).await?;
                if prepared.resolved() != &definition {
                    return Err(Code::Conflict.error("managed update definition pin").into());
                }
                (session, prepared, destination, None)
            };
        let authority = Arc::clone(&self.authority);
        let stage = Arc::clone(control);
        let store = Arc::clone(self.query.store());
        let current = current.clone();
        let memory = Arc::clone(session.memory());
        Engine::blocking(Arc::clone(control), (), move || {
            authority.check(&current.grant, PackageActionV1::Run)?;
            for bundle in prepared.images() {
                authority.admit(&current.grant, bundle)?;
            }
            let digest = prepared
                .resolved()
                .digest()
                .map_err(araphor_data::Error::from)?;
            if store.definition(
                current.spec.tenant,
                &prepared.resolved().definition.name,
                Some(&digest),
                &stage,
            )? != Some(prepared.resolved().clone())
            {
                return Err(Code::Missing.error("managed definition pin").into());
            }
            let (manifest, calls) = Instance::manifest(&prepared)?;
            let spec = ManagedSpec {
                tenant: current.spec.tenant,
                id: current.spec.id.clone(),
                definition: prepared.resolved().clone(),
                manifest,
                destination,
            };
            if retained.as_ref().is_some_and(|retained| retained != &spec) {
                return Err(Code::Conflict.error("managed rollback pin").into());
            }
            let measure = ManagedInstance {
                spec: spec.clone(),
                ..current
            };
            let metadata = memory
                .reserve_input(Instance::metadata_bytes(&measure, &calls)?)
                .map_err(|source| araphor_query::Error::Sql { source })?;
            stage.check()?;
            Ok(PreparedVersion {
                session,
                prepared,
                spec,
                calls,
                graph,
                metadata,
            })
        })
        .await
        .map_err(Into::into)
    }

    async fn version_result(
        candidate: Arc<Instance>,
        control: Arc<AnalysisReadControl>,
    ) -> Result<Arc<Instance>> {
        let store = Arc::clone(candidate.query.store());
        let tenant = candidate.admitted.spec.tenant;
        let id = candidate.admitted.spec.id.clone();
        let stage = Arc::clone(&control);
        let current = Engine::blocking(control, (), move || {
            store
                .managed_instance(tenant, &id, &stage)?
                .ok_or_else(|| Code::Missing.error("managed updated instance").into())
        })
        .await?;
        let mut candidate = Arc::try_unwrap(candidate)
            .map_err(|_| Code::Incomplete.error("managed update worker join"))?;
        if current.spec != candidate.admitted.spec
            || current.grant != candidate.admitted.grant
            || current.generation != candidate.admitted.generation
        {
            return Err(Code::Conflict.error("managed updated version").into());
        }
        candidate.admitted = current;
        Ok(Arc::new(candidate))
    }
}
