use std::sync::Arc;

use araphor_data::{
    AnalysisReadControl, ManagedRequest, PackageGrantV1, PackageRequestV1, PackageResponseV1,
};
use araphor_discovery_definition::ResolvedDefinition;
use araphor_query::execution::Engine;
use araphor_query::follow::{Clock as _, SystemClock};

use super::{Code, Instance, InstanceHost};
use crate::Result;

impl InstanceHost {
    pub async fn execute(
        self: &Arc<Self>,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        let action = request.action();
        grant.remaining()?;
        self.authority.check(&grant, action)?;
        control.check()?;
        let query = Arc::clone(&self.query);
        let authority = Arc::clone(&self.authority);
        let response = async {
            Ok(match &request {
                PackageRequestV1::AdmitInstance {
                    instance_id,
                    definition_name,
                    definition_revision,
                } => {
                    let definition = self
                        .request_definition(&grant, definition_name, definition_revision, control)
                        .await?;
                    let instance = Instance::admit(
                        query,
                        authority,
                        grant.clone(),
                        instance_id.clone(),
                        definition,
                        control,
                    )
                    .await?;
                    self.request_status(&grant, &instance.admitted.spec.id, control)
                        .await?
                }
                PackageRequestV1::RenewInstance {
                    instance_id,
                    expected_lifecycle,
                } => {
                    let owner = self
                        .renew(
                            grant.clone(),
                            instance_id.clone(),
                            *expected_lifecycle,
                            control,
                        )
                        .await?;
                    self.request_status(&grant, &owner.admitted.spec.id, control)
                        .await?
                }
                lifecycle @ (PackageRequestV1::StartInstance {
                    instance_id,
                    expected_lifecycle,
                }
                | PackageRequestV1::StopInstance {
                    instance_id,
                    expected_lifecycle,
                }
                | PackageRequestV1::RunInstance {
                    instance_id,
                    expected_lifecycle,
                    ..
                }
                | PackageRequestV1::UpdateInstance {
                    instance_id,
                    expected_lifecycle,
                    ..
                }
                | PackageRequestV1::RollbackInstance {
                    instance_id,
                    expected_lifecycle,
                    ..
                }) => {
                    let request = lifecycle.clone();
                    let id = instance_id.clone();
                    let expected = *expected_lifecycle;
                    let grant = grant.clone();
                    self.run_lifecycle(grant.clone(), control, move |host, read| async move {
                        let control = read.as_ref();
                        let current = host.current_for(&grant, &id, expected, &read).await?;
                        let instance = host.restore_current(current, &read).await?;
                        let instance = match request {
                            PackageRequestV1::StartInstance { .. } => {
                                host.set_running(
                                    instance,
                                    expected,
                                    true,
                                    Some(grant.clone()),
                                    control,
                                )
                                .await?
                            }
                            PackageRequestV1::StopInstance { .. } => {
                                host.set_running(
                                    instance,
                                    expected,
                                    false,
                                    Some(grant.clone()),
                                    control,
                                )
                                .await?
                            }
                            PackageRequestV1::RunInstance {
                                evaluation_id,
                                rebuild,
                                ..
                            } => {
                                let running = instance.admitted.running;
                                let pause = host
                                    .pause_and_join(&instance.admitted, Arc::clone(&read))
                                    .await?;
                                let request = ManagedRequest {
                                    id: evaluation_id,
                                    time_utc_ns: SystemClock::default().now_ns()?,
                                    seed: None,
                                    rebuild,
                                    witness_expiry: u64::MAX,
                                    frontier: None,
                                };
                                let result = instance.run_for(request, Some(grant), &read).await;
                                if result.is_ok() && running {
                                    pause.resume(instance).await;
                                } else {
                                    pause.release(None).await;
                                }
                                return Ok(PackageResponseV1::History(vec![result?]));
                            }
                            PackageRequestV1::UpdateInstance {
                                definition_name,
                                definition_revision,
                                rebuild,
                                ..
                            } => {
                                let definition = host
                                    .request_definition(
                                        &grant,
                                        &definition_name,
                                        &definition_revision,
                                        control,
                                    )
                                    .await?;
                                host.change_version(
                                    instance,
                                    expected,
                                    super::version::Target::Definition(definition),
                                    rebuild,
                                    u64::MAX,
                                    (control, Some(grant.clone())),
                                )
                                .await?
                            }
                            PackageRequestV1::RollbackInstance {
                                generation,
                                rebuild,
                                ..
                            } => {
                                host.change_version(
                                    instance,
                                    expected,
                                    super::version::Target::Retained(generation),
                                    rebuild,
                                    u64::MAX,
                                    (control, Some(grant.clone())),
                                )
                                .await?
                            }
                            _ => {
                                return Err(Code::Unsupported
                                    .error("instance lifecycle operation")
                                    .into())
                            }
                        };
                        host.request_status(&grant, &instance.admitted.spec.id, control)
                            .await
                    })
                    .await?
                }
                PackageRequestV1::RemoveInstance {
                    instance_id,
                    expected_lifecycle,
                } => {
                    let removed = self
                        .remove(
                            grant.clone(),
                            instance_id.clone(),
                            *expected_lifecycle,
                            control,
                        )
                        .await?;
                    self.request_status(&grant, &removed.spec.id, control)
                        .await?
                }
                PackageRequestV1::RecreateInstance {
                    instance_id,
                    expected_lifecycle,
                    definition_name,
                    definition_revision,
                } => {
                    let definition = self
                        .request_definition(&grant, definition_name, definition_revision, control)
                        .await?;
                    let recreated = self
                        .recreate(
                            grant.clone(),
                            instance_id.clone(),
                            *expected_lifecycle,
                            definition,
                            control,
                        )
                        .await?;
                    self.request_status(&grant, &recreated.admitted.spec.id, control)
                        .await?
                }
                PackageRequestV1::InspectInstance { instance_id } => PackageResponseV1::Instance(
                    Instance::read_status(query, authority, grant.clone(), instance_id, control)
                        .await?
                        .try_into()?,
                ),
                PackageRequestV1::InspectInstanceHistory { instance_id } => {
                    PackageResponseV1::History(
                        Instance::read_history(
                            query,
                            authority,
                            grant.clone(),
                            instance_id,
                            control,
                        )
                        .await?,
                    )
                }
                PackageRequestV1::ReadInstanceResult {
                    instance_id,
                    result_id,
                } => {
                    Instance::read_output(
                        query,
                        authority,
                        grant.clone(),
                        instance_id,
                        result_id,
                        control,
                    )
                    .await?
                }
                PackageRequestV1::QueryInstanceResult {
                    instance_id,
                    result_id,
                    sql,
                } => {
                    let output = Instance::query_result(
                        query,
                        authority,
                        grant.clone(),
                        instance_id,
                        result_id.as_deref(),
                        sql,
                        control,
                    )
                    .await?;
                    Engine::blocking(Arc::new(control.within(None)?), (), move || {
                        PackageResponseV1::try_from(&output.data).map_err(Into::into)
                    })
                    .await?
                }
                _ => return Err(Code::Unsupported.error("instance operation").into()),
            })
        }
        .await;
        grant.remaining()?;
        self.authority.check(&grant, action)?;
        control.check()?;
        response
    }

    async fn request_status(
        &self,
        grant: &PackageGrantV1,
        id: &str,
        control: &AnalysisReadControl,
    ) -> Result<PackageResponseV1> {
        let store = Arc::clone(self.query.store());
        let selected = grant.selection.clone();
        let id = id.to_owned();
        let read = Arc::new(control.within(grant.remaining()?)?);
        let stage = Arc::clone(&read);
        let status = Engine::blocking(read, (), move || {
            store
                .managed_status(&selected, &id, &stage)
                .map_err(Into::into)
        })
        .await?;
        Ok(PackageResponseV1::Instance(status.try_into()?))
    }

    async fn request_definition(
        &self,
        grant: &PackageGrantV1,
        name: &str,
        revision: &str,
        control: &AnalysisReadControl,
    ) -> Result<ResolvedDefinition> {
        let store = Arc::clone(self.query.store());
        let tenant = grant.selection.tenant_id;
        let (name, revision) = (name.to_owned(), revision.to_owned());
        let read = Arc::new(control.within(grant.remaining()?)?);
        let stage = Arc::clone(&read);
        Ok(Engine::blocking(read, (), move || {
            store
                .definition(tenant, &name, Some(&revision), &stage)?
                .ok_or_else(|| Code::Missing.error("discovery definition").into())
        })
        .await?)
    }
}
