use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, PackageActionV1, PackageAuthorization as _,
    PackageBundleRef, PackageErrorCodeV1, PackageGrantV1, PackageRequestV1, PackageResponseV1,
};

use super::*;

struct PackageRunGuard(Arc<AnalysisReadControl>);

impl Drop for PackageRunGuard {
    fn drop(&mut self) {
        let _cancelled = self.0.cancel();
    }
}

impl ClientGrpcOwner {
    pub(super) async fn package_request(
        &self,
        request: Request<proto::PackageOperationRequest>,
    ) -> Result<proto::PackageOperationReply, Status> {
        let access = self.authenticate(&request, false).await?;
        let operation: PackageRequestV1 =
            PackageRequestV1::from_bytes(&request.get_ref().definition)
                .map_err(|_| Status::invalid_argument("The package request is invalid."))?;
        let action = operation.action();
        if action != PackageActionV1::Inspect {
            self.authenticate(&request, true).await?;
        }
        let selection = self.select(request.into_inner().selection, access.tenant_id())?;
        let grant = access
            .package_grant(selection, action)
            .map_err(Self::auth_failure)?;
        let changes = (action == PackageActionV1::Test).then(|| self.auth.changes_for(&grant));
        let control = Arc::new(AnalysisReadControl::default());
        let _guard = PackageRunGuard(control.clone());
        let response = match operation {
            definition @ (PackageRequestV1::AdmitDefinition { .. }
            | PackageRequestV1::InspectDefinition { .. }) => {
                self.definition_request(grant.clone(), definition, control.clone())
                    .await?
            }
            instance @ (PackageRequestV1::InspectInstance { .. }
            | PackageRequestV1::InspectInstanceHistory { .. }
            | PackageRequestV1::ReadInstanceResult { .. }
            | PackageRequestV1::QueryInstanceResult { .. }) => {
                self.instance_request(grant.clone(), instance, control.clone())
                    .await?
            }
            image @ (PackageRequestV1::InstallImage { .. }
            | PackageRequestV1::InspectImage { .. }
            | PackageRequestV1::TestImage { .. }) => {
                self.image_request(grant.clone(), image, control.clone())
                    .await?
            }
        };
        let result = araphor_query::execution::Engine::blocking(control.clone(), (), move || {
            Ok(Self::package_response(&response))
        })
        .await
        .map_err(Self::failure)??;
        control.check().map_err(Self::failure)?;
        grant.remaining().map_err(Self::image_failure)?;
        self.auth
            .check(&grant, action)
            .map_err(Self::image_failure)?;
        access.check().map_err(Self::auth_failure)?;
        if changes
            .as_ref()
            .is_some_and(|changes| changes.has_changed().unwrap_or(true))
        {
            return Err(Self::image_failure(
                PackageErrorCodeV1::Denied.error("package authority changed"),
            ));
        }
        Ok(proto::PackageOperationReply { result })
    }

    pub(super) fn package_response(response: &PackageResponseV1) -> Result<Vec<u8>, Status> {
        response.encode().map_err(Self::image_failure)
    }

    async fn definition_request(
        &self,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PackageResponseV1, Status> {
        if grant.selection != AnalysisSelectionV1::tenant(grant.selection.tenant_id) {
            return Err(Status::invalid_argument(
                "A definition requires tenant selection.",
            ));
        }
        let store = self.data()?.store.clone();
        let query = self.data()?.query.clone();
        let authority = self.auth.clone();
        let action = request.action();
        grant.remaining().map_err(Self::image_failure)?;
        authority
            .check(&grant, action)
            .map_err(Self::image_failure)?;
        control.check().map_err(Self::failure)?;
        let definition = match request {
            PackageRequestV1::AdmitDefinition { definition } => {
                definition
                    .validate_captured()
                    .map_err(araphor_data::Error::from)
                    .map_err(Self::image_failure)?;
                let tenant = grant.selection.tenant_id;
                let admitted = control
                    .query_async(query.admit_definition(tenant, definition, Arc::clone(&control)))
                    .await
                    .map_err(Self::failure)?;
                let check = control.clone();
                let grant = grant.clone();
                let authority = authority.clone();
                tokio::task::spawn_blocking(move || -> araphor_data::Result<_> {
                    authority.commit_definition(&grant, &admitted, || {
                        store.admit_definition(grant.selection.tenant_id, &admitted, || {
                            grant.remaining()?;
                            check.check()
                        })
                    })?;
                    Ok(admitted)
                })
                .await
                .map_err(|_| Status::internal("The definition admission failed."))?
                .map_err(Self::image_failure)?
            }
            PackageRequestV1::InspectDefinition { name, revision } => {
                let check = control.clone();
                let tenant = grant.selection.tenant_id;
                tokio::task::spawn_blocking(move || {
                    store
                        .definition(tenant, &name, revision.as_deref(), &check)?
                        .ok_or_else(|| PackageErrorCodeV1::Missing.error("discovery definition"))
                })
                .await
                .map_err(|_| Status::internal("The definition inspection failed."))?
                .map_err(Self::image_failure)?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "The definition operation is invalid.",
                ));
            }
        };
        grant.remaining().map_err(Self::image_failure)?;
        authority
            .check(&grant, action)
            .map_err(Self::image_failure)?;
        control.check().map_err(Self::failure)?;
        Ok(PackageResponseV1::Definition(definition))
    }

    async fn image_request(
        &self,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PackageResponseV1, Status> {
        if grant.selection != AnalysisSelectionV1::tenant(grant.selection.tenant_id) {
            return Err(Status::invalid_argument(
                "An image requires tenant selection.",
            ));
        }
        if let PackageRequestV1::TestImage { image, fixture } = request {
            return araphor_analysis::Qualification::new(
                self.data()?.query.clone(),
                self.auth.clone(),
            )
            .run(&grant, &image, fixture.as_deref(), &control)
            .await
            .map(PackageResponseV1::Tests)
            .map_err(Self::failure);
        }
        let store = self.data()?.store.clone();
        let authority = self.auth.clone();
        tokio::task::spawn_blocking(move || -> araphor_data::Result<PackageResponseV1> {
            let action = request.action();
            grant.remaining()?;
            authority.check(&grant, action)?;
            control.check()?;
            let image = match request {
                PackageRequestV1::InstallImage { bundle } => {
                    let image = bundle.metadata()?;
                    let retained = PackageBundleRef::retained(&bundle, &image.digest);
                    authority.admit(&grant, &retained)?;
                    authority.commit(&grant, action, &retained, &mut || {
                        store.install_package_image(grant.selection.tenant_id, &bundle, || {
                            grant.remaining()?;
                            control.check()
                        })?;
                        Ok(())
                    })?;
                    image
                }
                PackageRequestV1::InspectImage {
                    package_id,
                    revision,
                } => {
                    araphor_data::validate_package_name(&package_id)?;
                    store
                        .package_image(
                            grant.selection.tenant_id,
                            &package_id,
                            revision.as_deref(),
                            &control,
                        )?
                        .ok_or_else(|| PackageErrorCodeV1::Missing.error("package image"))?
                        .metadata()?
                }
                _ => return Err(PackageErrorCodeV1::Unsupported.error("image operation")),
            };
            grant.remaining()?;
            authority.check(&grant, action)?;
            control.check()?;
            Ok(PackageResponseV1::Image(image))
        })
        .await
        .map_err(|_| Status::internal("The image task failed."))?
        .map_err(Self::image_failure)
    }

    async fn instance_request(
        &self,
        grant: PackageGrantV1,
        request: PackageRequestV1,
        control: Arc<AnalysisReadControl>,
    ) -> Result<PackageResponseV1, Status> {
        let query = self.data()?.query.clone();
        let response = match request {
            PackageRequestV1::InspectInstance { instance_id } => {
                let status = araphor_analysis::Instance::read_status(
                    query,
                    self.auth.clone(),
                    grant.clone(),
                    &instance_id,
                    &control,
                )
                .await
                .map_err(Self::failure)?;
                PackageResponseV1::Instance(status.try_into().map_err(Self::image_failure)?)
            }
            PackageRequestV1::InspectInstanceHistory { instance_id } => {
                let history = araphor_analysis::Instance::read_history(
                    query,
                    self.auth.clone(),
                    grant.clone(),
                    &instance_id,
                    &control,
                )
                .await
                .map_err(Self::failure)?;
                PackageResponseV1::History(history)
            }
            PackageRequestV1::ReadInstanceResult {
                instance_id,
                result_id,
            } => {
                let result = araphor_analysis::Instance::read_output(
                    query,
                    self.auth.clone(),
                    grant.clone(),
                    &instance_id,
                    &result_id,
                    &control,
                )
                .await
                .map_err(Self::failure)?;
                PackageResponseV1::Result(Box::new(result))
            }
            PackageRequestV1::QueryInstanceResult {
                instance_id,
                result_id,
                sql,
            } => {
                let output = araphor_analysis::Instance::query_result(
                    query,
                    self.auth.clone(),
                    grant.clone(),
                    &instance_id,
                    &result_id,
                    &sql,
                    &control,
                )
                .await
                .map_err(Self::failure)?;
                araphor_query::execution::Engine::blocking(control.clone(), (), move || {
                    PackageResponseV1::try_from(&output.data).map_err(Into::into)
                })
                .await
                .map_err(Self::failure)?
            }
            _ => {
                return Err(Status::invalid_argument(
                    "The instance operation is invalid.",
                ))
            }
        };
        grant.remaining().map_err(Self::image_failure)?;
        self.auth
            .check(&grant, PackageActionV1::Inspect)
            .map_err(Self::image_failure)?;
        control.check().map_err(Self::failure)?;
        Ok(response)
    }

    fn image_failure(error: araphor_data::Error) -> Status {
        let details = match &error {
            araphor_data::Error::Package { code, field, .. } => Some((*code, *field)),
            _ => None,
        };
        let status = Self::failure(error);
        match details {
            Some((code, field)) => Self::package_status(status, code, field),
            None => status,
        }
    }

    fn package_status(status: Status, code: PackageErrorCodeV1, field: &str) -> Status {
        match serde_json::to_vec(&serde_json::json!({"code": code, "field": field})) {
            Ok(details) => Status::with_details(
                status.code(),
                "The package operation failed.",
                details.into(),
            ),
            Err(_) => status,
        }
    }
}
