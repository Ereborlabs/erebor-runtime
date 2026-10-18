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
        let control = Arc::new(
            AnalysisReadControl::with_timeout(Duration::from_secs(300)).map_err(Self::failure)?,
        );
        let _guard = PackageRunGuard(control.clone());
        let response = match operation {
            image @ (PackageRequestV1::InstallImage { .. }
            | PackageRequestV1::InspectImage { .. }) => {
                self.image_request(grant, image, control).await?
            }
            operation => self
                .data()?
                .packages
                .execute(grant, operation, control)
                .await
                .map_err(Self::package_failure)?,
        };
        access.check().map_err(Self::auth_failure)?;
        let result_json = Self::package_response(&response)?;
        Ok(proto::PackageOperationReply { result_json })
    }

    pub(super) fn package_response(response: &PackageResponseV1) -> Result<Vec<u8>, Status> {
        serde_json::to_vec(response)
            .map_err(|_| Status::internal("The package response cannot be encoded."))
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
            Ok(PackageResponseV1 {
                scope_id: String::new(),
                package_id: image.root.package_id.clone(),
                image: Some(image),
                exports: Vec::new(),
                tests: Vec::new(),
                output: None,
            })
        })
        .await
        .map_err(|_| Status::internal("The image task failed."))?
        .map_err(Self::image_failure)
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

    fn package_failure(error: araphor_analysis_back::Error) -> Status {
        let details = match &error {
            araphor_analysis_back::Error::Data {
                source: araphor_data::Error::Package { code, field, .. },
            } => Some((*code, *field)),
            araphor_analysis_back::Error::PackageNative {
                code, operation, ..
            } => Some((*code, *operation)),
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
