use araphor_data::{
    AnalysisReadControl, PackageActionV1, PackageErrorCodeV1, PackageRequestV1, PackageResponseV1,
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
        let response = self
            .data()?
            .packages
            .execute(grant, operation, control)
            .await
            .map_err(Self::package_failure)?;
        access.check().map_err(Self::auth_failure)?;
        let result_json = Self::package_response(&response)?;
        Ok(proto::PackageOperationReply { result_json })
    }

    pub(super) fn package_response(response: &PackageResponseV1) -> Result<Vec<u8>, Status> {
        serde_json::to_vec(response)
            .map_err(|_| Status::internal("The package response cannot be encoded."))
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
