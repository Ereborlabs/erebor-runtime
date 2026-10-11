use araphor_data::{
    AnalysisReadControl, PackageActionV1, PackageErrorCodeV1, PackageRequestV1, PackageResponseV1,
    MAX_PACKAGE_BYTES,
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
        if request.get_ref().definition_json.len() > MAX_PACKAGE_BYTES + 64 * 1024 {
            return Err(Self::package_limit("request bytes"));
        }
        let access = self.authenticate(&request, false).await?;
        let operation: PackageRequestV1 =
            serde_json::from_slice(&request.get_ref().definition_json)
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
        let mut bytes = vec![0; MAX_PACKAGE_BYTES + 64 * 1024];
        let length = {
            let mut writer = std::io::Cursor::new(bytes.as_mut_slice());
            serde_json::to_writer(&mut writer, response)
                .map_err(|_| Self::package_limit("response bytes"))?;
            writer.position() as usize
        };
        bytes.truncate(length);
        Ok(bytes)
    }

    fn package_limit(field: &'static str) -> Status {
        Self::package_status(
            Status::resource_exhausted("The package operation exceeds its byte limit."),
            PackageErrorCodeV1::Limit,
            field,
        )
    }

    fn package_failure(error: araphor_data::Error) -> Status {
        if let araphor_data::Error::Package { code, field, .. } = &error {
            let (code, field) = (*code, *field);
            return Self::package_status(Self::failure(error), code, field);
        }
        Self::failure(error)
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
