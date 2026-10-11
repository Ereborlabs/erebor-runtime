use super::*;

impl AraphorClient {
    pub async fn package_operation(
        &self,
        operation: wire::PackageOperationRequest,
    ) -> AraphorResult<wire::PackageOperationReply> {
        let mut request = self.request(operation)?;
        request.set_timeout(Duration::from_secs(300));
        self.service()
            .package_operation(request)
            .await
            .map(tonic::Response::into_inner)
            .map_err(Self::package_error)
    }

    fn package_error(source: tonic::Status) -> AraphorError {
        if source.details().len() > 1024 {
            return Self::rpc_error(source);
        }
        let details = serde_json::from_slice::<serde_json::Value>(source.details()).ok();
        let fields = details.as_ref().and_then(|details| {
            Some((
                details.get("code")?.as_str()?,
                details.get("field")?.as_str()?,
            ))
        });
        if let Some((code, field)) = fields.filter(|(code, field)| {
            matches!(
                *code,
                "invalid"
                    | "limit"
                    | "denied"
                    | "conflict"
                    | "missing"
                    | "unsupported"
                    | "incomplete"
            ) && !field.is_empty()
                && field.len() <= 256
                && !field.chars().any(char::is_control)
        }) {
            return AraphorError::Rpc {
                source: Box::new(source),
                detail: format!(": Package {code}: {field}."),
                location: snafu::Location::default(),
            };
        }
        Self::rpc_error(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_failure_safe_fields() {
        let details = br#"{"code":"invalid","field":"output schema"}"#;
        let status = tonic::Status::with_details(
            tonic::Code::InvalidArgument,
            "The package operation failed.",
            details.as_slice().into(),
        );
        let error = AraphorClient::package_error(status);
        assert!(error
            .to_string()
            .contains("Package invalid: output schema."));
        for details in [
            br#"{"code":"invalid","field":"output\nschema"}"#.as_slice(),
            br#"{"code":"raw_sql","field":"SELECT secret"}"#.as_slice(),
        ] {
            let status = tonic::Status::with_details(
                tonic::Code::InvalidArgument,
                "The package operation failed.",
                details.to_vec().into(),
            );
            let message = AraphorClient::package_error(status).to_string();
            assert!(!message.contains("SELECT secret"));
            assert!(!message.contains("output\nschema"));
        }
    }
}
