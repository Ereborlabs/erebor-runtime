use super::{InterceptionOperation, InterceptionRequest};

impl InterceptionRequest {
    #[must_use]
    pub fn operation_family(&self) -> InterceptionOperation {
        let operation = InterceptionOperation::try_from(self.operation)
            .unwrap_or(InterceptionOperation::Unspecified);
        if operation == InterceptionOperation::Unspecified && self.has_legacy_process_exec_fields()
        {
            InterceptionOperation::ProcessExec
        } else {
            operation
        }
    }

    fn has_legacy_process_exec_fields(&self) -> bool {
        !self.executable.is_empty() || !self.argv.is_empty() || !self.matched_handler_id.is_empty()
    }
}

#[must_use]
pub const fn operation_name(operation: InterceptionOperation) -> &'static str {
    match operation {
        InterceptionOperation::Unspecified => "unspecified",
        InterceptionOperation::ProcessExec => "process_exec",
        InterceptionOperation::FileOpen => "file_open",
        InterceptionOperation::FileRead => "file_read",
        InterceptionOperation::FileMutation => "file_mutation",
        InterceptionOperation::SocketConnect => "socket_connect",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_process_exec_fields_infer_process_exec_operation() {
        let request = InterceptionRequest {
            executable: String::from("tool"),
            argv: vec![String::from("tool")],
            ..InterceptionRequest::default()
        };

        assert_eq!(
            request.operation_family(),
            InterceptionOperation::ProcessExec
        );
    }

    #[test]
    fn explicit_file_operation_is_not_process_exec() {
        let request = InterceptionRequest {
            operation: InterceptionOperation::FileRead as i32,
            executable: String::from("legacy-tool"),
            ..InterceptionRequest::default()
        };

        assert_eq!(request.operation_family(), InterceptionOperation::FileRead);
    }
}
