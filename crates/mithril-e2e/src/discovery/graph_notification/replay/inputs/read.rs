use super::*;

impl ReplayQualification {
    pub(in super::super) fn completion_inputs(
        &self,
        source_id: u8,
        name: &str,
        path: GraphReadPathV1,
        operation: KernelEffectOperationV1,
        completion: Option<(i64, u64)>,
    ) -> std::result::Result<(DiscoveryRecordV1, DiscoveryRecordV1, GraphFactV1), Box<dyn StdError>>
    {
        let mut raw = GraphNotificationQualification::native(1, false);
        raw.operation = operation as u16;
        let mut channel = GraphNotificationQualification::native(2, false);
        channel.effect_family = KernelEffectFamilyV1::Network as u16;
        channel.operation = KernelEffectOperationV1::Send as u16;
        let source = self.accept(source_id, &[raw, channel])?;
        let read = self.record(&source, 1)?;
        let network = self.record(&source, 2)?;
        let object: [u8; 16] = read.decode()?.exact_object_id.as_ref().try_into()?;
        let socket: [u8; 16] = network.decode()?.exact_object_id.as_ref().try_into()?;
        self.policy(&read)?;
        self.policy(&network)?;
        self.inputs.insert(
            GraphFactV1 {
                record_id: read.id.clone(),
                value: GraphFactValueV1::Credential {
                    object_id: object,
                    expected_access: false,
                    reviewed_policy_revision: "recorded-reviewed-source".into(),
                    completion: completion.map(|(result, byte_count)| GraphReadCompletionV1 {
                        admission_record: read.id.clone(),
                        owner: "recorded-read-completion".into(),
                        completion_id: name.into(),
                        task_cookie: 7,
                        process_instance_id: [8; 16],
                        object_id: object,
                        file_description_id: "fd-lifetime".into(),
                        path,
                        result,
                        byte_count,
                        credential_lease_id: Some("recorded-lease".into()),
                        principal_id: Some("principal".into()),
                    }),
                    proof_quality: Self::proof(),
                    principal_id: Some("principal".into()),
                },
            },
            "credential",
            1,
        )?;
        self.inputs.insert(
            GraphFactV1 {
                record_id: network.id.clone(),
                value: GraphFactValueV1::Channel {
                    task_cookie: 7,
                    process_instance_id: [8; 16],
                    socket_object_id: socket,
                    authority_id: "recorded-provider".into(),
                    carried_request_id: "request".into(),
                    credential_lease_id: "recorded-lease".into(),
                    principal_id: "principal".into(),
                    operation_id: "write".into(),
                    proof_quality: Self::proof(),
                },
            },
            "channel",
            1,
        )?;
        let authority = GraphFactV1 {
            record_id: network.id.clone(),
            value: GraphFactValueV1::AuthorityUse {
                authority_id: "recorded-provider".into(),
                process_instance_id: Some([8; 16]),
                task_cookie: Some(7),
                credential_object_id: Some(object),
                socket_object_id: Some(socket),
                request_id: Some("request".into()),
                credential_lease_id: Some("recorded-lease".into()),
                principal_id: "principal".into(),
                operation_id: "write".into(),
                outside_reviewed_behavior: true,
                proof_quality: Self::proof(),
                workload_binding: None,
            },
        };
        Ok((read, network, authority))
    }

    pub(in super::super) fn borrowed_completion(
        input: &GraphReplayInputV1,
        admission: &DiscoveryRecordIdV1,
        process: [u8; 16],
    ) -> std::result::Result<GraphReplayInputV1, Box<dyn StdError>> {
        let mut input = input.clone();
        for context in &mut input.facts {
            let mut fact = GraphFactV1::try_from(&*context)?;
            if let GraphFactValueV1::Credential {
                completion: Some(completion),
                ..
            } = &mut fact.value
            {
                completion.admission_record = admission.clone();
                completion.process_instance_id = process;
                context.body = serde_json::to_vec(&fact)?;
            }
        }
        Ok(input)
    }
}
