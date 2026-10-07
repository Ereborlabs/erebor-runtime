use super::*;

impl NodePolicyGenerationOwner {
    pub fn discovery_context(&self) -> Arc<NodeDiscoveryContextCatalog> {
        Arc::clone(&self.discovery_context)
    }

    pub(crate) fn next_generation_ref_id(
        config: &NodeConfig,
        host: &KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<u64> {
        // The allocator reconciles durable handles with live maps before it returns a new handle.
        GenerationHandleAllocator::load(
            config.state_directory.join("generation-handles-v1.json"),
            host,
            node_boot_id,
            label_epoch,
        )?
        .next_handle()
    }

    pub(crate) fn retire_profile_generation(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<bool> {
        let profile_id = parse_id("profile_id", profile_id)?;
        let observed = read_active_generation(host, &profile_id)?;
        ensure!(
            observed.is_none_or(|generation| generation == profile_generation_ref_id),
            IdentityStateSnafu {
                reason: "stale policy retirement found a different active profile generation",
            }
        );
        if observed.is_some() {
            host.delete_map_entry("active_profile_generations", profile_id.as_bytes())
                .context(InterceptorSnafu)?;
        }
        ensure!(
            read_active_generation(host, &profile_id)?.is_none(),
            IdentityStateSnafu {
                reason: "stale policy retirement active profile pointer survived deletion",
            }
        );
        reconcile_generation_retirement(host, node_boot_id, label_epoch)?;
        Ok(host
            .lookup_map(
                "profile_generation_descriptors",
                &profile_generation_ref_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .is_none())
    }

    #[cfg(feature = "test-support")]
    pub fn retire_profile_generation_for_test(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<bool> {
        Self::retire_profile_generation(
            host,
            profile_id,
            profile_generation_ref_id,
            node_boot_id,
            label_epoch,
        )
    }

    pub(crate) fn profile_generation_is_absent(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<bool> {
        let profile_id = parse_id("profile_id", profile_id)?;
        Ok(read_active_generation(host, &profile_id)?.is_none()
            && generation_publication_is_absent(host, profile_generation_ref_id)?)
    }

    #[cfg(feature = "test-support")]
    pub fn profile_generation_is_absent_for_test(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<bool> {
        Self::profile_generation_is_absent(host, profile_id, profile_generation_ref_id)
    }

    pub(crate) fn activation_receipt(
        host: &KernelHost,
        profile_id: &str,
        profile_generation_ref_id: u64,
    ) -> Result<PolicyActivationReceiptV1> {
        let profile_id = parse_id("profile_id", profile_id)?;
        // Read the published pointer and descriptor; staged bytes do not prove activation.
        let active = host
            .lookup_map("active_profile_generations", profile_id.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the activated profile has no active pointer",
            })?;
        ensure!(
            u64::read_from_bytes(&active)
                .is_ok_and(|active| { active == profile_generation_ref_id }),
            IdentityStateSnafu {
                reason: "the activated profile pointer failed exact readback",
            }
        );
        let descriptor = host
            .lookup_map(
                "profile_generation_descriptors",
                &profile_generation_ref_id.to_ne_bytes(),
            )
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the activated profile has no generation descriptor",
            })?;
        let parsed =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the activated generation descriptor is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            parsed.profile_id == profile_id
                && parsed.profile_generation_ref_id == profile_generation_ref_id
                && parsed.state == PolicyGenerationStateV1::Active,
            IdentityStateSnafu {
                reason: "the activated generation descriptor is not current",
            }
        );
        // Bind the acknowledgement to exact descriptor bytes and the controlled probe domain.
        let readback_digest = format!("{:x}", Sha256::digest(&descriptor));
        let mut probe = Sha256::new();
        probe.update(b"MITHRIL-POLICY-CONTROLLED-PROBE-V1\0");
        probe.update(parsed.table_digest);
        probe.update(profile_generation_ref_id.to_be_bytes());
        Ok(PolicyActivationReceiptV1 {
            node_bound_generation_digest: hex::encode(parsed.table_digest),
            profile_generation_ref_id,
            readback_digest,
            probe_result_digest: format!("{:x}", probe.finalize()),
        })
    }

    pub(crate) fn apply_exception_candidate(
        &self,
        host: &KernelHost,
        candidate: &ExceptionDeliveryCandidateV1,
        grant_handle: u32,
    ) -> Result<ExceptionRuntimeObservationV1> {
        let profile_id = parse_id("profile_id", &candidate.profile_id)?;
        let exception_instance_id =
            parse_id("exception_instance_id", &candidate.exception_instance_id)?;
        let descriptor_key = candidate.profile_generation_ref_id.to_ne_bytes();
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &descriptor_key)
            .context(InterceptorSnafu)?
            .map(|descriptor| {
                ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                    IdentityStateSnafu {
                        reason: format!("the exception base-policy descriptor is invalid: {error}"),
                    }
                    .build()
                })
            })
            .transpose()?;
        ensure!(
            descriptor.as_ref().is_none_or(|descriptor| {
                descriptor.profile_id == profile_id
                    && descriptor.profile_generation_ref_id == candidate.profile_generation_ref_id
                    && descriptor.node_boot_id == self.node_boot_id
                    && descriptor.label_epoch == self.label_epoch
                    && matches!(
                        descriptor.state,
                        PolicyGenerationStateV1::Active | PolicyGenerationStateV1::Retiring
                    )
            }),
            IdentityStateSnafu {
                reason: "the exception target differs from its local policy generation",
            }
        );
        ensure!(
            candidate.operation == ExceptionDeliveryOperationV1::Revoke || descriptor.is_some(),
            IdentityStateSnafu {
                reason: "the exception base-policy generation is not installed",
            }
        );
        let mut authority = self.exception_authority.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "exception authority owner lock is poisoned".to_owned(),
            }
            .build()
        })?;
        let runtime_key = ExceptionRuntimeStateKeyV1 {
            node_id: authority.node_id(),
            exception_instance_id,
        };
        let binding_key = ExceptionHandleBindingKeyV1 {
            profile_generation_ref_id: candidate.profile_generation_ref_id,
            exception_numeric_handle: grant_handle,
            reserved: 0,
        };
        match candidate.operation {
            ExceptionDeliveryOperationV1::Activate => {
                let now_utc_ns = current_utc_ns()?;
                let remaining_ns = u64::try_from(candidate.valid_until_utc_ns - now_utc_ns)
                    .map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!(
                                "the exception activation deadline is invalid: {error}"
                            ),
                        }
                        .build()
                    })?;
                let now_boottime_ns = current_boottime_ns()?;
                let deadline_boottime_ns =
                    now_boottime_ns.checked_add(remaining_ns).ok_or_else(|| {
                        IdentityStateSnafu {
                            reason: "the exception boottime deadline overflows".to_owned(),
                        }
                        .build()
                    })?;
                let definition_bytes =
                    hex::decode(&candidate.candidate_content_id).map_err(|error| {
                        IdentityStateSnafu {
                            reason: format!(
                                "the exception candidate content identity is invalid: {error}"
                            ),
                        }
                        .build()
                    })?;
                let definition: [u8; 32] = definition_bytes.try_into().map_err(|_| {
                    IdentityStateSnafu {
                        reason: "the exception candidate content identity has an invalid size"
                            .to_owned(),
                    }
                    .build()
                })?;
                let desired = ExceptionRuntimeStateV1 {
                    lock: 0,
                    maximum_uses: candidate.maximum_uses,
                    consumed_uses: 0,
                    bound_profile_generation_refs: 1,
                    deadline_boottime_ns,
                    transition_version: 1,
                    exception_definition_sha256: definition,
                    state: ExceptionRuntimeStateKindV1::Active,
                    reserved: [0; 7],
                };
                let existing = host
                    .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                    .context(InterceptorSnafu)?;
                let installed = authority.prepare_runtime(
                    runtime_key.as_bytes(),
                    desired,
                    candidate.valid_until_utc_ns,
                    existing.as_deref(),
                    now_utc_ns,
                    now_boottime_ns,
                )?;
                // Durable runtime authority must exist before a grant handle can reach it.
                if existing.is_none() {
                    host.update_map(
                        "exception_runtime_states",
                        runtime_key.as_bytes(),
                        installed.as_bytes(),
                    )
                    .context(InterceptorSnafu)?;
                }
                ensure!(
                    host.lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .is_some_and(|live| live == installed.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the exception runtime state failed exact readback",
                    }
                );
                let mut binding = ExceptionHandleBindingV1 {
                    runtime_state_key: runtime_key,
                    state: ExceptionBindingStateV1::Preparing,
                    reserved: [0; 7],
                };
                // Preparing readback makes a partial binding fail closed during recovery.
                host.update_map(
                    "exception_handle_bindings",
                    binding_key.as_bytes(),
                    binding.as_bytes(),
                )
                .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the preparing exception binding failed exact readback",
                    }
                );
                binding.state = ExceptionBindingStateV1::Active;
                host.update_map(
                    "exception_handle_bindings",
                    binding_key.as_bytes(),
                    binding.as_bytes(),
                )
                .context(InterceptorSnafu)?;
                ensure!(
                    host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                        .context(InterceptorSnafu)?
                        .as_deref()
                        == Some(binding.as_bytes()),
                    IdentityStateSnafu {
                        reason: "the active exception binding failed exact readback",
                    }
                );
                Ok(ExceptionRuntimeObservationV1 {
                    state: ExceptionActivationStateV1::Active,
                    consumed_uses: installed.consumed_uses,
                })
            }
            ExceptionDeliveryOperationV1::Revoke => {
                let binding = host
                    .lookup_map("exception_handle_bindings", binding_key.as_bytes())
                    .context(InterceptorSnafu)?;
                // A retired base generation may remove its binding before Control sends revoke.
                ensure!(
                    descriptor.is_some() || binding.is_none(),
                    IdentityStateSnafu {
                        reason: "an exception binding outlived its base-policy generation",
                    }
                );
                if let Some(binding) = binding {
                    let mut binding = ExceptionHandleBindingV1::try_read_from_bytes(&binding)
                        .map_err(|error| {
                            IdentityStateSnafu {
                                reason: format!("the exception binding is invalid: {error}"),
                            }
                            .build()
                        })?;
                    ensure!(
                        binding.runtime_state_key == runtime_key,
                        IdentityStateSnafu {
                            reason: "the exception grant is bound to another runtime instance",
                        }
                    );
                    // Retiring blocks new BPF claims before authority reconciliation runs.
                    binding.state = ExceptionBindingStateV1::Retiring;
                    host.update_map(
                        "exception_handle_bindings",
                        binding_key.as_bytes(),
                        binding.as_bytes(),
                    )
                    .context(InterceptorSnafu)?;
                    ensure!(
                        host.lookup_map("exception_handle_bindings", binding_key.as_bytes())
                            .context(InterceptorSnafu)?
                            .as_deref()
                            == Some(binding.as_bytes()),
                        IdentityStateSnafu {
                            reason: "the retiring exception binding failed exact readback",
                        }
                    );
                }
                authority.reconcile(host, current_utc_ns()?)?;
                // Keep the final use count after revocation for the durable Control receipt.
                let consumed_uses = host
                    .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
                    .context(InterceptorSnafu)?
                    .map_or(Ok(0), |state| {
                        ExceptionRuntimeStateV1::try_read_from_bytes(&state)
                            .map(|state| state.consumed_uses)
                            .map_err(|error| {
                                IdentityStateSnafu {
                                    reason: format!(
                                        "the revoked exception runtime state is invalid: {error}"
                                    ),
                                }
                                .build()
                            })
                    })?;
                Ok(ExceptionRuntimeObservationV1 {
                    state: ExceptionActivationStateV1::Revoked,
                    consumed_uses,
                })
            }
        }
    }

    #[cfg(feature = "test-support")]
    pub fn apply_exception_candidate_for_test(
        &self,
        host: &KernelHost,
        candidate: &ExceptionDeliveryCandidateV1,
        grant_handle: u32,
    ) -> Result<()> {
        self.apply_exception_candidate(host, candidate, grant_handle)
            .map(|_| ())
    }

    pub(crate) fn observe_exception_candidate(
        &self,
        host: &KernelHost,
        candidate: &ExceptionDeliveryCandidateV1,
    ) -> Result<ExceptionRuntimeObservationV1> {
        let exception_instance_id =
            parse_id("exception_instance_id", &candidate.exception_instance_id)?;
        let mut authority = self.exception_authority.lock().map_err(|_| {
            IdentityStateSnafu {
                reason: "exception authority owner lock is poisoned".to_owned(),
            }
            .build()
        })?;
        authority.reconcile(host, current_utc_ns()?)?;
        let runtime_key = ExceptionRuntimeStateKeyV1 {
            node_id: authority.node_id(),
            exception_instance_id,
        };
        let state = host
            .lookup_map_locked("exception_runtime_states", runtime_key.as_bytes())
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the active exception has no runtime state",
            })?;
        let state = ExceptionRuntimeStateV1::try_read_from_bytes(&state).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("the active exception runtime state is invalid: {error}"),
            }
            .build()
        })?;
        let observed = match state.state {
            // The deadline is authoritative even if no later BPF operation updates the map state.
            ExceptionRuntimeStateKindV1::Active
                if current_boottime_ns()? >= state.deadline_boottime_ns =>
            {
                ExceptionActivationStateV1::Expired
            }
            ExceptionRuntimeStateKindV1::Active => ExceptionActivationStateV1::Active,
            ExceptionRuntimeStateKindV1::Exhausted => ExceptionActivationStateV1::Consumed,
            ExceptionRuntimeStateKindV1::Expired => ExceptionActivationStateV1::Expired,
            ExceptionRuntimeStateKindV1::ReconciliationRequired
            | ExceptionRuntimeStateKindV1::Unknown => ExceptionActivationStateV1::Stale,
        };
        Ok(ExceptionRuntimeObservationV1 {
            state: observed,
            consumed_uses: state.consumed_uses,
        })
    }

    pub fn fence_network_socket(
        &self,
        host: &KernelHost,
        key: NetworkResponseFloorKeyV1,
    ) -> Result<bool> {
        ensure!(
            key.profile_generation_ref_id > 0 && key.socket_key_id > 0 && key.socket_generation > 0,
            IdentityStateSnafu {
                reason: "a network response fence needs exact nonzero socket identity",
            }
        );
        let generation_key = key.profile_generation_ref_id.to_ne_bytes();
        let descriptor = host
            .lookup_map("profile_generation_descriptors", &generation_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the network response generation does not exist",
            })?;
        let descriptor =
            ProfileGenerationDescriptorV1::try_read_from_bytes(&descriptor).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the network response generation is invalid: {error}"),
                }
                .build()
            })?;
        ensure!(
            descriptor.profile_generation_ref_id == key.profile_generation_ref_id
                && descriptor.node_boot_id == self.node_boot_id
                && descriptor.label_epoch == self.label_epoch
                && matches!(
                    descriptor.state,
                    PolicyGenerationStateV1::Active | PolicyGenerationStateV1::Retiring
                ),
            IdentityStateSnafu {
                reason: "the network response generation is not a live local generation",
            }
        );
        let references = host
            .lookup_map("profile_generation_socket_refs", &generation_key)
            .context(InterceptorSnafu)?
            .context(IdentityStateSnafu {
                reason: "the network response generation has no socket references",
            })?;
        ensure!(
            u64::read_from_bytes(&references).map_err(|error| {
                IdentityStateSnafu {
                    reason: format!("the network socket reference count is invalid: {error}"),
                }
                .build()
            })? > 0,
            IdentityStateSnafu {
                reason: "the network response generation has no live socket",
            }
        );
        let floor = NetworkResponseFloorV1 {
            scope: NetworkResponseScopeV1::WholeSocket,
            reserved: [0; 7],
        };
        let inserted = host
            .insert_map("network_response_floors", key.as_bytes(), floor.as_bytes())
            .context(InterceptorSnafu)?
            == MapInsertResult::Inserted;
        ensure!(
            host.lookup_map("network_response_floors", key.as_bytes())
                .context(InterceptorSnafu)?
                .as_deref()
                == Some(floor.as_bytes()),
            IdentityStateSnafu {
                reason: "the whole-socket response fence failed exact readback",
            }
        );
        Ok(inserted)
    }

    pub fn load_and_install(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates: Candidates::load(config)?,
                measured: PolicyMeasurements::default(),
                semantics: BTreeMap::new(),
                deferred: BTreeSet::new(),
            },
        )
    }

    pub fn load_and_install_for_bindings(
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let candidates = Candidates::load(config)?;
        let measured = Self::resolve_cri_exact_objects(
            config,
            host,
            &candidates,
            bindings.exact_object_binding_targets(),
            None,
        )?;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates,
                measured,
                semantics: BTreeMap::new(),
                deferred: bindings.held_binding_ids().map(str::to_owned).collect(),
            },
        )
    }

    pub fn reload_and_install_for_bindings(
        &self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let candidates = Candidates::load(config)?;
        let measured = Self::resolve_cri_exact_objects(
            config,
            host,
            &candidates,
            bindings.exact_object_binding_targets(),
            None,
        )?;
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates,
                measured,
                semantics: self.generation_semantics.clone(),
                deferred: bindings.held_binding_ids().map(str::to_owned).collect(),
            },
        )
    }

    pub fn reload_and_install(
        self,
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates: Candidates::load(config)?,
                measured: self.measured,
                semantics: self.generation_semantics,
                deferred: BTreeSet::new(),
            },
        )
    }

    #[cfg(feature = "test-support")]
    pub fn load_and_install_for_test_objects<I, S>(
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        objects: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        let candidates = Candidates::load(config)?;
        let objects = Self::resolve_test_exact_objects(config, &candidates, objects)?;
        let routes = Self::resolve_test_mount_routes(host, &objects)?;
        let mut measured = PolicyMeasurements::default();
        for item in objects {
            measured
                .bindings
                .entry(item.binding_id)
                .or_default()
                .objects
                .push(item.object);
        }
        for route in routes {
            measured
                .bindings
                .entry(route.binding_id.clone())
                .or_default()
                .routes
                .push(route);
        }
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates,
                measured,
                semantics: BTreeMap::new(),
                deferred: BTreeSet::new(),
            },
        )
    }

    #[cfg(feature = "test-support")]
    pub fn reload_and_install_for_test_objects<I, S>(
        self,
        config: &NodeConfig,
        host: &mut KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
        objects: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        let candidates = Candidates::load(config)?;
        let mut measured = self.measured;
        for binding in measured.bindings.values_mut() {
            binding.objects.clear();
        }
        for item in Self::resolve_test_exact_objects(config, &candidates, objects)? {
            measured
                .bindings
                .entry(item.binding_id)
                .or_default()
                .objects
                .push(item.object);
        }
        Self::install(
            config,
            host,
            node_boot_id,
            label_epoch,
            PolicyInput {
                candidates,
                measured,
                semantics: self.generation_semantics,
                deferred: BTreeSet::new(),
            },
        )
    }

    #[must_use]
    pub const fn prevention_enabled(&self) -> bool {
        self.prevention_enabled
    }

    #[must_use]
    pub(crate) fn administrative_enabled(&self) -> bool {
        !self.administrative_plans.is_empty()
    }

    pub fn reconcile_cri_exact_bindings(
        &mut self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
    ) -> Result<()> {
        self.reconcile_cri_exact_bindings_inner(config, host, bindings, None)?;
        retire_unreachable_mount_cache_rows(host)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn reconcile_cri_exact_bindings_for_oci_entries(
        &mut self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        binding_id: &str,
        held_initial_pid: u32,
        root_source_pid: u32,
        root_source_fd: u32,
        bundle: &Path,
    ) -> Result<()> {
        let view = crate::exact_object::ExactFileObjectView::acquire_oci(
            held_initial_pid,
            root_source_pid,
            root_source_fd,
            bundle,
        )?;
        self.reconcile_cri_exact_bindings_inner(
            config,
            host,
            bindings,
            Some((binding_id, held_initial_pid, view)),
        )?;
        self.log_staged_path_policy(binding_id);
        Ok(())
    }

    #[cfg(feature = "test-support")]
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_cri_exact_bindings_for_oci_entries_for_test(
        &mut self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        binding_id: &str,
        held_initial_pid: u32,
        root_source_pid: u32,
        root_source_fd: u32,
        bundle: &Path,
    ) -> Result<()> {
        self.reconcile_cri_exact_bindings_for_oci_entries(
            config,
            host,
            bindings,
            binding_id,
            held_initial_pid,
            root_source_pid,
            root_source_fd,
            bundle,
        )
    }

    fn reconcile_cri_exact_bindings_inner(
        &mut self,
        config: &NodeConfig,
        host: &mut KernelHost,
        bindings: &WorkloadBindingOwner,
        oci_entry_view: Option<(&str, u32, crate::exact_object::ExactFileObjectView)>,
    ) -> Result<()> {
        let active_binding_ids = bindings
            .active_binding_ids()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let targets = bindings.exact_object_binding_targets().collect::<Vec<_>>();
        let borrowed_oci_entry_view = oci_entry_view
            .as_ref()
            .map(|(binding_id, root_pid, view)| (*binding_id, *root_pid, view));
        let refreshed_binding_id = borrowed_oci_entry_view.map(|(binding_id, _, _)| binding_id);
        let candidates = Candidates::load(config)?;
        let mut measured = Self::resolve_cri_exact_objects(
            config,
            host,
            &candidates,
            targets.iter().copied(),
            borrowed_oci_entry_view,
        )?;
        measured
            .bindings
            .retain(|id, _| active_binding_ids.contains(id));
        for (id, retained) in &self.measured.bindings {
            if active_binding_ids.contains(id) && Some(id.as_str()) != refreshed_binding_id {
                measured.bindings.insert(id.clone(), retained.clone());
            }
        }
        if let Some((_, _, view)) = oci_entry_view {
            measured.views.insert(view.mount_namespace_inode()?, view);
        }
        let mut next = Self::install(
            config,
            host,
            self.node_boot_id,
            self.label_epoch,
            PolicyInput {
                candidates,
                measured,
                semantics: self.generation_semantics.clone(),
                deferred: bindings.held_binding_ids().map(str::to_owned).collect(),
            },
        )?;
        let mut retained_views = std::mem::take(&mut self.measured.views);
        retained_views.append(&mut next.measured.views);
        next.measured.views = retained_views;
        let previous = std::mem::replace(self, next);
        Self::retire_replaced_dynamic_dependencies(
            host,
            &previous.dynamic_rows,
            &self.dynamic_rows,
        )?;
        Ok(())
    }

    fn log_staged_path_policy(&self, binding_id: &str) {
        let Some(measured) = self.measured.bindings.get(binding_id) else {
            return;
        };
        for object in &measured.objects {
            erebor_telemetry::debug!(
                "staged stable exact entry policy",
                binding_id = %binding_id,
                exact_object_key_id = %object.exact_object_key_id,
                mount_namespace_inode = %object.mount_namespace_inode,
                mount_id_unique = %object.mount_id_unique,
                filesystem_device = %object.filesystem_device,
                inode = %object.inode,
                inode_generation = %object.inode_generation,
                selected_mount_id_unique = %object.selected_mount_id_unique,
                mount_topology_generation = %object.mount_topology_generation
            );
        }
        erebor_telemetry::debug!(
            "staged stable canonical mount policy",
            binding_id = %binding_id,
            route_count = %measured.routes.len()
        );
    }

    fn retire_replaced_dynamic_dependencies(
        host: &KernelHost,
        previous: &BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
        replacement: &BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    ) -> Result<()> {
        let mut tables = NativeTable::ALL;
        tables.sort_by_key(|table| table.retirement().map_or(u8::MAX, |(rank, _)| rank));
        for table in tables.into_iter().filter(|table| table.is_dynamic()) {
            let map = table.map_name();
            if let Some(keys) = previous.get(map) {
                Self::revoke_rows(
                    host,
                    map,
                    keys.iter()
                        .filter(|key| replacement.get(map).is_none_or(|rows| !rows.contains(*key))),
                    "replacement retirement",
                )?;
            }
        }
        Ok(())
    }

    fn revoke_rows<'a>(
        host: &KernelHost,
        map: &str,
        keys: impl IntoIterator<Item = &'a Vec<u8>>,
        operation: &str,
    ) -> Result<()> {
        for key in keys {
            if host
                .lookup_map(map, key)
                .context(InterceptorSnafu)?
                .is_some()
            {
                host.delete_map_entry(map, key).context(InterceptorSnafu)?;
            }
            ensure!(
                host.lookup_map(map, key)
                    .context(InterceptorSnafu)?
                    .is_none(),
                IdentityStateSnafu {
                    reason: format!("dynamic path authority remained in `{map}` after {operation}"),
                }
            );
        }
        Ok(())
    }

    fn resolve_cri_exact_objects<'a>(
        config: &NodeConfig,
        host: &KernelHost,
        candidates: &Candidates,
        bindings: impl IntoIterator<Item = ExactObjectBindingTargetV1<'a>>,
        oci_entry_view: Option<(&str, u32, &crate::exact_object::ExactFileObjectView)>,
    ) -> Result<PolicyMeasurements> {
        let topology_generation = Self::current_mount_topology_generation(host)?;
        let mut measured = PolicyMeasurements::default();
        let mut target_bindings = BTreeSet::new();
        let mut oci_entry_view_used = false;
        for target in bindings {
            ensure!(
                target_bindings.insert(target.binding_id),
                IdentityStateSnafu {
                    reason: format!(
                        "binding `{}` has more than one authenticated CRI exact-object target",
                        target.binding_id
                    ),
                }
            );
            let binding = config
                .workload_bindings
                .iter()
                .find(|binding| binding.binding_id == target.binding_id)
                .context(IdentityStateSnafu {
                    reason: format!(
                        "authenticated CRI exact-object target `{}` is not configured",
                        target.binding_id
                    ),
                })?;
            let artifact =
                candidates
                    .artifact(&binding.profile_id)
                    .context(IdentityStateSnafu {
                        reason: format!(
                            "binding `{}` has no verified candidate for exact-object resolution",
                            binding.binding_id
                        ),
                    })?;
            let selectors = artifact
                .policy_document
                .path_selectors
                .iter()
                .filter(|selector| selector.requires_exact_object());
            let target_oci_entry_view =
                oci_entry_view.filter(|(binding_id, _, _)| *binding_id == target.binding_id);
            if !target.process_path_view_allowed && target_oci_entry_view.is_none() {
                continue;
            }
            let view = crate::exact_object::ExactFileObjectView::acquire(target.init_pid)?;
            let process_root_is_container = !view.has_host_root()?;
            if let Some((_, held_initial_pid, _)) = target_oci_entry_view {
                ensure!(
                    held_initial_pid == target.init_pid,
                    IdentityStateSnafu {
                        reason: "OCI entry view differs from the held initial task",
                    }
                );
                oci_entry_view_used = true;
            }
            let route_view = target_oci_entry_view
                .map(|(_, _, oci_view)| oci_view)
                .or_else(|| process_root_is_container.then_some(&view));
            if let Some(route_view) = route_view {
                measured
                    .bindings
                    .entry(binding.binding_id.clone())
                    .or_default()
                    .routes
                    .extend(Self::authoritative_mount_routes(
                        binding,
                        target.init_pid,
                        topology_generation,
                        route_view.mount_root_routes()?,
                    ));
            }
            for selector in selectors {
                let canonical_path = selector.path_expression();
                let path = PathBuf::from(canonical_path);
                let object = match target_oci_entry_view {
                    Some((_, _, oci_view)) => oci_view.try_resolve_signed_selector(
                        host,
                        &path,
                        binding.active_profile_generation_ref_id,
                        selector.kernel_handle(),
                        selector.object_class_id.clone(),
                        selector.device_class_id.clone(),
                        topology_generation,
                    )?,
                    None if process_root_is_container => view.try_resolve_signed_selector(
                        host,
                        &path,
                        binding.active_profile_generation_ref_id,
                        selector.kernel_handle(),
                        selector.object_class_id.clone(),
                        selector.device_class_id.clone(),
                        topology_generation,
                    )?,
                    None => None,
                };
                let Some(object) = object else {
                    continue;
                };
                let expected_components =
                    canonical_path_components(artifact.header.profile_id.as_str(), canonical_path)
                        .context(PolicySnafu)?;
                ensure!(
                    object.canonical_component_hex
                        == expected_components
                            .iter()
                            .map(hex::encode)
                            .collect::<Vec<_>>(),
                    IdentityStateSnafu {
                        reason: format!(
                            "signed path selector `{}` resolved to a different canonical path",
                            selector.path_selector_id
                        ),
                    }
                );
                measured
                    .bindings
                    .entry(binding.binding_id.clone())
                    .or_default()
                    .objects
                    .push(object);
            }
            if process_root_is_container && target_oci_entry_view.is_none() {
                measured.views.insert(view.mount_namespace_inode()?, view);
            }
        }
        ensure!(
            oci_entry_view.is_none() || oci_entry_view_used,
            IdentityStateSnafu {
                reason: "OCI entry view has no authenticated exact-object target",
            }
        );
        Ok(measured)
    }

    pub(super) fn authoritative_mount_routes(
        binding: &WorkloadBindingConfig,
        mount_view_root_pid: u32,
        mount_topology_generation: u64,
        routes: Vec<crate::exact_object::LiveMountRootRouteV1>,
    ) -> Vec<MeasuredMountRouteV1> {
        routes
            .into_iter()
            .map(|route| MeasuredMountRouteV1 {
                binding_id: binding.binding_id.clone(),
                mount_view_root_pid,
                mount_topology_generation,
                route,
            })
            .collect()
    }

    #[cfg(feature = "test-support")]
    fn resolve_test_exact_objects<I, S>(
        config: &NodeConfig,
        candidates: &Candidates,
        objects: I,
    ) -> Result<Vec<MeasuredExactObjectV1>>
    where
        I: IntoIterator<Item = (S, ExactFileObjectConfig)>,
        S: Into<String>,
    {
        objects
            .into_iter()
            .map(|(binding_id, mut object)| {
                let binding_id = binding_id.into();
                let binding = config
                    .workload_bindings
                    .iter()
                    .find(|binding| binding.binding_id == binding_id)
                    .context(IdentityStateSnafu {
                        reason: format!("test object binding `{binding_id}` is not configured"),
                    })?;
                let artifact = candidates.artifact(&binding.profile_id).context(IdentityStateSnafu {
                    reason: format!("test object binding `{binding_id}` has no verified policy"),
                })?;
                let entry_selector_ids = entry_admission_path_selector_ids(artifact, binding)?;
                let mut selectors = artifact
                    .policy_document
                    .path_selectors
                    .iter()
                    .filter(|selector| {
                        if !(selector.requires_exact_object()
                            || entry_selector_ids.contains(&selector.path_selector_id))
                            || selector.object_class_id != object.object_class_id
                            || selector.device_class_id.as_deref()
                                != object
                                    .device
                                    .as_ref()
                                    .map(|device| device.device_class_id.as_str())
                        {
                            return false;
                        }
                        canonical_path_components(
                            artifact.header.profile_id.as_str(),
                            selector.path_expression(),
                        )
                        .is_ok_and(|components| {
                            object.canonical_component_hex
                                == components.iter().map(hex::encode).collect::<Vec<_>>()
                        })
                    });
                let selector = selectors.next().context(IdentityStateSnafu {
                    reason: format!(
                        "test object for binding `{binding_id}` has no signed path selector"
                    ),
                })?;
                ensure!(
                    selectors.next().is_none(),
                    IdentityStateSnafu {
                        reason: format!(
                            "test object for binding `{binding_id}` matches more than one signed path selector"
                        ),
                    }
                );
                object.profile_generation_ref_id = binding.active_profile_generation_ref_id;
                object.exact_object_key_id = selector.kernel_handle();
                Ok(MeasuredExactObjectV1 { binding_id, object })
            })
            .collect()
    }

    #[cfg(feature = "test-support")]
    fn resolve_test_mount_routes(
        host: &KernelHost,
        objects: &[MeasuredExactObjectV1],
    ) -> Result<Vec<MeasuredMountRouteV1>> {
        let mut targets = BTreeMap::<&str, u32>::new();
        for measured in objects {
            let root_pid = measured.object.mount_view_root_pid;
            if let Some(existing) = targets.insert(measured.binding_id.as_str(), root_pid) {
                ensure!(
                    existing == root_pid,
                    IdentityStateSnafu {
                        reason: format!(
                            "test binding `{}` has more than one live mount view",
                            measured.binding_id
                        ),
                    }
                );
            }
        }
        let topology_generation = Self::current_mount_topology_generation(host)?;
        let mut measured_routes = Vec::new();
        for (binding_id, root_pid) in targets {
            let view = crate::exact_object::ExactFileObjectView::acquire(root_pid)?;
            measured_routes.extend(view.mount_root_routes()?.into_iter().map(|route| {
                MeasuredMountRouteV1 {
                    binding_id: binding_id.to_owned(),
                    mount_view_root_pid: root_pid,
                    mount_topology_generation: topology_generation,
                    route,
                }
            }));
        }
        Ok(measured_routes)
    }

    fn current_mount_topology_generation(host: &KernelHost) -> Result<u64> {
        let key = 0_u32.to_ne_bytes();
        let Some(bytes) = host
            .lookup_map("mount_global_mutation_epoch", &key)
            .context(InterceptorSnafu)?
        else {
            return Ok(1);
        };
        let epoch = u64::read_from_bytes(&bytes).map_err(|error| {
            IdentityStateSnafu {
                reason: format!("global mount mutation epoch is invalid: {error}"),
            }
            .build()
        })?;
        Ok(epoch.max(1))
    }

    pub(super) fn dynamic_generation_rows<'a>(
        generations: impl IntoIterator<Item = &'a LoweredGeneration>,
    ) -> BTreeMap<&'static str, BTreeSet<Vec<u8>>> {
        let mut rows = BTreeMap::<&'static str, BTreeSet<Vec<u8>>>::new();
        for generation in generations {
            for table in NativeTable::ALL
                .into_iter()
                .filter(|table| table.is_dynamic())
            {
                rows.entry(table.map_name())
                    .or_default()
                    .extend(generation.rows[table].keys().cloned());
            }
        }
        rows
    }

    pub(crate) fn resolve_administrative_policy(
        &self,
        host: &KernelHost,
        target: &AdministrativeBindingTargetV1,
        requested_name: &[u8],
        approved_role_id: &str,
    ) -> Result<ResolvedAdministrativePolicyV1> {
        ensure!(
            (1..=4096).contains(&requested_name.len())
                && !requested_name.contains(&0)
                && !approved_role_id.is_empty(),
            IdentityStateSnafu {
                reason: "administrative command and role are not bounded",
            }
        );
        let plans = self
            .administrative_plans
            .iter()
            .filter(|plan| {
                plan.binding_id == target.binding_id
                    && plan.approved_role_id == approved_role_id
                    && plan.profile.profile_id == target.profile_id
                    && plan.profile_generation_ref_id == target.profile_generation_ref_id
            })
            .collect::<Vec<_>>();
        ensure!(
            plans.len() == 1,
            IdentityStateSnafu {
                reason: "signed profile does not have one administrative entry for the exact target and role",
            }
        );
        let plan = plans[0];
        let view = crate::exact_object::ExactFileObjectView::acquire(target.init_pid)?;
        let mount_namespace_inode = view.mount_namespace_inode()?;
        ensure!(
            mount_namespace_inode > 0,
            IdentityStateSnafu {
                reason: "administrative target has no stable mount view",
            }
        );
        let global_key = 0_u32.to_ne_bytes();
        let global_epoch = mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)?;
        ensure!(
            global_epoch > 0
                && mount_epoch_from(host, "mount_global_pending_mutations", &global_key)? == 0,
            IdentityStateSnafu {
                reason: "administrative executable mount view has an active mutation",
            }
        );
        let active = host
            .lookup_map("active_profile_generations", target.profile_id.as_bytes())
            .context(InterceptorSnafu)?
            .ok_or_else(|| {
                IdentityStateSnafu {
                    reason: "administrative profile has no active generation".to_owned(),
                }
                .build()
            })?;
        ensure!(
            u64::read_from_bytes(&active)
                .is_ok_and(|generation| { generation == target.profile_generation_ref_id }),
            IdentityStateSnafu {
                reason: "administrative target profile generation is not active",
            }
        );
        let requested = PathBuf::from(OsString::from_vec(requested_name.to_vec()));
        let (resolution_mode, candidates) = if requested.is_absolute() {
            (1, vec![requested])
        } else if requested_name.contains(&b'/') {
            (2, vec![target.working_directory.join(requested)])
        } else {
            (
                3,
                target
                    .path_entries
                    .iter()
                    .map(|entry| entry.join(&requested))
                    .collect::<Vec<_>>(),
            )
        };
        let mut selected = None;
        for path in candidates {
            let Some(live) = view.try_inspect(host, &path)? else {
                continue;
            };
            let is_regular_executable =
                u32::from(live.mode) & 0o170_000 == 0o100_000 && u32::from(live.mode) & 0o111 != 0;
            if !is_regular_executable && resolution_mode == 3 {
                continue;
            }
            ensure!(
                is_regular_executable,
                IdentityStateSnafu {
                    reason: "resolved administrative command is not a regular executable file",
                }
            );
            selected = Some((path, live));
            break;
        }
        let (path, live) = selected.ok_or_else(|| {
            IdentityStateSnafu {
                reason: "administrative command did not resolve in the target container view"
                    .to_owned(),
            }
            .build()
        })?;
        ensure!(
            live.mount_namespace_inode == mount_namespace_inode
                && live.mount_snapshot_digest_id > 0
                && live.inode_generation > 0
                && view.mount_namespace_inode()? == mount_namespace_inode
                && mount_epoch_from(host, "mount_global_mutation_epoch", &global_key)?
                    == global_epoch
                && mount_epoch_from(host, "mount_global_pending_mutations", &global_key)? == 0,
            IdentityStateSnafu {
                reason: "administrative command resolution crossed a mount mutation",
            }
        );
        let mount_namespace_id = derived_id(
            b"MITHRIL-MOUNT-NAMESPACE-V1\0",
            &[
                portable_id_bytes(self.node_boot_id),
                self.label_epoch.to_be_bytes().to_vec(),
                mount_namespace_inode.to_be_bytes().to_vec(),
            ],
        )?;
        let filesystem_instance_id = derived_id(
            b"MITHRIL-FILESYSTEM-INSTANCE-V1\0",
            &[
                portable_id_bytes(mount_namespace_id),
                live.filesystem_device.to_be_bytes().to_vec(),
            ],
        )?;
        let exact_live_object_id = derived_id(
            b"MITHRIL-EXACT-LIVE-FILE-V1\0",
            &[
                portable_id_bytes(filesystem_instance_id),
                live.mount_id.to_be_bytes().to_vec(),
                live.inode.to_be_bytes().to_vec(),
                live.inode_generation.to_be_bytes().to_vec(),
                global_epoch.to_be_bytes().to_vec(),
            ],
        )?;
        let backing_identity = derived_id(
            b"MITHRIL-ADMINISTRATIVE-EXECUTABLE-BACKING-V1\0",
            &[
                portable_id_bytes(plan.profile.profile_id),
                plan.profile_generation_ref_id.to_be_bytes().to_vec(),
                plan.admitted_entry_rule_id.to_be_bytes().to_vec(),
            ],
        )?;
        let live_interval_id = derived_id(
            b"MITHRIL-ADMINISTRATIVE-FILE-INTERVAL-V1\0",
            &[
                portable_id_bytes(target.binding_nonce),
                portable_id_bytes(exact_live_object_id),
                target.container_generation.to_be_bytes().to_vec(),
            ],
        )?;
        let resolved_display_path = path.as_os_str().as_bytes().to_vec();
        let container_working_directory = target.working_directory.as_os_str().as_bytes().to_vec();
        let effective_path_entries = target
            .path_entries
            .iter()
            .map(|entry| entry.as_os_str().as_bytes().to_vec())
            .collect::<Vec<_>>();
        ensure!(
            (1..=4096).contains(&resolved_display_path.len())
                && resolved_display_path.first() == Some(&b'/')
                && (1..=4096).contains(&container_working_directory.len())
                && container_working_directory.first() == Some(&b'/')
                && effective_path_entries.len() <= 64
                && effective_path_entries.iter().all(|entry| {
                    (1..=4096).contains(&entry.len()) && entry.first() == Some(&b'/')
                }),
            IdentityStateSnafu {
                reason: "administrative resolved path, working directory, or PATH exceeds its signed bounds",
            }
        );
        Ok(ResolvedAdministrativePolicyV1 {
            approved_role_numeric_id: plan.approved_role_numeric_id,
            admitted_entry_rule_id: plan.admitted_entry_rule_id,
            profile_generation_ref_id: plan.profile_generation_ref_id,
            exception_numeric_handle: 0,
            profile: plan.profile.clone(),
            resolved_executable: ResolvedAdministrativeExecutableIdentityV1 {
                requested_name: requested_name.to_vec(),
                resolution_mode,
                resolved_display_path,
                container_working_directory,
                effective_path_entries,
                target_mount_namespace_id: mount_namespace_id,
                target_mount_topology_generation: global_epoch,
                executable_object: AdministrativeFileObjectIdentityV1 {
                    mount_namespace_id,
                    mount_topology_generation: global_epoch,
                    mount_id: live.mount_id,
                    filesystem_instance_id,
                    inode: live.inode,
                    inode_generation: live.inode_generation,
                    exact_live_object_id,
                    object_kind: 1,
                    backing_identity,
                    live_interval_id,
                },
            },
            kernel_executable: ExactExecutableCandidateV1 {
                inode: live.inode,
                mount_namespace_inode,
                mount_id: live.mount_id,
                filesystem_device: live.filesystem_device,
                inode_generation: live.inode_generation,
                reserved: 0,
            },
        })
    }

    pub fn reconcile_policy_lifecycle(&self, host: &mut KernelHost) -> Result<bool> {
        self.exception_authority
            .lock()
            .map_err(|_| {
                IdentityStateSnafu {
                    reason: "exception authority owner lock is poisoned".to_owned(),
                }
                .build()
            })?
            .reconcile(host, current_utc_ns()?)?;
        let pending = reconcile_generation_retirement(host, self.node_boot_id, self.label_epoch)?;
        self.retirement_pending.store(pending, Ordering::Release);
        Ok(true)
    }

    pub(crate) fn retirement_pending(&self) -> bool {
        self.retirement_pending.load(Ordering::Acquire)
    }

    #[cfg(feature = "test-support")]
    pub fn retained_mount_views_are_readable_for_test(&self) -> Result<bool> {
        if self.measured.views.is_empty() {
            return Ok(false);
        }
        for view in self.measured.views.values() {
            if !view.retained_mountinfo_is_readable_for_test()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
