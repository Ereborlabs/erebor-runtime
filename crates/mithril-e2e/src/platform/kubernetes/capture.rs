use super::*;

pub(super) struct PodCapture {
    control: ControlPlane,
    traces: TraceOwner,
    directory: PathBuf,
    namespace: String,
    pod_name: String,
    tenant_id: [u8; 16],
    query_profile: AraphorProfile,
}

impl Kubernetes {
    fn capture_command(&self, target: &str, args: &[&str]) -> Command {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube_path)
            .args(["-n", &self.system, "exec", target, "--"])
            .args(args);
        command
    }

    fn capture_runtime(&self, target: &str, executable: &str, bundled: bool) -> TestResult<String> {
        let script = if bundled {
            "LD_LIBRARY_PATH=/qualification/runtime/lib /usr/bin/ldd \"$1\""
        } else {
            "/usr/bin/ldd \"$1\""
        };
        let output = self
            .capture_command(target, &["/bin/sh", "-ec", script, "preflight", executable])
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        if !output.status.success()
            || stdout.contains("not found")
            || stderr.contains("not found")
            || !stdout.contains("libc.so.6")
        {
            return Err(format!(
                "container runtime preflight failed for {executable}: {stdout}; {stderr}"
            )
            .into());
        }
        Ok(stdout)
    }

    fn capture_rollout(&self, target: &str) -> TestResult<()> {
        let mut command = Command::new(&self.k3s_path);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube_path)
            .args([
                "-n",
                &self.system,
                "rollout",
                "status",
                target,
                "--timeout=180s",
            ]);
        KubernetesState::run(&mut command, "wait for the qualification rollout")?;
        Ok(())
    }

    fn capture_library(name: &str) -> bool {
        name.contains(".so")
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+')
            })
            && ![
                "libc.so.6",
                "libm.so.6",
                "libgcc_s.so.1",
                "ld-linux-x86-64.so.2",
            ]
            .contains(&name)
    }

    fn capture_bundle() -> TestResult<(PathBuf, Vec<String>)> {
        let directory = fs::canonicalize(KubernetesState::required("MITHRIL_TRACE_RUNTIME")?)?;
        if std::env::consts::ARCH != "x86_64"
            || !directory
                .join("bpftrace")
                .symlink_metadata()?
                .file_type()
                .is_file()
        {
            return Err("the Pod fixture requires an x86-64 regular bpftrace executable".into());
        }
        let mut libraries = Vec::new();
        for entry in fs::read_dir(directory.join("lib"))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "a runtime library name is not UTF-8")?;
            if !entry.file_type()?.is_file() || !Self::capture_library(&name) {
                return Err(
                    format!("the runtime bundle has an unsupported library: {name}").into(),
                );
            }
            libraries.push(name);
        }
        if libraries.len() > 64 {
            return Err("the runtime bundle exceeds 64 backend dependencies".into());
        }
        libraries.sort();
        let expected = std::iter::once("bpftrace".to_owned())
            .chain(libraries.iter().map(|name| format!("lib/{name}")))
            .collect::<BTreeSet<_>>();
        let manifest = fs::read_to_string(directory.join("SHA256SUMS"))?;
        if manifest.len() > 16 * 1024 {
            return Err("the runtime checksum manifest exceeds its bound".into());
        }
        let mut recorded = BTreeSet::new();
        for line in manifest.lines() {
            let (digest, name) = line
                .split_once("  ")
                .ok_or("the runtime checksum line is invalid")?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !expected.contains(name)
                || !recorded.insert(name.to_owned())
            {
                return Err(
                    "the runtime checksum manifest has an invalid or duplicate file".into(),
                );
            }
        }
        if recorded != expected {
            return Err("the runtime checksum manifest is incomplete".into());
        }
        let mut command = Command::new("/usr/bin/sha256sum");
        command
            .current_dir(&directory)
            .args(["--check", "--strict", "--status", "SHA256SUMS"]);
        KubernetesState::run(&mut command, "verify the read-only runtime bundle")?;
        Ok((directory, libraries))
    }

    fn configure_capture(&self, config: &mithril_node::NodeTraceConfigV1) -> TestResult<()> {
        if config.executable != Path::new("/usr/bin/bpftrace") {
            return Err("the Pod fixture requires the /usr/bin/bpftrace path".into());
        }
        config.validate()?;
        let mut node: Value = serde_json::from_slice(&fs::read(&self.config_path)?)?;
        node["diagnostics"] = serde_json::to_value(config)?;
        fs::write(&self.config_path, serde_json::to_vec_pretty(&node)?)?;
        NodeConfig::load_with_kubernetes_runtime_identity(
            &self.config_path,
            self.node_name.clone(),
        )?;
        Ok(())
    }

    fn capture_installer(
        set: &DaemonSet,
        mounts: &[RuntimeRecoveryMountInputV1],
    ) -> TestResult<Vec<String>> {
        let installer = set
            .spec
            .as_ref()
            .and_then(|spec| spec.template.spec.as_ref())
            .and_then(|spec| spec.init_containers.as_ref())
            .and_then(|containers| {
                containers
                    .iter()
                    .find(|item| item.name == "install-runtime-gate")
            })
            .ok_or("the task Node has no runtime-gate installer")?;
        let command = installer
            .command
            .as_ref()
            .ok_or("the runtime-gate installer has no command")?;
        if command != &["/usr/local/bin/mithril-oci-hook", "install"] {
            return Err("the task Node has an unexpected runtime-gate installer".into());
        }
        let mut input = installer
            .args
            .as_ref()
            .ok_or("the runtime-gate installer has no arguments")?
            .iter();
        let mut args = Vec::with_capacity(input.len() + mounts.len());
        while let Some(arg) = input.next() {
            // The retained gate requires separate identity options and values.
            if matches!(
                arg.as_str(),
                "--node-read-only-mount"
                    | "--node-read-write-mount"
                    | "--runtime-cli-arg"
                    | "--runtime-service"
            ) {
                let value = input
                    .next()
                    .filter(|value| !value.is_empty() && !value.starts_with('-'))
                    .ok_or("the runtime-gate installer list option has no value")?;
                args.push(format!("{arg}={value}"));
            } else {
                args.push(arg.clone());
            }
        }
        for mount in mounts {
            let source = mount
                .source
                .to_str()
                .ok_or("a runtime mount source is not UTF-8")?;
            let destination = mount
                .destination
                .to_str()
                .ok_or("a runtime mount destination is not UTF-8")?;
            if !mount.read_only
                || !mount.source.is_absolute()
                || !mount.destination.is_absolute()
                || source.contains(['=', '\0', '\r', '\n'])
                || destination.contains(['=', '\0', '\r', '\n'])
            {
                return Err("the fixture runtime mount is not an exact read-only bind".into());
            }
            args.push(format!("--node-read-only-mount={source}={destination}"));
        }
        let count = args
            .iter()
            .filter(|arg| {
                matches!(
                    arg.split('=').next(),
                    Some("--node-read-only-mount" | "--node-read-write-mount")
                )
            })
            .count();
        if !(1..=32).contains(&count)
            || command.len() + args.len() > 64
            || args.iter().any(|arg| arg.is_empty() || arg.len() > 4096)
        {
            return Err(
                "the task Node exceeds the production recovery mount or argument bound".into(),
            );
        }
        Ok(args)
    }

    fn mount_capture(&self, bundle: &Path, cpus: usize) -> TestResult<()> {
        let directory = self.state_path.with_file_name("capture");
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770))?;
        rustix::fs::chown(
            &directory,
            Some(rustix::process::Uid::from_raw(65532)),
            Some(rustix::process::Gid::from_raw(65532)),
        )?;
        let sets = Api::<DaemonSet>::namespaced(self.client.clone(), &self.system);
        let args = Self::capture_installer(
            &self.runtime.block_on(sets.get("mithril-node"))?,
            &[
                RuntimeRecoveryMountInputV1 {
                    source: bundle.to_owned(),
                    destination: "/qualification/runtime".into(),
                    read_only: true,
                },
                RuntimeRecoveryMountInputV1 {
                    source: bundle.join("bpftrace"),
                    destination: "/usr/bin/bpftrace".into(),
                    read_only: true,
                },
            ],
        )?;
        self.runtime.block_on(sets.patch("mithril-node", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {
                "volumes": [
                    {"name": "qualification-runtime", "hostPath": {"path": bundle, "type": "Directory"}},
                    {"name": "qualification-backend", "hostPath": {"path": bundle.join("bpftrace"), "type": "File"}}
                ],
                "initContainers": [{"name": "install-runtime-gate", "args": args}],
                "containers": [{"name": "mithril-node", "resources": {
                    "requests": {"cpu": "100m"}, "limits": {"cpu": cpus.to_string()}},
                    "volumeMounts": [
                        {"name": "qualification-runtime", "mountPath": "/qualification/runtime", "readOnly": true},
                        {"name": "qualification-backend", "mountPath": "/usr/bin/bpftrace", "readOnly": true}
                    ]}]
            }}}
        }))))?;
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        self.runtime.block_on(deployments.patch("mithril-control", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {
                "volumes": [
                    {"name": "qualification-test", "hostPath": {"path": std::env::current_exe()?, "type": "File"}},
                    {"name": "qualification-capture", "hostPath": {"path": directory, "type": "Directory"}}
                ],
                "containers": [{"name": "mithril-control", "volumeMounts": [
                    {"name": "qualification-test", "mountPath": "/qualification/test", "readOnly": true},
                    {"name": "qualification-capture", "mountPath": "/qualification/capture"}
                ]}]
            }}}
        }))))?;
        self.capture_rollout("deployment/mithril-control")
    }

    fn prepare_runtime(&self, bundle: &Path, libraries: &[String]) -> TestResult<Value> {
        let closure = self.capture_runtime("daemonset/mithril-node", "/usr/bin/bpftrace", true)?;
        let mut mounts = Vec::new();
        let mut volumes = Vec::new();
        let mut recovery = Vec::new();
        for library in libraries {
            if !closure.contains(&format!("/qualification/runtime/lib/{library} ")) {
                continue;
            }
            let path = format!("/usr/lib/x86_64-linux-gnu/{library}");
            let output = self
                .capture_command(
                    "daemonset/mithril-node",
                    &["/bin/sh", "-ec", "test -e \"$1\"", "preflight", &path],
                )
                .output()?;
            match output.status.code() {
                Some(0) => {}
                Some(1) => {
                    let name = format!("qualification-library-{}", mounts.len());
                    let source = bundle.join("lib").join(library);
                    volumes
                        .push(json!({"name": name, "hostPath": {"path": source, "type": "File"}}));
                    mounts.push(json!({"name": name, "mountPath": path, "readOnly": true}));
                    recovery.push(RuntimeRecoveryMountInputV1 {
                        source,
                        destination: path.into(),
                        read_only: true,
                    });
                }
                _ => return Err("the Node base-library check failed".into()),
            }
        }
        if !mounts.is_empty() {
            let sets = Api::<DaemonSet>::namespaced(self.client.clone(), &self.system);
            let args = Self::capture_installer(
                &self.runtime.block_on(sets.get("mithril-node"))?,
                &recovery,
            )?;
            self.runtime.block_on(sets.patch(
                "mithril-node",
                &PatchParams::default(),
                &Patch::Strategic(json!({
                    "spec": {"template": {"spec": {"volumes": volumes,
                        "initContainers": [{"name": "install-runtime-gate", "args": args}],
                        "containers": [{"name": "mithril-node", "volumeMounts": mounts}]}}}
                })),
            ))?;
            self.capture_rollout("daemonset/mithril-node")?;
            self.wait_node()?;
        }
        Ok(json!({
            "node": self.capture_runtime("daemonset/mithril-node", "/usr/local/bin/mithril-node", false)?,
            "backend": self.capture_runtime("daemonset/mithril-node", "/usr/bin/bpftrace", false)?,
            "control_child": self.capture_runtime("deployment/mithril-control", "/qualification/test", false)?,
            "mounted_libraries": mounts,
        }))
    }

    fn start_capture(&self) -> TestResult<()> {
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        self.runtime.block_on(deployments.patch("mithril-control", &PatchParams::default(), &Patch::Strategic(json!({
            "spec": {"template": {"spec": {"containers": [{"name": "mithril-control",
                "command": ["/qualification/test"],
                "args": ["platform::kubernetes::observability_pod_child", "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                "env": [
                    {"name": "MITHRIL_TRACE_DIRECTORY", "value": "/qualification/capture"},
                    {"name": "MITHRIL_TRACE_NAMESPACE", "value": self.namespace},
                    {"name": "MITHRIL_TRACE_POD", "value": self.actor_name}
                ]
            }]}}}
        }))))?;
        self.capture_rollout("deployment/mithril-control")?;
        self.wait_node()
    }

    fn capture_input(&self, name: &str, record: &impl serde::Serialize) -> TestResult<()> {
        let path = self.state_path.with_file_name("capture").join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    fn capture_record(&self, name: &str) -> TestResult<Value> {
        let path = self.state_path.with_file_name("capture").join(name);
        Ok(wait_for(
            &path,
            "Control capture result",
            READY_LIMIT,
            || {
                if !path.is_file() {
                    return Ok(None);
                }
                let bytes = fs::read(&path).context(IoSnafu { path: &path })?;
                serde_json::from_slice(&bytes).map(Some).map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: format!("invalid Control capture record: {source}"),
                    }
                    .build()
                })
            },
            || self.diagnostics(),
        )?)
    }

    fn capture_ack(&self, result: &Value, sequence: u64) -> TestResult<Value> {
        let terminal: mithril_control::TraceTerminalV1 =
            serde_json::from_value(result["terminal"].clone())?;
        terminal.validate()?;
        if terminal.last_sequence < sequence {
            return Err("the terminal does not cover the output after the query error".into());
        }
        let directory = self
            .state_path
            .join("diagnostics")
            .join(hex::encode(terminal.execution_id));
        let path = directory.join("ack.json");
        let ack = wait_for(
            &path,
            "Node durable diagnostic acknowledgement",
            READY_LIMIT,
            || {
                let file = match File::open(&path) {
                    Ok(file) => file,
                    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(None);
                    }
                    Err(source) => return Err(source).context(IoSnafu { path: &path }),
                };
                let mut bytes = Vec::new();
                file.take(4097)
                    .read_to_end(&mut bytes)
                    .context(IoSnafu { path: &path })?;
                if bytes.len() > 4096 {
                    return Err(InvalidInputSnafu {
                        path: &path,
                        reason: "the Node acknowledgement exceeds its byte bound",
                    }
                    .build());
                }
                let ack: mithril_control::TraceTerminalV1 = serde_json::from_slice(&bytes)
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: &path,
                            reason: format!("invalid Node acknowledgement: {source}"),
                        }
                        .build()
                    })?;
                if ack != terminal {
                    return Err(InvalidInputSnafu {
                        path: &path,
                        reason: "the Node acknowledgement differs from the Control terminal",
                    }
                    .build());
                }
                let output = directory.join("output.jsonl");
                if fs::metadata(&output)
                    .context(IoSnafu { path: &output })?
                    .len()
                    != 0
                {
                    return Ok(None);
                }
                Ok(Some(ack))
            },
            || self.diagnostics(),
        )?;
        Ok(serde_json::to_value(ack)?)
    }

    fn capture_denial(&mut self, actor: &mut ProcessFixture, name: &str) -> TestResult<Value> {
        actor.send(b"/fixtures/policy_replace.py\n")?;
        let text = actor.wait_text(&self.work_path.join(name).join("0.json"), "protected read")?;
        let result: (i32, usize) = serde_json::from_str(&text)?;
        if result != (libc::EACCES, 0) {
            return Err(format!("the protected read changed its physical decision: {text}").into());
        }
        let task = self.task(actor.id(), "protected Pod reader")?;
        let path = self.pin_path.clone();
        let event = wait_for(
            &path,
            "protected read evidence",
            READY_LIMIT,
            || {
                let snapshot = self
                    .snapshot()
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu { path: &path })?;
                Ok(snapshot.recent_effects.into_iter().find(|event| {
                    task.matches_effect(
                        event,
                        "EXACT_POLICY_DENY",
                        erebor_interceptor_abi::KernelEffectFamilyV1::File,
                        erebor_interceptor_abi::KernelEffectOperationV1::OpenRead,
                        -libc::EACCES,
                    )
                }))
            },
            || self.diagnostics(),
        )?;
        actor.ensure_running("protected Pod reader")?;
        Ok(json!({"errno": result.0, "size": result.1, "event": {
            "reason": event.reason, "kernel_result": event.kernel_result,
            "effect_family": event.effect_family, "operation": event.operation,
            "task_cookie": event.task_cookie, "binding_id": event.binding_id,
            "profile_generation_ref_id": event.profile_generation_ref_id,
            "source_sequence": event.source_sequence,
        }}))
    }

    fn capture_cleanup(
        &self,
        expected: &crate::observability::OwnedResources,
        observed: &crate::observability::ResourceSnapshot,
    ) -> TestResult<()> {
        let last = RefCell::new(None);
        wait_stable(
            &self.pin_path,
            "diagnostic BPF cleanup",
            READY_LIMIT,
            2,
            || {
                let actual = crate::observability::ResourceSnapshot::read()
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu {
                        path: &self.pin_path,
                    })?;
                let owned = crate::observability::ResourceSnapshot::owned(&self.pin_path)
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .context(IoSnafu {
                        path: &self.pin_path,
                    })?;
                let complete = actual.cleanup_matches(expected, observed, &owned)
                    && observed
                        .absent()
                        .map_err(|error| std::io::Error::other(error.to_string()))
                        .context(IoSnafu {
                            path: &self.pin_path,
                        })?;
                *last.borrow_mut() = Some((actual, owned));
                Ok(complete)
            },
            || {
                format!(
                    "expected={expected:?}, observed={observed:?}, actual={:?}",
                    last.borrow()
                )
            },
        )?;
        Ok(())
    }

    fn capture_resources(
        &self,
        initial: &crate::observability::ResourceSnapshot,
        expected: &crate::observability::OwnedResources,
    ) -> TestResult<crate::observability::ResourceSnapshot> {
        if crate::observability::ResourceSnapshot::owned(&self.pin_path)? != *expected {
            return Err("the real capture changed enforcement resources".into());
        }
        crate::observability::ResourceSnapshot::failed_opens(initial)
    }

    fn capture_identity(&self, accepted: &Value, uid: &str) -> TestResult<()> {
        let target = &accepted["request"]["targets"][0];
        let group = self
            .actor_cgroup
            .as_ref()
            .ok_or("the Pod has no real cgroup")?;
        if target["fact"]["pod_uid"].as_str() != Some(uid)
            || target["fact"]["kubernetes"]["pod_name"].as_str() != Some(ACTOR)
            || target["runtime_container_id"].as_str() != self.actor_id.as_deref()
            || target["cgroup_id"].as_u64() != Some(fs::metadata(group)?.ino())
        {
            return Err("Control did not freeze the actual Pod, CRI container, and cgroup".into());
        }
        Ok(())
    }

    fn capture_exit(actor: &mut ProcessFixture) -> TestResult<()> {
        actor.stop()?;
        Ok(())
    }

    fn delete_capture(&mut self, actor: &mut ProcessFixture) -> TestResult<()> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.namespace);
        let original = self
            .pod()?
            .metadata
            .uid
            .ok_or("the original Pod has no UID")?;
        self.runtime.block_on(pods.delete(
            &self.actor_name,
            &DeleteParams {
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(original.clone()),
                    resource_version: None,
                }),
                grace_period_seconds: Some(1),
                ..DeleteParams::default()
            },
        ))?;
        wait_for(
            &self.work_path,
            "original Pod deletion",
            STOP_LIMIT,
            || match self.runtime.block_on(pods.get(&self.actor_name)) {
                Err(kube::Error::Api(response)) if response.code == 404 => Ok(Some(())),
                Ok(pod) if pod.metadata.uid.as_deref() == Some(&original) => Ok(None),
                Ok(_) => Err(InvalidInputSnafu {
                    path: &self.work_path,
                    reason: "the Pod name changed before deletion completed",
                }
                .build()),
                Err(source) => Err(std::io::Error::other(source.to_string())).context(IoSnafu {
                    path: &self.work_path,
                }),
            },
            || self.diagnostics(),
        )?;
        Self::capture_exit(actor)?;
        self.actor_id = None;
        self.actor_pid = None;
        self.actor_cgroup = None;
        self.actors.clear();
        self.wait_policy(0)
    }

    pub(super) fn qualify_pods() -> TestResult<()> {
        let test_admission = super::super::shared::Shared::test_admission()?;
        let proof = PathBuf::from(KubernetesState::required("MITHRIL_TRACE_PROOF")?);
        if proof.exists() || !proof.is_absolute() {
            return Err("the Pod proof must name a new absolute file".into());
        }
        let (bundle, libraries) = Self::capture_bundle()?;
        let config = if test_admission {
            super::super::shared::Shared::capture_config(
                &bundle.join("bpftrace"),
                PathBuf::from("/usr/bin/bpftrace"),
                std::thread::available_parallelism()?.get(),
                1,
            )?
        } else {
            serde_json::from_slice(&fs::read(KubernetesState::required(
                "MITHRIL_TRACE_CONFIG",
            )?)?)?
        };
        use sha2::Digest as _;
        let digest: [u8; 32] = sha2::Sha256::digest(fs::read(bundle.join("bpftrace"))?).into();
        if digest != config.qualification.executable_sha256 {
            return Err("the bundled backend differs from its pinned configuration".into());
        }
        let mut env = Self::setup("observability-pods")?;
        let capture = env.state_path.with_file_name("capture");
        let result = (|| {
            env.configure_capture(&config)?;
            env.start_control()?;
            env.mount_capture(&bundle, config.qualification.logical_cpus)?;
            let labels = env.install_policy("multi_policy_deny.json")?;
            env.start_node()?;
            let preflight = env.prepare_runtime(&bundle, &libraries)?;
            env.start_capture()?;
            env.node_ready()?;
            let mut actor = env.start_actor("read_path.py", &["before"], &labels)?;
            env.wait_workload_ready()?;
            env.running(actor.id())?;
            let initial = crate::observability::ResourceSnapshot::capture_baseline()?;
            let enforcement = crate::observability::ResourceSnapshot::owned(&env.pin_path)?;
            let original_uid = env
                .pod()?
                .metadata
                .uid
                .ok_or("the original Pod has no UID")?;
            env.capture_input(
                "start-0.json",
                &json!({"pod_uid": original_uid, "request_id": uuid::Uuid::new_v4().as_bytes()}),
            )?;
            let original = env.capture_record("ready-0.json")?;
            env.capture_identity(&original, &original_uid)?;
            let active = env.capture_resources(&initial, &enforcement)?;
            env.capture_record("query-failed-0.json")?;
            let before = env.capture_denial(&mut actor, "before")?;
            let mut failure = env.capture_record("query-after-0.json")?;
            env.delete_capture(&mut actor)?;
            let completed = env.capture_record("done-0.json")?;
            let sequence = failure["post_failure_sequence"]
                .as_u64()
                .ok_or("the query case has no new output sequence")?;
            failure["node_acknowledgement"] = env.capture_ack(&completed, sequence)?;
            failure["post_failure_acknowledged"] = json!(true);
            env.capture_cleanup(&enforcement, &active)?;

            let mut actor = env.start_actor("read_path.py", &["after"], &labels)?;
            env.wait_workload_ready()?;
            env.running(actor.id())?;
            let baseline = crate::observability::ResourceSnapshot::capture_baseline()?;
            let replacement_uid = env
                .pod()?
                .metadata
                .uid
                .ok_or("the replacement Pod has no UID")?;
            if replacement_uid == original_uid || env.actor_name != ACTOR {
                return Err("the fixture did not replace the same Pod name with a new UID".into());
            }
            env.capture_input(
                "start-1.json",
                &json!({"pod_uid": replacement_uid, "request_id": uuid::Uuid::new_v4().as_bytes()}),
            )?;
            let replacement = env.capture_record("ready-1.json")?;
            env.capture_identity(&replacement, &replacement_uid)?;
            let active_after = env.capture_resources(&baseline, &enforcement)?;
            let after = env.capture_denial(&mut actor, "after")?;
            env.capture_input("stop-1.json", &json!({"stop": true}))?;
            let mut record = env.capture_record("result.json")?;
            env.capture_cleanup(&enforcement, &active_after)?;
            let pods = Api::<Pod>::namespaced(env.client.clone(), &env.system);
            let control =
                env.runtime
                    .block_on(pods.list(
                        &ListParams::default().labels("app.kubernetes.io/name=mithril-control"),
                    ))?
                    .items;
            if control.len() != 1
                || control[0]
                    .status
                    .as_ref()
                    .and_then(|status| status.container_statuses.as_ref())
                    .is_none_or(|statuses| statuses.len() != 1 || statuses[0].restart_count != 0)
            {
                return Err("the finite Control child restarted during the case".into());
            }
            record["physical"] = json!(true);
            record["query_failure"] = failure;
            record["physical_denials"] = json!([before, after]);
            record["runtime_preflight"] = preflight;
            if test_admission {
                record["diagnostic_admission"] = json!("synthetic-test-only");
                record["performance_qualified"] = json!(false);
                record["performance_claim"] = json!(false);
            } else {
                record["diagnostic_admission"] = json!("qualified-config");
                record["qualification"] = serde_json::to_value(config)?;
            }
            record["enforcement_resources_unchanged"] = json!(true);
            record["cleanup_observed"] = json!(true);
            record["diagnostic_resources"] =
                json!({"original": active, "replacement": active_after});
            record["resources"] = json!({"initial": enforcement, "final": crate::observability::ResourceSnapshot::owned(&env.pin_path)?});
            actor.stop()?;
            let finish = env.state_path.with_file_name("capture").join("finish.json");
            let temporary = finish.with_extension("tmp");
            fs::write(
                &temporary,
                serde_json::to_vec_pretty(&json!({"finish": true}))?,
            )?;
            Self::capture_finish(&mut env, &temporary, &finish, |env| env.clean_test())?;
            fs::write(proof, serde_json::to_vec_pretty(&record)?)?;
            Ok(())
        })();
        Self::capture_result(&capture, result, || env.snapshot())
    }

    fn capture_result(
        path: &Path,
        result: TestResult<()>,
        snapshot: impl FnOnce() -> TestResult<MithrilObservationSnapshot>,
    ) -> TestResult<()> {
        if let Err(error) = &result {
            if path.exists() {
                let (name, bytes) = match snapshot() {
                    Ok(snapshot) => ("node-snapshot.pb", snapshot.encode_to_vec()),
                    Err(source) => ("node-snapshot-error.txt", source.to_string().into_bytes()),
                };
                for (name, bytes) in [
                    ("capture-failure.txt", error.to_string().into_bytes()),
                    (name, bytes),
                ] {
                    let file = path.join(name);
                    if let Err(source) = fs::write(&file, bytes) {
                        erebor_telemetry::warn!(
                            "capture diagnostics could not be retained",
                            path = %file.display(),
                            error = %source,
                        );
                    }
                }
                let retained = path
                    .parent()
                    .ok_or("the capture directory has no parent")?
                    .with_extension("capture-failed");
                if retained.exists() {
                    return Err(format!(
                        "{error}; the retained capture directory already exists: {}",
                        retained.display()
                    )
                    .into());
                }
                fs::rename(path, &retained).map_err(|source| {
                    format!(
                        "{error}; capture evidence could not be retained at {}: {source}",
                        retained.display()
                    )
                })?;
                erebor_telemetry::info!(
                    "retained failed capture evidence",
                    path = %retained.display()
                );
            }
        }
        result
    }

    fn capture_finish<P: Platform>(
        env: &mut P,
        temporary: &Path,
        finish: &Path,
        retire: impl FnOnce(&mut P) -> TestResult<()>,
    ) -> TestResult<()> {
        retire(env)?;
        env.stop_node()?;
        env.stop()?;
        fs::rename(temporary, finish)?;
        Ok(())
    }
}

impl PodCapture {
    fn now() -> TestResult<u64> {
        Ok(u64::try_from(
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        )?)
    }

    fn write(&self, name: &str, record: &impl serde::Serialize) -> TestResult<()> {
        let path = self.directory.join(name);
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(record)?)?;
        fs::rename(temporary, path)?;
        Ok(())
    }

    async fn input(&self, name: &str) -> TestResult<Value> {
        let path = self.directory.join(name);
        let deadline = Instant::now() + READY_LIMIT;
        loop {
            match fs::read(&path) {
                Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
                Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(source.into()),
            }
            if Instant::now() >= deadline {
                return Err(format!("capture input is absent: {}", path.display()).into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn submit(&self, input: &Value) -> TestResult<TraceAcceptedV1> {
        let uid = input["pod_uid"]
            .as_str()
            .ok_or("capture input has no Pod UID")?;
        let request_id: [u8; 16] = serde_json::from_value(input["request_id"].clone())?;
        let deadline = Instant::now() + READY_LIMIT;
        loop {
            let facts = self
                .control
                .kubernetes_workload_inventory()
                .into_iter()
                .filter(|fact| {
                    fact.pod_uid == uid
                        && fact.container_name == CONTAINER
                        && fact.kubernetes.as_ref().is_some_and(|identity| {
                            identity.namespace_name == self.namespace
                                && identity.pod_name == self.pod_name
                        })
                })
                .collect::<Vec<_>>();
            if facts.len() > 1 {
                return Err("capture inventory has more than one matching container".into());
            }
            if !facts.is_empty() {
                let grant = TraceAccessV1 {
                    tenant_id: self.tenant_id,
                    principal: "pod-qualification".to_owned(),
                    valid_until_unix_ns: Self::now()? + 900_000_000_000,
                    revoked: false,
                };
                let participants = self.control.resolve_trace_targets(facts, &grant).await?;
                if let [participant] = participants.as_slice() {
                    if let Some(target) = &participant.target {
                        let request = TraceRequestV1 {
                            tenant_id: self.tenant_id,
                            request_id,
                            source: TraceRecipeV1::FailedOpens.manifest()?.source,
                            targets: vec![target.clone()],
                            unresolved: Vec::new(),
                            collection_seconds: 120,
                            selection: None,
                            finding_reference: None,
                        };
                        self.control.accept_trace(request, grant.clone())?;
                        return Ok(self
                            .traces
                            .read(self.tenant_id, request_id, &grant, Self::now()?)?
                            .1);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err("Control did not resolve the live Pod through Node".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn output(&self, accepted: &TraceAcceptedV1) -> TestResult<Vec<TraceBatchV1>> {
        let mut after = 0;
        let mut retained = Vec::new();
        loop {
            let page = self.traces.output(
                self.tenant_id,
                accepted.request.request_id,
                0,
                &accepted.access,
                Self::now()?,
                after,
            )?;
            let last = page
                .iter()
                .rev()
                .find_map(|batch| batch.frames.last().map(|frame| frame.sequence));
            let terminal = page.iter().any(|batch| batch.terminal.is_some());
            retained.extend(page);
            if terminal || last.is_none() {
                return Ok(retained);
            }
            let next = last.ok_or("capture page has no sequence")?;
            if next <= after || next > 4096 {
                return Err("capture output did not advance within its frame bound".into());
            }
            after = next;
        }
    }

    fn receipt(
        &self,
        accepted: &TraceAcceptedV1,
    ) -> TestResult<araphor_data::TraceOutputReceiptV1> {
        let data = self
            .control
            .analysis_store()
            .ok_or("capture store is absent")?;
        let execution = accepted.execution_id(0)?;
        let (_, intent) = data
            .trace_intent(self.tenant_id, accepted.request.request_id)?
            .ok_or("capture intent is absent")?;
        let binding = intent
            .bindings
            .iter()
            .find(|binding| binding.identity.execution_id == execution)
            .ok_or("capture binding is absent")?;
        Ok(data
            .trace_receipt(&binding.identity)?
            .ok_or("capture receipt is absent")?)
    }

    async fn query_capture(&self, accepted: &TraceAcceptedV1) -> TestResult<Value> {
        let before = self.receipt(accepted)?;
        let prefix = self.output(accepted)?;
        let prior = prefix
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= before.last_sequence)
            .collect::<Vec<_>>();
        if before.terminal.is_some()
            || prefix.iter().any(|batch| batch.terminal.is_some())
            || prior.last().map(|frame| frame.sequence) != Some(before.last_sequence)
        {
            return Err("the query case has no active durable capture prefix".into());
        }
        let client = AraphorClient::connect(self.query_profile.clone()).await?;
        let mut failure =
            crate::observability::ObservabilityQualification::query_failure(&client).await?;
        let baseline = self.receipt(accepted)?;
        let retained = self.output(accepted)?;
        let current = retained
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= before.last_sequence)
            .collect::<Vec<_>>();
        let data = self
            .control
            .analysis_store()
            .ok_or("capture store is absent")?;
        if baseline.terminal.is_some()
            || baseline.identity != before.identity
            || baseline.last_sequence < before.last_sequence
            || retained.iter().any(|batch| batch.terminal.is_some())
            || current != prior
            || !data.storage_health()?.write_ready
            || self
                .traces
                .read(
                    self.tenant_id,
                    accepted.request.request_id,
                    &accepted.access,
                    Self::now()?,
                )?
                .1
                != *accepted
        {
            return Err("the public query error changed the capture or durable prefix".into());
        }
        let count = retained
            .iter()
            .flat_map(|batch| &batch.frames)
            .filter(|frame| frame.sequence <= baseline.last_sequence)
            .filter_map(|frame| TraceRecipeV1::FailedOpens.measurements(frame))
            .flatten()
            .filter(|row| row.errno == -i64::from(libc::EACCES))
            .map(|row| row.count)
            .max()
            .unwrap_or(0);
        failure["prefix_sequence"] = json!(baseline.last_sequence);
        failure["prefix_revision"] = json!(baseline.commit_revision);
        failure["prefix_output_bytes"] = json!(baseline.output_bytes);
        failure["prefix_count"] = json!(count);
        failure["capture_active"] = json!(true);
        failure["prefix_unchanged"] = json!(true);
        failure["writer_ready"] = json!(true);
        self.write("query-failed-0.json", &failure)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let receipt = self.receipt(accepted)?;
            let output = self.output(accepted)?;
            if receipt.terminal.is_some()
                || output.iter().any(|batch| batch.terminal.is_some())
                || receipt.identity != baseline.identity
            {
                return Err("capture stopped before new output after the query error".into());
            }
            let next = output
                .iter()
                .flat_map(|batch| &batch.frames)
                .filter(|frame| {
                    frame.sequence > baseline.last_sequence
                        && frame.sequence <= receipt.last_sequence
                })
                .find_map(|frame| {
                    TraceRecipeV1::FailedOpens
                        .measurements(frame)?
                        .into_iter()
                        .find(|row| row.errno == -i64::from(libc::EACCES) && row.count > count)
                        .map(|row| (frame.sequence, row.count))
                });
            if let Some((sequence, count)) = next {
                if receipt.commit_revision <= baseline.commit_revision
                    || receipt.output_bytes <= baseline.output_bytes
                    || !data.storage_health()?.write_ready
                {
                    return Err("new capture output has no advanced durable receipt".into());
                }
                failure["post_failure_sequence"] = json!(sequence);
                failure["post_failure_revision"] = json!(receipt.commit_revision);
                failure["post_failure_output_bytes"] = json!(receipt.output_bytes);
                failure["post_failure_count"] = json!(count);
                failure["durable_receipt_advanced"] = json!(true);
                self.write("query-after-0.json", &failure)?;
                return Ok(failure);
            }
            if Instant::now() >= deadline {
                return Err("capture has no new denied-open output after the query error".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn ready(&self, accepted: &TraceAcceptedV1) -> TestResult<()> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let output = self.output(accepted)?;
            if output.iter().flat_map(|batch| &batch.frames).any(|frame| {
                frame.kind == mithril_control::TraceFrameKindV1::Diagnostic
                    && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
            }) {
                return Ok(());
            }
            if output.iter().any(|batch| batch.terminal.is_some()) || Instant::now() >= deadline {
                return Err("Node capture did not provide the real attachment notification".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn terminal(
        &self,
        accepted: &TraceAcceptedV1,
        reason: TraceTerminalReasonV1,
    ) -> TestResult<Value> {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let output = self.output(accepted)?;
            if let Some(terminal) = output.iter().find_map(|batch| batch.terminal.as_ref()) {
                let execution = accepted.execution_id(0)?;
                let attachments = output
                    .iter()
                    .flat_map(|batch| &batch.frames)
                    .filter(|frame| {
                        frame.kind == mithril_control::TraceFrameKindV1::Diagnostic
                            && frame.bytes == b"__BPFTRACE_NOTIFY_PROBES_ATTACHED\n"
                    })
                    .count();
                if terminal.reason != reason
                    || terminal.execution_id != execution
                    || attachments != 1
                    || !terminal.output_incomplete
                    || terminal.kernel_lost_events.is_some()
                    || terminal.cleanup == mithril_control::TraceCleanupV1::Failed
                    || output.iter().any(|batch| batch.execution_id != execution)
                {
                    return Err(
                        format!("Node capture has an unexpected terminal: {terminal:?}").into(),
                    );
                }
                if self
                    .traces
                    .read(
                        self.tenant_id,
                        accepted.request.request_id,
                        &accepted.access,
                        Self::now()?,
                    )?
                    .1
                    != *accepted
                {
                    return Err("the frozen accepted trace intent changed".into());
                }
                if !output
                    .iter()
                    .flat_map(|batch| &batch.frames)
                    .filter_map(|frame| TraceRecipeV1::FailedOpens.measurements(frame))
                    .flatten()
                    .any(|row| row.errno == -i64::from(libc::EACCES) && row.count > 0)
                {
                    return Err("the reviewed capture has no denied-open measurement".into());
                }
                let receipt = self.receipt(accepted)?;
                if receipt.terminal.as_ref() != Some(terminal)
                    || receipt.last_sequence != terminal.last_sequence
                {
                    return Err("the retained terminal differs from its durable receipt".into());
                }
                return Ok(json!({
                    "accepted": accepted, "output": output, "terminal": terminal,
                    "attachment_notifications": attachments,
                    "receipt": {"identity": receipt.identity, "last_sequence": receipt.last_sequence,
                        "output_bytes": receipt.output_bytes, "commit_revision": receipt.commit_revision},
                }));
            }
            if Instant::now() >= deadline {
                return Err("Node capture has no retained terminal within the bound".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn capture(&self) -> TestResult<()> {
        let original = self.submit(&self.input("start-0.json").await?).await?;
        self.ready(&original).await?;
        self.write("ready-0.json", &original)?;
        self.query_capture(&original).await?;
        let original_result = self
            .terminal(&original, TraceTerminalReasonV1::TargetChanged)
            .await?;
        self.write("done-0.json", &original_result)?;

        let replacement = self.submit(&self.input("start-1.json").await?).await?;
        let first = &original.request.targets[0];
        let second = &replacement.request.targets[0];
        if first.fact.pod_uid == second.fact.pod_uid
            || first.runtime_container_id == second.runtime_container_id
            || first.cgroup_id == second.cgroup_id
            || first.root_cgroup_live_interval_id == second.root_cgroup_live_interval_id
        {
            return Err("the replacement request reused the original target lifetime".into());
        }
        self.ready(&replacement).await?;
        self.write("ready-1.json", &replacement)?;
        self.input("stop-1.json").await?;
        self.traces.cancel(
            self.tenant_id,
            replacement.request.request_id,
            &replacement.access,
            Self::now()?,
            false,
        )?;
        let replacement_result = self
            .terminal(&replacement, TraceTerminalReasonV1::Cancelled)
            .await?;
        self.control
            .accept_trace(original.request.clone(), original.access.clone())?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        if serde_json::to_value(self.output(&original)?)? != original_result["output"] {
            return Err("the original execution acquired output after Pod replacement".into());
        }
        self.write("result.json", &json!({
            "schema_version": 1, "case": "owned-pod-replacement", "result": "PASS",
            "original": original_result, "replacement": replacement_result,
            "original_retry": true, "original_output_unchanged": true,
            "discovery_enabled": false, "performance_claim": false,
            "storage": self.control.analysis_store().ok_or("capture store is absent")?.storage_health()?,
        }))?;
        self.input("finish.json").await?;
        Ok(())
    }

    pub(super) async fn run_child() -> TestResult<()> {
        let config = ControlConfig::load(Path::new("/etc/mithril/control.json"))?;
        let policy = config
            .kubernetes_policy
            .as_ref()
            .ok_or("the fixture has no policy owner")?
            .clone();
        let signing: [u8; 32] =
            hex::decode(fs::read_to_string(&policy.signer.signing_key_path)?.trim())?
                .try_into()
                .map_err(|_| "the fixture signer is not 32 bytes")?;
        let mut parts = config.into_parts()?;
        if let Some(error) = parts.data_error {
            return Err(error.into());
        }
        parts.control = parts.control.with_trace_signer(
            policy.signer.signing_key_id,
            policy.signer.distribution_sequence_epoch,
            ed25519_dalek::SigningKey::from_bytes(&signing),
        )?;
        let directory = PathBuf::from(KubernetesState::required("MITHRIL_TRACE_DIRECTORY")?);
        let tenant_id = *uuid::Uuid::parse_str(&policy.tenant_id)?.as_bytes();
        let tls = MtlsFixture::in_directory(tempfile::tempdir_in(&directory)?, false)?;
        let provider =
            crate::control_fixture::oidc::OidcFixture::start(&tls.files, "pod-query-qualification")
                .await?;
        let mut client = parts
            .client
            .take()
            .ok_or("the fixture has no shared client listener")?;
        let client_ca = client
            .auth
            .oidc
            .ca_path
            .clone()
            .ok_or("the fixture has no client TLS trust file")?;
        client.auth = provider.auth(&client.auth.origin, Some(tenant_id), tls.files.ca.clone());
        client.investigation = Some(mithril_control::ClientGrpcConfig::default());
        let mut credential = tempfile::NamedTempFile::new_in(&directory)?;
        credential.write_all(b"fixture-access")?;
        let query_profile = AraphorProfile {
            endpoint: format!("https://localhost:{}", client.listen.port()),
            tenant_id: uuid::Uuid::from_bytes(tenant_id).to_string(),
            credential_file: credential.path().to_path_buf(),
            ca_file: Some(client_ca),
        };
        let owner = Self {
            traces: TraceOwner::new(
                parts
                    .control
                    .analysis_store()
                    .ok_or("capture store is absent")?,
            ),
            control: parts.control,
            directory,
            namespace: KubernetesState::required("MITHRIL_TRACE_NAMESPACE")?,
            pod_name: KubernetesState::required("MITHRIL_TRACE_POD")?,
            tenant_id,
            query_profile,
        };
        let policies = owner
            .control
            .policy_desired_state()
            .ok_or("the fixture has no policy controller")?;
        let nodes = parts
            .kubernetes_nodes
            .ok_or("the fixture has no Node controller")?;
        let admission = parts
            .kubernetes_admission
            .ok_or("the fixture has no admission listener")?;
        let result = tokio::select! {
            result = owner.capture() => result,
            result = mithril_control::serve(parts.listen, &parts.tls, owner.control.clone(), std::future::pending::<()>()) => {
                result?; Err("the Control listener stopped before fixture completion".into())
            },
            _ = policies.clone().run_kubernetes(owner.control.clone()) => Err("the policy controller stopped".into()),
            _ = nodes.clone().run_kubernetes(owner.control.clone()) => Err("the Node controller stopped".into()),
            result = mithril_control::KubernetesAdmissionOwner::serve(admission, owner.control.clone(), policies, nodes, std::future::pending::<()>()) => {
                result?; Err("the admission listener stopped".into())
            },
            result = async {
                mithril_control::ClientListener::load(client, owner.control.clone()).await?
                    .serve(std::future::pending::<()>()).await
            } => {
                result?; Err("the shared client listener stopped".into())
            },
            _ = tokio::time::sleep(Duration::from_secs(900)) => Err("the Control fixture exceeded its lifetime".into()),
        };
        let stopped = provider.shutdown().await;
        result?;
        stopped?;
        Ok(())
    }
}

#[test]
fn observability_capture_cleanup() -> TestResult<()> {
    let directory = tempfile::tempdir()?;
    for failed in [false, true] {
        let path = directory
            .path()
            .join(if failed { "failed" } else { "success" });
        let out = ProbeDirectory::create(&path)?;
        let capture = path.join("capture");
        fs::create_dir(&capture)?;
        fs::write(capture.join("ready-1.json"), b"retained capture prefix")?;
        fs::write(path.join("unrelated"), b"scenario input")?;
        let result = Kubernetes::capture_result(
            &capture,
            if failed {
                Err("the capture child failed".into())
            } else {
                Ok(())
            },
            || {
                assert!(failed, "successful capture read failure diagnostics");
                Ok(MithrilObservationSnapshot::default())
            },
        );
        assert_eq!(result.is_err(), failed);
        if let Err(error) = result {
            assert_eq!(error.to_string(), "the capture child failed");
        }
        drop(out);
        assert!(!path.exists());
        let retained = path.with_extension("capture-failed");
        assert_eq!(retained.exists(), failed);
        if failed {
            assert_eq!(
                fs::read(retained.join("ready-1.json"))?,
                b"retained capture prefix"
            );
            assert!(!retained.join("unrelated").exists());
        }
    }
    Ok(())
}

#[test]
fn observability_startup_failure() -> TestResult<()> {
    use erebor_runtime_ipc::v1::MithrilEffectObservation;

    let directory = tempfile::tempdir()?;
    let error = "Kubernetes actor worker exited with code 1; Fatal Python error: Failed to import encodings module; PermissionError: [Errno 13] Permission denied: '/usr/local/lib/python3.13/encodings/aliases.py'";
    // These event fields are test input, not a measured cause.
    let event = MithrilEffectObservation {
        reason: "EXACT_POLICY_DENY".to_owned(),
        kernel_result: -libc::EACCES,
        source_sequence: 1,
        source_cpu_id: 2,
        operation_argument: 7,
        execution_approval_trace_stage: u32::from(
            erebor_interceptor_abi::EXECUTION_APPROVAL_TRACE_STAGE_EXECVE_ENTRY_V1,
        ),
        ..Default::default()
    };
    let mut snapshot = MithrilObservationSnapshot {
        cgroup_scope: "/".to_owned(),
        effect_health_available: true,
        unresolved_effects: 3,
        evidence_errors: 4,
        recent_effects: vec![event.clone()],
        ..Default::default()
    };
    snapshot
        .recent_effects
        .extend((2..=1024).map(|sequence| MithrilEffectObservation {
            reason: "APPLICATION_DEFAULT_ALLOW".to_owned(),
            kernel_result: 0,
            source_sequence: sequence,
            ..event.clone()
        }));
    assert!(snapshot
        .recent_effects
        .iter()
        .rev()
        .take(16)
        .all(|event| event.kernel_result == 0));
    for available in [true, false] {
        let path = directory
            .path()
            .join(if available { "observed" } else { "unavailable" });
        let out = ProbeDirectory::create(&path)?;
        let capture = path.join("capture");
        fs::create_dir(&capture)?;
        let result = Kubernetes::capture_result(&capture, Err(error.into()), || {
            if available {
                Ok(snapshot.clone())
            } else {
                Err("the Node observation socket is unavailable".into())
            }
        });
        assert_eq!(
            result
                .err()
                .ok_or("the startup failure succeeded")?
                .to_string(),
            error
        );
        drop(out);
        let retained = path.with_extension("capture-failed");
        assert!(!path.exists());
        assert_eq!(
            fs::read_to_string(retained.join("capture-failure.txt"))?,
            error
        );
        for name in ["start-0.json", "ready-0.json", "result.json"] {
            assert!(!retained.join(name).exists());
        }
        if available {
            let bytes = fs::read(retained.join("node-snapshot.pb"))?;
            assert_eq!(
                MithrilObservationSnapshot::decode(bytes.as_slice())?,
                snapshot
            );
            assert!(!retained.join("node-snapshot-error.txt").exists());
        } else {
            assert!(!retained.join("node-snapshot.pb").exists());
            assert_eq!(
                fs::read_to_string(retained.join("node-snapshot-error.txt"))?,
                "the Node observation socket is unavailable"
            );
        }
    }
    Ok(())
}

#[test]
fn observability_pod_finish() -> TestResult<()> {
    struct CapturePlatform {
        finish: PathBuf,
        reader: KernelStateReader,
        retired: bool,
        node_stopped: bool,
        closed: bool,
        fail_stop: bool,
    }

    impl Platform for CapturePlatform {
        fn source(&self) -> &Path {
            &self.finish
        }

        fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
            Err("the shutdown double has no observation snapshot".into())
        }

        fn maps(&self) -> (&Path, &KernelStateReader) {
            (&self.finish, &self.reader)
        }

        fn stop_node(&mut self) -> TestResult<()> {
            if self.finish.exists() || self.closed || !self.retired {
                return Err("Node stop needs live Control, a held guard and retired work".into());
            }
            if self.fail_stop {
                return Err("Node stop failed".into());
            }
            self.node_stopped = true;
            Ok(())
        }

        fn stop(&mut self) -> TestResult<()> {
            if self.finish.exists() || !self.node_stopped {
                return Err("the guard closes before Node stop".into());
            }
            self.closed = true;
            Ok(())
        }
    }

    for failure in [None, Some("retirement"), Some("node")] {
        let directory = tempfile::tempdir()?;
        let temporary = directory.path().join("finish.tmp");
        let finish = directory.path().join("finish.json");
        fs::write(&temporary, b"{\"finish\":true}")?;
        let mut env = CapturePlatform {
            finish: finish.clone(),
            reader: KernelStateReader::new(directory.path()),
            retired: false,
            node_stopped: false,
            closed: false,
            fail_stop: failure == Some("node"),
        };
        let result = Kubernetes::capture_finish(&mut env, &temporary, &finish, |env| {
            if failure == Some("retirement") {
                return Err("scenario retirement failed".into());
            }
            if env.closed || env.node_stopped || env.finish.exists() {
                return Err("scenario retirement needs live Node and Control".into());
            }
            env.retired = true;
            Ok(())
        });
        if failure.is_none() {
            result?;
            assert!(env.retired && env.node_stopped && env.closed);
            assert_eq!(fs::read(&finish)?, b"{\"finish\":true}");
            assert!(!temporary.exists());
        } else {
            assert!(result.is_err());
            assert!(!env.node_stopped && !env.closed && !finish.exists());
            assert!(temporary.exists());
            assert_eq!(env.retired, failure == Some("node"));
        }
    }
    Ok(())
}

#[test]
fn observability_pod_exec_exit() -> TestResult<()> {
    let path = Path::new("/bin/cat");
    let mut command = Command::new(path);
    let mut remote = ProcessFixture::spawn(&mut command, path)?;
    let mut actor = ProcessFixture::spawn(&mut command, path)?;
    let transport_pid = actor.id();
    let remote_pid = remote.id();
    actor.set_actor(remote_pid)?;
    actor.set_exit_probe(|| Ok(None));
    remote.close();
    assert!(remote
        .wait_exit("remote Pod actor", Duration::from_secs(2))?
        .success());
    remote.stop()?;
    assert!(!Path::new(&format!("/proc/{remote_pid}")).exists());
    actor.ensure_running("local exec transport with open stdin")?;
    assert!(Path::new(&format!("/proc/{transport_pid}")).exists());
    Kubernetes::capture_exit(&mut actor)?;
    assert!(!Path::new(&format!("/proc/{transport_pid}")).exists());
    Ok(())
}

#[test]
fn observability_runtime_mount_args() -> TestResult<()> {
    let chart_pairs = [
        ("--owner", "mithril-pid-test/mithril"),
        ("--hook-host-directory", "/usr/libexec/oci/hooks.d"),
        (
            "--containerd-host-directory",
            "/var/lib/rancher/k3s/agent/etc/containerd",
        ),
        ("--containerd-drop-in-directory", "config-v3.toml.d"),
        ("--runtime-cli-host-path", "/usr/local/bin/k3s"),
        ("--runtime-cli-arg", "ctr"),
        ("--runtime-cli-arg", "oci"),
        ("--runtime-cli-arg", "spec"),
        ("--runtime-service", "k3s"),
        ("--socket", "/run/mithril/mithril-pid-test.sock"),
        ("--timeout-ms", "4000"),
        ("--runtime-timeout-seconds", "5"),
        (
            "--log-filter",
            "info,mithril_node::node=debug,mithril_node::policy=debug",
        ),
        ("--decommission-state-directory", "/var/lib/mithril"),
        ("--control-read-only-mount", "/etc/mithril"),
        ("--control-read-write-mount", "/var/lib/mithril-control"),
        ("--control-read-only-mount", "/etc/mithril/admission-tls"),
        (
            "--node-read-only-mount",
            "/qualification/node.json=/etc/mithril/node.json",
        ),
        (
            "--node-read-only-mount",
            "/qualification/identity=/etc/mithril/identity",
        ),
        ("--node-read-only-mount", "/sys/kernel/btf=/sys/kernel/btf"),
        (
            "--node-read-only-mount",
            "/sys/kernel/tracing=/sys/kernel/tracing",
        ),
        ("--node-read-only-mount", "/sys/fs/cgroup=/sys/fs/cgroup"),
        (
            "--node-read-only-mount",
            "/run/k3s/containerd=/run/k3s/containerd",
        ),
        ("--node-read-write-mount", "/sys/fs/bpf=/sys/fs/bpf"),
        (
            "--node-read-write-mount",
            "/qualification/node=/var/lib/mithril",
        ),
        ("--node-read-write-mount", "/run/mithril=/run/mithril"),
        (
            "--node-read-write-mount",
            "/run/erebor-interceptor=/run/erebor-interceptor",
        ),
        (
            "--node-read-write-mount",
            "/usr/libexec/oci/hooks.d=/host-hook-bin",
        ),
        (
            "--node-read-write-mount",
            "/var/lib/rancher/k3s/agent/etc/containerd=/host-containerd",
        ),
    ];
    let chart_args = chart_pairs
        .iter()
        .flat_map(|(option, value)| [(*option).to_owned(), (*value).to_owned()])
        .collect::<Vec<_>>();
    let fixture = |args: &[String]| {
        serde_json::from_value::<DaemonSet>(json!({
            "spec": {"selector": {}, "template": {"spec": {
                "containers": [], "initContainers": [{
                    "name": "install-runtime-gate",
                    "command": ["/usr/local/bin/mithril-oci-hook", "install"],
                    "args": args,
                }]
            }}}
        }))
    };
    let backend_mounts = [
        RuntimeRecoveryMountInputV1 {
            source: "/qualification-input/runtime".into(),
            destination: "/qualification/runtime".into(),
            read_only: true,
        },
        RuntimeRecoveryMountInputV1 {
            source: "/qualification-input/runtime/bpftrace".into(),
            destination: "/usr/bin/bpftrace".into(),
            read_only: true,
        },
    ];
    let libraries = (0..19)
        .map(|index| RuntimeRecoveryMountInputV1 {
            source: format!("/qualification-input/runtime/lib/libtest-{index}.so.1").into(),
            destination: format!("/usr/lib/x86_64-linux-gnu/libtest-{index}.so.1").into(),
            read_only: true,
        })
        .collect::<Vec<_>>();
    let initial = Kubernetes::capture_installer(&fixture(&chart_args)?, &backend_mounts)?;
    let full = Kubernetes::capture_installer(&fixture(&initial)?, &libraries[..18])?;
    assert_eq!(full.len() + 2, 64);
    assert_eq!(
        full.iter()
            .filter(|arg| arg.starts_with("--node-read-only-mount=")
                || arg.starts_with("--node-read-write-mount="))
            .count(),
        32
    );
    assert_eq!(&full[..initial.len()], initial);
    assert_eq!(Kubernetes::capture_installer(&fixture(&full)?, &[])?, full);
    assert!(Kubernetes::capture_installer(&fixture(&initial)?, &libraries).is_err());
    let mut extra_arg = full.clone();
    extra_arg.push("--runtime-service=k3s".to_owned());
    assert!(Kubernetes::capture_installer(&fixture(&extra_arg)?, &[]).is_err());

    let base_args = [
        "--owner",
        "mithril-pid-test/mithril",
        "--hook-host-directory",
        "/usr/libexec/oci/hooks.d",
        "--containerd-host-directory",
        "/var/lib/rancher/k3s/agent/etc/containerd",
        "--containerd-drop-in-directory",
        "config-v3.toml.d",
        "--runtime-cli-host-path",
        "/usr/local/bin/k3s",
        "--runtime-cli-arg=ctr",
        "--runtime-cli-arg=oci",
        "--runtime-cli-arg=spec",
        "--runtime-service=k3s",
        "--socket",
        "/run/mithril/mithril-pid-test.sock",
        "--timeout-ms",
        "4000",
        "--runtime-timeout-seconds",
        "5",
        "--log-filter",
        "info,mithril_node::node=debug,mithril_node::policy=debug",
        "--decommission-state-directory",
        "/var/lib/mithril",
        "--control-read-only-mount",
        "/etc/mithril",
        "--control-read-write-mount",
        "/var/lib/mithril-control",
        "--control-read-only-mount",
        "/etc/mithril/admission-tls",
        "--node-read-only-mount=/qualification/node.json=/etc/mithril/node.json",
        "--node-read-only-mount=/qualification/identity=/etc/mithril/identity",
        "--node-read-only-mount=/sys/kernel/btf=/sys/kernel/btf",
        "--node-read-only-mount=/sys/kernel/tracing=/sys/kernel/tracing",
        "--node-read-only-mount=/sys/fs/cgroup=/sys/fs/cgroup",
        "--node-read-only-mount=/run/k3s/containerd=/run/k3s/containerd",
        "--node-read-write-mount=/sys/fs/bpf=/sys/fs/bpf",
        "--node-read-write-mount=/qualification/node=/var/lib/mithril",
        "--node-read-write-mount=/run/mithril=/run/mithril",
        "--node-read-write-mount=/run/erebor-interceptor=/run/erebor-interceptor",
        "--node-read-write-mount=/usr/libexec/oci/hooks.d=/host-hook-bin",
        "--node-read-write-mount=/var/lib/rancher/k3s/agent/etc/containerd=/host-containerd",
    ]
    .map(str::to_owned)
    .to_vec();
    let mut expected = base_args.clone();
    expected.extend([
        "--node-read-only-mount=/qualification-input/runtime=/qualification/runtime".to_owned(),
        "--node-read-only-mount=/qualification-input/runtime/bpftrace=/usr/bin/bpftrace".to_owned(),
    ]);
    assert_eq!(initial, expected);
    let mut repeated = chart_args.clone();
    repeated.extend(
        [
            "--runtime-cli-arg",
            "ctr",
            "--runtime-cli-arg=--address=/run/k3s/containerd/containerd.sock",
            "--runtime-service",
            "k3s",
            "--runtime-service=k3s",
        ]
        .map(str::to_owned),
    );
    let mut expected = base_args;
    expected.extend([
        "--runtime-cli-arg=ctr".to_owned(),
        "--runtime-cli-arg=--address=/run/k3s/containerd/containerd.sock".to_owned(),
        "--runtime-service=k3s".to_owned(),
        "--runtime-service=k3s".to_owned(),
    ]);
    assert_eq!(
        Kubernetes::capture_installer(&fixture(&repeated)?, &[])?,
        expected
    );

    for option in [
        "--node-read-only-mount",
        "--node-read-write-mount",
        "--runtime-cli-arg",
        "--runtime-service",
    ] {
        for value in [None, Some(""), Some("--socket"), Some("-x")] {
            let mut invalid = chart_args.clone();
            invalid.push(option.to_owned());
            invalid.extend(value.map(str::to_owned));
            assert!(
                Kubernetes::capture_installer(&fixture(&invalid)?, &[]).is_err(),
                "{option}: {value:?}"
            );
        }
    }
    let option = "--node-read-only-mount";
    let value = format!(
        "/bundle/{}=/runtime",
        "a".repeat(4096 - option.len() - 1 - "/bundle/=/runtime".len())
    );
    let mut bounded = chart_args;
    bounded.extend([option.to_owned(), value]);
    let compact = Kubernetes::capture_installer(&fixture(&bounded)?, &[])?;
    assert_eq!(
        compact.last().ok_or("the compact mount is absent")?.len(),
        4096
    );
    bounded
        .last_mut()
        .ok_or("the mount value is absent")?
        .push('a');
    assert!(Kubernetes::capture_installer(&fixture(&bounded)?, &[]).is_err());
    Ok(())
}

#[test]
fn observability_runtime_library_names() {
    for name in ["libstdc++.so.6", "libLLVM-18.so.1", "libbpf.so.1"] {
        assert!(Kubernetes::capture_library(name), "{name}");
    }
    for name in [
        "../libstdc++.so.6",
        "libstdc++.so.6/child",
        "libstdc++.so.6;command",
        "libstdc++.so.6\n",
        "libstdc++.so.6 ",
        "$(command).so",
        "bpftrace",
        "libc.so.6",
        "libm.so.6",
        "libgcc_s.so.1",
        "ld-linux-x86-64.so.2",
    ] {
        assert!(!Kubernetes::capture_library(name), "{name}");
    }
}
