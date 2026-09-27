use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Command;

use k8s_openapi::api::core::v1::{Lifecycle, LifecycleHandler, Pod, SleepAction};
use kube::api::PostParams;
use kube::Api;
use snafu::ResultExt as _;

use super::super::{actor_script, GroupActor, Labels, Platform, TestResult, PROCESS_FIXTURES};
use super::{Kubernetes, KubernetesState, ACTOR, READY_LIMIT};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::{wait_for, ProbeDirectory};
use crate::process::ProcessFixture;

impl Kubernetes {
    pub(super) fn start_group<F>(
        &mut self,
        manifest: &str,
        actors: &[GroupActor<'_>],
        labels: &Labels,
        before_app: F,
    ) -> TestResult<Vec<(ProcessFixture, PathBuf)>>
    where
        F: FnOnce(&mut Self, &mut Vec<(ProcessFixture, PathBuf)>) -> TestResult<()>,
    {
        if actors.is_empty() {
            return Err("the Kubernetes actor group is empty".into());
        }
        if self.actor_id.is_some() {
            if let Some(work) = self.work.take() {
                self.directories.push(work);
            }
            if let Some(group) = self.move_group.take() {
                self.groups.push(group);
            }
            self.actor_name = format!("{ACTOR}-{}", self.directories.len());
            self.work_path = self.work_path.with_file_name(&self.actor_name);
            self.work = Some(ProbeDirectory::create(&self.work_path)?);
        }
        self.labels = labels.clone();
        self.policy_name = self.policies.get(labels).cloned();
        self.actor_id = None;
        self.actor_pid = None;
        self.actor_cgroup = None;

        let fixtures = self.root.join(PROCESS_FIXTURES);
        let mut pod: Pod = serde_saphyr::from_slice(&fs::read(self.fixture(manifest))?)?;
        pod.metadata.namespace = Some(self.namespace.clone());
        pod.metadata.name = Some(self.actor_name.clone());
        pod.metadata.labels = Some(labels.clone());
        let spec = pod.spec.as_mut().ok_or("the actor Pod has no spec")?;
        let sleep = self.post_sleep.take();
        if sleep.is_some() && actors.len() != 1 {
            return Err("post-start sleep requires one actor".into());
        }
        if let [base] = spec.containers.as_slice() {
            if actors.len() > 1 && spec.init_containers.as_ref().is_none_or(Vec::is_empty) {
                spec.containers = actors
                    .iter()
                    .map(|actor| {
                        let mut container = base.clone();
                        container.name = actor.name.to_owned();
                        container
                    })
                    .collect();
            }
        }
        let count = spec.containers.len() + spec.init_containers.as_ref().map_or(0, Vec::len);
        if count != actors.len() {
            return Err("the actor names do not match the Pod containers".into());
        }
        if let Some(seconds) = sleep {
            spec.termination_grace_period_seconds = Some(seconds + 10);
        }
        spec.node_selector = Some(BTreeMap::from([(
            "kubernetes.io/hostname".to_owned(),
            self.node_name.clone(),
        )]));
        let mut names = BTreeSet::new();
        for actor in actors {
            if !names.insert(actor.name) {
                return Err(format!("duplicate actor name {}", actor.name).into());
            }
            let container = spec
                .init_containers
                .as_mut()
                .and_then(|items| items.iter_mut().find(|item| item.name == actor.name))
                .or_else(|| {
                    spec.containers
                        .iter_mut()
                        .find(|item| item.name == actor.name)
                })
                .ok_or_else(|| format!("the actor Pod has no {} container", actor.name))?;
            if let Some(script) = actor.script {
                actor_script(&self.root, script)?;
                KubernetesState::require_image(&self.k3s_path, &self.actor_image)?;
                let mut args = vec![format!("/fixtures/{script}"), "/work".to_owned()];
                args.extend(actor.args.iter().map(|arg| (*arg).to_owned()));
                container.image = Some(self.actor_image.clone());
                container.command = Some(vec![self.actor_python.clone()]);
                container.args = Some(args);
            }
            if let Some(seconds) = sleep {
                container.lifecycle = Some(Lifecycle {
                    post_start: Some(LifecycleHandler {
                        sleep: Some(SleepAction { seconds }),
                        ..LifecycleHandler::default()
                    }),
                    ..Lifecycle::default()
                });
            }
        }
        if actors.iter().any(|actor| actor.script.is_some()) {
            let volumes = spec
                .volumes
                .as_mut()
                .ok_or("the actor Pod has no volumes")?;
            for (name, path) in [
                ("fixtures", fixtures.as_path()),
                ("work", self.work_path.as_path()),
            ] {
                let source = volumes
                    .iter_mut()
                    .find(|volume| volume.name == name)
                    .and_then(|volume| volume.host_path.as_mut())
                    .ok_or_else(|| format!("the actor Pod has no {name} hostPath"))?;
                source.path = path.display().to_string();
            }
        }
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.namespace);
        self.runtime
            .block_on(pods.create(&PostParams::default(), &pod))?;

        let mut group = Vec::with_capacity(actors.len());
        let mut before_app = Some(before_app);
        for actor in actors {
            if actor.kind(&pod)? == mithril_control::ContainerKindV1::Application {
                if let Some(check) = before_app.take() {
                    check(self, &mut group)?;
                }
            }
            let path = actor
                .script
                .map(|script| fixtures.join(script))
                .unwrap_or_else(|| self.fixture(manifest));
            let last = RefCell::new(String::from("<absent>"));
            let id = wait_for(
                &path,
                "Kubernetes actor container identity",
                READY_LIMIT,
                || match if sleep.is_some() {
                    self.runtime_id()
                } else {
                    self.container_id_for(actor.name)
                } {
                    Ok(id) => Ok(Some(id)),
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        Ok(None)
                    }
                },
                || {
                    format!(
                        "last runtime state: {}; {}",
                        last.borrow(),
                        self.diagnostics()
                    )
                },
            )?;
            let last = RefCell::new(String::from("<absent>"));
            let (pid, cgroup) = wait_for(
                &path,
                "Kubernetes actor runtime identity",
                READY_LIMIT,
                || match self
                    .inspect_pid(&id)
                    .and_then(|pid| KubernetesState::cgroup(pid).map(|group| (pid, group)))
                {
                    Ok(value) => Ok(Some(value)),
                    Err(source) => {
                        let exit = self.pod().ok().and_then(|pod| {
                            KubernetesState::member_status(&pod, actor.name)
                                .and_then(|state| state.state.as_ref())
                                .and_then(|state| state.terminated.clone())
                        });
                        if let Some(exit) = exit {
                            return Err(InvalidInputSnafu {
                                path: &path,
                                reason: format!(
                                    "Kubernetes actor {} exited with code {}; reason: {:?}; message: {:?}; {}",
                                    actor.name, exit.exit_code, exit.reason, exit.message, self.diagnostics()
                                ),
                            }
                            .build());
                        }
                        *last.borrow_mut() = source.to_string();
                        Ok(None)
                    }
                },
                || {
                    format!(
                        "last runtime state: {}; {}",
                        last.borrow(),
                        self.diagnostics()
                    )
                },
            )?;
            if actor.script.is_some() {
                if sleep.is_some() {
                    let ready = self.work_path.join("ready");
                    wait_for(
                        &ready,
                        "Kubernetes actor readiness",
                        READY_LIMIT,
                        || Ok(ready.is_file().then_some(())),
                        || {
                            format!(
                                "ready file exists: {}; {}",
                                ready.exists(),
                                self.diagnostics()
                            )
                        },
                    )?;
                } else {
                    let last = RefCell::new(String::from("<absent>"));
                    wait_for(
                        &path,
                        "Kubernetes actor readiness",
                        READY_LIMIT,
                        || match self.logs_for(actor.name) {
                            Ok(logs) => {
                                *last.borrow_mut() = logs.clone();
                                Ok(logs
                                    .lines()
                                    .any(|line| line == "native-fixture-ready")
                                    .then_some(()))
                            }
                            Err(source) => {
                                *last.borrow_mut() = source.to_string();
                                Ok(None)
                            }
                        },
                        || format!("last logs: {:?}; {}", last.borrow(), self.diagnostics()),
                    )?;
                }
            }

            let k3s = self.k3s_path.clone();
            let kube = self.kube_path.clone();
            let namespace = self.namespace.clone();
            let pod_name = self.actor_name.clone();
            let member = actor.name.to_owned();
            let mut process = if actor.script.is_some() && self.hook_up {
                let mut command = Command::new(&self.k3s_path);
                command
                    .arg("kubectl")
                    .arg("--kubeconfig")
                    .arg(&self.kube_path)
                    .args([
                        "-n",
                        &self.namespace,
                        "attach",
                        "-i",
                        &self.actor_name,
                        "-c",
                        actor.name,
                    ]);
                let mut process = ProcessFixture::spawn(&mut command, &path)?;
                process.ensure_running("Kubernetes actor attach")?;
                process
            } else {
                let input_path = if actor.script.is_some() {
                    PathBuf::from(format!("/proc/{pid}/fd/0"))
                } else {
                    PathBuf::from("/dev/null")
                };
                let input = File::options()
                    .write(true)
                    .open(&input_path)
                    .context(IoSnafu { path: &input_path })?;
                ProcessFixture::from_pid(pid, input, &path)
            };
            process.set_exit_probe(move || {
                let output = Command::new(&k3s)
                    .arg("kubectl")
                    .arg("--kubeconfig")
                    .arg(&kube)
                    .args(["-n", &namespace, "get", "pod", &pod_name, "-o", "json"])
                    .output()?;
                if !output.status.success() {
                    return Ok(None);
                }
                let pod: Pod =
                    serde_json::from_slice(&output.stdout).map_err(std::io::Error::other)?;
                let exit = KubernetesState::member_status(&pod, &member)
                    .and_then(|state| state.state.as_ref())
                    .and_then(|state| state.terminated.as_ref());
                Ok(exit.map(|exit| std::process::ExitStatus::from_raw(exit.exit_code << 8)))
            });
            process.set_init(pid)?;
            process.set_group(&cgroup);
            if self.actor_id.is_none() {
                self.actor_id = Some(id);
                self.actor_pid = Some(pid);
                self.actor_cgroup = Some(cgroup);
            }
            group.push((process, self.work_path.join(actor.name)));
        }
        if actors.len() > 1 || actors[0].script.is_none() {
            self.wait_workload_ready()?;
            let pod = self.pod()?;
            for actor in actors {
                let state = KubernetesState::member_status(&pod, actor.name)
                    .ok_or_else(|| format!("the actor Pod has no {} status", actor.name))?;
                let ready = if actor.kind(&pod)? == mithril_control::ContainerKindV1::Init {
                    state
                        .state
                        .as_ref()
                        .and_then(|state| state.terminated.as_ref())
                        .is_some_and(|exit| exit.exit_code == 0)
                } else {
                    state.ready
                };
                if !ready || state.restart_count != 0 {
                    return Err(format!(
                        "actor {} is not ready without restart: {state:?}",
                        actor.name
                    )
                    .into());
                }
            }
        }
        *self.actors.entry(labels.clone()).or_default() += u32::try_from(actors.len())?;
        Ok(group)
    }
}
