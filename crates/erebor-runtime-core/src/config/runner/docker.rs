use std::path::PathBuf;

use erebor_runtime_events::SessionId;

use super::super::SessionRunPlan;
use super::DockerSessionRunnerConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerSessionEnvironment {
    variables: Vec<(String, String)>,
    requires_host_gateway: bool,
}

impl DockerSessionEnvironment {
    fn for_session(
        docker: &DockerSessionRunnerConfig,
        environment: &[(String, String)],
    ) -> DockerSessionEnvironment {
        let mut requires_host_gateway = false;
        let variables = environment
            .iter()
            .map(|(key, value)| {
                let value = if let Some(rewritten) = Self::reachable_endpoint_value(docker, value) {
                    requires_host_gateway = true;
                    rewritten
                } else {
                    value.clone()
                };
                (key.clone(), value)
            })
            .collect();

        DockerSessionEnvironment {
            variables,
            requires_host_gateway,
        }
    }

    fn reachable_endpoint_value(docker: &DockerSessionRunnerConfig, value: &str) -> Option<String> {
        if !docker.needs_host_reachable_endpoints() {
            return None;
        }

        for host in ["127.0.0.1", "localhost", "0.0.0.0"] {
            for scheme in ["ws", "http"] {
                let prefix = format!("{scheme}://{host}");
                if let Some(suffix) = value.strip_prefix(&prefix) {
                    return Some(format!("{scheme}://host.docker.internal{suffix}"));
                }
            }
        }

        None
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionCommandPlan {
    program: String,
    args: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DockerSessionCommandOptions {
    extra_environment: Vec<(String, String)>,
    mounts: Vec<DockerSessionMount>,
    entrypoint: Option<String>,
}

impl DockerSessionCommandOptions {
    pub fn add_environment(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra_environment.push((key.into(), value.into()));
    }

    pub fn add_mount(&mut self, mount: DockerSessionMount) {
        self.mounts.push(mount);
    }

    pub fn set_entrypoint(&mut self, entrypoint: impl Into<String>) {
        self.entrypoint = Some(entrypoint.into());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionMount {
    host_path: PathBuf,
    container_path: PathBuf,
    read_only: bool,
}

impl DockerSessionMount {
    #[must_use]
    pub fn new(
        host_path: impl Into<PathBuf>,
        container_path: impl Into<PathBuf>,
        read_only: bool,
    ) -> Self {
        Self {
            host_path: host_path.into(),
            container_path: container_path.into(),
            read_only,
        }
    }
}

impl DockerSessionCommandPlan {
    #[must_use]
    pub fn from_session_run_plan(plan: &SessionRunPlan) -> Self {
        Self::from_session_run_plan_with_environment(plan, &[])
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
    ) -> Self {
        Self::from_session_run_plan_with_environment_and_options(
            plan,
            environment,
            &DockerSessionCommandOptions::default(),
        )
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment_and_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &DockerSessionCommandOptions,
    ) -> Self {
        DockerSessionCommandPlanner::from_session_run_plan_with_command_and_environment(
            plan,
            environment,
            plan.command(),
            false,
            options,
        )
    }

    #[must_use]
    pub fn detached_from_session_run_plan_with_command_and_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        command: &[String],
    ) -> Self {
        DockerSessionCommandPlanner::from_session_run_plan_with_command_and_environment(
            plan,
            environment,
            command,
            true,
            &DockerSessionCommandOptions::default(),
        )
    }
}

struct DockerSessionCommandPlanner;

impl DockerSessionCommandPlanner {
    fn from_session_run_plan_with_command_and_environment(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        command: &[String],
        detached: bool,
        options: &DockerSessionCommandOptions,
    ) -> DockerSessionCommandPlan {
        let docker = plan.runner().docker();
        let mut combined_environment = environment.to_vec();
        combined_environment.extend(options.extra_environment.iter().cloned());
        let environment = DockerSessionEnvironment::for_session(docker, &combined_environment);
        let mut args = vec![
            String::from("run"),
            String::from("--rm"),
            String::from("--name"),
            DockerContainerName::for_session(plan.session_id()),
            String::from("--label"),
            format!("dev.erebor.session_id={}", plan.session_id().as_str()),
            String::from("--label"),
            format!("dev.erebor.actor_id={}", plan.actor().id),
            String::from("--network"),
            docker.network().to_owned(),
            String::from("-e"),
            format!("EREBOR_SESSION_ID={}", plan.session_id().as_str()),
            String::from("-e"),
            format!("EREBOR_ACTOR_ID={}", plan.actor().id),
            String::from("-e"),
            String::from("EREBOR_SESSION_RUNNER=docker"),
        ];

        if detached {
            args.push(String::from("-d"));
        }

        if plan.tty() {
            args.push(String::from("-i"));
            args.push(String::from("-t"));
        }

        if environment.requires_host_gateway {
            args.push(String::from("--add-host"));
            args.push(String::from("host.docker.internal:host-gateway"));
        }

        for (key, value) in environment.variables {
            args.push(String::from("-e"));
            args.push(format!("{key}={value}"));
        }

        for mount in &options.mounts {
            args.push(String::from("-v"));
            let mut spec = format!(
                "{}:{}",
                mount.host_path.display(),
                mount.container_path.display()
            );
            if mount.read_only {
                spec.push_str(":ro");
            }
            args.push(spec);
        }

        if let Some(workspace) = plan.workspace() {
            args.push(String::from("-v"));
            args.push(format!(
                "{}:{}",
                workspace.display(),
                docker.workdir().display()
            ));
            args.push(String::from("-w"));
            args.push(docker.workdir().display().to_string());
        }

        if let Some(entrypoint) = options.entrypoint.as_deref() {
            args.push(String::from("--entrypoint"));
            args.push(entrypoint.to_owned());
        }

        args.push(docker.image().to_owned());
        args.extend(command.iter().cloned());

        DockerSessionCommandPlan {
            program: String::from("docker"),
            args,
        }
    }
}

impl DockerSessionCommandPlan {
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

struct DockerContainerName;

impl DockerContainerName {
    fn for_session(session_id: &SessionId) -> String {
        let suffix = session_id
            .as_str()
            .chars()
            .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
            .collect::<String>();

        if suffix.is_empty() {
            String::from("erebor-session")
        } else {
            format!("erebor-{suffix}")
        }
    }
}

#[cfg(test)]
mod tests;
