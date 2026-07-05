use std::path::{Path, PathBuf};

use erebor_runtime_events::SessionId;

use super::super::{SessionAdoptPlan, SessionRunPlan};
use super::SessionRunnerKind;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxHostSessionCommandPlan {
    program: String,
    args: Vec<String>,
    environment: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LinuxHostSessionCommandOptions {
    extra_environment: Vec<(String, String)>,
    wrapper_programs: Vec<PathBuf>,
    adopt_pid: Option<i32>,
}

impl LinuxHostSessionCommandOptions {
    pub fn add_environment(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extra_environment.push((key.into(), value.into()));
    }

    pub fn add_wrapper_program(&mut self, wrapper: impl Into<PathBuf>) {
        self.wrapper_programs.push(wrapper.into());
    }

    pub fn add_outer_wrapper_program(&mut self, wrapper: impl Into<PathBuf>) {
        self.wrapper_programs.insert(0, wrapper.into());
    }

    pub fn set_adopt_pid(&mut self, pid: i32) {
        self.adopt_pid = Some(pid);
    }
}

impl LinuxHostSessionCommandPlan {
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
            &LinuxHostSessionCommandOptions::default(),
        )
    }

    #[must_use]
    pub fn from_session_run_plan_with_environment_and_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Self {
        LinuxHostSessionCommandPlanner::from_session_run_plan_with_environment_and_options(
            plan,
            environment,
            options,
        )
    }

    #[must_use]
    pub fn from_session_adopt_plan_with_environment_and_options(
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> Self {
        LinuxHostSessionCommandPlanner::from_session_adopt_plan_with_environment_and_options(
            plan,
            environment,
            options,
        )
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    #[must_use]
    pub fn environment(&self) -> &[(String, String)] {
        &self.environment
    }

    #[must_use]
    pub fn current_dir(&self) -> Option<&Path> {
        self.current_dir.as_deref()
    }
}

struct LinuxHostSessionCommandPlanner;

impl LinuxHostSessionCommandPlanner {
    fn from_session_run_plan_with_environment_and_options(
        plan: &SessionRunPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> LinuxHostSessionCommandPlan {
        let mut combined_environment =
            LinuxHostSessionEnvironment::base(plan.session_id(), &plan.actor().id);
        combined_environment.extend(environment.iter().cloned());
        combined_environment.extend(options.extra_environment.iter().cloned());

        let (program, args) =
            if let Some((wrapper, wrappers)) = options.wrapper_programs.split_first() {
                let mut args = wrappers
                    .iter()
                    .map(|wrapper| wrapper.display().to_string())
                    .collect::<Vec<_>>();
                args.extend(plan.command().iter().map(ToOwned::to_owned));
                (wrapper.display().to_string(), args)
            } else {
                let command = plan.command();
                (
                    command[0].clone(),
                    command.iter().skip(1).map(ToOwned::to_owned).collect(),
                )
            };

        LinuxHostSessionCommandPlan {
            program,
            args,
            environment: combined_environment,
            current_dir: plan.workspace().map(Path::to_path_buf),
        }
    }

    fn from_session_adopt_plan_with_environment_and_options(
        plan: &SessionAdoptPlan,
        environment: &[(String, String)],
        options: &LinuxHostSessionCommandOptions,
    ) -> LinuxHostSessionCommandPlan {
        let mut combined_environment =
            LinuxHostSessionEnvironment::base(plan.session_id(), &plan.actor().id);
        combined_environment.extend(environment.iter().cloned());
        combined_environment.extend(options.extra_environment.iter().cloned());
        combined_environment.push((
            String::from("EREBOR_GUARD_ADOPT_PID"),
            options.adopt_pid.unwrap_or_else(|| plan.pid()).to_string(),
        ));

        let (program, args) = options.wrapper_programs.split_first().map_or_else(
            || (String::new(), Vec::new()),
            |(wrapper, wrappers)| {
                (
                    wrapper.display().to_string(),
                    wrappers
                        .iter()
                        .map(|wrapper| wrapper.display().to_string())
                        .collect(),
                )
            },
        );

        LinuxHostSessionCommandPlan {
            program,
            args,
            environment: combined_environment,
            current_dir: plan.workspace().map(Path::to_path_buf),
        }
    }
}

struct LinuxHostSessionEnvironment;

impl LinuxHostSessionEnvironment {
    fn base(session_id: &SessionId, actor_id: &str) -> Vec<(String, String)> {
        vec![
            (
                String::from("EREBOR_SESSION_ID"),
                session_id.as_str().to_owned(),
            ),
            (String::from("EREBOR_ACTOR_ID"), actor_id.to_owned()),
            (
                String::from("EREBOR_SESSION_RUNNER"),
                SessionRunnerKind::LinuxHost.as_str().to_owned(),
            ),
        ]
    }
}

#[cfg(test)]
mod tests;
