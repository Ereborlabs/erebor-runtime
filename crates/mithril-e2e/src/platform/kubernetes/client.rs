use super::*;

impl Kubernetes {
    pub(super) fn edit_control(
        &mut self,
        update: impl FnOnce(&mut Value) -> TestResult<()>,
    ) -> TestResult<()> {
        if self.system_up || self.helm_up {
            return Err("Control configuration must be set before startup".into());
        }
        let mut config: Value = serde_json::from_slice(&fs::read(&self.control_path)?)?;
        update(&mut config)?;
        let parent = self
            .control_path
            .parent()
            .ok_or("Control configuration parent")?;
        let staged = tempfile::NamedTempFile::new_in(parent)?;
        fs::write(staged.path(), serde_json::to_vec_pretty(&config)?)?;
        ControlConfig::load(staged.path())?;
        staged.persist(&self.control_path)?;
        Ok(())
    }

    pub(super) fn run_client<T, F, Fut>(&mut self, tenant: &str, operation: F) -> TestResult<T>
    where
        F: FnOnce(AraphorProfile) -> Fut,
        Fut: std::future::Future<Output = TestResult<T>>,
    {
        let profile = {
            let mut approval = KubernetesState::approval(self)?;
            approval.start_forward(&self.runtime, &self.system)?;
            approval.query_profile(tenant)
        };
        let pods = self.runtime.block_on(
            Api::<Pod>::namespaced(self.client.clone(), &self.system).list(
                &ListParams::default()
                    .labels("app.kubernetes.io/name in (mithril-control,mithril-node)"),
            ),
        )?;
        let mut images = BTreeMap::new();
        for pod in pods.items {
            let name = pod.metadata.name.as_deref().ok_or("platform Pod name")?;
            let uid = pod.metadata.uid.as_deref().ok_or("platform Pod UID")?;
            let spec = pod.spec.as_ref().ok_or("platform Pod specification")?;
            for container in spec.containers.iter().filter(|container| {
                matches!(container.name.as_str(), "mithril-control" | "mithril-node")
            }) {
                let status = pod
                    .status
                    .as_ref()
                    .and_then(|status| status.container_statuses.as_ref())
                    .and_then(|statuses| {
                        statuses.iter().find(|status| status.name == container.name)
                    })
                    .ok_or("platform container status")?;
                let image = container
                    .image
                    .as_deref()
                    .ok_or("platform container image")?;
                let id = status.image_id.as_str();
                if id.is_empty() {
                    return Err("platform container image ID".into());
                }
                if images
                    .insert(
                        container.name.clone(),
                        json!({"namespace": self.system, "pod": name, "uid": uid,
                            "container": container.name, "image": image, "image_id": id}),
                    )
                    .is_some()
                {
                    return Err("duplicate platform image role".into());
                }
            }
        }
        if images.len() != 2 {
            return Err("both platform image roles are required".into());
        }
        eprintln!(
            "MITHRIL_PLATFORM_IMAGES={}",
            serde_json::to_string(&images)?
        );
        self.runtime.block_on(operation(profile))
    }
}
