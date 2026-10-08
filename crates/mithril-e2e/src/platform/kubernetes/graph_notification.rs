use k8s_openapi::api::core::v1::PersistentVolume;

use super::*;

impl KubernetesState {
    pub(crate) fn graph_store(&mut self) -> TestResult<(PathBuf, PathBuf)> {
        if !self.system_up || !self.helm_up || self.hook_up {
            return Err("graph storage requires an owned release with Node stopped".into());
        }
        let deployments = Api::<Deployment>::namespaced(self.client.clone(), &self.system);
        self.runtime.block_on(deployments.patch(
            "mithril-control",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"replicas": 0}})),
        ))?;
        let pods = Api::<Pod>::namespaced(self.client.clone(), &self.system);
        let params = ListParams::default().labels("app.kubernetes.io/name=mithril-control");
        let path = Self::resource(&self.system, "pod", "mithril-control");
        wait_for(
            &path,
            "Control Pod stop",
            STOP_LIMIT,
            || {
                let list = self
                    .runtime
                    .block_on(pods.list(&params))
                    .map_err(|source| {
                        InvalidInputSnafu {
                            path: &path,
                            reason: source.to_string(),
                        }
                        .build()
                    })?;
                Ok(list.items.is_empty().then_some(()))
            },
            || "Control still has a Pod".into(),
        )?;
        let claims = Api::<PersistentVolumeClaim>::namespaced(self.client.clone(), &self.system);
        let claim = self.runtime.block_on(claims.get("mithril-control-state"))?;
        let volume = claim
            .spec
            .as_ref()
            .and_then(|spec| spec.volume_name.as_deref())
            .ok_or("the owned Control claim has no volume")?;
        let volumes = Api::<PersistentVolume>::all(self.client.clone());
        let volume = self.runtime.block_on(volumes.get(volume))?;
        let spec = volume.spec.ok_or("the Control volume has no spec")?;
        let reference = spec.claim_ref.ok_or("the Control volume has no claim")?;
        if reference.namespace.as_deref() != Some(self.system.as_str())
            || reference.name.as_deref() != Some("mithril-control-state")
            || reference.uid != claim.metadata.uid
        {
            return Err("the volume is not bound to the owned Control claim".into());
        }
        let location = spec
            .local
            .map(|local| local.path)
            .or_else(|| spec.host_path.map(|host| host.path))
            .ok_or("the Control volume is not a local path")?;
        let location = fs::canonicalize(location)?;
        let base = fs::canonicalize("/var/lib/rancher/k3s/storage")?;
        if !location.starts_with(base) {
            return Err("the Control volume is outside the K3s local storage directory".into());
        }
        let config = ControlConfig::load(&self.control_path)?;
        let mount = Path::new("/var/lib/mithril-control");
        let store = config
            .control_store_directory
            .as_deref()
            .ok_or("the Control store directory is absent")?
            .strip_prefix(mount)?;
        let evidence = config.evidence_directory.strip_prefix(mount)?;
        let store = fs::canonicalize(location.join(store))?;
        let analysis = fs::canonicalize(location.join(evidence).join("analysis"))?;
        if !store.starts_with(&location) || !analysis.starts_with(&location) {
            return Err("the Control store leaves its owned volume".into());
        }
        Ok((store, analysis))
    }
}
