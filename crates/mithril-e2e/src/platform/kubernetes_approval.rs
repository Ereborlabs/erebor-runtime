use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use mithril_control::{AdministrativeExecDraftRequestV1, AdministrativeExecDraftResponseV1};
use reqwest::{redirect::Policy, Certificate, Client, RequestBuilder, Response, StatusCode};
use serde_json::json;

use super::TestResult;
use crate::error::InvalidInputSnafu;
use crate::physical::wait_for;
use crate::process::ProcessFixture;

const READY_LIMIT: Duration = Duration::from_secs(180);
const ADMIN_URL: &str = "https://localhost:19444";
const WEBHOOK_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const CA_PATH: &str = "/var/lib/rancher/k3s/server/tls/server-ca.crt";
const CA_KEY_PATH: &str = "/var/lib/rancher/k3s/server/tls/server-ca.key";
const CERT_PATH: &str = "/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.crt";
const KEY_PATH: &str = "/var/lib/rancher/k3s/server/tls/serving-kube-apiserver.key";

pub(super) struct KubernetesApproval {
    root: PathBuf,
    _key_dir: tempfile::TempDir,
    key: PathBuf,
    cert: PathBuf,
    kube: PathBuf,
    k3s: PathBuf,
    node_ip: String,
    oidc: Option<ProcessFixture>,
    forward: Option<ProcessFixture>,
    credential: Option<PathBuf>,
}

impl KubernetesApproval {
    pub(super) fn new(
        root: &Path,
        kube: &Path,
        k3s: &Path,
        node_ip: String,
        server_name: &str,
    ) -> TestResult<Self> {
        for path in [CA_PATH, CA_KEY_PATH, CERT_PATH, KEY_PATH] {
            if !Path::new(path).is_file() {
                return Err(format!("the K3s TLS fixture is missing: {path}").into());
            }
        }
        let key_dir = tempfile::tempdir()?;
        let key = key_dir.path().join("oidc-key.pem");
        let mut command = Command::new("/usr/bin/openssl");
        command
            .args(["genpkey", "-algorithm", "RSA", "-pkeyopt"])
            .arg("rsa_keygen_bits:2048")
            .arg("-out")
            .arg(&key);
        Self::run(&mut command, "generate the administrative key")?;
        let csr = key_dir.path().join("administrative.csr");
        let mut command = Command::new("/usr/bin/openssl");
        command
            .args(["req", "-new", "-sha256", "-subj", "/CN=localhost"])
            .arg("-addext")
            .arg(format!("subjectAltName=DNS:localhost,DNS:{server_name}"))
            .arg("-key")
            .arg(&key)
            .arg("-out")
            .arg(&csr);
        Self::run(
            &mut command,
            "create the administrative certificate request",
        )?;
        let cert = key_dir.path().join("administrative.pem");
        let mut command = Command::new("/usr/bin/openssl");
        command
            .args(["x509", "-req", "-days", "1", "-sha256", "-in"])
            .arg(&csr)
            .args(["-CA", CA_PATH, "-CAkey", CA_KEY_PATH, "-set_serial", "1"])
            .args(["-copy_extensions", "copy", "-out"])
            .arg(&cert);
        Self::run(&mut command, "sign the administrative certificate")?;
        Ok(Self {
            root: root.to_owned(),
            _key_dir: key_dir,
            key,
            cert,
            kube: kube.to_owned(),
            k3s: k3s.to_owned(),
            node_ip,
            oidc: None,
            forward: None,
            credential: None,
        })
    }

    fn run(command: &mut Command, operation: &str) -> TestResult<()> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!(
                "{operation} failed with {}; stderr: {:?}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn issuer(&self) -> String {
        format!("https://{}:19445", self.node_ip)
    }

    pub(super) fn ca(&self) -> &Path {
        Path::new(CA_PATH)
    }

    pub(super) fn secrets(&self) -> TestResult<BTreeMap<String, String>> {
        Ok(BTreeMap::from([
            ("k3s-ca.crt".to_owned(), fs::read_to_string(CA_PATH)?),
            (
                "administrative.crt".to_owned(),
                fs::read_to_string(&self.cert)?,
            ),
            (
                "administrative.key".to_owned(),
                fs::read_to_string(&self.key)?,
            ),
            (
                "administrative-webhook-token".to_owned(),
                WEBHOOK_TOKEN.to_owned(),
            ),
        ]))
    }

    fn client(&self, runtime: &tokio::runtime::Runtime) -> TestResult<Client> {
        let _guard = runtime.enter();
        let k3s_ca = Certificate::from_pem(&fs::read(CA_PATH)?)?;
        Ok(Client::builder()
            .add_root_certificate(k3s_ca)
            .redirect(Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?)
    }

    pub(super) fn start_oidc(&mut self, runtime: &tokio::runtime::Runtime) -> TestResult<()> {
        if self.oidc.is_some() {
            return Ok(());
        }
        let script = self
            .root
            .join("crates/mithril-e2e/harness/vm/oidc-fixture.py");
        let issuer = self.issuer();
        let mut command = Command::new("/usr/bin/python3");
        command
            .arg(&script)
            .args(["--listen", &format!("{}:19445", self.node_ip)])
            .args(["--certificate", CERT_PATH, "--private-key", KEY_PATH])
            .arg("--signing-key")
            .arg(&self.key)
            .args(["--issuer", &issuer]);
        let mut process = ProcessFixture::spawn(&mut command, &script)?;
        let client = self.client(runtime)?;
        let last = RefCell::new(String::from("<absent>"));
        let stderr = RefCell::new(String::from("<empty>"));
        wait_for(
            &script,
            "OIDC fixture readiness",
            READY_LIMIT,
            || {
                process.ensure_running("OIDC fixture readiness")?;
                let output = process.stderr()?;
                if !output.is_empty() {
                    *stderr.borrow_mut() = output;
                }
                match runtime
                    .block_on(async { client.get(format!("{issuer}/healthz")).send().await })
                {
                    Ok(response) if response.status().is_success() => Ok(Some(())),
                    Ok(response) => {
                        *last.borrow_mut() = response.status().to_string();
                        Ok(None)
                    }
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        Ok(None)
                    }
                }
            },
            || {
                format!(
                    "last response: {}; stderr: {}",
                    last.borrow(),
                    stderr.borrow()
                )
            },
        )?;
        self.oidc = Some(process);
        Ok(())
    }

    pub(super) fn start_forward(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        namespace: &str,
    ) -> TestResult<()> {
        if self.forward.is_some() {
            return Ok(());
        }
        let mut command = Command::new(&self.k3s);
        command
            .arg("kubectl")
            .arg("--kubeconfig")
            .arg(&self.kube)
            .args(["-n", namespace, "port-forward", "--address", "127.0.0.1"])
            .args(["deployment/mithril-control", "19444:9444"]);
        let path = Path::new("Kubernetes Control administrative port");
        let mut process = ProcessFixture::spawn(&mut command, path)?;
        let client = self.client(runtime)?;
        let last = RefCell::new(String::from("<absent>"));
        let stderr = RefCell::new(String::from("<empty>"));
        wait_for(
            path,
            "Control administrative HTTPS readiness",
            READY_LIMIT,
            || {
                process.ensure_running("Control administrative HTTPS readiness")?;
                let output = process.stderr()?;
                if !output.is_empty() {
                    *stderr.borrow_mut() = output;
                }
                match runtime.block_on(async {
                    client
                        .get(format!("{ADMIN_URL}/activate/missing"))
                        .send()
                        .await
                }) {
                    Ok(response) if response.status() == StatusCode::NOT_FOUND => Ok(Some(())),
                    Ok(response) => {
                        *last.borrow_mut() = response.status().to_string();
                        Ok(None)
                    }
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        Ok(None)
                    }
                }
            },
            || {
                format!(
                    "last response: {}; stderr: {}",
                    last.borrow(),
                    stderr.borrow()
                )
            },
        )?;
        self.forward = Some(process);
        Ok(())
    }

    fn send(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        request: RequestBuilder,
        expected: StatusCode,
        operation: &str,
    ) -> TestResult<Response> {
        let response = match runtime.block_on(async { request.send().await }) {
            Ok(response) => response,
            Err(source) => {
                let state = match self.forward.as_mut() {
                    Some(process) => match process.ensure_running(operation) {
                        Ok(()) => format!("running; stderr: {:?}", process.stderr()?),
                        Err(error) => error.to_string(),
                    },
                    None => "not started".to_owned(),
                };
                return Err(format!("{operation} failed: {source}; port-forward: {state}").into());
            }
        };
        if response.status() != expected {
            let status = response.status();
            let body = runtime.block_on(response.text()).unwrap_or_default();
            return Err(format!("{operation} returned {status}: {body}").into());
        }
        Ok(response)
    }

    fn redirect(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        request: RequestBuilder,
        status: StatusCode,
        operation: &str,
    ) -> TestResult<String> {
        let response = self.send(runtime, request, status, operation)?;
        Ok(response
            .headers()
            .get(reqwest::header::LOCATION)
            .ok_or_else(|| format!("{operation} returned no redirect"))?
            .to_str()?
            .to_owned())
    }

    pub(super) fn approve(
        &mut self,
        runtime: &tokio::runtime::Runtime,
        work: &Path,
        namespace: &str,
        command: &str,
        args: &[&str],
    ) -> TestResult<()> {
        let client = self.client(runtime)?;
        let argv = std::iter::once(command)
            .chain(args.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let response = self.send(
            runtime,
            client
                .post(format!("{ADMIN_URL}/v1/administrative-exec/requests"))
                .json(&AdministrativeExecDraftRequestV1 {
                    namespace: namespace.to_owned(),
                    pod: "pid-reuse".to_owned(),
                    container: "worker".to_owned(),
                    argv: argv.clone(),
                    stdin: true,
                    stdout: true,
                    stderr: true,
                    tty: false,
                    approved_role_id: "runtime-external-administrative".to_owned(),
                }),
            StatusCode::CREATED,
            "administrative draft",
        )?;
        let draft: AdministrativeExecDraftResponseV1 = runtime.block_on(response.json())?;
        let activation = self.send(
            runtime,
            client.get(&draft.activation_url),
            StatusCode::OK,
            "activation page",
        )?;
        let page = runtime.block_on(activation.text())?;
        if !page.contains(&argv.join(" ")) {
            return Err("activation page changed the approved command".into());
        }
        let authorize = self.redirect(
            runtime,
            client.get(format!("{}/authorize", draft.activation_url)),
            StatusCode::SEE_OTHER,
            "OIDC authorization",
        )?;
        let callback = self.redirect(
            runtime,
            client.get(authorize),
            StatusCode::FOUND,
            "OIDC provider authorization",
        )?;
        let confirmation = self.send(
            runtime,
            client.get(callback),
            StatusCode::OK,
            "OIDC callback",
        )?;
        let page = runtime.block_on(confirmation.text())?;
        if !page.contains("operator@mithril.invalid")
            || !page.contains("I accept this race and approve once")
        {
            return Err("approval confirmation omitted the authenticated risk statement".into());
        }
        let approved = self.send(
            runtime,
            client.post(format!("{}/approve", draft.activation_url)),
            StatusCode::OK,
            "administrative approval",
        )?;
        if !runtime
            .block_on(approved.text())?
            .contains("Administrative exec approved")
        {
            return Err("Control did not confirm administrative approval".into());
        }
        let poll = format!(
            "{ADMIN_URL}/v1/administrative-exec/requests/{}",
            draft.poll_token
        );
        let path = work.join("administrative-kubeconfig.json");
        let last = RefCell::new(String::from("<absent>"));
        let credential = wait_for(
            &path,
            "administrative credential",
            READY_LIMIT,
            || {
                let response = match runtime.block_on(async { client.get(&poll).send().await }) {
                    Ok(response) => response,
                    Err(source) => {
                        *last.borrow_mut() = source.to_string();
                        return Ok(None);
                    }
                };
                let status = response.status();
                let body = runtime.block_on(response.text()).map_err(|source| {
                    InvalidInputSnafu {
                        path: &path,
                        reason: source.to_string(),
                    }
                    .build()
                })?;
                *last.borrow_mut() = format!("{status}: {body}");
                if status == StatusCode::ACCEPTED {
                    return Ok(None);
                }
                if status != StatusCode::OK {
                    return InvalidInputSnafu {
                        path: &path,
                        reason: format!("credential poll returned {status}: {body}"),
                    }
                    .fail();
                }
                let response: mithril_control::AdministrativeExecPollResponseV1 =
                    serde_json::from_str(&body).map_err(|source| {
                        InvalidInputSnafu {
                            path: &path,
                            reason: source.to_string(),
                        }
                        .build()
                    })?;
                Ok(response.credential)
            },
            || format!("last response: {}", last.borrow()),
        )?;
        let config = json!({
            "apiVersion": "v1",
            "kind": "Config",
            "clusters": [{
                "name": "k3s",
                "cluster": {
                    "certificate-authority": CA_PATH,
                    "server": "https://127.0.0.1:6443"
                }
            }],
            "contexts": [{
                "name": "k3s",
                "context": {"cluster": "k3s", "user": "mithril"}
            }],
            "current-context": "k3s",
            "users": [{"name": "mithril", "user": {"token": credential}}]
        });
        fs::write(&path, serde_json::to_vec_pretty(&config)?)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        self.credential = Some(path);
        Ok(())
    }

    pub(super) fn kubeconfig(&self) -> Option<&Path> {
        self.credential.as_deref()
    }

    pub(super) fn clear(&mut self) {
        self.credential = None;
    }

    pub(super) fn stop(&mut self) -> TestResult<()> {
        self.credential = None;
        let forward = self.forward.as_mut().map(ProcessFixture::stop).transpose();
        let oidc = self.oidc.as_mut().map(ProcessFixture::stop).transpose();
        self.forward = None;
        self.oidc = None;
        forward?;
        oidc?;
        Ok(())
    }
}
