use std::fs;
use std::path::{Path, PathBuf};

use rcgen::{
    date_time_ymd, BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use sha2::{Digest as _, Sha256};

pub(crate) struct Certificates {
    ca: Certificate,
    server: Certificate,
    server_key: KeyPair,
    node: Certificate,
    node_key: KeyPair,
}

impl Certificates {
    pub(crate) fn issue(expired_node: bool) -> Result<Self, rcgen::Error> {
        Self::issue_for(expired_node, &["localhost"])
    }

    pub(super) fn issue_for(
        expired_node: bool,
        server_names: &[&str],
    ) -> Result<Self, rcgen::Error> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;

        let mut server_params = CertificateParams::new(
            server_names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )?;
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate()?;
        let server = server_params.signed_by(&server_key, &ca, &ca_key)?;

        let mut node_params = CertificateParams::new(vec!["node-a.local".to_owned()])?;
        node_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        if expired_node {
            node_params.not_before = date_time_ymd(2010, 1, 1);
            node_params.not_after = date_time_ymd(2011, 1, 1);
        }
        let node_key = KeyPair::generate()?;
        let node = node_params.signed_by(&node_key, &ca, &ca_key)?;
        Ok(Self {
            ca,
            server,
            server_key,
            node,
            node_key,
        })
    }

    pub(crate) fn node_digest(&self) -> String {
        format!("{:x}", Sha256::digest(self.node.der().as_ref()))
    }

    pub(crate) fn write(&self, directory: &Path) -> Result<CertificateFiles, std::io::Error> {
        let files = CertificateFiles {
            ca: directory.join("ca.pem"),
            server_certificate: directory.join("server.pem"),
            server_key: directory.join("server-key.pem"),
            node_certificate: directory.join("node.pem"),
            node_key: directory.join("node-key.pem"),
        };
        fs::write(&files.ca, self.ca.pem())?;
        fs::write(&files.server_certificate, self.server.pem())?;
        fs::write(&files.server_key, self.server_key.serialize_pem())?;
        fs::write(&files.node_certificate, self.node.pem())?;
        fs::write(&files.node_key, self.node_key.serialize_pem())?;
        Ok(files)
    }
}

pub(crate) struct CertificateFiles {
    pub(crate) ca: PathBuf,
    pub(crate) server_certificate: PathBuf,
    pub(crate) server_key: PathBuf,
    pub(crate) node_certificate: PathBuf,
    pub(crate) node_key: PathBuf,
}
