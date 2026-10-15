use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::Path;

use oci_spec::image::{
    Descriptor, ImageIndex, ImageIndexBuilder, ImageManifest, ImageManifestBuilder, MediaType,
    OciLayout, OciLayoutBuilder,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use crate::{EncodingSnafu, Error, ErrorCode, IoSnafu, Result};

#[cfg(test)]
mod tests;

pub const ARTIFACT_TYPE: &str = "application/vnd.araphor.analysis.package.v1";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.araphor.analysis.config.v1+json";
pub const WASM_MEDIA_TYPE: &str = "application/vnd.araphor.analysis.wasm.v1";
pub const NATIVE_MEDIA_TYPE: &str = "application/vnd.araphor.analysis.native.v1";
pub const NATIVE_DEPENDENCY_MEDIA_TYPE: &str =
    "application/vnd.araphor.analysis.native-dependency.v1";
pub const PYTHON_MEDIA_TYPE: &str = "application/vnd.araphor.analysis.python.v1";
pub const ARROW_IPC_MEDIA_TYPE: &str = "application/vnd.araphor.analysis.arrow-ipc.v1";

pub struct Layer<'a> {
    pub media_type: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config<T> {
    pub package: T,
    pub blobs: Vec<Descriptor>,
}

pub struct Layout<'a> {
    files: BTreeMap<String, Cow<'a, [u8]>>,
    manifest_digest: String,
    config_path: String,
}

pub struct Content {
    pub config: Vec<u8>,
    pub layers: Vec<Blob>,
    pub manifest: Vec<u8>,
}

pub struct Blob {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

impl<'a> Layout<'a> {
    pub fn new<T: Serialize>(package: &T, layers: &[Layer<'a>]) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut descriptors = Vec::new();
        for layer in layers {
            Self::check_media(layer.media_type)?;
            let descriptor = Self::descriptor(layer.media_type, layer.bytes)?;
            files.insert(Self::blob_path(&descriptor)?, Cow::Borrowed(layer.bytes));
            descriptors.push(descriptor);
        }
        let config = Self::json(&Config {
            package,
            blobs: descriptors.clone(),
        })?;
        let config_descriptor = Self::descriptor(CONFIG_MEDIA_TYPE, &config)?;
        let manifest = Self::manifest(config_descriptor.clone(), descriptors)?;
        let manifest_descriptor = Self::descriptor(MediaType::ImageManifest.as_ref(), &manifest)?;
        let index = ImageIndexBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageIndex)
            .manifests(vec![manifest_descriptor.clone()])
            .build()
            .map_err(|_| Self::invalid("OCI index"))?;
        let layout = OciLayoutBuilder::default()
            .image_layout_version("1.0.0")
            .build()
            .map_err(|_| Self::invalid("OCI layout"))?;
        let config_path = Self::blob_path(&config_descriptor)?;
        files.insert(config_path.clone(), Cow::Owned(config));
        files.insert(Self::blob_path(&manifest_descriptor)?, Cow::Owned(manifest));
        files.insert("index.json".into(), Cow::Owned(Self::json(&index)?));
        files.insert("oci-layout".into(), Cow::Owned(Self::json(&layout)?));
        Ok(Self {
            files,
            manifest_digest: manifest_descriptor.digest().to_string(),
            config_path,
        })
    }

    pub fn digest(&self) -> String {
        self.manifest_digest.clone()
    }

    pub fn config(&self) -> &[u8] {
        &self.files[&self.config_path]
    }

    pub fn matches(&self, content: &Content) -> bool {
        self.config() == content.config
            && self.manifest_digest == format!("sha256:{:x}", Sha256::digest(&content.manifest))
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes) in &self.files {
            let mut header = tar::Header::new_ustar();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            archive
                .append_data(&mut header, path, bytes.as_ref())
                .context(IoSnafu {
                    path: Path::new("<OCI archive>"),
                })?;
        }
        archive.into_inner().context(IoSnafu {
            path: Path::new("<OCI archive>"),
        })
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(path.join("blobs/sha256")).context(IoSnafu { path })?;
        for (name, bytes) in &self.files {
            let target = path.join(name);
            std::fs::write(&target, bytes).context(IoSnafu { path: &target })?;
        }
        Ok(())
    }

    pub fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(value).context(EncodingSnafu)?;
        value.sort_all_objects();
        serde_json::to_vec(&value).context(EncodingSnafu)
    }

    fn manifest(config: Descriptor, layers: Vec<Descriptor>) -> Result<Vec<u8>> {
        let manifest = ImageManifestBuilder::default()
            .schema_version(2u32)
            .media_type(MediaType::ImageManifest)
            .artifact_type(MediaType::from(ARTIFACT_TYPE))
            .config(config)
            .layers(layers)
            .build()
            .map_err(|_| Self::invalid("OCI manifest"))?;
        Self::json(&manifest)
    }

    fn descriptor(media_type: &str, bytes: &[u8]) -> Result<Descriptor> {
        let digest: oci_spec::image::Digest = format!("sha256:{:x}", Sha256::digest(bytes))
            .parse()
            .map_err(|_| Self::invalid("OCI digest"))?;
        Ok(Descriptor::new(
            MediaType::from(media_type),
            bytes.len() as u64,
            digest,
        ))
    }

    fn blob_path(descriptor: &Descriptor) -> Result<String> {
        let digest = descriptor.digest().to_string();
        let hash = digest
            .strip_prefix("sha256:")
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| Self::invalid("OCI digest"))?;
        Ok(format!("blobs/sha256/{hash}"))
    }

    fn check_media(media: &str) -> Result<()> {
        if [
            WASM_MEDIA_TYPE,
            NATIVE_MEDIA_TYPE,
            NATIVE_DEPENDENCY_MEDIA_TYPE,
            PYTHON_MEDIA_TYPE,
            ARROW_IPC_MEDIA_TYPE,
        ]
        .contains(&media)
        {
            Ok(())
        } else {
            Err(Self::invalid("OCI layer media type"))
        }
    }

    fn invalid(field: &str) -> Error {
        Error::contract(ErrorCode::Invalid, field)
    }
}

impl Content {
    pub fn package<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        let config: Config<T> = serde_json::from_slice(&self.config).context(EncodingSnafu)?;
        Ok(config.package)
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut files = BTreeMap::new();
        let mut end_of_entries = 0usize;
        let mut archive = tar::Archive::new(bytes);
        for entry in archive
            .entries()
            .context(IoSnafu {
                path: Path::new("<OCI archive>"),
            })?
            .raw(true)
        {
            let entry = entry.context(IoSnafu {
                path: Path::new("<OCI archive>"),
            })?;
            if !entry.header().entry_type().is_file() {
                return Err(Layout::invalid("OCI archive entry type"));
            }
            let path = entry.path().context(IoSnafu {
                path: Path::new("<OCI archive>"),
            })?;
            let path = path
                .to_str()
                .ok_or_else(|| Layout::invalid("OCI archive path"))?
                .to_owned();
            if path != "oci-layout" && path != "index.json" && !Self::valid_blob_path(&path) {
                return Err(Layout::invalid("OCI archive path"));
            }
            if files.contains_key(&path) {
                return Err(Layout::invalid("duplicate OCI archive path"));
            }
            let size =
                usize::try_from(entry.size()).map_err(|_| Layout::invalid("OCI archive size"))?;
            let start = usize::try_from(entry.raw_file_position())
                .map_err(|_| Layout::invalid("OCI archive size"))?;
            let end = start
                .checked_add(size)
                .ok_or_else(|| Layout::invalid("OCI archive size"))?;
            let content = bytes
                .get(start..end)
                .ok_or_else(|| Layout::invalid("OCI archive size"))?;
            end_of_entries = end
                .checked_add(511)
                .map(|end| end / 512 * 512)
                .ok_or_else(|| Layout::invalid("OCI archive size"))?;
            files.insert(path, content);
        }
        if bytes.len().saturating_sub(end_of_entries) < 1024
            || bytes[end_of_entries..].iter().any(|byte| *byte != 0)
        {
            return Err(Layout::invalid("OCI archive trailer"));
        }
        Self::read_files(|path| {
            files
                .get(path)
                .map(|bytes| bytes.to_vec())
                .ok_or_else(|| Layout::invalid("missing OCI file"))
        })
    }

    pub fn read_files(mut read: impl FnMut(&str) -> Result<Vec<u8>>) -> Result<Self> {
        let layout: OciLayout =
            serde_json::from_slice(&read("oci-layout")?).context(EncodingSnafu)?;
        if layout.image_layout_version() != "1.0.0" {
            return Err(Layout::invalid("OCI layout version"));
        }
        let index: ImageIndex =
            serde_json::from_slice(&read("index.json")?).context(EncodingSnafu)?;
        if index.schema_version() != 2 || index.manifests().len() != 1 {
            return Err(Layout::invalid("OCI index"));
        }
        let manifest_descriptor = &index.manifests()[0];
        let manifest = Self::read_blob(
            &mut read,
            manifest_descriptor,
            MediaType::ImageManifest.as_ref(),
        )?;
        let parsed: ImageManifest = serde_json::from_slice(&manifest).context(EncodingSnafu)?;
        if parsed.schema_version() != 2
            || parsed.media_type().as_ref() != Some(&MediaType::ImageManifest)
            || parsed.artifact_type().as_ref().map(MediaType::as_ref) != Some(ARTIFACT_TYPE)
            || parsed.subject().is_some()
        {
            return Err(Layout::invalid("OCI artifact manifest"));
        }
        let config = Self::read_blob(&mut read, parsed.config(), CONFIG_MEDIA_TYPE)?;
        let parsed_config: Config<serde_json::Value> =
            serde_json::from_slice(&config).context(EncodingSnafu)?;
        if &parsed_config.blobs != parsed.layers() {
            return Err(Layout::invalid("OCI config layers"));
        }
        let mut layers = Vec::new();
        for descriptor in parsed.layers() {
            Layout::check_media(descriptor.media_type().as_ref())?;
            let bytes = Self::read_blob(&mut read, descriptor, descriptor.media_type().as_ref())?;
            layers.push(Blob {
                media_type: descriptor.media_type().to_string(),
                bytes,
            });
        }
        let content = Self {
            config,
            layers,
            manifest,
        };
        if Layout::json(&parsed_config)? != content.config
            || Layout::manifest(parsed.config().clone(), parsed.layers().clone())?
                != content.manifest
        {
            return Err(Layout::invalid("noncanonical Araphor OCI artifact"));
        }
        Ok(content)
    }

    fn read_blob(
        read: &mut impl FnMut(&str) -> Result<Vec<u8>>,
        descriptor: &Descriptor,
        media_type: &str,
    ) -> Result<Vec<u8>> {
        if descriptor.media_type().as_ref() != media_type
            || descriptor.urls().is_some()
            || descriptor.data().is_some()
        {
            return Err(Layout::invalid("OCI descriptor"));
        }
        let bytes = read(&Layout::blob_path(descriptor)?)?;
        if Layout::descriptor(media_type, &bytes)? != *descriptor {
            return Err(Layout::invalid("OCI blob identity"));
        }
        Ok(bytes)
    }

    fn valid_blob_path(path: &str) -> bool {
        path.strip_prefix("blobs/sha256/").is_some_and(|hash| {
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    }
}
