use std::{fs, sync::Arc};

use araphor_data::{PackageBundleV1, PackageRequestV1, PackageResponseV1};
use mithril_control::{ClientAuth, PackageTrustPinV1};

use crate::control_fixture::{oidc::OidcFixture, MtlsFixture};

mod bundle;
mod definitions;
mod fixture;
mod images;
mod wasm;

use bundle::Denials;
use fixture::Fixture;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
