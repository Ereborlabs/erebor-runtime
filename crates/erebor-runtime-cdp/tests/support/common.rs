#[path = "chrome.rs"]
mod chrome;
#[path = "chrome_http.rs"]
mod chrome_http;
#[path = "error_helpers.rs"]
mod error_helpers;
#[path = "mini.rs"]
mod mini;
#[path = "policy.rs"]
mod policy;

pub use chrome::{real_chrome_available, RealChromeInstance};
pub use mini::{mini_cdp_handler, session_context};
pub use policy::{
    allow_all_policy, deny_payload_script_eval_policy, deny_script_eval_policy,
    deny_target_script_eval_policy, require_approval_script_eval_policy,
};

pub(crate) use error_helpers::{closed_error, external_error, timeout_error};
