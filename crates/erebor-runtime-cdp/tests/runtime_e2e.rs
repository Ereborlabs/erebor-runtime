#[path = "support/common.rs"]
mod common;
#[path = "support/runtime.rs"]
mod support;

#[path = "runtime_e2e/mini_upstream.rs"]
mod mini_upstream;
#[path = "runtime_e2e/owned_browser.rs"]
mod owned_browser;
#[path = "runtime_e2e/real_chrome.rs"]
mod real_chrome;
#[path = "runtime_e2e/session.rs"]
mod session;
