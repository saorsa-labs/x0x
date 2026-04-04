#![no_main]
#![allow(dead_code)]
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
struct DaemonConfig {
    pub api_host: Option<String>,
    pub api_port: Option<u16>,
    pub transport_port: Option<u16>,
    pub machine_key_path: Option<String>,
    pub agent_key_path: Option<String>,
    pub user_key_path: Option<String>,
    pub bootstrap_peers: Option<Vec<String>>,
    pub mdns: Option<bool>,
    pub name: Option<String>,
    pub gui_title: Option<String>,
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = toml::from_str::<DaemonConfig>(s);
    }
});
