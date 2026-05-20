use std::fs;
use std::process::Command;

use x0x::api::{EndpointDef, Method, ENDPOINTS};

fn registry_key(path: &str) -> String {
    path.split('/')
        .map(|seg| if seg.starts_with(':') { "*" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

fn method_str(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    }
}

fn endpoint_key(endpoint: &EndpointDef) -> String {
    format!(
        "{} {}",
        method_str(endpoint.method),
        registry_key(endpoint.path)
    )
}

#[test]
fn whitelisted_calls_do_not_count_toward_cli_coverage() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let gui_path = temp.path().join("gui.html");
    let whitelist_path = temp.path().join("coverage-whitelist.txt");

    fs::write(&gui_path, "api('/health');\n")?;

    let counted_endpoint = "GET /status";
    let whitelist = ENDPOINTS
        .iter()
        .map(endpoint_key)
        .filter(|key| key != counted_endpoint)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&whitelist_path, whitelist)?;

    let output = Command::new(env!("CARGO_BIN_EXE_gui-coverage"))
        .arg("--gui")
        .arg(&gui_path)
        .arg("--whitelist")
        .arg(&whitelist_path)
        .arg("--threshold")
        .arg("100")
        .arg("--json")
        .output()?;

    assert!(
        !output.status.success(),
        "gui-coverage should fail when only a whitelisted endpoint is called"
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["pass"], false);
    assert_eq!(report["counted_total"], 1);
    assert_eq!(report["covered"], 0);
    assert_eq!(report["coverage_pct"], 0.0);
    assert_eq!(report["uncovered"], serde_json::json!([counted_endpoint]));

    Ok(())
}
