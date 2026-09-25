//! `x0x acl connect|exec list|add|rm` + `x0x acl reload` — ADR-0070 §3
//! management of API-managed connect/exec ACL entries over the TOML floor.

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// Which ACL plane a command addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclPlane {
    /// Connect (tailnet port-forward) ACL.
    Connect,
    /// Remote exec ACL.
    Exec,
}

impl AclPlane {
    fn base(self) -> &'static str {
        match self {
            Self::Connect => "/acl/connect",
            Self::Exec => "/acl/exec",
        }
    }
}

/// `x0x acl <plane> list` — floor and API entries with their ids.
pub async fn list(client: &DaemonClient, plane: AclPlane) -> Result<()> {
    let resp = client.get(plane.base()).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x acl <plane> add ENTRY_JSON` — ENTRY_JSON is the TOML allow-entry
/// schema as JSON: a literal, `@path`, or `-` for stdin.
pub async fn add(client: &DaemonClient, plane: AclPlane, entry_json: &str) -> Result<()> {
    let entry = read_entry_json(entry_json)?;
    let resp = client.post(plane.base(), &entry).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x acl <plane> rm ID` — remove an API-managed entry by id.
pub async fn remove(client: &DaemonClient, plane: AclPlane, id: &str) -> Result<()> {
    let resp = client.delete(&format!("{}/{id}", plane.base())).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x acl reload` — re-read both TOML floors and API overlays.
pub async fn reload(client: &DaemonClient) -> Result<()> {
    let resp = client.post_empty("/acl/reload").await?;
    print_value(client.format(), &resp);
    Ok(())
}

fn read_entry_json(spec: &str) -> Result<serde_json::Value> {
    let text = if spec == "-" {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| anyhow::anyhow!("stdin read failed: {e}"))?;
        buf
    } else if let Some(path) = spec.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("read {path}: {e}"))?
    } else {
        spec.to_string()
    };
    serde_json::from_str(&text).map_err(|e| anyhow::anyhow!("ACL entry JSON parse: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_json_literal_parses_and_garbage_is_rejected() {
        let v = read_entry_json(r#"{"principal":"owner","targets":["127.0.0.1:22"]}"#)
            .expect("literal parses");
        assert_eq!(v["principal"], "owner");
        assert!(read_entry_json("{not json").is_err());
    }

    #[test]
    fn plane_paths_match_the_registry() {
        // The CLI must hit exactly the registered routes.
        for (plane, cli) in [
            (AclPlane::Connect, "acl connect list"),
            (AclPlane::Exec, "acl exec list"),
        ] {
            let ep = crate::api::find_by_cli_name(cli).expect("registered");
            assert_eq!(ep.path, plane.base());
        }
    }
}
