//! `x0x names …` — ADR-0074 §1 names for agents and machines
//! (`[agent:|machine:]<label>.<owner>`; durable API token only).

use crate::cli::{print_value, DaemonClient};
use anyhow::Result;

/// `x0x names list` — owner petnames and pinned names.
pub async fn list(client: &DaemonClient) -> Result<()> {
    let resp = client.get("/names").await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x names resolve NAME` — resolve locally; pins the name at first use.
pub async fn resolve(client: &DaemonClient, name: &str) -> Result<()> {
    let resp = client.post("/names/resolve", &resolve_body(name)).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x names owner add LABEL USER_ID` — bind an owner petname.
pub async fn owner_add(client: &DaemonClient, label: &str, user_id: &str) -> Result<()> {
    let resp = client
        .post("/names/owners", &owner_add_body(label, user_id))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x names owner rm LABEL` — remove an owner petname and its pins.
pub async fn owner_remove(client: &DaemonClient, label: &str) -> Result<()> {
    let resp = client.delete(&owner_remove_path(label)?).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x names machine label NAME MACHINE_ID` — label a shared machine.
pub async fn machine_label(client: &DaemonClient, name: &str, machine_id: &str) -> Result<()> {
    let resp = client
        .post("/names/machines", &machine_label_body(name, machine_id))
        .await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// `x0x names unpin NAME` — drop a pin (canonical `agent:`/`machine:` name).
pub async fn unpin(client: &DaemonClient, name: &str) -> Result<()> {
    let resp = client.delete(&unpin_path(name)?).await?;
    print_value(client.format(), &resp);
    Ok(())
}

/// Owner-label path. The label is checked before the path exists, so a
/// value such as `../../contacts/<id>` never becomes a DELETE URL.
fn owner_remove_path(label: &str) -> Result<String> {
    crate::names::validate_label(label)
        .map_err(|error| anyhow::anyhow!("invalid owner label: {error}"))?;
    Ok(format!("/names/owners/{label}"))
}

/// Pin path. The name is checked before the path exists, so a value such
/// as `../../contacts/<id>` never becomes a DELETE URL.
fn unpin_path(name: &str) -> Result<String> {
    let parsed = crate::names::NameRef::parse(name)
        .map_err(|error| anyhow::anyhow!("invalid pin name: {error}"))?;
    if parsed.kind.is_none() {
        return Err(anyhow::anyhow!(
            "invalid pin name: {name:?}: a pin key needs agent: or machine:"
        ));
    }
    Ok(format!("/names/pins/{name}"))
}

fn resolve_body(name: &str) -> serde_json::Value {
    serde_json::json!({ "name": name })
}

fn owner_add_body(label: &str, user_id: &str) -> serde_json::Value {
    serde_json::json!({ "label": label, "user_id": user_id })
}

fn machine_label_body(name: &str, machine_id: &str) -> serde_json::Value {
    serde_json::json!({ "name": name, "machine_id": machine_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WHY: the CLI bodies must match the daemon's `deny_unknown_fields`
    /// request structs exactly, or every call fails with a 4xx.
    #[test]
    fn names_bodies_match_the_daemon_request_structs() {
        assert_eq!(
            resolve_body("agent:studio.me"),
            serde_json::json!({ "name": "agent:studio.me" })
        );
        assert_eq!(
            owner_add_body("bob", "ab"),
            serde_json::json!({ "label": "bob", "user_id": "ab" })
        );
        assert_eq!(
            machine_label_body("machine:box.bob", "cd"),
            serde_json::json!({ "name": "machine:box.bob", "machine_id": "cd" })
        );
    }

    /// WHY: `names owner rm ../../contacts/<id>` must fail before reqwest
    /// normalises that path into `DELETE /contacts/<id>`. The unpin sibling
    /// has the same check.
    #[test]
    fn owner_remove_and_unpin_reject_path_traversal_before_the_url() {
        let traversal = "../../contacts/ab";
        let owner_err = owner_remove_path(traversal).expect_err("owner path");
        assert!(
            !owner_err.to_string().contains("/names/owners/"),
            "rejected before the URL: {owner_err}"
        );
        let pin_err = unpin_path(traversal).expect_err("pin path");
        assert!(
            !pin_err.to_string().contains("/names/pins/"),
            "rejected before the URL: {pin_err}"
        );
        assert_eq!(owner_remove_path("bob").unwrap(), "/names/owners/bob");
        assert_eq!(
            unpin_path("agent:studio.bob").unwrap(),
            "/names/pins/agent:studio.bob"
        );
    }
}
