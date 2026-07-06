//! Command implementations for the `x0x` CLI.

pub mod auth;
pub mod connect;
pub mod constitution;
pub mod contacts;
pub mod daemon;
pub mod direct;
pub mod discovery;
pub mod exec;
pub mod files;
pub mod find;
pub mod forward;
pub mod group;
pub mod groups;
pub mod identity;
pub mod machines;
pub mod messaging;
pub mod network;
pub mod presence;
pub mod purge;
pub mod store;
pub mod tasks;
pub mod upgrade;
pub mod user_id;
pub mod ws;

#[cfg(test)]
pub(crate) mod test_support;

use crate::api;
use serde::Serialize;

/// JSON shape of one endpoint in `routes --json`.
///
/// Field order/names are the public contract consumed by `just routes-json`
/// and other tooling: `method`, `path`, `cli_name`, `description`, `category`.
#[derive(Serialize)]
struct RouteEntry<'a> {
    method: String,
    path: &'a str,
    cli_name: &'a str,
    description: &'a str,
    category: &'a str,
}

/// Print the full API route table.
///
/// When `json` is true, emits a JSON array — one object per endpoint with
/// `method`, `path`, `cli_name`, `description`, `category` fields. Used by
/// `just routes-json` and other downstream tooling to treat the registry as
/// the source of truth.
pub fn routes(json: bool) -> anyhow::Result<()> {
    if json {
        let entries: Vec<RouteEntry<'_>> = api::ENDPOINTS
            .iter()
            .map(|ep| RouteEntry {
                method: ep.method.to_string(),
                path: ep.path,
                cli_name: ep.cli_name,
                description: ep.description,
                category: ep.category,
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }

    let method_width = 6;
    let path_width = 50;
    let cmd_width = 24;

    println!(
        "{:<method_width$}  {:<path_width$}  {:<cmd_width$}  DESCRIPTION",
        "METHOD", "PATH", "CLI COMMAND"
    );
    println!("{}", "-".repeat(method_width + path_width + cmd_width + 30));

    for cat in api::categories() {
        let endpoints = api::by_category(cat);
        for ep in endpoints {
            println!(
                "{:<method_width$}  {:<path_width$}  {:<cmd_width$}  {}",
                ep.method, ep.path, ep.cli_name, ep.description
            );
        }
    }

    println!("\n{} endpoints total", api::ENDPOINTS.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::cli::OutputFormat;

    /// The `routes --json` payload is a public contract: tooling parses it and
    /// keys off `method`/`path`/`cli_name`/`description`/`category`. Pin the
    /// serialized shape so a serializer change cannot silently break it.
    #[test]
    fn routes_json_contract_is_stable() {
        let entries: Vec<RouteEntry<'_>> = api::ENDPOINTS
            .iter()
            .map(|ep| RouteEntry {
                method: ep.method.to_string(),
                path: ep.path,
                cli_name: ep.cli_name,
                description: ep.description,
                category: ep.category,
            })
            .collect();
        let json = serde_json::to_string_pretty(&entries).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().expect("routes json is an array");
        assert_eq!(arr.len(), api::ENDPOINTS.len());
        for (entry, ep) in arr.iter().zip(api::ENDPOINTS.iter()) {
            let obj = entry.as_object().expect("each entry is an object");
            for field in ["method", "path", "cli_name", "description", "category"] {
                assert!(obj.contains_key(field), "missing field {field}");
            }
            assert_eq!(obj["method"], serde_json::json!(ep.method.to_string()));
            assert_eq!(obj["path"], serde_json::json!(ep.path));
            assert_eq!(obj["cli_name"], serde_json::json!(ep.cli_name));
        }
    }

    /// Special characters must survive serialization — this is what the old
    /// hand-rolled escaper guarded. A `"`/newline/tab in a description must
    /// round-trip without producing invalid JSON.
    #[test]
    fn routes_json_escapes_special_characters() {
        let entries = vec![RouteEntry {
            method: "GET".to_string(),
            path: "/x",
            cli_name: "x",
            description: "say \"hi\"\nand\ttab",
            category: "test",
        }];
        let json = serde_json::to_string(&entries).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["description"], "say \"hi\"\nand\ttab");
    }

    #[test]
    fn routes_json_output_is_valid() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            routes(true).unwrap();
        }));
        assert!(result.is_ok());
    }

    #[test]
    fn routes_text_output_is_valid() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            routes(false).unwrap();
        }));
        assert!(result.is_ok());
    }

    #[test]
    fn output_format_defaults() {
        let fmt = OutputFormat::Text;
        let _fmt2 = fmt;
        assert!(matches!(fmt, OutputFormat::Text));
        let json_fmt = OutputFormat::Json;
        assert!(matches!(json_fmt, OutputFormat::Json));
    }
}
