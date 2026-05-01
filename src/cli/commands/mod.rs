//! Command implementations for the `x0x` CLI.

pub mod connect;
pub mod constitution;
pub mod contacts;
pub mod daemon;
pub mod direct;
pub mod discovery;
pub mod exec;
pub mod files;
pub mod find;
pub mod group;
pub mod groups;
pub mod identity;
pub mod machines;
pub mod messaging;
pub mod network;
pub mod presence;
pub mod store;
pub mod tasks;
pub mod upgrade;
pub mod ws;

use crate::api;

/// Print the full API route table.
///
/// When `json` is true, emits a JSON array — one object per endpoint with
/// `method`, `path`, `cli_name`, `description`, `category` fields. Used by
/// `just gui-coverage` and other downstream tooling to treat the registry as
/// the source of truth.
pub fn routes(json: bool) -> anyhow::Result<()> {
    if json {
        let mut out = String::from("[\n");
        let total = api::ENDPOINTS.len();
        for (i, ep) in api::ENDPOINTS.iter().enumerate() {
            out.push_str(&format!(
                "  {{\"method\":\"{}\",\"path\":{},\"cli_name\":{},\"description\":{},\"category\":{}}}",
                ep.method,
                json_escape(ep.path),
                json_escape(ep.cli_name),
                json_escape(ep.description),
                json_escape(ep.category),
            ));
            if i + 1 < total {
                out.push(',');
            }
            out.push('\n');
        }
        out.push(']');
        println!("{out}");
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

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
