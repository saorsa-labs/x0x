//! Command implementations for the `x0x` CLI.

pub mod constitution;
pub mod contacts;
pub mod daemon;
pub mod direct;
pub mod discovery;
pub mod find;
pub mod files;
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
pub fn routes() -> anyhow::Result<()> {
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
