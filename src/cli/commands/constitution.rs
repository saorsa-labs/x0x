//! Constitution display command.

use crate::constitution::{CONSTITUTION_MD, CONSTITUTION_STATUS, CONSTITUTION_VERSION};
use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

/// Display the x0x Constitution.
pub fn display(raw: bool, json: bool) -> Result<()> {
    if json {
        let out = serde_json::json!({
            "version": CONSTITUTION_VERSION,
            "status": CONSTITUTION_STATUS,
            "content": CONSTITUTION_MD,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if raw {
        println!("{CONSTITUTION_MD}");
        return Ok(());
    }

    // Prettify the markdown for terminal display
    let rendered = render_for_terminal(CONSTITUTION_MD);

    // Page the output
    page_output(&rendered)?;

    Ok(())
}

fn render_for_terminal(md: &str) -> String {
    use termimad::MadSkin;

    let skin = MadSkin::default();
    let width = terminal_width().min(100); // Cap at 100 columns for readability
    let text = skin.text(md, Some(width));
    text.to_string()
}

fn terminal_width() -> usize {
    // Try to detect terminal width, fall back to 80
    if let Some((w, _)) = terminal_size::terminal_size() {
        w.0 as usize
    } else {
        80
    }
}

fn page_output(content: &str) -> Result<()> {
    // Try system pager: $PAGER > less > more > direct print
    let pager = std::env::var("PAGER")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            if Command::new("less").arg("--version").output().is_ok() {
                "less".to_string()
            } else {
                "more".to_string()
            }
        });

    let pager_args: Vec<&str> = if pager.contains("less") {
        vec!["-R"] // -R preserves ANSI colour codes
    } else {
        vec![]
    };

    match Command::new(&pager)
        .args(&pager_args)
        .stdin(Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(content.as_bytes());
            }
            child.wait()?;
        }
        Err(_) => {
            // Fallback: print directly
            print!("{content}");
        }
    }

    Ok(())
}
