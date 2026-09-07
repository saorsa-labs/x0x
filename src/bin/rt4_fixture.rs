//! #491 RT-4 fixture writer/inspector — a real CLI binary that creates
//! and inspects `bootstrap_cache.json` through the pinned ant-quic 0.27.49
//! public `BootstrapCache` API. Used by `tests/rt4_harness.sh`.
//!
//! Usage:
//!   rt4_fixture write <cache_dir> <self_id_hex> [nonself_id_hex]
//!   rt4_fixture inspect <cache_dir> [must_contain_hex|-] [must_not_contain_hex|-]
//!   rt4_fixture corrupt-checksum <cache_dir>

use ant_quic::bootstrap_cache::{BootstrapCache, BootstrapCacheConfig};
use ant_quic::PeerId;

fn config_for(dir: &std::path::Path) -> BootstrapCacheConfig {
    BootstrapCacheConfig::builder()
        .cache_dir(dir.to_path_buf())
        .min_peers_to_save(1)
        .persist(true)
        .enable_file_locking(false)
        .build()
}

fn parse_peer_id(hex: &str) -> Result<PeerId, String> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid hex peer id: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("peer id must be 32 bytes, got {}", v.len()))?;
    Ok(PeerId(arr))
}

fn print_usage() {
    eprintln!("usage: rt4_fixture write <cache_dir> <self_id_hex> [nonself_id_hex]");
    eprintln!(
        "       rt4_fixture inspect <cache_dir> [must_contain_hex|-] [must_not_contain_hex|-]"
    );
    eprintln!("       rt4_fixture corrupt-checksum <cache_dir>");
}

fn parse_optional_peer_id(args: &[String], index: usize) -> Result<Option<PeerId>, String> {
    match args.get(index) {
        None => Ok(None),
        Some(value) if value == "-" => Ok(None),
        Some(value) => parse_peer_id(value).map(Some),
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        print_usage();
        return std::process::ExitCode::FAILURE;
    }

    let command = args[1].as_str();
    let dir = std::path::PathBuf::from(&args[2]);

    match command {
        "write" => {
            if args.len() < 4 {
                eprintln!("write requires at least <self_id_hex>");
                print_usage();
                return std::process::ExitCode::FAILURE;
            }
            let self_id = match parse_peer_id(&args[3]) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("error: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let nonself_id = if args.len() > 4 {
                match parse_peer_id(&args[4]) {
                    Ok(id) => Some(id),
                    Err(e) => {
                        eprintln!("error: {e}");
                        return std::process::ExitCode::FAILURE;
                    }
                }
            } else {
                None
            };

            let config = config_for(&dir);
            let cache = match BootstrapCache::open(config).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to open cache: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            // Compile-time-valid loopback — no parse failure path.
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 51820));
            cache.add_seed(self_id, vec![addr]).await;
            if let Some(nonself) = nonself_id {
                cache.add_seed(nonself, vec![addr]).await;
            }
            let count = cache.peer_count().await;
            if let Err(e) = cache.save().await {
                eprintln!("error: failed to save: {e}");
                return std::process::ExitCode::FAILURE;
            }
            println!("written: count={count} dir={}", dir.display());
            std::process::ExitCode::SUCCESS
        }
        "inspect" => {
            let must_contain = match parse_optional_peer_id(&args, 3) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("error: invalid required peer id: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let must_not_contain = match parse_optional_peer_id(&args, 4) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("error: invalid forbidden peer id: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let config = config_for(&dir);
            let cache = match BootstrapCache::open(config).await {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to open: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let count = cache.peer_count().await;
            let contains_expected = match must_contain {
                Some(id) => cache.contains(&id).await,
                None => true,
            };
            let contains_forbidden = match must_not_contain {
                Some(id) => cache.contains(&id).await,
                None => false,
            };
            println!(
                "count={count} contains_expected={} contains_forbidden={}",
                u8::from(contains_expected),
                u8::from(contains_forbidden)
            );
            if contains_expected && !contains_forbidden {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            }
        }
        "corrupt-checksum" => {
            let file = dir.join("bootstrap_cache.json");
            let bytes = match std::fs::read(&file) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: cannot read {}: {e}", file.display());
                    return std::process::ExitCode::FAILURE;
                }
            };
            let mut json: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: cannot parse JSON: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            let checksum = json["checksum"].as_u64().unwrap_or(0);
            json["checksum"] = serde_json::Value::from(checksum.saturating_add(1));
            let out = match serde_json::to_vec_pretty(&json) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error: cannot serialize: {e}");
                    return std::process::ExitCode::FAILURE;
                }
            };
            if let Err(e) = std::fs::write(&file, out) {
                eprintln!("error: cannot write {}: {e}", file.display());
                return std::process::ExitCode::FAILURE;
            }
            println!(
                "corrupted: checksum {} -> {}",
                checksum,
                checksum.saturating_add(1)
            );
            std::process::ExitCode::SUCCESS
        }
        _ => {
            eprintln!("unknown command: {command}");
            print_usage();
            std::process::ExitCode::FAILURE
        }
    }
}
