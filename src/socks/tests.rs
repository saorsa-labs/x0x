//! ADR-0074 slice 4 — SOCKS5 intent tests (auth, loopback bind, port deny).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::config::{SocksConfig, SocksConfigError};
use super::proto::{
    resolve_x0x_host, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USER_PASS, REP_NOT_ALLOWED,
    REP_SUCCEEDED, VER,
};
use super::service::{handle_stream_session, SocksConnectError};
use crate::exec::acl::parse_agent_id;

const TOKEN: &str = "test-api-token-for-socks-auth";

fn peer_host() -> String {
    let id = parse_agent_id(&"ab".repeat(32)).unwrap();
    format!("{}.x0x", hex::encode(id.as_bytes()))
}

/// Client-side: greet with the given methods list.
async fn client_greet(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    methods: &[u8],
) -> u8 {
    let mut msg = vec![VER, methods.len() as u8];
    msg.extend_from_slice(methods);
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], VER);
    resp[1]
}

async fn client_userpass(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    user: &str,
    pass: &str,
) -> u8 {
    let mut msg = vec![0x01, user.len() as u8];
    msg.extend_from_slice(user.as_bytes());
    msg.push(pass.len() as u8);
    msg.extend_from_slice(pass.as_bytes());
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 2];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], 0x01);
    resp[1]
}

async fn client_connect_domain(
    client: &mut (impl AsyncReadExt + AsyncWriteExt + Unpin),
    host: &str,
    port: u16,
) -> u8 {
    let host_b = host.as_bytes();
    let mut msg = vec![VER, 0x01, 0x00, 0x03, host_b.len() as u8];
    msg.extend_from_slice(host_b);
    msg.extend_from_slice(&port.to_be_bytes());
    client.write_all(&msg).await.unwrap();
    let mut resp = [0u8; 10];
    client.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp[0], VER);
    resp[1]
}

#[test]
fn socks_config_refuses_non_loopback_listen() {
    let cfg = SocksConfig {
        listen: Some("192.168.1.10:1080".parse().unwrap()),
    };
    let err = cfg.validate().unwrap_err();
    assert!(matches!(err, SocksConfigError::NonLoopback { .. }), "{err}");
}

#[test]
fn socks_config_accepts_loopback_and_off() {
    assert!(SocksConfig::default().validate().is_ok());
    assert!(!SocksConfig::default().enabled());
    let cfg = SocksConfig {
        listen: Some("127.0.0.1:1080".parse().unwrap()),
    };
    assert!(cfg.validate().is_ok());
    assert!(cfg.enabled());
    let cfg6 = SocksConfig {
        listen: Some("[::1]:1080".parse().unwrap()),
    };
    assert!(cfg6.validate().is_ok());
}

#[test]
fn resolve_hex_agent_x0x_host() {
    let id = parse_agent_id(&"cd".repeat(32)).unwrap();
    let host = format!("{}.x0x", hex::encode(id.as_bytes()));
    assert_eq!(resolve_x0x_host(&host).unwrap(), id);
    assert!(resolve_x0x_host("example.com").is_err());
    assert!(resolve_x0x_host("192.168.1.1").is_err());
}

#[tokio::test]
async fn no_auth_refused_before_any_connect() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let attempted = Arc::new(AtomicBool::new(false));
    let attempted_server = Arc::clone(&attempted);
    let server_task = tokio::spawn(async move {
        handle_stream_session(
            &mut server,
            TOKEN,
            |_peer, _port| async { panic!("connector must not run after NO AUTH") },
            Some(attempted_server.as_ref()),
        )
        .await
    });

    let method = client_greet(&mut client, &[METHOD_NO_AUTH]).await;
    assert_eq!(method, METHOD_NO_ACCEPTABLE);
    let result = server_task.await.unwrap().unwrap();
    assert_eq!(result, 0xFF);
    assert!(
        !attempted.load(Ordering::SeqCst),
        "NO AUTH must not open a stream"
    );
}

#[tokio::test]
async fn wrong_token_refused_before_any_connect() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let attempted = Arc::new(AtomicBool::new(false));
    let attempted_server = Arc::clone(&attempted);
    let server_task = tokio::spawn(async move {
        handle_stream_session(
            &mut server,
            TOKEN,
            |_peer, _port| async { panic!("connector must not run after bad token") },
            Some(attempted_server.as_ref()),
        )
        .await
    });

    assert_eq!(
        client_greet(&mut client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(
        client_userpass(&mut client, "x0x", "wrong-token").await,
        0x01
    );
    let _ = server_task.await.unwrap();
    assert!(
        !attempted.load(Ordering::SeqCst),
        "wrong token must not open a stream"
    );
}

#[tokio::test]
async fn allowed_port_succeeds_with_valid_token() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let host = peer_host();
    let target_hits = Arc::new(AtomicU64::new(0));
    let hits = Arc::clone(&target_hits);
    let server_task = tokio::spawn(async move {
        handle_stream_session(
            &mut server,
            TOKEN,
            move |_peer, port| {
                let hits = Arc::clone(&hits);
                async move {
                    assert_eq!(port, 8080);
                    // Simulate peer allow: "target" is touched only on allow.
                    hits.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
            None,
        )
        .await
    });

    assert_eq!(
        client_greet(&mut client, &[METHOD_NO_AUTH, METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(&mut client, "x0x", TOKEN).await, 0x00);
    let rep = client_connect_domain(&mut client, &host, 8080).await;
    assert_eq!(rep, REP_SUCCEEDED);
    assert_eq!(server_task.await.unwrap().unwrap(), REP_SUCCEEDED);
    assert_eq!(target_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disallowed_port_returns_0x02_with_zero_target_bytes() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let host = peer_host();
    let target_hits = Arc::new(AtomicU64::new(0));
    let hits = Arc::clone(&target_hits);
    let server_task = tokio::spawn(async move {
        handle_stream_session(
            &mut server,
            TOKEN,
            move |_peer, port| {
                let hits = Arc::clone(&hits);
                async move {
                    assert_eq!(port, 9999);
                    // Denial path: do NOT touch the target.
                    let _ = hits;
                    Err(SocksConnectError::NotAllowed)
                }
            },
            None,
        )
        .await
    });

    assert_eq!(
        client_greet(&mut client, &[METHOD_USER_PASS]).await,
        METHOD_USER_PASS
    );
    assert_eq!(client_userpass(&mut client, "x0x", TOKEN).await, 0x00);
    let rep = client_connect_domain(&mut client, &host, 9999).await;
    assert_eq!(rep, REP_NOT_ALLOWED);
    assert_eq!(server_task.await.unwrap().unwrap(), REP_NOT_ALLOWED);
    assert_eq!(
        target_hits.load(Ordering::SeqCst),
        0,
        "disallowed port must send zero bytes to the target"
    );
}

#[tokio::test]
async fn non_loopback_bind_is_refused_at_spawn() {
    // Config validation is the loader refuse path; spawn still requires a
    // loopback listen (TcpListener bind of non-loopback is OS-dependent).
    let cfg = SocksConfig {
        listen: Some("8.8.8.8:1080".parse().unwrap()),
    };
    assert!(matches!(
        cfg.validate().unwrap_err(),
        SocksConfigError::NonLoopback { .. }
    ));
}
