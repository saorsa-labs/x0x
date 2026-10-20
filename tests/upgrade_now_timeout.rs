// Expanded inside cli::tests. Metadata controls build actual production requests;
// the Linux-only transport control requires the isolated CI network namespace.
#[allow(unused_macros)]
macro_rules! upgrade_now_timeout_regression_tests {
    () => {
        mod upgrade_now_timeout_regressions {
            use super::*;

            fn client(base_url: String) -> DaemonClient {
                DaemonClient {
                    client: reqwest::Client::builder().timeout(Duration::from_secs(30)).build().unwrap(),
                    base_url, format: OutputFormat::Json,
                    api_token: Some("owned-builder-token".into()), dump: false,
                }
            }

            #[test]
            fn upgrade_now_timeout_real_builder_classifies_only_the_exact_apply_path() {
                let client = client("http://127.0.0.1:1".into());
                for (path, upgrade) in [
                    ("/upgrade/apply", true), ("/upgrade/apply?now=true", true),
                    ("/upgrade/apply?now=false", true), ("/upgrade/apply/", false),
                    ("/upgrade/apply-other", false), ("/upgrade/check", false),
                    ("/other?next=/upgrade/apply", false),
                ] {
                    let (_client, request) = client.post_empty_request(path).unwrap().build_split();
                    let request = request.unwrap();
                    assert_eq!(request.method(), reqwest::Method::POST);
                    assert_eq!(request.url().as_str(), format!("http://127.0.0.1:1{path}"));
                    assert_eq!(request.headers()[reqwest::header::AUTHORIZATION], "Bearer owned-builder-token");
                    assert!(request.body().is_none());
                    assert_eq!(*request.timeout(), if upgrade { None } else { Some(Duration::from_secs(30)) });
                    // None is only request metadata. The real transport control
                    // below proves the dedicated client has no inherited limit.
                }
            }

            #[cfg(target_os = "linux")]
            #[tokio::test(start_paused = true)]
            async fn upgrade_now_timeout_real_transport_keeps_only_apply_pending_after_ten_minutes() {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                struct Server(Option<tokio::task::JoinHandle<()>>);
                impl Drop for Server { fn drop(&mut self) { if let Some(task) = &self.0 { task.abort(); } } }
                for (path, upgrade) in [
                    ("/upgrade/check", false), ("/upgrade/apply", true),
                    ("/upgrade/apply?now=true", true),
                ] {
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let (received, mut received_rx) = tokio::sync::oneshot::channel();
                    let mut server = Server(Some(tokio::spawn(async move {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let mut header = Vec::new();
                        let mut byte = [0_u8; 1];
                        while !header.ends_with(b"\r\n\r\n") {
                            assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
                            header.push(byte[0]);
                            assert!(header.len() <= 8192);
                        }
                        received.send(String::from_utf8(header).unwrap()).unwrap();
                        // Deliberately no response. This is an owned loopback
                        // peer, not x0xd, and executes no daemon/store code.
                        let mut discard = [0_u8; 128];
                        loop {
                            match stream.read(&mut discard).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        let _ = stream.shutdown().await;
                    })));
                    let client = client(format!("http://{address}"));
                    let (transport, request) = client.post_empty_request(path).unwrap().build_split();
                    let mut pending = Box::pin(transport.execute(request.unwrap()));
                    let deadline = std::time::Instant::now() + Duration::from_secs(10);
                    let header = loop {
                        assert!(std::time::Instant::now() < deadline, "request did not reach owned listener");
                        tokio::select! {
                            biased;
                            response = &mut pending => panic!("request ended before response was withheld: {response:?}"),
                            header = &mut received_rx => break header.unwrap(),
                            _ = tokio::task::yield_now() => {}
                        }
                    };
                    assert!(header.starts_with(&format!("POST {path} HTTP/1.1\r\n")));
                    tokio::time::advance(Duration::from_secs(31)).await;
                    if upgrade {
                        for advance in [Duration::ZERO, Duration::from_secs(570)] {
                            tokio::time::advance(advance).await;
                            let settle = std::time::Instant::now() + Duration::from_millis(100);
                            while std::time::Instant::now() < settle {
                                tokio::select! {
                                    biased;
                                    response = &mut pending => panic!("apply inherited a total timeout: {response:?}"),
                                    _ = tokio::task::yield_now() => {}
                                }
                            }
                        }
                    } else {
                        let response = loop {
                            assert!(std::time::Instant::now() < deadline, "ordinary timeout did not fire");
                            tokio::select! {
                                biased;
                                response = &mut pending => break response,
                                _ = tokio::task::yield_now() => {}
                            }
                        };
                        assert!(response.unwrap_err().is_timeout());
                    }
                    drop(pending);
                    drop(transport);
                    // Reap the owned async peer after the cancelled/failed
                    // request closes it. This says nothing about arbitrary
                    // daemon-side disconnect or pipelined HTTP cancellation.
                    while !server.0.as_ref().unwrap().is_finished() {
                        assert!(std::time::Instant::now() < deadline, "owned peer did not close");
                        tokio::task::yield_now().await;
                    }
                    server.0.take().unwrap().await.unwrap();
                }
            }
        }
    };
}
