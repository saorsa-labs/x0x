//! Shared test helpers for command modules.
//!
//! Hoists the previously copy-pasted `start_mock_server` helper into one place
//! so every command test module shares a single implementation.

#![cfg(test)]
#![allow(clippy::unwrap_used)]

/// Start a mock axum server that returns the given JSON for any request.
///
/// Returns the base URL and a oneshot sender that shuts the server down when
/// dropped or signalled.
pub async fn start_mock_server(
    response_json: serde_json::Value,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    use std::sync::Arc;

    let json = Arc::new(response_json);
    let app = axum::Router::new().fallback(move |_req: axum::extract::Request| {
        let json = Arc::clone(&json);
        async move {
            let body = serde_json::to_vec(&*json).unwrap();
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (format!("http://{addr}"), tx)
}

/// Like [`start_mock_server`], but records every `(path, JSON body)` the
/// client sends, so tests can assert the request actually hit the expected
/// endpoint with the expected fields.
pub async fn start_capturing_mock_server(
    response_json: serde_json::Value,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    std::sync::Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
) {
    use std::sync::{Arc, Mutex};

    let json = Arc::new(response_json);
    let captured: Arc<Mutex<Vec<(String, serde_json::Value)>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = Arc::clone(&captured);
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let json = Arc::clone(&json);
        let cap = Arc::clone(&cap);
        async move {
            let path = req.uri().path().to_string();
            let bytes = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .unwrap_or_default();
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            cap.lock().unwrap().push((path, body));
            let resp = serde_json::to_vec(&*json).unwrap();
            axum::response::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(resp))
                .unwrap()
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .ok();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (format!("http://{addr}"), tx, captured)
}
