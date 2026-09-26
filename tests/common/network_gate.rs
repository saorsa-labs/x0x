//! Shared skip-or-fail gate for loopback network tests.
//!
//! Sandboxed developer hosts may refuse UDP binds; those runs skip. A CI job
//! that exists to prove these tests sets `X0X_REQUIRE_NETWORK_TESTS=1`, so a
//! refused bind fails loudly instead of passing without testing anything.

/// Env var that turns a refused-network skip into a test failure.
pub const REQUIRE_NETWORK_TESTS_ENV: &str = "X0X_REQUIRE_NETWORK_TESTS";

/// Returns `true` when `error` is a refused UDP bind / network init and the
/// test should skip. Panics instead when `X0X_REQUIRE_NETWORK_TESTS=1`.
pub fn skip_on_refused_network(error: &impl std::fmt::Display) -> bool {
    let message = error.to_string();
    let refused = message.contains("Operation not permitted")
        && (message.contains("bind UDP socket")
            || message.contains("network initialization failed"));
    if refused && std::env::var(REQUIRE_NETWORK_TESTS_ENV).as_deref() == Ok("1") {
        panic!(
            "network setup refused but {REQUIRE_NETWORK_TESTS_ENV}=1 requires these \
             tests to run, not skip: {message}"
        );
    }
    refused
}

/// Route `x0x::streams` gate/accept-loop decisions into the captured test
/// output, so a CI failure shows WHY an inbound stream was reset. Idempotent.
pub fn init_stream_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("x0x::streams=debug"))
        .with_ansi(false)
        .with_test_writer()
        .try_init();
}
