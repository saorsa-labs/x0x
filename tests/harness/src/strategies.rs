//! Proptest strategies for x0x types.
//!
//! Reusable strategies for generating random x0x data in property-based tests.

use proptest::prelude::*;
use x0x::api::Method;

/// Generate a random 32-byte ID (used for AgentId, MachineId, etc.).
pub fn arb_id_bytes() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generate a random API method.
pub fn arb_method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Get),
        Just(Method::Post),
        Just(Method::Put),
        Just(Method::Patch),
        Just(Method::Delete),
    ]
}

/// Generate an arbitrary JSON value (recursive, for API fuzzing).
pub fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
        "[a-zA-Z0-9 ]{0,50}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(
        3,  // depth
        64, // max nodes
        10, // items per collection
        |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..10).prop_map(serde_json::Value::Array),
                prop::collection::hash_map("[a-z]{1,8}", inner, 0..5)
                    .prop_map(|m| { serde_json::Value::Object(m.into_iter().collect()) }),
            ]
        },
    )
}

/// Generate an arbitrary API path from the ENDPOINTS registry.
pub fn arb_api_path() -> impl Strategy<Value = String> {
    let paths: Vec<String> = x0x::api::ENDPOINTS
        .iter()
        .map(|ep| ep.path.to_string())
        .collect();
    prop::sample::select(paths)
}

/// Generate a random API request: (method, path, optional body).
pub fn arb_api_request() -> impl Strategy<Value = (Method, String, Option<serde_json::Value>)> {
    (
        arb_method(),
        arb_api_path(),
        proptest::option::of(arb_json_value()),
    )
}

/// Generate a random short string (1-20 chars, alphanumeric).
pub fn arb_short_string() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9]{1,20}"
}

/// Generate a random byte vector (0-256 bytes).
pub fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..256)
}

/// Generate a random timestamp (reasonable range).
pub fn arb_timestamp() -> impl Strategy<Value = u64> {
    1_000_000_000u64..2_000_000_000u64
}

/// Generate a random priority (0-255).
pub fn arb_priority() -> impl Strategy<Value = u8> {
    any::<u8>()
}

/// Generate a random NAT type string.
pub fn arb_nat_type() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some("None".to_string())),
        Just(Some("FullCone".to_string())),
        Just(Some("Symmetric".to_string())),
        Just(Some("RestrictedCone".to_string())),
        Just(Some("PortRestrictedCone".to_string())),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::test_runner::{Config, TestRunner};

    #[test]
    fn strategies_generate_values() {
        let mut runner = TestRunner::new(Config::with_cases(10));

        runner
            .run(&arb_id_bytes(), |bytes| {
                assert_eq!(bytes.len(), 32);
                Ok(())
            })
            .expect("arb_id_bytes works");

        runner
            .run(&arb_json_value(), |_val| Ok(()))
            .expect("arb_json_value works");

        runner
            .run(&arb_api_path(), |path| {
                assert!(path.starts_with('/'));
                Ok(())
            })
            .expect("arb_api_path works");
    }
}
