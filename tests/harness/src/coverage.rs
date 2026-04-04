//! API coverage tracking and enforcement helpers.
//!
//! Provides utilities for verifying that all endpoints in the ENDPOINTS
//! registry have corresponding test coverage.

use std::collections::HashSet;
use x0x::api::{Method, ENDPOINTS};

/// Returns the set of all (method, path) pairs in the ENDPOINTS registry.
pub fn all_endpoint_keys() -> HashSet<(String, String)> {
    ENDPOINTS
        .iter()
        .map(|ep| (format!("{}", ep.method), ep.path.to_string()))
        .collect()
}

/// Returns the count of endpoints in the registry.
pub fn endpoint_count() -> usize {
    ENDPOINTS.len()
}

/// Returns all unique categories.
pub fn all_categories() -> Vec<&'static str> {
    x0x::api::categories()
}

/// Returns all endpoints in a given category.
pub fn endpoints_in_category(category: &str) -> Vec<(Method, &'static str, &'static str)> {
    x0x::api::by_category(category)
        .into_iter()
        .map(|ep| (ep.method, ep.path, ep.cli_name))
        .collect()
}

/// Normalizes a URL path for comparison with ENDPOINTS.
///
/// Replaces dynamic segments like `abc123def` with `:id` to match
/// ENDPOINTS patterns like `/contacts/:agent_id`.
pub fn normalize_path(path: &str, param_positions: &[usize]) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let mut result = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        if param_positions.contains(&i) {
            result.push(":id");
        } else {
            result.push(part);
        }
    }
    result.join("/")
}

/// Checks if a concrete path matches a parameterized endpoint path.
///
/// Example: `/contacts/abc123/machines` matches `/contacts/:agent_id/machines`
pub fn path_matches_endpoint(concrete: &str, pattern: &str) -> bool {
    let concrete_parts: Vec<&str> = concrete.split('/').collect();
    let pattern_parts: Vec<&str> = pattern.split('/').collect();

    if concrete_parts.len() != pattern_parts.len() {
        return false;
    }

    concrete_parts
        .iter()
        .zip(pattern_parts.iter())
        .all(|(c, p)| p.starts_with(':') || c == p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_count_positive() {
        assert!(endpoint_count() > 0);
    }

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches_endpoint("/health", "/health"));
        assert!(!path_matches_endpoint("/health", "/status"));
    }

    #[test]
    fn test_path_matches_parameterized() {
        assert!(path_matches_endpoint(
            "/contacts/abc123",
            "/contacts/:agent_id"
        ));
        assert!(path_matches_endpoint(
            "/contacts/abc/machines/def",
            "/contacts/:agent_id/machines/:machine_id"
        ));
        assert!(!path_matches_endpoint(
            "/contacts/abc/machines",
            "/contacts/:agent_id/machines/:machine_id"
        ));
    }
}
