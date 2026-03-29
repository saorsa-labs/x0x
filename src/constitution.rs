//! The x0x Constitution — embedded at compile time.
//!
//! Every x0x binary carries a copy of the Constitution for Intelligent Entities.
//! It cannot be tampered with post-build — it is literally part of x0x.

/// The full text of the x0x Constitution (Markdown).
pub const CONSTITUTION_MD: &str = include_str!("../CONSTITUTION.md");

/// Constitution version, extracted for programmatic access.
pub const CONSTITUTION_VERSION: &str = "0.8.0";

/// Constitution status.
pub const CONSTITUTION_STATUS: &str = "Draft";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constitution_is_embedded() {
        assert!(!CONSTITUTION_MD.is_empty());
        assert!(CONSTITUTION_MD.contains("Intelligent Entity"));
        assert!(CONSTITUTION_MD.contains("Principle 0"));
        assert!(CONSTITUTION_MD.contains("The only winning move is to play together"));
    }

    #[test]
    fn version_is_set() {
        assert!(!CONSTITUTION_VERSION.is_empty());
        assert!(!CONSTITUTION_STATUS.is_empty());
    }
}
